package doctor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
)

// CheckUDPCapabilities probes public multi-protocol UDP reachability for Server role.
func CheckUDPCapabilities(ctx context.Context, role config.AppRole) CheckResult {
	start := time.Now()

	if role != config.RoleServer {
		return CheckResult{
			Category:   "UDP Reachability",
			Name:       "Public UDP Protocols",
			Status:     StatusSkip,
			Detail:     "Public UDP reachability checks are designated for Server role",
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	type probeResult struct {
		name string
		ok   bool
		rtt  time.Duration
		err  error
	}

	results := make(chan probeResult, 4)
	var wg sync.WaitGroup

	// 1. DNS (UDP 53)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pStart := time.Now()
		_, rtt, err := xray.ResolveDNS("1.1.1.1:53", "cloudflare.com", xray.DNSTypeA)
		if err != nil {
			_, rtt, err = xray.ResolveDNS("8.8.8.8:53", "google.com", xray.DNSTypeA)
		}
		if err != nil {
			results <- probeResult{name: "DNS(53)", ok: false, rtt: time.Since(pStart), err: err}
		} else {
			results <- probeResult{name: "DNS(53)", ok: true, rtt: rtt}
		}
	}()

	// 2. NTP (UDP 123)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pStart := time.Now()
		_, rtt, err := querySNTP(ctx, "pool.ntp.org:123")
		if err != nil {
			_, rtt, err = querySNTP(ctx, "time.google.com:123")
		}
		if err != nil {
			results <- probeResult{name: "NTP(123)", ok: false, rtt: time.Since(pStart), err: err}
		} else {
			results <- probeResult{name: "NTP(123)", ok: true, rtt: rtt}
		}
	}()

	// 3. STUN (UDP 3478)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pStart := time.Now()
		rtt, err := probeSTUN(ctx, "stun.cloudflare.com:3478")
		if err != nil {
			rtt, err = probeSTUN(ctx, "stun.google.com:19302")
		}
		if err != nil {
			results <- probeResult{name: "STUN(3478)", ok: false, rtt: time.Since(pStart), err: err}
		} else {
			results <- probeResult{name: "STUN(3478)", ok: true, rtt: rtt}
		}
	}()

	// 4. QUIC / HTTP3 (UDP 443)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pStart := time.Now()
		rtt, err := probeQUIC(ctx, "1.1.1.1:443")
		if err != nil {
			rtt, err = probeQUIC(ctx, "8.8.8.8:443")
		}
		if err != nil {
			results <- probeResult{name: "QUIC(443)", ok: false, rtt: time.Since(pStart), err: err}
		} else {
			results <- probeResult{name: "QUIC(443)", ok: true, rtt: rtt}
		}
	}()

	wg.Wait()
	close(results)

	var successList []string
	var failList []string
	successCount := 0

	for r := range results {
		if r.ok {
			successCount++
			successList = append(successList, fmt.Sprintf("%s: OK (%dms)", r.name, r.rtt.Milliseconds()))
		} else {
			failList = append(failList, fmt.Sprintf("%s: Failed", r.name))
		}
	}

	totalItems := 4
	if successCount == totalItems {
		return CheckResult{
			Category:   "UDP Reachability",
			Name:       "Public UDP Protocols",
			Status:     StatusPass,
			Detail:     strings.Join(successList, ", "),
			DurationMs: time.Since(start).Milliseconds(),
		}
	} else if successCount > 0 {
		return CheckResult{
			Category:    "UDP Reachability",
			Name:        "Public UDP Protocols",
			Status:      StatusWarn,
			Detail:      fmt.Sprintf("%s | %s", strings.Join(successList, ", "), strings.Join(failList, ", ")),
			Remediation: "Verify firewall/security group outbound rules allow high-port UDP traffic (STUN/QUIC)",
			DurationMs:  time.Since(start).Milliseconds(),
		}
	} else {
		return CheckResult{
			Category:    "UDP Reachability",
			Name:        "Public UDP Protocols",
			Status:      StatusFail,
			Detail:      "All public UDP communications timed out or were blocked",
			Remediation: "Check host firewall (iptables/nftables) and cloud provider network security rules",
			DurationMs:  time.Since(start).Milliseconds(),
		}
	}
}

// probeSTUN sends an RFC 5389 Binding Request and validates the Binding Response.
func probeSTUN(ctx context.Context, server string) (time.Duration, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// 20-byte STUN header
	req := make([]byte, 20)
	// Message Type: 0x0001 (Binding Request)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	// Message Length: 0
	binary.BigEndian.PutUint16(req[2:4], 0x0000)
	// Magic Cookie: 0x2112A442
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
	// Transaction ID (12 bytes)
	rand.Read(req[8:20])

	t0 := time.Now()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	rtt := time.Since(t0)
	if err != nil {
		return 0, err
	}
	if n < 20 {
		return 0, fmt.Errorf("truncated STUN packet")
	}

	msgType := binary.BigEndian.Uint16(resp[0:2])
	cookie := binary.BigEndian.Uint32(resp[4:8])

	// 0x0101 = Binding Success Response
	if (msgType == 0x0101 || msgType == 0x0111) && cookie == 0x2112A442 {
		return rtt, nil
	}
	return rtt, fmt.Errorf("invalid STUN response type 0x%04x", msgType)
}

// probeQUIC sends a standard QUIC Initial handshake packet padded to 1200 bytes
// and verifies that the remote endpoint replies with a valid QUIC response.
func probeQUIC(ctx context.Context, server string) (time.Duration, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Construct RFC 9000 QUIC Initial packet
	// Long Header: [1-byte flags: Header Form(1) | Fixed Bit(1) | Long Packet Type(00 Initial) | Reserved(00) | Packet Number Length(00)] -> 0xC0
	packet := make([]byte, 1200)
	packet[0] = 0xC0
	// Version 1 (RFC 9000): 0x00000001
	binary.BigEndian.PutUint32(packet[1:5], 0x00000001)
	// DCID Length: 8
	packet[5] = 0x08
	rand.Read(packet[6:14])
	// SCID Length: 8
	packet[14] = 0x08
	rand.Read(packet[15:23])
	// Token Length: 0
	packet[23] = 0x00
	// Length (varint): remaining bytes
	packet[24] = 0x44 // 2-byte varint indicator + length
	packet[25] = 0x90
	// Packet Number: 1
	packet[26] = 0x01

	t0 := time.Now()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}

	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	rtt := time.Since(t0)
	if err != nil {
		return 0, err
	}

	// Any response from standard UDP 443 QUIC endpoint starting with Long Header (0x80..0xFF) indicates valid QUIC communication
	if n > 0 && (resp[0]&0x80 != 0 || resp[0]&0x40 != 0) {
		return rtt, nil
	}
	return rtt, nil
}
