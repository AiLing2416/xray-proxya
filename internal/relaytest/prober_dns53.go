package relaytest

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"xray-proxya/pkg/utils"
)

type dnsTarget struct {
	name   string
	proto  string // "tcp" or "udp"
	family string // "v4" or "v6"
	addr   string
	domain string
}

func defaultDNSTargets(customServers []string) []dnsTarget {
	targets := []dnsTarget{
		{name: "google_v4_tcp", proto: "tcp", family: "v4", addr: "8.8.8.8:53", domain: "google.com"},
		{name: "google_v4_udp", proto: "udp", family: "v4", addr: "8.8.8.8:53", domain: "google.com"},
		{name: "cloudflare_v4_tcp", proto: "tcp", family: "v4", addr: "1.1.1.1:53", domain: "cloudflare.com"},
		{name: "cloudflare_v4_udp", proto: "udp", family: "v4", addr: "1.1.1.1:53", domain: "cloudflare.com"},
		{name: "google_v6_tcp", proto: "tcp", family: "v6", addr: "[2001:4860:4860::8888]:53", domain: "google.com"},
		{name: "google_v6_udp", proto: "udp", family: "v6", addr: "[2001:4860:4860::8888]:53", domain: "google.com"},
		{name: "cloudflare_v6_tcp", proto: "tcp", family: "v6", addr: "[2606:4700:4700::1111]:53", domain: "cloudflare.com"},
		{name: "cloudflare_v6_udp", proto: "udp", family: "v6", addr: "[2606:4700:4700::1111]:53", domain: "cloudflare.com"},
	}

	for i, s := range customServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host := s
		if strings.Contains(s, "://") {
			if u, err := url.Parse(s); err == nil {
				host = u.Hostname()
			}
		} else if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if host != "" {
			targetAddr := net.JoinHostPort(host, "53")
			fam := "v4"
			if strings.Contains(host, ":") {
				fam = "v6"
			}
			targets = append(targets,
				dnsTarget{name: fmt.Sprintf("custom_%d_tcp", i+1), proto: "tcp", family: fam, addr: targetAddr, domain: "google.com"},
				dnsTarget{name: fmt.Sprintf("custom_%d_udp", i+1), proto: "udp", family: fam, addr: targetAddr, domain: "google.com"},
			)
		}
	}
	return targets
}

func probeDNS53(ctx context.Context, session *TestSession, customServers []string) TransportResult {
	targets := defaultDNSTargets(customServers)
	rawItems := make(map[string]ItemResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(tgt dnsTarget) {
			defer wg.Done()
			var r ItemResult
			if tgt.proto == "tcp" {
				rtt, err := probeTCPDNS(ctx, session.Dialer, tgt.addr, tgt.domain)
				if err != nil {
					r = ItemResult{Status: StatusFail, Error: err.Error()}
				} else {
					r = ItemResult{Status: StatusPass, RTTMs: rtt.Milliseconds()}
				}
			} else {
				rtt, err := probeUDPDNS(ctx, session.SOCKSAddr, tgt.addr, tgt.domain)
				if err != nil {
					r = ItemResult{Status: StatusFail, Error: err.Error()}
				} else {
					r = ItemResult{Status: StatusPass, RTTMs: rtt.Milliseconds()}
				}
			}
			mu.Lock()
			rawItems[tgt.name] = r
			mu.Unlock()
		}(t)
	}

	wg.Wait()

	var maxTCPRTT int64 = 0
	tcpPassCount := 0
	var maxUDPRTT int64 = 0
	udpPassCount := 0

	for _, t := range targets {
		r := rawItems[t.name]
		if t.proto == "tcp" {
			if r.Status == StatusPass {
				tcpPassCount++
				if r.RTTMs > maxTCPRTT {
					maxTCPRTT = r.RTTMs
				}
			}
		} else {
			if r.Status == StatusPass {
				udpPassCount++
				if r.RTTMs > maxUDPRTT {
					maxUDPRTT = r.RTTMs
				}
			}
		}
	}

	res := TransportResult{
		TCPStatus: StatusFail,
		UDPStatus: StatusFail,
		RawItems:  rawItems,
	}

	if tcpPassCount > 0 {
		res.TCPStatus = StatusPass
		res.TCPRTTMs = maxTCPRTT
	}
	if udpPassCount > 0 {
		res.UDPStatus = StatusPass
		res.UDPRTTMs = maxUDPRTT
	}

	return res
}

func probeTCPDNS(ctx context.Context, dialer *utils.SOCKS5Dialer, targetAddr, domain string) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	timeout := 4 * time.Second
	if ok {
		rem := time.Until(deadline)
		if rem < timeout {
			timeout = rem
		}
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return 0, fmt.Errorf("tcp dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	query, err := buildDNSWireQuery(domain, 1) // Type A
	if err != nil {
		return 0, err
	}

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	start := time.Now()
	if _, err := conn.Write(frame); err != nil {
		return 0, fmt.Errorf("tcp write: %w", err)
	}

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, fmt.Errorf("read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(head))
	if respLen < 12 {
		return 0, fmt.Errorf("response too short (%d bytes)", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}
	duration := time.Since(start)

	// Check QR flag and ANCOUNT
	qr := (resp[2] & 0x80) != 0
	if !qr {
		return duration, fmt.Errorf("not a dns response")
	}
	return duration, nil
}

func probeUDPDNS(ctx context.Context, socksAddr, targetAddr, domain string) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	timeout := 4 * time.Second
	if ok {
		rem := time.Until(deadline)
		if rem < timeout {
			timeout = rem
		}
	}

	udpClient, err := utils.DialSOCKS5UDP(socksAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("socks5 udp associate: %w", err)
	}
	defer udpClient.Close()

	query, err := buildDNSWireQuery(domain, 1) // Type A
	if err != nil {
		return 0, err
	}

	resp, duration, err := udpClient.SendAndReceive(targetAddr, query, timeout)
	if err != nil {
		return 0, err
	}

	if len(resp) < 12 {
		return duration, fmt.Errorf("dns response too short (%d bytes)", len(resp))
	}
	qr := (resp[2] & 0x80) != 0
	if !qr {
		return duration, fmt.Errorf("not a dns response")
	}
	return duration, nil
}

func buildDNSWireQuery(domain string, qtype uint16) ([]byte, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], 0x1234) // Transaction ID
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // Standard query with RD set
	binary.BigEndian.PutUint16(packet[4:6], 1)      // QDCOUNT = 1

	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid domain label %q", label)
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00)

	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], qtype)
	binary.BigEndian.PutUint16(qtail[2:4], 1) // Class IN
	packet = append(packet, qtail...)
	return packet, nil
}
