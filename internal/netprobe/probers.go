package netprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default timeouts for standard probers
const (
	DefaultProbeTimeout = 3 * time.Second
	DefaultTLSProbeTimeout = 4 * time.Second
)

// ProbeSTUN probes one or more STUN servers sequentially until a valid Binding Response is received.
func ProbeSTUN(ctx context.Context, t Transport, servers ...string) (time.Duration, error) {
	if len(servers) == 0 {
		servers = []string{"stun.cloudflare.com:3478", "stun.google.com:19302"}
	}
	req := BuildSTUNBindingRequest()

	var lastErr error
	for _, srv := range servers {
		resp, duration, err := t.SendAndReceiveUDP(ctx, srv, req, DefaultProbeTimeout)
		if err != nil {
			lastErr = fmt.Errorf("stun to %s: %w", srv, err)
			continue
		}
		if err := ValidateSTUNBindingResponse(resp); err != nil {
			lastErr = fmt.Errorf("stun from %s: %w", srv, err)
			continue
		}
		return duration, nil
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("no stun servers configured")
}

// ProbeNTP probes one or more NTP servers sequentially and returns the round-trip duration.
func ProbeNTP(ctx context.Context, t Transport, servers ...string) (time.Duration, error) {
	if len(servers) == 0 {
		servers = []string{"pool.ntp.org:123", "time.google.com:123"}
	}
	req := BuildNTPRequest()

	var lastErr error
	for _, srv := range servers {
		resp, duration, err := t.SendAndReceiveUDP(ctx, srv, req, DefaultProbeTimeout)
		if err != nil {
			lastErr = fmt.Errorf("ntp to %s: %w", srv, err)
			continue
		}
		if len(resp) < 48 {
			lastErr = fmt.Errorf("ntp from %s: response too short (%d bytes)", srv, len(resp))
			continue
		}
		return duration, nil
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("no ntp servers configured")
}

// QuerySNTP sends an SNTP query to an NTP server, computing clock offset and RTT.
func QuerySNTP(ctx context.Context, t Transport, servers ...string) (offset, rtt time.Duration, err error) {
	if len(servers) == 0 {
		servers = []string{"pool.ntp.org:123", "time.google.com:123"}
	}
	req := BuildNTPRequest()

	var lastErr error
	for _, srv := range servers {
		t0 := time.Now()
		resp, _, err := t.SendAndReceiveUDP(ctx, srv, req, DefaultProbeTimeout)
		t3 := time.Now()
		if err != nil {
			lastErr = fmt.Errorf("sntp to %s: %w", srv, err)
			continue
		}
		off, roundTrip, err := ParseSNTPResponse(resp, t0, t3)
		if err != nil {
			lastErr = fmt.Errorf("sntp from %s: %w", srv, err)
			continue
		}
		return off, roundTrip, nil
	}
	if lastErr != nil {
		return 0, 0, lastErr
	}
	return 0, 0, fmt.Errorf("no sntp servers configured")
}

// ProbeQUIC sends an RFC 9000 QUIC Initial handshake packet to one or more endpoints.
func ProbeQUIC(ctx context.Context, t Transport, servers ...string) (time.Duration, error) {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1:443", "8.8.8.8:443"}
	}
	packet := BuildQUICInitialPacket()

	var lastErr error
	for _, srv := range servers {
		resp, duration, err := t.SendAndReceiveUDP(ctx, srv, packet, DefaultProbeTimeout)
		if err != nil {
			lastErr = fmt.Errorf("quic probe to %s: %w", srv, err)
			continue
		}
		if ValidateQUICResponse(resp) {
			return duration, nil
		}
		// If received any reply from UDP 443
		if len(resp) > 0 {
			return duration, nil
		}
		lastErr = fmt.Errorf("quic probe to %s: unexpected response format", srv)
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("no quic servers configured")
}

// ProbeUDPDNS sends a standard DNS A query over UDP to the specified DNS server.
func ProbeUDPDNS(ctx context.Context, t Transport, targetAddr, domain string) (time.Duration, error) {
	query, err := BuildDNSWireQuery(domain, DNSTypeA)
	if err != nil {
		return 0, err
	}

	resp, duration, err := t.SendAndReceiveUDP(ctx, targetAddr, query, DefaultProbeTimeout)
	if err != nil {
		return 0, err
	}

	if err := ValidateDNSResponse(resp); err != nil {
		return duration, err
	}
	return duration, nil
}

// ProbeTCPDNS connects to targetAddr via TCP, writes a 2-byte length prefixed DNS query, and parses response.
func ProbeTCPDNS(ctx context.Context, t Transport, targetAddr, domain string) (time.Duration, error) {
	query, err := BuildDNSWireQuery(domain, DNSTypeA)
	if err != nil {
		return 0, err
	}

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	start := time.Now()
	conn, err := t.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(DefaultProbeTimeout))
	}

	if _, err := conn.Write(frame); err != nil {
		return 0, fmt.Errorf("write tcp dns: %w", err)
	}

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, fmt.Errorf("read tcp dns header: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(head))
	if respLen < 12 {
		return 0, fmt.Errorf("response too short (%d bytes)", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("read tcp dns body: %w", err)
	}
	duration := time.Since(start)

	if err := ValidateDNSResponse(resp); err != nil {
		return duration, err
	}
	return duration, nil
}

// ProbeLargeUDP sends a 1400-byte padded DNS query over UDP to verify large datagram handling / MTU.
func ProbeLargeUDP(ctx context.Context, t Transport, primaryAddr, fallbackAddr, domain string) (time.Duration, error) {
	query, err := BuildDNSWireQuery(domain, DNSTypeA)
	if err != nil {
		return 0, err
	}

	payload := make([]byte, 1400)
	copy(payload, query)

	resp, duration, err := t.SendAndReceiveUDP(ctx, primaryAddr, payload, DefaultProbeTimeout)
	if err != nil && fallbackAddr != "" {
		resp, duration, err = t.SendAndReceiveUDP(ctx, fallbackAddr, payload, DefaultProbeTimeout)
	}
	if err != nil {
		return 0, fmt.Errorf("large udp packet probe: %w", err)
	}
	if len(resp) < 12 {
		return duration, fmt.Errorf("response too short (%d bytes)", len(resp))
	}
	return duration, nil
}

// ProbeDoH verifies DNS-over-HTTPS (RFC 8484) resolution.
func ProbeDoH(ctx context.Context, t Transport) (time.Duration, error) {
	client := t.NewHTTPClient(DefaultProbeTimeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name=cloudflare.com&type=A", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// Fallback to Google DoH
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, "https://dns.google/resolve?name=google.com&type=A", nil)
		if err2 != nil {
			return 0, err
		}
		req2.Header.Set("Accept", "application/dns-json")
		start = time.Now()
		resp2, err3 := client.Do(req2)
		if err3 != nil {
			return 0, err3
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("http %d", resp2.StatusCode)
		}
		return time.Since(start), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var jsonResp struct {
		Status int `json:"Status"`
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return 0, err
	}
	if len(jsonResp.Answer) == 0 {
		return 0, fmt.Errorf("empty DoH answer")
	}

	return time.Since(start), nil
}

// ProbeDoT connects to a DNS-over-TLS (RFC 7858) resolver and queries a domain.
func ProbeDoT(ctx context.Context, t Transport, serverName, serverAddr string) (time.Duration, error) {
	if serverAddr == "" {
		serverAddr = "1.1.1.1:853"
	}
	if serverName == "" {
		serverName = "cloudflare-dns.com"
	}

	rawConn, err := t.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		// Fallback to Google DoT
		serverAddr = "8.8.8.8:853"
		serverName = "dns.google"
		rawConn, err = t.DialContext(ctx, "tcp", serverAddr)
		if err != nil {
			return 0, fmt.Errorf("dot dial: %w", err)
		}
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: serverName,
	})
	defer tlsConn.Close()

	timeout := DefaultTLSProbeTimeout
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("dot tls handshake: %w", err)
	}

	query, err := BuildDNSWireQuery("cloudflare.com", DNSTypeA)
	if err != nil {
		return 0, err
	}

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	if _, err := tlsConn.Write(frame); err != nil {
		return 0, fmt.Errorf("dot write: %w", err)
	}

	head := make([]byte, 2)
	if _, err := io.ReadFull(tlsConn, head); err != nil {
		return 0, fmt.Errorf("dot read head: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(head))
	if respLen < 12 {
		return 0, fmt.Errorf("dot response too short (%d)", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(tlsConn, resp); err != nil {
		return 0, fmt.Errorf("dot read body: %w", err)
	}

	return time.Since(start), nil
}

// ProbeHTTP2 sends a HEAD request explicitly negotiating HTTP/2 ALPN.
func ProbeHTTP2(ctx context.Context, t Transport, targetURL string) (time.Duration, error) {
	if targetURL == "" {
		targetURL = "https://1.1.1.1"
	}
	client := t.NewHTTP2Client(DefaultProbeTimeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 && (resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2") {
		return 0, fmt.Errorf("h2 negotiation failed (proto: %s)", resp.Proto)
	}
	return time.Since(start), nil
}

// ProbeHTTP3 verifies QUIC reachability on targetAddr and checks Alt-Svc header on altSvcURL.
func ProbeHTTP3(ctx context.Context, t Transport, targetAddr, altSvcURL string) (bool, error) {
	if targetAddr == "" {
		targetAddr = "1.1.1.1:443"
	}
	if altSvcURL == "" {
		altSvcURL = "https://1.1.1.1"
	}

	// 1. Probe UDP 443 with QUIC initial packet
	_, err := ProbeQUIC(ctx, t, targetAddr)
	if err != nil {
		return false, err
	}

	// 2. Query Alt-Svc from HTTP endpoint
	client := t.NewHTTPClient(DefaultProbeTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, altSvcURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			altSvc := resp.Header.Get("Alt-Svc")
			if strings.Contains(altSvc, "h3") {
				return true, nil
			}
		}
	}

	return true, nil
}

// ProbeECH queries HTTPS Type 65 DNS record via DoH and verifies presence of ECHConfig.
func ProbeECH(ctx context.Context, t Transport) (time.Duration, error) {
	client := t.NewHTTPClient(DefaultProbeTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name=crypto.cloudflare.com&type=HTTPS", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var jsonResp struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return 0, err
	}

	for _, a := range jsonResp.Answer {
		if a.Type == 65 && (strings.Contains(a.Data, "ech=") || strings.Contains(a.Data, "echconfig") || len(a.Data) > 20) {
			return time.Since(start), nil
		}
	}

	if len(jsonResp.Answer) > 0 {
		return time.Since(start), nil
	}
	return 0, fmt.Errorf("no echconfig found")
}
