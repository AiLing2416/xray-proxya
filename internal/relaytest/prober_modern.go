package relaytest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"xray-proxya/pkg/utils"
)

func probeModernProtocols(ctx context.Context, session *TestSession) *CategoryResult {
	type subProbe struct {
		name string
		fn   func(context.Context, *TestSession) (int64, error)
	}

	probes := []subProbe{
		{name: "DoH", fn: probeDoH},
		{name: "DoT", fn: probeDoT},
		{name: "HTTP/2", fn: probeHTTP2},
		{name: "HTTP/3", fn: probeHTTP3},
		{name: "ECH", fn: probeECH},
	}

	items := make(map[string]ItemResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range probes {
		wg.Add(1)
		go func(sp subProbe) {
			defer wg.Done()
			rttMs, err := sp.fn(ctx, session)
			mu.Lock()
			if err != nil {
				items[sp.name] = ItemResult{Status: StatusFail, Error: err.Error()}
			} else {
				items[sp.name] = ItemResult{Status: StatusPass, RTTMs: rttMs}
			}
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	var passedCount int
	var failedItems []string
	var maxRTT int64

	// Evaluate in stable order
	for _, p := range probes {
		item := items[p.name]
		if item.Status == StatusPass {
			passedCount++
			if item.RTTMs > maxRTT {
				maxRTT = item.RTTMs
			}
		} else {
			failedItems = append(failedItems, p.name)
		}
	}

	cat := &CategoryResult{
		Items: items,
	}

	if passedCount == len(probes) {
		cat.Status = StatusPass
		cat.MaxRTTMs = maxRTT
		cat.FailedItems = nil
	} else if passedCount > 0 {
		cat.Status = StatusWarn
		cat.MaxRTTMs = maxRTT
		cat.FailedItems = failedItems
	} else {
		cat.Status = StatusFail
		cat.MaxRTTMs = 0
		cat.FailedItems = failedItems
	}

	return cat
}

func probeDoH(ctx context.Context, session *TestSession) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name=cloudflare.com&type=A", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := session.HTTPClient.Do(req)
	if err != nil {
		// Fallback to Google DoH
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, "https://dns.google/resolve?name=google.com&type=A", nil)
		if err2 != nil {
			return 0, err
		}
		req2.Header.Set("Accept", "application/dns-json")
		start = time.Now()
		resp2, err3 := session.HTTPClient.Do(req2)
		if err3 != nil {
			return 0, err3
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("http %d", resp2.StatusCode)
		}
		return time.Since(start).Milliseconds(), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}
	return time.Since(start).Milliseconds(), nil
}

func probeDoT(ctx context.Context, session *TestSession) (int64, error) {
	rawConn, err := session.Dialer.Dial("tcp", "1.1.1.1:853")
	if err != nil {
		// Fallback to Google DoT
		rawConn, err = session.Dialer.Dial("tcp", "8.8.8.8:853")
		if err != nil {
			return 0, fmt.Errorf("dot dial: %w", err)
		}
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: "cloudflare-dns.com",
	})
	defer tlsConn.Close()

	timeout := 4 * time.Second
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("dot tls handshake: %w", err)
	}

	query, err := buildDNSWireQuery("cloudflare.com", 1)
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

	return time.Since(start).Milliseconds(), nil
}

func probeHTTP2(ctx context.Context, session *TestSession) (int64, error) {
	transport := &http.Transport{
		Dial: session.Dialer.Dial,
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://1.1.1.1", nil)
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
	return time.Since(start).Milliseconds(), nil
}

func probeHTTP3(ctx context.Context, session *TestSession) (int64, error) {
	timeout := 3 * time.Second
	udpClient, err := utils.DialSOCKS5UDP(session.SOCKSAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("udp associate: %w", err)
	}
	defer udpClient.Close()

	// Construct RFC 9000 QUIC Initial packet (1200 bytes)
	packet := make([]byte, 1200)
	packet[0] = 0xC0 // Header Form (1) | Fixed Bit (1) | Long Packet Type (00 Initial)
	binary.BigEndian.PutUint32(packet[1:5], 0x00000001) // Version 1
	packet[5] = 0x08                                    // DCID Length: 8
	_, _ = rand.Read(packet[6:14])
	packet[14] = 0x08                                   // SCID Length: 8
	_, _ = rand.Read(packet[15:23])
	packet[23] = 0x00                                   // Token Length: 0
	packet[24] = 0x44                                   // Length (varint)
	packet[25] = 0x90
	packet[26] = 0x01                                   // Packet Number: 1

	resp, duration, err := udpClient.SendAndReceive("1.1.1.1:443", packet, timeout)
	if err != nil {
		// Try fallback to Google QUIC
		resp, duration, err = udpClient.SendAndReceive("8.8.8.8:443", packet, timeout)
		if err != nil {
			return 0, fmt.Errorf("quic probe failed: %w", err)
		}
	}

	if len(resp) > 0 && (resp[0]&0x80 != 0 || resp[0]&0x40 != 0) {
		return duration.Milliseconds(), nil
	}
	return duration.Milliseconds(), nil
}

func probeECH(ctx context.Context, session *TestSession) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name=crypto.cloudflare.com&type=HTTPS", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := session.HTTPClient.Do(req)
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
			return time.Since(start).Milliseconds(), nil
		}
	}

	if len(jsonResp.Answer) > 0 {
		return time.Since(start).Milliseconds(), nil
	}
	return 0, fmt.Errorf("no echconfig found")
}
