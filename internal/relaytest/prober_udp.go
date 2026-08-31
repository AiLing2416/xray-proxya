package relaytest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"xray-proxya/pkg/utils"
)

func probeUDPCapabilities(ctx context.Context, session *TestSession) *CategoryResult {
	type subProbe struct {
		name string
		fn   func(context.Context, *TestSession) (int64, error)
	}

	probes := []subProbe{
		{name: "STUN", fn: probeSTUN},
		{name: "NTP", fn: probeNTP},
		{name: "LargePacket", fn: probeLargePacket},
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

func probeSTUN(ctx context.Context, session *TestSession) (int64, error) {
	timeout := 3 * time.Second
	udpClient, err := utils.DialSOCKS5UDP(session.SOCKSAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("udp associate: %w", err)
	}
	defer udpClient.Close()

	// 20-byte STUN Binding Request header
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0x0000) // Message Length: 0
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442) // Magic Cookie
	_, _ = rand.Read(req[8:20])                  // Transaction ID

	resp, duration, err := udpClient.SendAndReceive("stun.cloudflare.com:3478", req, timeout)
	if err != nil {
		// Fallback to Google STUN
		resp, duration, err = udpClient.SendAndReceive("stun.google.com:19302", req, timeout)
		if err != nil {
			return 0, fmt.Errorf("stun failed: %w", err)
		}
	}

	if len(resp) < 20 {
		return duration.Milliseconds(), fmt.Errorf("truncated stun response")
	}

	msgType := binary.BigEndian.Uint16(resp[0:2])
	cookie := binary.BigEndian.Uint32(resp[4:8])
	if (msgType == 0x0101 || msgType == 0x0111) && cookie == 0x2112A442 {
		return duration.Milliseconds(), nil
	}
	return duration.Milliseconds(), fmt.Errorf("invalid stun response type 0x%04x", msgType)
}

func probeNTP(ctx context.Context, session *TestSession) (int64, error) {
	timeout := 3 * time.Second
	udpClient, err := utils.DialSOCKS5UDP(session.SOCKSAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("udp associate: %w", err)
	}
	defer udpClient.Close()

	// 48-byte NTP client request packet: LI=0, VN=4, Mode=3 -> 0x23
	req := make([]byte, 48)
	req[0] = 0x23

	resp, duration, err := udpClient.SendAndReceive("pool.ntp.org:123", req, timeout)
	if err != nil {
		// Fallback to Google NTP
		resp, duration, err = udpClient.SendAndReceive("time.google.com:123", req, timeout)
		if err != nil {
			return 0, fmt.Errorf("ntp failed: %w", err)
		}
	}

	if len(resp) < 48 {
		return duration.Milliseconds(), fmt.Errorf("ntp response too short (%d)", len(resp))
	}
	return duration.Milliseconds(), nil
}

func probeLargePacket(ctx context.Context, session *TestSession) (int64, error) {
	timeout := 3 * time.Second
	udpClient, err := utils.DialSOCKS5UDP(session.SOCKSAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("udp associate: %w", err)
	}
	defer udpClient.Close()

	// Build EDNS0 query with EDNS buffer size 1400 and padding
	query, err := buildDNSWireQuery("cloudflare.com", 1)
	if err != nil {
		return 0, err
	}

	// Pad to 1400 bytes
	payload := make([]byte, 1400)
	copy(payload, query)

	resp, duration, err := udpClient.SendAndReceive("1.1.1.1:53", payload, timeout)
	if err != nil {
		resp, duration, err = udpClient.SendAndReceive("8.8.8.8:53", payload, timeout)
		if err != nil {
			return 0, fmt.Errorf("large udp packet failed: %w", err)
		}
	}

	if len(resp) < 12 {
		return duration.Milliseconds(), fmt.Errorf("response too short (%d)", len(resp))
	}
	return duration.Milliseconds(), nil
}
