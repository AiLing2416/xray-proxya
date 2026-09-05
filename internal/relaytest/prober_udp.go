package relaytest

import (
	"context"
	"sync"

	"xray-proxya/internal/netprobe"
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
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeSTUN(ctx, pt, "stun.cloudflare.com:3478", "stun.google.com:19302")
	return dur.Milliseconds(), err
}

func probeNTP(ctx context.Context, session *TestSession) (int64, error) {
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeNTP(ctx, pt, "pool.ntp.org:123", "time.google.com:123")
	return dur.Milliseconds(), err
}

func probeLargePacket(ctx context.Context, session *TestSession) (int64, error) {
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeLargeUDP(ctx, pt, "1.1.1.1:53", "8.8.8.8:53", "cloudflare.com")
	return dur.Milliseconds(), err
}
