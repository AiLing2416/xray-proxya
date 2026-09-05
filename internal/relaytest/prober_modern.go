package relaytest

import (
	"context"
	"sync"

	"xray-proxya/internal/netprobe"
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
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeDoH(ctx, pt)
	return dur.Milliseconds(), err
}

func probeDoT(ctx context.Context, session *TestSession) (int64, error) {
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeDoT(ctx, pt, "cloudflare-dns.com", "1.1.1.1:853")
	return dur.Milliseconds(), err
}

func probeHTTP2(ctx context.Context, session *TestSession) (int64, error) {
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeHTTP2(ctx, pt, "https://1.1.1.1")
	return dur.Milliseconds(), err
}

func probeHTTP3(ctx context.Context, session *TestSession) (int64, error) {
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeQUIC(ctx, pt, "1.1.1.1:443", "8.8.8.8:443")
	return dur.Milliseconds(), err
}

func probeECH(ctx context.Context, session *TestSession) (int64, error) {
	pt := netprobe.NewProxyTransport(session.Dialer, session.HTTPClient, session.SOCKSAddr)
	dur, err := netprobe.ProbeECH(ctx, pt)
	return dur.Milliseconds(), err
}
