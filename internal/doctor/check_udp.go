package doctor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/netprobe"
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
	dt := &netprobe.DirectTransport{}

	// 1. DNS (UDP 53)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pStart := time.Now()
		rtt, err := netprobe.ProbeUDPDNS(ctx, dt, "1.1.1.1:53", "cloudflare.com")
		if err != nil {
			rtt, err = netprobe.ProbeUDPDNS(ctx, dt, "8.8.8.8:53", "google.com")
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
		_, rtt, err := netprobe.QuerySNTP(ctx, dt, "pool.ntp.org:123", "time.google.com:123")
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
		rtt, err := netprobe.ProbeSTUN(ctx, dt, "stun.cloudflare.com:3478", "stun.google.com:19302")
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
		rtt, err := netprobe.ProbeQUIC(ctx, dt, "1.1.1.1:443", "8.8.8.8:443")
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
