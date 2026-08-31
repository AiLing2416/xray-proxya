package relaytest

import (
	"context"
	"fmt"
	"sync"
	"time"
	"xray-proxya/internal/config"
)

// RunTest executes diagnostics for a single relay node.
func RunTest(ctx context.Context, cfg *config.UserConfig, alias string, mode Mode) (*TestResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil configuration")
	}

	var targetCO *config.CustomOutbound
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			targetCO = &co
			break
		}
	}
	if targetCO == nil {
		return nil, fmt.Errorf("relay %q not found", alias)
	}

	start := time.Now()
	result := &TestResult{
		Alias:  alias,
		Mode:   mode,
		Status: StatusFail,
	}

	session, err := StartTestSession(ctx, cfg, alias)
	if err != nil {
		result.Error = err.Error()
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}
	defer session.Close()

	// 1. Stage 1: Dual-Stack DNS 53 Transport Probe
	transport := probeDNS53(ctx, session, targetCO.DNSServers)
	result.Transport = transport

	// 2. Stage 1: Exit IP Dual-Stack Probe (non-blocking context, fail-fast if transport dead)
	exitIP := probeExitIP(ctx, session, transport)
	result.ExitIP = exitIP

	// 3. Stage 2 (Full Mode Only): Modern Protocols & UDP Capabilities
	if mode == ModeFull {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			result.ModernProtocols = probeModernProtocols(ctx, session)
		}()
		go func() {
			defer wg.Done()
			result.UDPCapabilities = probeUDPCapabilities(ctx, session)
		}()
		wg.Wait()
	}

	result.DurationMs = time.Since(start).Milliseconds()
	result.Status = evaluateOverallStatus(result)
	return result, nil
}

// RunTests executes tests across multiple relay nodes concurrently.
func RunTests(ctx context.Context, cfg *config.UserConfig, aliases []string, mode Mode, concurrency int) ([]*TestResult, error) {
	if len(aliases) == 0 {
		return nil, nil
	}
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > len(aliases) {
		concurrency = len(aliases)
	}

	results := make([]*TestResult, len(aliases))
	type testJob struct {
		index int
		alias string
	}

	jobs := make(chan testJob, len(aliases))
	for i, alias := range aliases {
		jobs <- testJob{index: i, alias: alias}
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				res, err := RunTest(ctx, cfg, job.alias, mode)
				if err != nil {
					res = &TestResult{
						Alias:  job.alias,
						Mode:   mode,
						Status: StatusFail,
						Error:  err.Error(),
					}
				}
				results[job.index] = res
			}
		}()
	}

	wg.Wait()
	return results, nil
}

func evaluateOverallStatus(r *TestResult) Status {
	if r.Transport.TCPStatus == StatusFail && r.Transport.UDPStatus == StatusFail {
		return StatusFail
	}

	if r.Mode == ModeSimple {
		if r.Transport.TCPStatus == StatusPass && r.Transport.UDPStatus == StatusPass {
			return StatusPass
		}
		return StatusWarn
	}

	// ModeFull
	hasWarn := false
	hasFail := false
	allPass := true

	checkCat := func(cat *CategoryResult) {
		if cat == nil {
			return
		}
		if cat.Status == StatusFail {
			hasFail = true
			allPass = false
		} else if cat.Status == StatusWarn {
			hasWarn = true
			allPass = false
		}
	}

	checkCat(r.ModernProtocols)
	checkCat(r.UDPCapabilities)

	if r.Transport.TCPStatus == StatusFail || r.Transport.UDPStatus == StatusFail {
		hasWarn = true
		allPass = false
	}

	if allPass {
		return StatusPass
	}
	if hasFail && r.Transport.TCPStatus == StatusFail && r.Transport.UDPStatus == StatusFail {
		return StatusFail
	}
	if hasWarn || hasFail {
		return StatusWarn
	}
	return StatusPass
}
