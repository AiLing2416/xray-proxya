package relayinfo

import (
	"context"
	"fmt"
	"sync"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/relaytest"
)

// RunInfo executes landing profile and unlock checks for a single relay node with IP family policy.
func RunInfo(ctx context.Context, cfg *config.UserConfig, alias string, mode Mode, family IPFamily) (*InfoResult, error) {
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

	if family == "" {
		family = IPFamilyAuto
	}

	start := time.Now()
	res := &InfoResult{
		Alias:  alias,
		Mode:   mode,
		Family: family,
	}

	session, err := relaytest.StartTestSession(ctx, cfg, alias)
	if err != nil {
		res.Error = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}
	defer session.Close()

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// If family is explicitly known (-4, -6, -n), we can probe everything fully in parallel.
	if family != IPFamilyAuto {
		directedClient := newDirectedHTTPClient(session, family)
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			res.Profile = probeProfile(probeCtx, session, mode, family)
		}()

		go func() {
			defer wg.Done()
			res.Streaming = probeStreaming(probeCtx, directedClient)
		}()

		go func() {
			defer wg.Done()
			res.General = probeGeneral(probeCtx, directedClient)
		}()

		wg.Wait()
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}

	// In Auto mode: probe Profile first to discover IPv4/IPv6 capability.
	res.Profile = probeProfile(probeCtx, session, mode, family)

	// Determine effective family: prefer IPv4, fallback to IPv6 if node is IPv6-only.
	effectiveFamily := IPFamilyIPv4
	if res.Profile.IPv4 == "" && res.Profile.IPv6 != "" {
		effectiveFamily = IPFamilyIPv6
	} else if res.Profile.IPv4 == "" && res.Profile.IPv6 == "" {
		effectiveFamily = IPFamilyNatural
	}
	res.Family = effectiveFamily

	directedClient := newDirectedHTTPClient(session, effectiveFamily)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		res.Streaming = probeStreaming(probeCtx, directedClient)
	}()

	go func() {
		defer wg.Done()
		res.General = probeGeneral(probeCtx, directedClient)
	}()

	wg.Wait()

	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// RunInfos executes landing profile and unlock checks across multiple relay nodes concurrently.
func RunInfos(ctx context.Context, cfg *config.UserConfig, aliases []string, mode Mode, family IPFamily, concurrency int) ([]*InfoResult, error) {
	if len(aliases) == 0 {
		return nil, nil
	}
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > len(aliases) {
		concurrency = len(aliases)
	}

	results := make([]*InfoResult, len(aliases))
	type infoJob struct {
		index int
		alias string
	}

	jobs := make(chan infoJob, len(aliases))
	for i, alias := range aliases {
		jobs <- infoJob{index: i, alias: alias}
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				res, err := RunInfo(ctx, cfg, job.alias, mode, family)
				if err != nil {
					res = &InfoResult{
						Alias:  job.alias,
						Mode:   mode,
						Family: family,
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
