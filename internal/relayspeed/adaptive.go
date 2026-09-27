package relayspeed

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultProbeBytes     int64   = 1024 * 1024        // 1MB probe request
	minAdaptiveBytes      int64   = 2 * 1024 * 1024    // 2MB safe lower bound
	maxAdaptiveBytes      int64   = 100 * 1024 * 1024  // 100MB safe upper bound
	defaultTargetDuration float64 = 2.5                // 2.5 seconds target steady-state duration
	probeTimeout                  = 4 * time.Second
)

// ProbeBandwidth sends a lightweight ~1MB request to estimate node bandwidth and round-trip time.
// It sets a short timeout (4s). If the probe does not complete 1MB within timeout, it estimates
// bandwidth from the partially received bytes and elapsed time without deadlocking or failing.
func ProbeBandwidth(ctx context.Context, client *http.Client, provider Provider) (bps float64, rtt time.Duration, err error) {
	if client == nil || provider == nil {
		return 0, 0, fmt.Errorf("nil client or provider")
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := provider.GetDownloadRequest(probeCtx, client, defaultProbeBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("create probe request: %w", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("probe request: %w", err)
	}
	defer resp.Body.Close()

	ttfb := time.Since(start)
	if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
		return 0, ttfb, fmt.Errorf("probe HTTP %d", resp.StatusCode)
	}

	buf := make([]byte, defaultChunkSize)
	var totalBytes int64

	for {
		select {
		case <-probeCtx.Done():
			goto FINISH
		default:
		}

		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
		}
		if rErr != nil {
			break
		}
	}

FINISH:
	elapsed := time.Since(start)
	if totalBytes == 0 {
		if probeCtx.Err() != nil {
			return 0, ttfb, probeCtx.Err()
		}
		return 0, ttfb, fmt.Errorf("probe received 0 bytes")
	}

	if elapsed <= 0 {
		elapsed = time.Millisecond
	}

	bps = float64(totalBytes*8) / elapsed.Seconds()
	return bps, ttfb, nil
}

// CalculateAdaptiveSize infers the target test size in bytes based on estimated probe bandwidth
// and target duration. The result is clamped to [minAdaptiveBytes, maxAdaptiveBytes] (2MB ~ 100MB).
func CalculateAdaptiveSize(probeBps float64, targetDurationSec float64) int64 {
	if targetDurationSec <= 0 {
		targetDurationSec = defaultTargetDuration
	}

	targetBytes := int64(probeBps * targetDurationSec / 8.0)
	if targetBytes < minAdaptiveBytes {
		return minAdaptiveBytes
	}
	if targetBytes > maxAdaptiveBytes {
		return maxAdaptiveBytes
	}
	return targetBytes
}
