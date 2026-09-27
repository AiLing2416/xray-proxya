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

var AutoThreadLadder = []int{1, 2, 4, 6, 8}

const (
	MaxAutoTransferBytes      int64   = 240 * 1024 * 1024 // 240MB cumulative limit
	InitialStepBytes          int64   = 5 * 1024 * 1024   // 5MB initial step (1 stream)
	MinPerThreadChunkBytes    int64   = 2 * 1024 * 1024   // 2MB min per stream
	SpeedImprovementThreshold float64 = 0.12              // 12% improvement required to escalate
)

// RunAdaptiveDownload performs active concurrency & size escalation probing.
// It steps through 1, 2, 4, 6, 8 threads, dynamically adjusting test chunk size.
// If a higher thread count achieves higher speed (>12% gain), it continues to escalate.
// Once speed plateaus or 8 threads / 240MB cumulative transfer is reached, it locks in
// the converged stable throughput and optimal thread count.
func RunAdaptiveDownload(
	ctx context.Context,
	client *http.Client,
	prober *LatencyProber,
	provider Provider,
	idleLat time.Duration,
	alias string,
	progressCb ProgressCallback,
) (*SpeedMetrics, int, error) {
	if client == nil || provider == nil {
		return nil, 0, fmt.Errorf("nil client or provider")
	}

	startTime := time.Now()
	var (
		cumulativeBytes int64
		bestMetrics     *SpeedMetrics
		bestThreads     = 1
		prevSpeed       = 0.0
	)

	for stepIdx, threads := range AutoThreadLadder {
		select {
		case <-ctx.Done():
			if bestMetrics != nil {
				goto FINISH
			}
			return nil, 0, ctx.Err()
		default:
		}

		// Calculate step size
		var stepSize int64
		if stepIdx == 0 {
			stepSize = InitialStepBytes // 5MB
		} else {
			// Estimate size for ~2.0 seconds based on previous measured speed
			est := int64(prevSpeed * 2.0 / 8.0)
			minReq := int64(threads) * MinPerThreadChunkBytes
			if est < minReq {
				est = minReq
			}
			stepSize = est
		}

		// Enforce cumulative 240MB budget
		remBudget := MaxAutoTransferBytes - cumulativeBytes
		minReq := int64(threads) * MinPerThreadChunkBytes
		if remBudget < minReq && bestMetrics != nil {
			if progressCb != nil {
				progressCb(ProgressUpdate{
					Alias:       alias,
					Phase:       "auto_step_stable",
					StepThreads: bestThreads,
					StepMessage: fmt.Sprintf("Budget ceiling reached (%s / 240MB)", FormatDecimalBytes(cumulativeBytes)),
				})
			}
			break
		}
		if stepSize > remBudget {
			stepSize = remBudget
		}

		if progressCb != nil {
			progressCb(ProgressUpdate{
				Alias:       alias,
				Phase:       "auto_step_testing",
				Direction:   DirectionDownload,
				StepThreads: threads,
				TotalBytes:  stepSize,
				BytesDone:   cumulativeBytes,
			})
		}

		// Run download for this step (fixedSize=true so it terminates at stepSize)
		stepMetrics, err := runBandwidthTest(ctx, client, prober, provider, DirectionDownload, stepSize, 0, true, threads, idleLat, alias, nil)
		if err != nil {
			if bestMetrics != nil {
				break
			}
			return nil, 0, fmt.Errorf("adaptive step with %d threads failed: %w", threads, err)
		}

		cumulativeBytes += stepMetrics.BytesTransferred
		curSpeed := stepMetrics.AvgSpeedBps

		if stepIdx == 0 {
			bestMetrics = stepMetrics
			bestThreads = threads
			prevSpeed = curSpeed
			if progressCb != nil {
				progressCb(ProgressUpdate{
					Alias:       alias,
					Phase:       "auto_step_result",
					Direction:   DirectionDownload,
					StepThreads: threads,
					CurrentBps:  curSpeed,
					TotalBytes:  stepSize,
					StepGain:    0,
					StepMessage: "Baseline established, escalating",
				})
			}
			continue
		}

		gain := (curSpeed - prevSpeed) / prevSpeed
		if gain >= SpeedImprovementThreshold {
			// Significant speedup! Concurrency is unlocking bandwidth!
			bestMetrics = stepMetrics
			bestThreads = threads
			prevSpeed = curSpeed

			if progressCb != nil {
				progressCb(ProgressUpdate{
					Alias:       alias,
					Phase:       "auto_step_result",
					Direction:   DirectionDownload,
					StepThreads: threads,
					CurrentBps:  curSpeed,
					TotalBytes:  stepSize,
					StepGain:    gain,
					StepMessage: fmt.Sprintf("↑ %.1f%% gain, escalating", gain*100),
				})
			}

			// If already at maximum threads (8) or remaining budget exhausted
			if stepIdx == len(AutoThreadLadder)-1 || cumulativeBytes >= MaxAutoTransferBytes {
				break
			}
		} else {
			// Plateau or regression detected! Reached stable rate.
			if curSpeed > bestMetrics.AvgSpeedBps {
				bestMetrics = stepMetrics
				bestThreads = threads
			}
			if progressCb != nil {
				statusMsg := "Plateau detected"
				if gain < 0 {
					statusMsg = "Speed peaked"
				}
				progressCb(ProgressUpdate{
					Alias:       alias,
					Phase:       "auto_step_stable",
					Direction:   DirectionDownload,
					StepThreads: threads,
					CurrentBps:  curSpeed,
					TotalBytes:  stepSize,
					StepGain:    gain,
					StepMessage: fmt.Sprintf("%s (gain: %.1f%%), reached stable rate", statusMsg, gain*100),
				})
			}
			break
		}
	}

FINISH:
	if bestMetrics == nil {
		return nil, 0, fmt.Errorf("adaptive download produced no metrics")
	}

	bestMetrics.BytesTransferred = cumulativeBytes
	bestMetrics.DurationMs = time.Since(startTime).Milliseconds()

	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias:       alias,
			Phase:       "auto_converged",
			Direction:   DirectionDownload,
			StepThreads: bestThreads,
			CurrentBps:  bestMetrics.AvgSpeedBps,
			BytesDone:   cumulativeBytes,
		})
	}

	return bestMetrics, bestThreads, nil
}
