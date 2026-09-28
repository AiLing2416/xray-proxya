package relayspeed

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"
)

const (
	defaultProbeBytes     int64   = 1024 * 1024        // 1MB probe request
	minAdaptiveBytes      int64   = 2 * 1024 * 1024    // 2MB safe lower bound
	maxAdaptiveBytes      int64   = 100 * 1024 * 1024  // 100MB safe upper bound
	defaultTargetDuration float64 = 2.5                // 2.5 seconds target steady-state duration
	probeTimeout                  = 4 * time.Second
	MaxAutoTransferBytes  int64   = 240 * 1024 * 1024  // 240MB cumulative budget
)

var (
	AutoThreadLadder   = []int{1, 2, 4, 6, 8}
	MinSustainDuration = 3500 * time.Millisecond // 3.5s minimum sustain duration before convergence
	ConvergenceWindow  = 1500 * time.Millisecond // 1.5s moving window for CV check
	MaxCV              = 0.06                    // CV <= 6% relative fluctuation
	MaxMeanDelta       = 0.05                    // Moving avg delta < 5%
	MaxAutoDuration    = 10 * time.Second        // Global safety upper bound
)

// ProbeBandwidth sends a lightweight ~1MB request to estimate download bandwidth and round-trip time.
func ProbeBandwidth(ctx context.Context, client *http.Client, provider Provider) (bps float64, rtt time.Duration, err error) {
	return ProbeBandwidthDir(ctx, client, provider, DirectionDownload)
}

// ProbeBandwidthDir sends a lightweight ~1MB request in the specified direction (download or upload)
// to estimate baseline bandwidth and round-trip time.
func ProbeBandwidthDir(ctx context.Context, client *http.Client, provider Provider, dir Direction) (bps float64, rtt time.Duration, err error) {
	if client == nil || provider == nil {
		return 0, 0, fmt.Errorf("nil client or provider")
	}

	if dir == DirectionUpload {
		if !provider.SupportsUpload() {
			return 0, 0, fmt.Errorf("provider %s does not support upload", provider.DisplayName())
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()

		var totalBytes int64
		zeroSrc := io.LimitReader(zeroReader{}, defaultProbeBytes)
		cr := &countingReader{reader: zeroSrc, count: &totalBytes}

		req, err := provider.GetUploadRequest(probeCtx, client, cr, defaultProbeBytes)
		if err != nil {
			return 0, 0, fmt.Errorf("create upload probe request: %w", err)
		}

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0, fmt.Errorf("upload probe request: %w", err)
		}
		defer resp.Body.Close()

		ttfb := time.Since(start)
		if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
			return 0, ttfb, fmt.Errorf("upload probe HTTP %d", resp.StatusCode)
		}

		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		elapsed := time.Since(start)
		if elapsed <= 0 {
			elapsed = time.Millisecond
		}
		sent := totalBytes
		if sent == 0 {
			sent = defaultProbeBytes
		}
		bps = float64(sent*8) / elapsed.Seconds()
		return bps, ttfb, nil
	}

	// Default: DirectionDownload
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

// SelectInitialConcurrency determines starting concurrency based on probe speed and RTT.
func SelectInitialConcurrency(probeBps float64, rtt time.Duration) int {
	const mbps = 1_000_000.0
	speedMbps := probeBps / mbps

	if speedMbps >= 100 {
		return 6
	}
	if speedMbps >= 50 || (speedMbps >= 25 && rtt >= 70*time.Millisecond) {
		return 4
	}
	// For high-latency links (RTT >= 80ms) with decent throughput (>= 5 Mbps),
	// 1MB probe is throttled by TCP slow start, so at least 4 streams are needed to saturate BDP.
	if rtt >= 80*time.Millisecond && speedMbps >= 5 {
		return 4
	}
	if speedMbps >= 30 {
		return 4
	}
	if speedMbps >= 10 || rtt >= 40*time.Millisecond {
		return 2
	}
	if rtt <= 50*time.Millisecond && speedMbps < 5 {
		return 1
	}
	return 2
}

type timeSample struct {
	t   time.Time
	bps float64
}

// ConvergenceDetector tracks continuous throughput samples and evaluates whether steady-state
// convergence has been reached using Coefficient of Variation (CV = sigma / mu) and window moving averages.
type ConvergenceDetector struct {
	mu             sync.Mutex
	minDuration    time.Duration
	windowDuration time.Duration
	maxCV          float64
	maxMeanDelta   float64
	samples        []timeSample
	startTime      time.Time
}

func NewConvergenceDetector(minDuration, windowDuration time.Duration, maxCV, maxMeanDelta float64) *ConvergenceDetector {
	if minDuration <= 0 {
		minDuration = MinSustainDuration
	}
	if windowDuration <= 0 {
		windowDuration = ConvergenceWindow
	}
	if maxCV <= 0 {
		maxCV = MaxCV
	}
	if maxMeanDelta <= 0 {
		maxMeanDelta = MaxMeanDelta
	}
	return &ConvergenceDetector{
		minDuration:    minDuration,
		windowDuration: windowDuration,
		maxCV:          maxCV,
		maxMeanDelta:   maxMeanDelta,
	}
}

func (cd *ConvergenceDetector) Reset() {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.samples = nil
	cd.startTime = time.Time{}
}

// AddSample evaluates steady-state convergence upon each throughput sample.
// Returns converged (bool), cv (float64), stability (float64 percentage 0~100).
func (cd *ConvergenceDetector) AddSample(t time.Time, bps float64) (converged bool, cv float64, stability float64) {
	if bps <= 0 || math.IsNaN(bps) || math.IsInf(bps, 0) {
		return false, 0, 0
	}

	cd.mu.Lock()
	defer cd.mu.Unlock()

	if cd.startTime.IsZero() {
		cd.startTime = t
	}

	cd.samples = append(cd.samples, timeSample{t: t, bps: bps})
	elapsed := t.Sub(cd.startTime)

	cutoff := t.Add(-cd.windowDuration)
	var window []float64
	for i := len(cd.samples) - 1; i >= 0; i-- {
		if cd.samples[i].t.Before(cutoff) {
			break
		}
		window = append(window, cd.samples[i].bps)
	}

	n := len(window)
	if n < 4 {
		return false, 0, 0
	}

	var sum float64
	for _, v := range window {
		sum += v
	}
	mean := sum / float64(n)
	if mean <= 0 {
		return false, 0, 0
	}

	var varSum float64
	for _, v := range window {
		diff := v - mean
		varSum += diff * diff
	}
	stdDev := math.Sqrt(varSum / float64(n))
	cv = stdDev / mean

	stability = math.Max(0, math.Min(100, (1.0-cv)*100.0))

	if elapsed < cd.minDuration {
		return false, cv, stability
	}

	if cv <= cd.maxCV {
		return true, cv, stability
	}

	// Secondary check: moving average change between consecutive halves < maxMeanDelta,
	// applicable when CV is within a reasonable plateau envelope (CV <= 2.0 * maxCV).
	if n >= 6 && cv <= cd.maxCV*2.0 {
		mid := n / 2
		var sum1, sum2 float64
		for i := 0; i < mid; i++ {
			sum2 += window[i]
		}
		for i := mid; i < n; i++ {
			sum1 += window[i]
		}
		m1 := sum1 / float64(n-mid)
		m2 := sum2 / float64(mid)
		if m1 > 0 {
			delta := math.Abs(m2-m1) / m1
			if delta < cd.maxMeanDelta {
				return true, cv, stability
			}
		}
	}

	return false, cv, stability
}

// RunAdaptiveBandwidthTest executes a 3-phase adaptive test for either DirectionDownload or DirectionUpload:
// Phase 1 (Base Probe): Lightweight probe (~1s / 1MB) for initial baseline speed and RTT.
// Phase 2 (Concurrency Selection): Intelligently selects initial concurrency.
// Phase 3 (Sustained Stream & Convergence): Runs sustained multi-stream transfer (4~6s), evaluating
// real-time CV variance and moving average stability until convergence or budget ceiling.
func RunAdaptiveBandwidthTest(
	ctx context.Context,
	client *http.Client,
	prober *LatencyProber,
	provider Provider,
	dir Direction,
	targetThreads int,
	idleLat time.Duration,
	alias string,
	progressCb ProgressCallback,
) (*SpeedMetrics, int, error) {
	if client == nil || provider == nil {
		return nil, 0, fmt.Errorf("nil client or provider")
	}
	if dir == DirectionUpload && !provider.SupportsUpload() {
		return nil, 0, fmt.Errorf("provider %s does not support upload testing", provider.DisplayName())
	}
	if dir == "" {
		dir = DirectionDownload
	}

	startTime := time.Now()
	var cumulativeBytes int64

	// Phase 1: Base Probe
	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias:     alias,
			Phase:     "auto_probe",
			Direction: dir,
		})
	}

	probeBps, rtt, probeErr := ProbeBandwidthDir(ctx, client, provider, dir)
	if probeErr != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		probeBps = 10 * 1000 * 1000 // 10 Mbps fallback baseline
		rtt = 50 * time.Millisecond
	} else {
		cumulativeBytes += defaultProbeBytes
	}

	// Phase 2: Concurrency Selection
	threads := targetThreads
	if threads <= 1 {
		threads = SelectInitialConcurrency(probeBps, rtt)
	}
	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias:       alias,
			Phase:       "auto_ramp",
			Direction:   dir,
			StepThreads: threads,
			CurrentBps:  probeBps,
			BytesDone:   cumulativeBytes,
			TotalBytes:  MaxAutoTransferBytes,
		})
	}

	// Phase 3: Sustained Stream & Convergence Monitoring
	remBudget := MaxAutoTransferBytes - cumulativeBytes
	if remBudget <= 0 {
		remBudget = 10 * 1024 * 1024
	}

	detector := NewConvergenceDetector(MinSustainDuration, ConvergenceWindow, MaxCV, MaxMeanDelta)

	sustainCtx, cancelSustain := context.WithTimeout(ctx, MaxAutoDuration)
	defer cancelSustain()

	var (
		converged  bool
		lastUpdate time.Time
		convMu     sync.Mutex
	)

	internalCb := func(u ProgressUpdate) {
		now := time.Now()
		isConv, _, stability := detector.AddSample(now, u.CurrentBps)

		phase := "auto_sustaining"

		convMu.Lock()
		if isConv && !converged {
			converged = true
			phase = "auto_converged"
			cancelSustain()
		}
		if cumulativeBytes+u.BytesDone >= remBudget && !converged {
			converged = true
			cancelSustain()
		}
		convMu.Unlock()

		if progressCb != nil {
			if phase == "auto_converged" || now.Sub(lastUpdate) >= 150*time.Millisecond {
				lastUpdate = now
				progressCb(ProgressUpdate{
					Alias:       alias,
					Phase:       phase,
					Direction:   dir,
					StepThreads: threads,
					BytesDone:   cumulativeBytes + u.BytesDone,
					TotalBytes:  MaxAutoTransferBytes,
					CurrentBps:  u.CurrentBps,
					Elapsed:     time.Since(startTime),
					StepGain:    stability,
				})
			}
		}
	}

	metrics, err := runBandwidthTest(
		sustainCtx, client, prober, provider, dir,
		remBudget, int(MaxAutoDuration.Seconds()), false, threads, idleLat, alias, internalCb,
	)

	if ctx.Err() != nil && !converged {
		return nil, 0, ctx.Err()
	}

	if metrics == nil {
		if err != nil {
			return nil, 0, err
		}
		return nil, 0, fmt.Errorf("adaptive %s test produced no metrics", dir)
	}

	if metrics.BytesTransferred > remBudget {
		metrics.BytesTransferred = remBudget
	}
	cumulativeBytes += metrics.BytesTransferred
	if cumulativeBytes > MaxAutoTransferBytes {
		cumulativeBytes = MaxAutoTransferBytes
	}
	metrics.BytesTransferred = cumulativeBytes
	metrics.DurationMs = time.Since(startTime).Milliseconds()

	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias:       alias,
			Phase:       "auto_converged",
			Direction:   dir,
			StepThreads: threads,
			CurrentBps:  metrics.AvgSpeedBps,
			BytesDone:   cumulativeBytes,
			TotalBytes:  MaxAutoTransferBytes,
			Elapsed:     time.Since(startTime),
		})
	}

	return metrics, threads, nil
}

// RunAdaptiveDownload is a backwards-compatible wrapper around RunAdaptiveBandwidthTest.
func RunAdaptiveDownload(
	ctx context.Context,
	client *http.Client,
	prober *LatencyProber,
	provider Provider,
	idleLat time.Duration,
	alias string,
	progressCb ProgressCallback,
) (*SpeedMetrics, int, error) {
	return RunAdaptiveBandwidthTest(ctx, client, prober, provider, DirectionDownload, 1, idleLat, alias, progressCb)
}
