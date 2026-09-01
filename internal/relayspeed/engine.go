package relayspeed

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultChunkSize      = 32 * 1024 // 32KB
	sampleInterval        = 100 * time.Millisecond
	latencySampleInterval = 100 * time.Millisecond // 10Hz high-frequency sampling
	defaultIdlePingRuns   = 3
	defaultSpeedTimeout   = 60 * time.Second
)

type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type countingReader struct {
	reader io.Reader
	count  *int64
}

func (cr *countingReader) Read(p []byte) (n int, err error) {
	n, err = cr.reader.Read(p)
	if n > 0 {
		atomic.AddInt64(cr.count, int64(n))
	}
	return n, err
}

func measureIdleLatency(ctx context.Context, prober *LatencyProber, count int) time.Duration {
	if count <= 0 {
		count = defaultIdlePingRuns
	}
	if prober == nil {
		return 0
	}

	// 1. Silent warm-up probe: triggers initial Xray outbound TLS/REALITY handshake and Anycast socket connection.
	// Discard this cold-start probe so it does not skew the baseline idle latency average.
	_, _ = prober.Probe(ctx, 3*time.Second)
	time.Sleep(50 * time.Millisecond)

	// 2. Measure steady-state warm baseline idle latency
	var latencies []time.Duration
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return 0
		default:
		}

		lat, err := prober.Probe(ctx, 2*time.Second)
		if err == nil && lat > 0 {
			latencies = append(latencies, lat)
		}
		time.Sleep(30 * time.Millisecond)
	}

	if len(latencies) == 0 {
		return 0
	}

	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	return sum / time.Duration(len(latencies))
}

func runBandwidthTest(
	ctx context.Context,
	client *http.Client,
	prober *LatencyProber,
	provider Provider,
	direction Direction,
	sizeLimit int64,
	durationSec int,
	idleLat time.Duration,
	alias string,
	progressCb ProgressCallback,
) (*SpeedMetrics, error) {
	if sizeLimit <= 0 {
		sizeLimit = 25 * 1024 * 1024 // 25MB default
	}

	timeout := defaultSpeedTimeout
	if durationSec > 0 {
		timeout = time.Duration(durationSec)*time.Second + 5*time.Second
	}
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Setup load latency measurement using persistent Anycast prober
	var (
		loadLatencies   []time.Duration
		loadMu          sync.Mutex
		loadProbeTotal  int
		loadProbeFailed int
		stopLoadProbe   = make(chan struct{})
	)

	var wgLoad sync.WaitGroup
	if prober != nil {
		wgLoad.Add(1)
		go func() {
			defer wgLoad.Done()

			probeOnce := func() {
				lat, err := prober.Probe(testCtx, 1500*time.Millisecond)
				loadMu.Lock()
				loadProbeTotal++
				if err != nil {
					loadProbeFailed++
				} else {
					loadLatencies = append(loadLatencies, lat)
				}
				loadMu.Unlock()
			}

			// Immediate initial probe shortly after transfer begins (20ms)
			select {
			case <-stopLoadProbe:
				return
			case <-testCtx.Done():
				return
			case <-time.After(20 * time.Millisecond):
				probeOnce()
			}

			ticker := time.NewTicker(latencySampleInterval)
			defer ticker.Stop()

			for {
				select {
				case <-stopLoadProbe:
					return
				case <-testCtx.Done():
					return
				case <-ticker.C:
					probeOnce()
				}
			}
		}()
	}

	var (
		bytesTransferred int64
		samples          []float64
		startTime        = time.Now()
		deadline         = startTime.Add(timeout)
	)

	if durationSec > 0 {
		deadline = startTime.Add(time.Duration(durationSec) * time.Second)
	}

	var err error
	if direction == DirectionDownload {
		err = executeDownload(testCtx, client, provider, sizeLimit, deadline, &bytesTransferred, &samples, alias, progressCb)
	} else {
		err = executeUpload(testCtx, client, provider, sizeLimit, deadline, &bytesTransferred, &samples, alias, progressCb)
	}

	close(stopLoadProbe)
	wgLoad.Wait()

	totalDuration := time.Since(startTime)
	if err != nil && bytesTransferred == 0 {
		return nil, err
	}

	metrics := &SpeedMetrics{
		Direction:        direction,
		BytesTransferred: bytesTransferred,
		DurationMs:       totalDuration.Milliseconds(),
		IdleLatencyAvg:   idleLat,
	}

	if totalDuration > 0 && bytesTransferred > 0 {
		metrics.AvgSpeedBps = float64(bytesTransferred*8) / totalDuration.Seconds()
	}

	metrics.PeakSpeedBps, metrics.Low20SpeedBps = computeSpeedStats(samples, metrics.AvgSpeedBps)

	// Summarize load latencies
	loadMu.Lock()
	metrics.LoadLatencySamples = len(loadLatencies)
	if loadProbeTotal > 0 {
		metrics.LoadLatencyLossRate = float64(loadProbeFailed) / float64(loadProbeTotal)
	}
	if len(loadLatencies) > 0 {
		var sum time.Duration
		for _, l := range loadLatencies {
			sum += l
		}
		metrics.LoadLatencyAvg = sum / time.Duration(len(loadLatencies))
		metrics.LoadLatencyWorst5 = computeWorst5Percentile(loadLatencies)
	}
	loadMu.Unlock()

	return metrics, nil
}

func executeDownload(
	ctx context.Context,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	deadline time.Time,
	bytesTransferred *int64,
	samples *[]float64,
	alias string,
	progressCb ProgressCallback,
) error {
	req, err := provider.GetDownloadRequest(ctx, client, sizeLimit)
	if err != nil {
		return fmt.Errorf("prepare download request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("execute download: %w", err)
	}
	defer resp.Body.Close()

	if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	buf := make([]byte, defaultChunkSize)
	lastSampleTime := time.Now()
	lastSampleBytes := int64(0)

	for {
		if time.Now().After(deadline) {
			break
		}
		if sizeLimit > 0 && *bytesTransferred >= sizeLimit {
			break
		}

		toRead := len(buf)
		if sizeLimit > 0 && int64(toRead) > (sizeLimit-*bytesTransferred) {
			toRead = int(sizeLimit - *bytesTransferred)
		}

		n, rErr := resp.Body.Read(buf[:toRead])
		if n > 0 {
			*bytesTransferred += int64(n)

			now := time.Now()
			elapsed := now.Sub(lastSampleTime)
			if elapsed >= sampleInterval {
				chunkBytes := *bytesTransferred - lastSampleBytes
				bps := float64(chunkBytes*8) / elapsed.Seconds()
				*samples = append(*samples, bps)

				if progressCb != nil {
					progressCb(ProgressUpdate{
						Alias:      alias,
						Phase:      "download",
						Direction:  DirectionDownload,
						BytesDone:  *bytesTransferred,
						TotalBytes: sizeLimit,
						CurrentBps: bps,
					})
				}
				lastSampleTime = now
				lastSampleBytes = *bytesTransferred
			}
		}

		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			return rErr
		}
	}

	return nil
}

func executeUpload(
	ctx context.Context,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	deadline time.Time,
	bytesTransferred *int64,
	samples *[]float64,
	alias string,
	progressCb ProgressCallback,
) error {
	if !provider.SupportsUpload() {
		return fmt.Errorf("provider %s does not support upload testing", provider.DisplayName())
	}

	zeroSrc := io.LimitReader(zeroReader{}, sizeLimit)
	cr := &countingReader{reader: zeroSrc, count: bytesTransferred}

	req, err := provider.GetUploadRequest(ctx, client, cr, sizeLimit)
	if err != nil {
		return fmt.Errorf("prepare upload request: %w", err)
	}

	// Sampler ticker during upload
	ticker := time.NewTicker(sampleInterval)
	stopSampler := make(chan struct{})
	defer ticker.Stop()

	go func() {
		lastSampleTime := time.Now()
		lastBytes := int64(0)
		for {
			select {
			case <-stopSampler:
				return
			case now := <-ticker.C:
				current := atomic.LoadInt64(bytesTransferred)
				elapsed := now.Sub(lastSampleTime)
				if elapsed > 0 {
					chunkBytes := current - lastBytes
					bps := float64(chunkBytes*8) / elapsed.Seconds()
					*samples = append(*samples, bps)

					if progressCb != nil {
						progressCb(ProgressUpdate{
							Alias:      alias,
							Phase:      "upload",
							Direction:  DirectionUpload,
							BytesDone:  current,
							TotalBytes: sizeLimit,
							CurrentBps: bps,
						})
					}
					lastSampleTime = now
					lastBytes = current
				}
			}
		}
	}()

	resp, err := client.Do(req)
	close(stopSampler)

	if err != nil {
		return fmt.Errorf("execute upload: %w", err)
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("upload HTTP %d", resp.StatusCode)
	}

	return nil
}

func computeSpeedStats(samples []float64, fallback float64) (peak float64, low20 float64) {
	if len(samples) == 0 {
		return fallback, fallback
	}

	peak = samples[0]
	for _, s := range samples {
		if s > peak {
			peak = s
		}
	}

	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)

	low20Count := int(math.Ceil(float64(len(sorted)) * 0.2))
	if low20Count < 1 {
		low20Count = 1
	}

	var sumLow float64
	for i := 0; i < low20Count; i++ {
		sumLow += sorted[i]
	}
	low20 = sumLow / float64(low20Count)

	return peak, low20
}

func computeWorst5Percentile(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(math.Floor(float64(len(sorted)-1) * 0.95))
	return sorted[idx]
}
