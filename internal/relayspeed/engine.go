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
	defaultChunkSize            = 32 * 1024 // 32KB
	defaultMultiStreamChunkSize = 10 * 1024 * 1024 // 10MB
	sampleInterval              = 100 * time.Millisecond
	latencySampleInterval       = 100 * time.Millisecond // 10Hz high-frequency sampling
	defaultIdlePingRuns         = 3
	defaultSpeedTimeout         = 60 * time.Second
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
	return measureIdleLatencyWithProgress(ctx, prober, count, "", nil)
}

func measureIdleLatencyWithProgress(ctx context.Context, prober *LatencyProber, count int, alias string, progressCb ProgressCallback) time.Duration {
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
			if progressCb != nil {
				progressCb(ProgressUpdate{
					Alias:   alias,
					Phase:   "idle_ping",
					Elapsed: lat,
				})
			}
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
	avg := sum / time.Duration(len(latencies))
	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias:   alias,
			Phase:   "idle_ping",
			Elapsed: avg,
		})
	}
	return avg
}

func runBandwidthTest(
	ctx context.Context,
	client *http.Client,
	prober *LatencyProber,
	provider Provider,
	direction Direction,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	threads int,
	idleLat time.Duration,
	alias string,
	progressCb ProgressCallback,
) (*SpeedMetrics, error) {
	if sizeLimit <= 0 {
		sizeLimit = 25 * 1024 * 1024 // 25MB default
	}
	if threads <= 0 {
		threads = 1
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
		speedSamples     []SpeedSample
		startTime        = time.Now()
		deadline         = startTime.Add(timeout)
	)

	if durationSec > 0 {
		deadline = startTime.Add(time.Duration(durationSec) * time.Second)
	}

	var err error
	if direction == DirectionDownload {
		err = executeDownload(testCtx, client, provider, sizeLimit, durationSec, fixedSize, deadline, threads, &bytesTransferred, &samples, &speedSamples, alias, progressCb)
	} else {
		err = executeUpload(testCtx, client, provider, sizeLimit, durationSec, fixedSize, deadline, threads, &bytesTransferred, &samples, &speedSamples, alias, progressCb)
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
		Samples:          speedSamples,
	}

	if totalDuration > 0 && bytesTransferred > 0 {
		metrics.AvgSpeedBps = float64(bytesTransferred*8) / totalDuration.Seconds()
	}

	metrics.AvgSpeedBps, metrics.PeakSpeedBps, metrics.Low20SpeedBps = computeSpeedStats(samples, metrics.AvgSpeedBps)

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
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	threads int,
	bytesTransferred *int64,
	samples *[]float64,
	speedSamples *[]SpeedSample,
	alias string,
	progressCb ProgressCallback,
) error {
	dlCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	startTime := time.Now()
	stopSampler := make(chan struct{})
	var samplerWg sync.WaitGroup
	samplerWg.Add(1)

	go func() {
		defer samplerWg.Done()
		ticker := time.NewTicker(sampleInterval)
		defer ticker.Stop()

		lastSampleTime := time.Now()
		lastBytes := int64(0)
		smoothedBps := 0.0

		for {
			select {
			case <-stopSampler:
				return
			case <-dlCtx.Done():
				return
			case now := <-ticker.C:
				current := atomic.LoadInt64(bytesTransferred)
				elapsed := now.Sub(lastSampleTime)
				if elapsed <= 0 {
					continue
				}
				chunkBytes := current - lastBytes
				lastSampleTime = now

				if chunkBytes > 0 {
					lastBytes = current
					instantBps := float64(chunkBytes*8) / elapsed.Seconds()
					if samples != nil {
						*samples = append(*samples, instantBps)
					}
					if speedSamples != nil && len(*speedSamples) < 500 {
						*speedSamples = append(*speedSamples, SpeedSample{
							ElapsedMs: time.Since(startTime).Milliseconds(),
							BytesDone: current,
							Bps:       instantBps,
						})
					}

					if smoothedBps == 0 {
						smoothedBps = instantBps
					} else {
						smoothedBps = 0.7*instantBps + 0.3*smoothedBps
					}
				} else if current > 0 {
					// In-between chunks or waiting for response: smooth decay instead of abrupt zero
					smoothedBps *= 0.8
					if smoothedBps < 1000 {
						smoothedBps = 0
					}
				} else {
					smoothedBps = 0
				}

				if progressCb != nil {
					progressCb(ProgressUpdate{
						Alias:       alias,
						Phase:       "download",
						Direction:   DirectionDownload,
						BytesDone:   current,
						TotalBytes:  sizeLimit,
						CurrentBps:  smoothedBps,
						Elapsed:     time.Since(startTime),
						StepThreads: threads,
					})
				}
			}
		}
	}()

	var dlErr error
	if sp, ok := provider.(StreamDownloadProvider); ok {
		dlErr = sp.ExecuteDownloadStream(dlCtx, client, sizeLimit, durationSec, fixedSize, deadline, threads, bytesTransferred)
	} else if threads <= 1 {
		dlErr = executeDownloadSingle(dlCtx, cancel, client, provider, sizeLimit, durationSec, fixedSize, deadline, bytesTransferred)
	} else {
		dlErr = executeDownloadMulti(dlCtx, cancel, client, provider, sizeLimit, durationSec, fixedSize, deadline, threads, bytesTransferred)
	}

	close(stopSampler)
	samplerWg.Wait()

	if fixedSize && sizeLimit > 0 && *bytesTransferred > sizeLimit {
		*bytesTransferred = sizeLimit
	}

	if (samples == nil || len(*samples) == 0) && *bytesTransferred > 0 {
		elapsedSec := time.Since(startTime).Seconds()
		if elapsedSec > 0 {
			rate := float64(*bytesTransferred*8) / elapsedSec
			if samples != nil {
				*samples = append(*samples, rate)
			}
			if speedSamples != nil && len(*speedSamples) == 0 {
				*speedSamples = append(*speedSamples, SpeedSample{
					ElapsedMs: time.Since(startTime).Milliseconds(),
					BytesDone: *bytesTransferred,
					Bps:       rate,
				})
			}
		}
	}

	return dlErr
}

func executeDownloadSingle(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	bytesTransferred *int64,
) error {
	isDurationMode := durationSec > 0 && !fixedSize
	chunkSize := sizeLimit
	if isDurationMode {
		chunkSize = 25 * 1024 * 1024 // 25MB per chunk in duration mode
		if sizeLimit > 0 && sizeLimit < chunkSize {
			chunkSize = sizeLimit
		}
	}

	for {
		if time.Now().After(deadline) {
			break
		}
		cur := atomic.LoadInt64(bytesTransferred)
		if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
			break
		}

		reqSize := chunkSize
		if fixedSize && sizeLimit > 0 {
			rem := sizeLimit - cur
			if rem <= 0 {
				break
			}
			reqSize = rem
		}

		req, err := provider.GetDownloadRequest(ctx, client, reqSize)
		if err != nil {
			return fmt.Errorf("prepare download request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("execute download: %w", err)
		}

		if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
			resp.Body.Close()
			return fmt.Errorf("download HTTP %d", resp.StatusCode)
		}

		buf := make([]byte, defaultChunkSize)
		streamDone := false
		for !streamDone {
			select {
			case <-ctx.Done():
				resp.Body.Close()
				cancel()
				return nil
			default:
			}
			if time.Now().After(deadline) {
				resp.Body.Close()
				cancel()
				return nil
			}

			cur := atomic.LoadInt64(bytesTransferred)
			if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
				resp.Body.Close()
				cancel()
				return nil
			}

			toRead := len(buf)
			if fixedSize && sizeLimit > 0 {
				rem := sizeLimit - cur
				if rem <= 0 {
					resp.Body.Close()
					cancel()
					return nil
				}
				if int64(toRead) > rem {
					toRead = int(rem)
				}
			}

			n, rErr := resp.Body.Read(buf[:toRead])
			if n > 0 {
				atomic.AddInt64(bytesTransferred, int64(n))
				if fixedSize && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
					resp.Body.Close()
					cancel()
					return nil
				}
			}

			if rErr != nil {
				resp.Body.Close()
				if rErr == io.EOF {
					streamDone = true
					break
				}
				if ctx.Err() != nil {
					return nil
				}
				return rErr
			}
		}

		if !isDurationMode && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
			break
		}
	}
	return nil
}

func executeDownloadMulti(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	threads int,
	bytesTransferred *int64,
) error {
	var (
		wg        sync.WaitGroup
		errOnce   sync.Once
		workerErr error
	)

	isDurationMode := durationSec > 0 && !fixedSize

	chunkReqBytes := int64(defaultMultiStreamChunkSize)
	if isDurationMode {
		chunkReqBytes = 10 * 1024 * 1024 // 10MB per chunk in duration mode
		if sizeLimit > 0 && sizeLimit < chunkReqBytes {
			chunkReqBytes = sizeLimit
		}
	} else if sizeLimit > 0 {
		workerChunk := sizeLimit / int64(threads)
		const minWorkerChunk int64 = 2 * 1024 * 1024
		if workerChunk < minWorkerChunk {
			workerChunk = minWorkerChunk
		}
		chunkReqBytes = workerChunk
	}

	for w := 0; w < threads; w++ {
		wIdx := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerCtx := WithWorkerIndex(ctx, wIdx)
			buf := make([]byte, defaultChunkSize)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if time.Now().After(deadline) {
					cancel()
					return
				}

				cur := atomic.LoadInt64(bytesTransferred)
				if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
					cancel()
					return
				}

				reqBytes := chunkReqBytes
				if fixedSize && sizeLimit > 0 {
					rem := sizeLimit - cur
					if rem <= 0 {
						cancel()
						return
					}
					if rem < reqBytes {
						reqBytes = rem
					}
				}

				req, err := provider.GetDownloadRequest(workerCtx, client, reqBytes)
				if err != nil {
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("prepare download chunk: %w", err) })
						cancel()
					}
					return
				}

				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("execute download chunk: %w", err) })
						cancel()
					}
					return
				}

				if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
					resp.Body.Close()
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("download HTTP %d", resp.StatusCode) })
						cancel()
					}
					return
				}

				chunkDone := false
				for !chunkDone {
					select {
					case <-ctx.Done():
						resp.Body.Close()
						cancel()
						return
					default:
					}

					if time.Now().After(deadline) {
						resp.Body.Close()
						cancel()
						return
					}

					current := atomic.LoadInt64(bytesTransferred)
					if fixedSize && sizeLimit > 0 && current >= sizeLimit {
						resp.Body.Close()
						cancel()
						return
					}

					toRead := len(buf)
					if fixedSize && sizeLimit > 0 {
						rem := sizeLimit - current
						if rem <= 0 {
							resp.Body.Close()
							cancel()
							return
						}
						if int64(toRead) > rem {
							toRead = int(rem)
						}
					}

					n, rErr := resp.Body.Read(buf[:toRead])
					if n > 0 {
						atomic.AddInt64(bytesTransferred, int64(n))
						if fixedSize && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
							resp.Body.Close()
							cancel()
							return
						}
					}

					if rErr != nil {
						resp.Body.Close()
						if rErr == io.EOF {
							chunkDone = true
							break
						}
						if ctx.Err() == nil {
							errOnce.Do(func() { workerErr = fmt.Errorf("read chunk: %w", rErr) })
							cancel()
						}
						return
					}
				}

				// If not in duration mode and fixed size reached, worker finishes
				if !isDurationMode && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
					return
				}
			}
		}()
	}

	wg.Wait()

	if workerErr != nil && atomic.LoadInt64(bytesTransferred) == 0 {
		return workerErr
	}
	return nil
}

func executeUpload(
	ctx context.Context,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	threads int,
	bytesTransferred *int64,
	samples *[]float64,
	speedSamples *[]SpeedSample,
	alias string,
	progressCb ProgressCallback,
) error {
	if !provider.SupportsUpload() {
		return fmt.Errorf("provider %s does not support upload testing", provider.DisplayName())
	}
	if threads <= 0 {
		threads = 1
	}

	ulCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	startTime := time.Now()
	stopSampler := make(chan struct{})
	var samplerWg sync.WaitGroup
	samplerWg.Add(1)

	go func() {
		defer samplerWg.Done()
		ticker := time.NewTicker(sampleInterval)
		defer ticker.Stop()

		lastSampleTime := time.Now()
		lastBytes := int64(0)
		smoothedBps := 0.0

		for {
			select {
			case <-stopSampler:
				return
			case <-ulCtx.Done():
				return
			case now := <-ticker.C:
				current := atomic.LoadInt64(bytesTransferred)
				elapsed := now.Sub(lastSampleTime)
				if elapsed <= 0 {
					continue
				}
				chunkBytes := current - lastBytes
				lastSampleTime = now

				if chunkBytes > 0 {
					lastBytes = current
					instantBps := float64(chunkBytes*8) / elapsed.Seconds()
					if samples != nil {
						*samples = append(*samples, instantBps)
					}
					if speedSamples != nil && len(*speedSamples) < 500 {
						*speedSamples = append(*speedSamples, SpeedSample{
							ElapsedMs: time.Since(startTime).Milliseconds(),
							BytesDone: current,
							Bps:       instantBps,
						})
					}

					if smoothedBps == 0 {
						smoothedBps = instantBps
					} else {
						smoothedBps = 0.7*instantBps + 0.3*smoothedBps
					}
				} else if current > 0 {
					// In-between chunks or waiting for response: smooth decay instead of abrupt zero
					smoothedBps *= 0.8
					if smoothedBps < 1000 {
						smoothedBps = 0
					}
				} else {
					smoothedBps = 0
				}

				if progressCb != nil {
					progressCb(ProgressUpdate{
						Alias:       alias,
						Phase:       "upload",
						Direction:   DirectionUpload,
						BytesDone:   current,
						TotalBytes:  sizeLimit,
						CurrentBps:  smoothedBps,
						Elapsed:     time.Since(startTime),
						StepThreads: threads,
					})
				}
			}
		}
	}()

	var ulErr error
	if sp, ok := provider.(StreamUploadProvider); ok {
		ulErr = sp.ExecuteUploadStream(ulCtx, client, sizeLimit, durationSec, fixedSize, deadline, threads, bytesTransferred)
	} else if threads <= 1 {
		ulErr = executeUploadSingle(ulCtx, cancel, client, provider, sizeLimit, durationSec, fixedSize, deadline, bytesTransferred)
	} else {
		ulErr = executeUploadMulti(ulCtx, cancel, client, provider, sizeLimit, durationSec, fixedSize, deadline, threads, bytesTransferred)
	}

	close(stopSampler)
	samplerWg.Wait()

	if fixedSize && sizeLimit > 0 && *bytesTransferred > sizeLimit {
		*bytesTransferred = sizeLimit
	}

	if (samples == nil || len(*samples) == 0) && *bytesTransferred > 0 {
		elapsedSec := time.Since(startTime).Seconds()
		if elapsedSec > 0 {
			rate := float64(*bytesTransferred*8) / elapsedSec
			if samples != nil {
				*samples = append(*samples, rate)
			}
			if speedSamples != nil && len(*speedSamples) == 0 {
				*speedSamples = append(*speedSamples, SpeedSample{
					ElapsedMs: time.Since(startTime).Milliseconds(),
					BytesDone: *bytesTransferred,
					Bps:       rate,
				})
			}
		}
	}

	return ulErr
}

func executeUploadSingle(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	bytesTransferred *int64,
) error {
	isDurationMode := durationSec > 0 && !fixedSize
	chunkSize := sizeLimit
	if isDurationMode {
		chunkSize = 10 * 1024 * 1024 // 10MB per chunk in duration mode
		if sizeLimit > 0 && sizeLimit < chunkSize {
			chunkSize = sizeLimit
		}
	} else if chunkSize <= 0 || chunkSize > 25*1024*1024 {
		chunkSize = 25 * 1024 * 1024 // 25MB max chunk
	}
	if limitProv, ok := provider.(UploadChunkLimitProvider); ok {
		if maxChunk := limitProv.MaxUploadChunkSize(); maxChunk > 0 && chunkSize > maxChunk {
			chunkSize = maxChunk
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}
		cur := atomic.LoadInt64(bytesTransferred)
		if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
			break
		}

		reqSize := chunkSize
		if fixedSize && sizeLimit > 0 {
			rem := sizeLimit - cur
			if rem <= 0 {
				break
			}
			if rem < reqSize {
				reqSize = rem
			}
		}

		zeroSrc := io.LimitReader(zeroReader{}, reqSize)
		cr := &countingReader{reader: zeroSrc, count: bytesTransferred}

		req, err := provider.GetUploadRequest(ctx, client, cr, reqSize)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("prepare upload request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("execute upload: %w", err)
		}

		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
			return fmt.Errorf("upload HTTP %d", resp.StatusCode)
		}

		if !isDurationMode && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
			break
		}
	}
	return nil
}

func executeUploadMulti(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	provider Provider,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	threads int,
	bytesTransferred *int64,
) error {
	var (
		wg        sync.WaitGroup
		errOnce   sync.Once
		workerErr error
	)

	isDurationMode := durationSec > 0 && !fixedSize

	chunkReqBytes := int64(5 * 1024 * 1024) // 5MB per chunk in duration mode
	if isDurationMode {
		if sizeLimit > 0 && sizeLimit < chunkReqBytes {
			chunkReqBytes = sizeLimit
		}
	} else if sizeLimit > 0 {
		workerChunk := sizeLimit / int64(threads)
		const minWorkerChunk int64 = 2 * 1024 * 1024
		if workerChunk < minWorkerChunk {
			workerChunk = minWorkerChunk
		}
		chunkReqBytes = workerChunk
	}
	if limitProv, ok := provider.(UploadChunkLimitProvider); ok {
		if maxChunk := limitProv.MaxUploadChunkSize(); maxChunk > 0 && chunkReqBytes > maxChunk {
			chunkReqBytes = maxChunk
		}
	}

	for w := 0; w < threads; w++ {
		wIdx := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerCtx := WithWorkerIndex(ctx, wIdx)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if time.Now().After(deadline) {
					cancel()
					return
				}

				cur := atomic.LoadInt64(bytesTransferred)
				if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
					cancel()
					return
				}

				reqBytes := chunkReqBytes
				if fixedSize && sizeLimit > 0 {
					rem := sizeLimit - cur
					if rem <= 0 {
						cancel()
						return
					}
					if rem < reqBytes {
						reqBytes = rem
					}
				}

				zeroSrc := io.LimitReader(zeroReader{}, reqBytes)
				cr := &countingReader{reader: zeroSrc, count: bytesTransferred}

				req, err := provider.GetUploadRequest(workerCtx, client, cr, reqBytes)
				if err != nil {
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("prepare upload chunk: %w", err) })
						cancel()
					}
					return
				}

				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("execute upload chunk: %w", err) })
						cancel()
					}
					return
				}

				io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				resp.Body.Close()

				if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusSwitchingProtocols {
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("upload HTTP %d", resp.StatusCode) })
						cancel()
					}
					return
				}

				if !isDurationMode && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
					return
				}
			}
		}()
	}

	wg.Wait()

	if workerErr != nil && atomic.LoadInt64(bytesTransferred) == 0 {
		return workerErr
	}
	return nil
}

func computeSpeedStats(samples []float64, fallback float64) (avg float64, peak float64, low20 float64) {
	var valid []float64
	for _, s := range samples {
		if s > 0 && !math.IsNaN(s) && !math.IsInf(s, 0) {
			valid = append(valid, s)
		}
	}

	if len(valid) == 0 {
		return fallback, fallback, fallback
	}

	// Warm-up trimming:
	// The first ~500ms (or first 2-3 samples) correspond to TCP slow-start ramp-up.
	// Trim them from the statistical pool if we have enough samples.
	steady := valid
	if len(valid) >= 6 {
		// Discard first 3 samples (approx 300ms-500ms warm-up)
		steady = valid[3:]
	} else if len(valid) >= 4 {
		// Discard first 2 samples
		steady = valid[2:]
	} else if len(valid) >= 3 {
		steady = valid[1:]
	}

	var sum float64
	peak = steady[0]
	for _, s := range steady {
		sum += s
		if s > peak {
			peak = s
		}
	}
	avg = sum / float64(len(steady))

	sorted := make([]float64, len(steady))
	copy(sorted, steady)
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

	return avg, peak, low20
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
