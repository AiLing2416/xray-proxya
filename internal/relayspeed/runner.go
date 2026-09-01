package relayspeed

import (
	"context"
	"fmt"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/relaytest"
)

// RunSpeed executes a speed test against a single relay node.
func RunSpeed(
	ctx context.Context,
	cfg *config.UserConfig,
	alias string,
	opts Options,
	progressCb ProgressCallback,
) (*SpeedResult, error) {
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

	provider, err := GetProvider(opts.Provider, opts.CustomDownloadURL, opts.CustomUploadURL)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	res := &SpeedResult{
		Alias:    alias,
		Provider: provider.DisplayName(),
	}

	session, err := relaytest.StartTestSession(ctx, cfg, alias)
	if err != nil {
		res.Error = err.Error()
		res.TotalDurationMs = time.Since(start).Milliseconds()
		return res, nil
	}
	defer session.Close()

	client := session.HTTPClient
	prober := NewLatencyProber(session.Dialer)
	defer prober.Close()

	// 1. Measure Idle Latency
	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias: alias,
			Phase: "idle_ping",
		})
	}
	idleLat := measureIdleLatency(ctx, prober, defaultIdlePingRuns)

	runDL := opts.Direction == DirectionDownload || opts.Direction == DirectionBoth || opts.Direction == ""
	runUL := opts.Direction == DirectionUpload || opts.Direction == DirectionBoth

	// 2. Download Test
	if runDL {
		if progressCb != nil {
			progressCb(ProgressUpdate{
				Alias:     alias,
				Phase:     "download",
				Direction: DirectionDownload,
			})
		}
		dlMetrics, dlErr := runBandwidthTest(ctx, client, prober, provider, DirectionDownload, opts.SizeBytes, opts.DurationSeconds, idleLat, alias, progressCb)
		if dlErr != nil {
			if opts.Direction == DirectionDownload {
				res.Error = fmt.Sprintf("download failed: %v", dlErr)
				res.TotalDurationMs = time.Since(start).Milliseconds()
				return res, nil
			}
			// If both, record partial error
			res.Error = fmt.Sprintf("download failed: %v", dlErr)
		} else {
			res.Download = dlMetrics
		}
	}

	// 3. Upload Test
	if runUL {
		if !provider.SupportsUpload() {
			if opts.Direction == DirectionUpload {
				res.Error = fmt.Sprintf("provider %s does not support upload testing", provider.DisplayName())
				res.TotalDurationMs = time.Since(start).Milliseconds()
				return res, nil
			}
		} else {
			if progressCb != nil {
				progressCb(ProgressUpdate{
					Alias:     alias,
					Phase:     "upload",
					Direction: DirectionUpload,
				})
			}
			ulMetrics, ulErr := runBandwidthTest(ctx, client, prober, provider, DirectionUpload, opts.SizeBytes, opts.DurationSeconds, idleLat, alias, progressCb)
			if ulErr != nil {
				if res.Error != "" {
					res.Error += fmt.Sprintf("; upload failed: %v", ulErr)
				} else {
					res.Error = fmt.Sprintf("upload failed: %v", ulErr)
				}
			} else {
				res.Upload = ulMetrics
			}
		}
	}

	res.TotalDurationMs = time.Since(start).Milliseconds()
	if progressCb != nil {
		progressCb(ProgressUpdate{
			Alias: alias,
			Phase: "done",
		})
	}

	return res, nil
}

// RunSpeedQueue executes speed tests sequentially across multiple relay nodes (strict FIFO queue).
func RunSpeedQueue(
	ctx context.Context,
	cfg *config.UserConfig,
	aliases []string,
	opts Options,
	progressCb ProgressCallback,
) ([]*SpeedResult, error) {
	if len(aliases) == 0 {
		return nil, nil
	}

	results := make([]*SpeedResult, 0, len(aliases))

	for _, alias := range aliases {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		res, err := RunSpeed(ctx, cfg, alias, opts, progressCb)
		if err != nil {
			res = &SpeedResult{
				Alias:    alias,
				Provider: opts.Provider,
				Error:    err.Error(),
			}
		}
		results = append(results, res)
	}

	return results, nil
}
