package relayspeed

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"xray-proxya/pkg/units"
)

// RenderTerminal renders speed test results in terminal format (card view for single node, table for multi-node).
func RenderTerminal(results []*SpeedResult) string {
	if len(results) == 0 {
		return ""
	}
	if len(results) == 1 {
		return RenderSingleCard(results[0])
	}
	return RenderTable(results)
}

// RenderSingleCard formats a single node result as a compact card.
func RenderSingleCard(r *SpeedResult) string {
	if r == nil {
		return ""
	}
	if r.Error != "" && r.Download == nil && r.Upload == nil {
		return fmt.Sprintf("[%s] (Provider: %s)\n  ❌ Error: %s\n", r.Alias, r.Provider, r.Error)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] (Provider: %s)\n", r.Alias, r.Provider))

	var idleLat, loadLat time.Duration
	var lossRate float64
	var totalBytesDL, totalBytesUL int64
	var durationDL, durationUL time.Duration

	if r.Download != nil {
		sb.WriteString(fmt.Sprintf("Download  : %s (Peak: %s | Low 20%%: %s)\n",
			FormatBitrate(r.Download.AvgSpeedBps),
			FormatBitrate(r.Download.PeakSpeedBps),
			FormatBitrate(r.Download.Low20SpeedBps),
		))
		idleLat = r.Download.IdleLatencyAvg
		loadLat = r.Download.LoadLatencyAvg
		lossRate = r.Download.LoadLatencyLossRate
		totalBytesDL = r.Download.BytesTransferred
		durationDL = time.Duration(r.Download.DurationMs) * time.Millisecond
	}

	if r.Upload != nil {
		sb.WriteString(fmt.Sprintf("Upload    : %s (Peak: %s | Low 20%%: %s)\n",
			FormatBitrate(r.Upload.AvgSpeedBps),
			FormatBitrate(r.Upload.PeakSpeedBps),
			FormatBitrate(r.Upload.Low20SpeedBps),
		))
		if idleLat == 0 {
			idleLat = r.Upload.IdleLatencyAvg
		}
		if loadLat == 0 {
			loadLat = r.Upload.LoadLatencyAvg
			lossRate = r.Upload.LoadLatencyLossRate
		}
		totalBytesUL = r.Upload.BytesTransferred
		durationUL = time.Duration(r.Upload.DurationMs) * time.Millisecond
	}

	// Data line
	totalTime := time.Duration(r.TotalDurationMs) * time.Millisecond
	if totalTime == 0 {
		totalTime = durationDL + durationUL
	}

	if r.Download != nil && r.Upload != nil {
		sb.WriteString(fmt.Sprintf("Data      : ↓ %s / ↑ %s (Time: %s)\n",
			FormatDecimalBytes(totalBytesDL),
			FormatDecimalBytes(totalBytesUL),
			formatDurationSec(totalTime),
		))
	} else if r.Download != nil {
		sb.WriteString(fmt.Sprintf("Data      : ↓ %s (Time: %s)\n",
			FormatDecimalBytes(totalBytesDL),
			formatDurationSec(totalTime),
		))
	} else if r.Upload != nil {
		sb.WriteString(fmt.Sprintf("Data      : ↑ %s (Time: %s)\n",
			FormatDecimalBytes(totalBytesUL),
			formatDurationSec(totalTime),
		))
	}

	// Latency line: Idle: Xms | Under Load: Yms | Loss: Z%
	idleStr := FormatDurationMetric(idleLat)
	loadStr := FormatDurationMetric(loadLat)
	sb.WriteString(fmt.Sprintf("Latency   : Idle: %s | Under Load: %s | Loss: %.1f%%\n",
		idleStr, loadStr, lossRate*100,
	))

	if r.Error != "" {
		sb.WriteString(fmt.Sprintf("Warning   : %s\n", r.Error))
	}

	return sb.String()
}

// RenderTable formats multiple node results into a summary table.
func RenderTable(results []*SpeedResult) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	header := fmt.Sprintf("%-10s | %-12s | %-13s | %-13s | %-10s | %-10s | %-6s\n",
		"ALIAS", "PROVIDER", "DOWNLOAD", "UPLOAD", "IDLE PING", "LOAD PING", "LOSS")
	sep := strings.Repeat("-", 86) + "\n"

	sb.WriteString(header)
	sb.WriteString(sep)

	for _, r := range results {
		dlStr := "N/A"
		ulStr := "N/A"
		idleStr := "N/A"
		loadStr := "N/A"
		lossStr := "0.0%"

		if r.Error != "" && r.Download == nil && r.Upload == nil {
			sb.WriteString(fmt.Sprintf("%-10s | %-12s | %-60s\n",
				truncate(r.Alias, 10), truncate(r.Provider, 12), "FAIL: "+truncate(r.Error, 50)))
			continue
		}

		if r.Download != nil {
			dlStr = FormatBitrate(r.Download.AvgSpeedBps)
			if r.Download.IdleLatencyAvg > 0 {
				idleStr = FormatDurationMetric(r.Download.IdleLatencyAvg)
			}
			if r.Download.LoadLatencyAvg > 0 {
				loadStr = FormatDurationMetric(r.Download.LoadLatencyAvg)
			}
			lossStr = fmt.Sprintf("%.1f%%", r.Download.LoadLatencyLossRate*100)
		}

		if r.Upload != nil {
			ulStr = FormatBitrate(r.Upload.AvgSpeedBps)
			if idleStr == "N/A" && r.Upload.IdleLatencyAvg > 0 {
				idleStr = FormatDurationMetric(r.Upload.IdleLatencyAvg)
			}
			if loadStr == "N/A" && r.Upload.LoadLatencyAvg > 0 {
				loadStr = FormatDurationMetric(r.Upload.LoadLatencyAvg)
				lossStr = fmt.Sprintf("%.1f%%", r.Upload.LoadLatencyLossRate*100)
			}
		}

		sb.WriteString(fmt.Sprintf("%-10s | %-12s | %-13s | %-13s | %-10s | %-10s | %-6s\n",
			truncate(r.Alias, 10),
			truncate(r.Provider, 12),
			dlStr,
			ulStr,
			idleStr,
			loadStr,
			lossStr,
		))
	}

	return sb.String()
}

// RenderJSON formats results as structured JSON.
func RenderJSON(results interface{}) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func FormatBitrate(bps float64) string {
	if bps <= 0 {
		return "0.00 Mbps"
	}
	mbps := bps / 1_000_000.0
	if mbps >= 1000.0 {
		return fmt.Sprintf("%.2f Gbps", mbps/1000.0)
	}
	if mbps >= 1.0 {
		return fmt.Sprintf("%.2f Mbps", mbps)
	}
	kbps := bps / 1_000.0
	return fmt.Sprintf("%.2f Kbps", kbps)
}

func FormatDecimalBytes(bytes int64) string {
	if bytes <= 0 {
		return "0 B"
	}
	switch {
	case bytes >= units.GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(units.GB))
	case bytes >= units.MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(units.MB))
	case bytes >= units.KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(units.KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func FormatDurationMetric(d time.Duration) string {
	if d <= 0 {
		return "N/A"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func formatDurationSec(d time.Duration) string {
	if d <= 0 {
		return "0.0s"
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-2] + ".."
}

func ParseSize(s string) (int64, error) {
	val, err := units.ParseBytes(s, units.Byte)
	if err != nil {
		return 0, err
	}
	if val < 0 {
		return 0, fmt.Errorf("size cannot be negative")
	}
	return val, nil
}
