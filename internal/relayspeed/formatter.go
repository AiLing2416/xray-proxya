package relayspeed

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"xray-proxya/pkg/units"
)

func isColorSupported() bool {
	return IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

// FormatBitrateColored formats a bitrate with ANSI color coding based on speed tiers when color is enabled:
// >100 Mbps: Bold Cyan/Green
// 20~100 Mbps: Green
// <20 Mbps: Yellow
func FormatBitrateColored(bps float64, colorEnabled bool) string {
	raw := FormatBitrate(bps)
	if !colorEnabled || bps <= 0 {
		return raw
	}
	mbps := bps / 1_000_000.0
	var colorCode string
	switch {
	case mbps >= 100.0:
		colorCode = "\033[1;36m" // Bold Cyan (High speed >100 Mbps)
	case mbps >= 20.0:
		colorCode = "\033[32m"   // Green (Normal 20~100 Mbps)
	default:
		colorCode = "\033[33m"   // Yellow (Slow <20 Mbps)
	}
	return colorCode + raw + "\033[0m"
}

func formatTableBitrate(bps float64, width int, colorEnabled bool) string {
	raw := FormatBitrate(bps)
	if !colorEnabled || bps <= 0 {
		if len(raw) < width {
			return raw + strings.Repeat(" ", width-len(raw))
		}
		return raw
	}
	colored := FormatBitrateColored(bps, true)
	if len(raw) < width {
		return colored + strings.Repeat(" ", width-len(raw))
	}
	return colored
}

// RenderTerminal renders speed test results in terminal format (card view for single node, table for multi-node).
func RenderTerminal(results []*SpeedResult) string {
	return RenderTerminalWithChart(results, false, isColorSupported())
}

// RenderTerminalWithChart formats speed test results with optional chart display.
func RenderTerminalWithChart(results []*SpeedResult, showChart bool, colorEnabled bool) string {
	if len(results) == 0 {
		return ""
	}
	if len(results) == 1 {
		return RenderSingleCardWithChart(results[0], showChart, colorEnabled)
	}
	return RenderTableWithChart(results, showChart, colorEnabled)
}

// RenderSingleCard formats a single node result as a compact card.
func RenderSingleCard(r *SpeedResult) string {
	return RenderSingleCardStyled(r, isColorSupported())
}

// RenderSingleCardStyled formats a single node result with explicit color styling control.
func RenderSingleCardStyled(r *SpeedResult, colorEnabled bool) string {
	return RenderSingleCardWithChart(r, false, colorEnabled)
}

// RenderSingleCardWithChart formats a single node result with optional 2D waveform chart.
func RenderSingleCardWithChart(r *SpeedResult, showChart bool, colorEnabled bool) string {
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
		streamsSuffix := ""
		if r.OptimalThreads > 1 {
			streamsSuffix = fmt.Sprintf(" | Streams: %d", r.OptimalThreads)
		}
		sb.WriteString(fmt.Sprintf("Download  : %s (Peak: %s | Low 20%%: %s%s)\n",
			FormatBitrateColored(r.Download.AvgSpeedBps, colorEnabled),
			FormatBitrate(r.Download.PeakSpeedBps),
			FormatBitrate(r.Download.Low20SpeedBps),
			streamsSuffix,
		))
		idleLat = r.Download.IdleLatencyAvg
		loadLat = r.Download.LoadLatencyAvg
		lossRate = r.Download.LoadLatencyLossRate
		totalBytesDL = r.Download.BytesTransferred
		durationDL = time.Duration(r.Download.DurationMs) * time.Millisecond
	}

	if r.Upload != nil {
		streamsSuffix := ""
		if r.UploadOptimalThreads > 1 {
			streamsSuffix = fmt.Sprintf(" | Streams: %d", r.UploadOptimalThreads)
		}
		sb.WriteString(fmt.Sprintf("Upload    : %s (Peak: %s | Low 20%%: %s%s)\n",
			FormatBitrateColored(r.Upload.AvgSpeedBps, colorEnabled),
			FormatBitrate(r.Upload.PeakSpeedBps),
			FormatBitrate(r.Upload.Low20SpeedBps),
			streamsSuffix,
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

	// Latency line: Idle: 32ms | Load: 46ms (+14ms) | Loss: 0.0%
	idleStr := FormatDurationMetric(idleLat)
	loadStr := FormatDurationMetric(loadLat)
	diffStr := ""
	if loadLat > 0 && idleLat > 0 {
		diff := loadLat - idleLat
		if diff >= 0 {
			diffStr = fmt.Sprintf(" (+%s)", FormatDurationMetric(diff))
		} else {
			diffStr = fmt.Sprintf(" (-%s)", FormatDurationMetric(-diff))
		}
	}
	sb.WriteString(fmt.Sprintf("Latency   : Idle: %s | Load: %s%s | Loss: %.1f%%\n",
		idleStr, loadStr, diffStr, lossRate*100,
	))

	if r.Error != "" {
		sb.WriteString(fmt.Sprintf("Warning   : %s\n", r.Error))
	}

	if showChart && r != nil {
		chartW, chartH := CalculateChartDimensions(0, 0)
		if r.Download != nil && len(r.Download.Samples) > 0 {
			wf := RenderWaveform("Download Speed Waveform", r.Download.Samples, r.Download.AvgSpeedBps, chartW, chartH, colorEnabled)
			if wf != "" {
				sb.WriteString("\n" + wf)
			}
		}
		if r.Upload != nil && len(r.Upload.Samples) > 0 {
			wf := RenderWaveform("Upload Speed Waveform", r.Upload.Samples, r.Upload.AvgSpeedBps, chartW, chartH, colorEnabled)
			if wf != "" {
				sb.WriteString("\n" + wf)
			}
		}
	}

	return sb.String()
}

// RenderTable formats multiple node results into a summary table.
func RenderTable(results []*SpeedResult) string {
	return RenderTableStyled(results, isColorSupported())
}

// RenderTableWithChart formats multiple node results with optional sparkline column.
func RenderTableWithChart(results []*SpeedResult, showChart bool, colorEnabled bool) string {
	return renderTableInternal(results, colorEnabled, showChart)
}

// RenderTableStyled formats multiple node results with explicit color control.
func RenderTableStyled(results []*SpeedResult, colorEnabled bool) string {
	return renderTableInternal(results, colorEnabled, false)
}

func renderTableInternal(results []*SpeedResult, colorEnabled bool, showChart bool) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	var header, sep string
	if showChart {
		header = fmt.Sprintf("%-10s | %-12s | %-13s | %-13s | %-10s | %-10s | %-6s | %-12s\n",
			"ALIAS", "PROVIDER", "DOWNLOAD", "UPLOAD", "IDLE PING", "LOAD PING", "LOSS", "TREND (DL)")
		sep = strings.Repeat("-", 101) + "\n"
	} else {
		header = fmt.Sprintf("%-10s | %-12s | %-13s | %-13s | %-10s | %-10s | %-6s\n",
			"ALIAS", "PROVIDER", "DOWNLOAD", "UPLOAD", "IDLE PING", "LOAD PING", "LOSS")
		sep = strings.Repeat("-", 86) + "\n"
	}

	sb.WriteString(header)
	sb.WriteString(sep)

	for _, r := range results {
		dlStr := fmt.Sprintf("%-13s", "N/A")
		ulStr := fmt.Sprintf("%-13s", "N/A")
		idleStr := "N/A"
		loadStr := "N/A"
		lossStr := "0.0%"

		if r.Error != "" && r.Download == nil && r.Upload == nil {
			failStr := "FAIL: " + truncate(r.Error, 50)
			if colorEnabled {
				failStr = "\033[31mFAIL:\033[0m " + truncate(r.Error, 50)
			}
			failWidth := 60
			if showChart {
				failWidth = 75
			}
			sb.WriteString(fmt.Sprintf("%-10s | %-12s | %-*s\n",
				truncate(r.Alias, 10), truncate(r.Provider, 12), failWidth, failStr))
			continue
		}

		if r.Download != nil {
			dlStr = formatTableBitrate(r.Download.AvgSpeedBps, 13, colorEnabled)
			if r.Download.IdleLatencyAvg > 0 {
				idleStr = FormatDurationMetric(r.Download.IdleLatencyAvg)
			}
			if r.Download.LoadLatencyAvg > 0 {
				loadStr = FormatDurationMetric(r.Download.LoadLatencyAvg)
			}
			lossStr = fmt.Sprintf("%.1f%%", r.Download.LoadLatencyLossRate*100)
		}

		if r.Upload != nil {
			ulStr = formatTableBitrate(r.Upload.AvgSpeedBps, 13, colorEnabled)
			if idleStr == "N/A" && r.Upload.IdleLatencyAvg > 0 {
				idleStr = FormatDurationMetric(r.Upload.IdleLatencyAvg)
			}
			if loadStr == "N/A" && r.Upload.LoadLatencyAvg > 0 {
				loadStr = FormatDurationMetric(r.Upload.LoadLatencyAvg)
				lossStr = fmt.Sprintf("%.1f%%", r.Upload.LoadLatencyLossRate*100)
			}
		}

		trendCol := ""
		if showChart {
			if r.Download != nil && len(r.Download.Samples) > 0 {
				trendCol = " | " + RenderSparkline(r.Download.Samples, 12)
			} else {
				trendCol = " | " + fmt.Sprintf("%-12s", "N/A")
			}
		}

		sb.WriteString(fmt.Sprintf("%-10s | %-12s | %s | %s | %-10s | %-10s | %-6s%s\n",
			truncate(r.Alias, 10),
			truncate(r.Provider, 12),
			dlStr,
			ulStr,
			idleStr,
			loadStr,
			lossStr,
			trendCol,
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
