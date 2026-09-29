package relayspeed

import (
	"fmt"
	"math"
	"strings"
)

var sparklineBlocks = []rune{
	' ', // U+2581 Lower one eighth block
	'▂', // U+2582 Lower one quarter block
	'▃', // U+2583 Lower three eighths block
	'▄', // U+2584 Lower half block
	'▅', // U+2585 Lower five eighths block
	'▆', // U+2586 Lower three quarters block
	'▇', // U+2587 Lower seven eighths block
	'█', // U+2588 Full block
}

// RenderSparkline compresses a sequence of samples into a single-line sparkline of fixed character width.
func RenderSparkline(samples []SpeedSample, width int) string {
	if width <= 0 {
		width = 12
	}
	if len(samples) == 0 {
		return strings.Repeat("-", width)
	}

	// Filter out non-positive samples
	var valid []float64
	for _, s := range samples {
		if s.Bps > 0 && !math.IsNaN(s.Bps) && !math.IsInf(s.Bps, 0) {
			valid = append(valid, s.Bps)
		}
	}
	if len(valid) == 0 {
		return strings.Repeat(" ", width)
	}

	bucketValues := resampleValues(valid, width)

	// Determine min and max across buckets
	minBps := bucketValues[0]
	maxBps := bucketValues[0]
	for _, v := range bucketValues {
		if v < minBps {
			minBps = v
		}
		if v > maxBps {
			maxBps = v
		}
	}

	// Flatline protection: if dynamic range is zero or negligible
	if maxBps-minBps < 1e-6 {
		if maxBps > 0 {
			// Middle block for stable constant non-zero speed
			return strings.Repeat(string(sparklineBlocks[3]), width)
		}
		return strings.Repeat(string(sparklineBlocks[0]), width)
	}

	// Map each bucket value to 8 levels (0..7)
	var sb strings.Builder
	for _, v := range bucketValues {
		ratio := (v - minBps) / (maxBps - minBps)
		if ratio < 0 {
			ratio = 0
		} else if ratio > 1 {
			ratio = 1
		}
		level := int(math.Round(ratio * 7.0))
		if level < 0 {
			level = 0
		} else if level > 7 {
			level = 7
		}
		sb.WriteRune(sparklineBlocks[level])
	}

	return sb.String()
}

// resampleValues projects a slice of float64 into exactly 'width' buckets by averaging chunks.
func resampleValues(values []float64, width int) []float64 {
	buckets := make([]float64, width)
	if len(values) == 0 {
		return buckets
	}

	if len(values) <= width {
		for i := 0; i < width; i++ {
			idx := int(float64(i) * float64(len(values)) / float64(width))
			if idx >= len(values) {
				idx = len(values) - 1
			}
			buckets[i] = values[idx]
		}
		return buckets
	}

	chunkSize := float64(len(values)) / float64(width)
	for i := 0; i < width; i++ {
		start := int(float64(i) * chunkSize)
		end := int(float64(i+1) * chunkSize)
		if end > len(values) {
			end = len(values)
		}
		if start >= end {
			start = end - 1
		}
		var sum float64
		count := 0
		for j := start; j < end; j++ {
			sum += values[j]
			count++
		}
		if count > 0 {
			buckets[i] = sum / float64(count)
		} else {
			buckets[i] = values[start]
		}
	}
	return buckets
}

// RenderWaveform generates a multi-line 2D ASCII/Unicode waveform chart of bandwidth over time.
func RenderWaveform(title string, samples []SpeedSample, avgBps float64, width int, height int, colorEnabled bool) string {
	if len(samples) == 0 {
		return ""
	}
	if width <= 0 {
		width = 50
	}
	if height <= 0 {
		height = 6
	}

	var validBps []float64
	for _, s := range samples {
		if s.Bps > 0 && !math.IsNaN(s.Bps) && !math.IsInf(s.Bps, 0) {
			validBps = append(validBps, s.Bps)
		}
	}
	if len(validBps) == 0 {
		return ""
	}

	cols := resampleValues(validBps, width)

	peakBps := cols[0]
	for _, v := range cols {
		if v > peakBps {
			peakBps = v
		}
	}
	if peakBps <= 0 {
		return ""
	}

	yMax := peakBps * 1.05
	rowHeight := yMax / float64(height)

	yAxisWidth := 11
	var sb strings.Builder

	if title != "" {
		sb.WriteString(title + ":\n")
	}

	// Calculate which row is closest to avgBps
	avgRow := -1
	if avgBps > 0 && avgBps <= yMax {
		avgRow = int(avgBps / rowHeight)
		if avgRow >= height {
			avgRow = height - 1
		}
	}

	// Render from top row down to bottom row
	for r := height - 1; r >= 0; r-- {
		// Y-axis label
		var yLabel string
		switch {
		case r == height-1:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, FormatBitrate(peakBps))
		case r == avgRow:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, FormatBitrate(avgBps))
		default:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, "")
		}
		sb.WriteString(yLabel)

		// Render columns in this row
		rowLower := float64(r) * rowHeight
		rowUpper := float64(r+1) * rowHeight

		var rowChars strings.Builder
		for c := 0; c < width; c++ {
			val := cols[c]
			switch {
			case val >= rowUpper:
				rowChars.WriteRune('█')
			case val <= rowLower:
				rowChars.WriteRune(' ')
			default:
				frac := (val - rowLower) / rowHeight
				level := int(math.Round(frac * 7.0))
				if level < 0 {
					level = 0
				} else if level > 7 {
					level = 7
				}
				rowChars.WriteRune(sparklineBlocks[level])
			}
		}

		lineStr := rowChars.String()
		if colorEnabled {
			// Apply colored highlight to non-space characters
			lineStr = colorizeWaveformLine(lineStr, r, avgRow)
		}
		sb.WriteString(lineStr)

		if r == avgRow {
			if colorEnabled {
				sb.WriteString(" \033[2m(Avg)\033[0m")
			} else {
				sb.WriteString(" (Avg)")
			}
		}
		sb.WriteString("\n")
	}

	// Baseline axis
	sb.WriteString(fmt.Sprintf("%*s +%s\n", yAxisWidth, FormatBitrate(0), strings.Repeat("-", width)))

	// X-axis time labels
	startSec := "0.0s"
	endSec := "0.0s"
	totalElapsedMs := samples[len(samples)-1].ElapsedMs
	if totalElapsedMs > 0 {
		endSec = fmt.Sprintf("%.1fs", float64(totalElapsedMs)/1000.0)
	}

	midSec := ""
	if totalElapsedMs > 1000 {
		midSec = fmt.Sprintf("%.1fs", float64(totalElapsedMs)/2000.0)
	}

	// Format bottom time line with padding
	prefix := strings.Repeat(" ", yAxisWidth+3)
	if midSec != "" && width >= 30 {
		leftGap := (width / 2) - len(startSec) - len(midSec)/2
		if leftGap < 1 {
			leftGap = 1
		}
		rightGap := width - len(startSec) - leftGap - len(midSec) - len(endSec)
		if rightGap < 1 {
			rightGap = 1
		}
		sb.WriteString(fmt.Sprintf("%s%s%s%s%s%s\n",
			prefix,
			startSec,
			strings.Repeat(" ", leftGap),
			midSec,
			strings.Repeat(" ", rightGap),
			endSec,
		))
	} else {
		gap := width - len(startSec) - len(endSec)
		if gap < 1 {
			gap = 1
		}
		sb.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, startSec, strings.Repeat(" ", gap), endSec))
	}

	return sb.String()
}

func colorizeWaveformLine(line string, row int, avgRow int) string {
	// Colorize blocks while keeping spaces uncolored
	var sb strings.Builder
	inColor := false
	currentColor := ""

	targetColor := "\033[32m" // Default green
	if row >= avgRow {
		targetColor = "\033[1;36m" // Cyan above average
	}

	for _, ch := range line {
		if ch == ' ' {
			if inColor {
				sb.WriteString("\033[0m")
				inColor = false
				currentColor = ""
			}
			sb.WriteRune(' ')
		} else {
			if !inColor || currentColor != targetColor {
				sb.WriteString(targetColor)
				inColor = true
				currentColor = targetColor
			}
			sb.WriteRune(ch)
		}
	}
	if inColor {
		sb.WriteString("\033[0m")
	}
	return sb.String()
}
