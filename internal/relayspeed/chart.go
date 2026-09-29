package relayspeed

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
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

// GetTerminalSize returns the current terminal width and height in columns and rows.
// Falls back to (80, 24) when running in non-TTY or when ioctl fails.
func GetTerminalSize() (width int, height int) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err == nil && ws.Col > 0 && ws.Row > 0 {
		return int(ws.Col), int(ws.Row)
	}
	ws, err = unix.IoctlGetWinsize(int(os.Stderr.Fd()), unix.TIOCGWINSZ)
	if err == nil && ws.Col > 0 && ws.Row > 0 {
		return int(ws.Col), int(ws.Row)
	}
	ws, err = unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err == nil && ws.Col > 0 && ws.Row > 0 {
		return int(ws.Col), int(ws.Row)
	}
	if f, err := os.Open("/dev/tty"); err == nil {
		ws, err = unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
		_ = f.Close()
		if err == nil && ws.Col > 0 && ws.Row > 0 {
			return int(ws.Col), int(ws.Row)
		}
	}
	if colsStr := os.Getenv("COLUMNS"); colsStr != "" {
		if c, err := strconv.Atoi(colsStr); err == nil && c > 0 {
			lines := 24
			if lStr := os.Getenv("LINES"); lStr != "" {
				if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
					lines = l
				}
			}
			return c, lines
		}
	}
	return 80, 24
}

// CalculateChartDimensions computes the optimal width (columns) and height for the 2D waveform
// based on terminal dimensions, mirroring the responsive terminal filling of cf-speedtest.py.
func CalculateChartDimensions(termWidth, termHeight int) (cols int, height int) {
	if termWidth <= 0 || termHeight <= 0 {
		w, h := GetTerminalSize()
		if termWidth <= 0 {
			termWidth = w
		}
		if termHeight <= 0 {
			termHeight = h
		}
	}

	labelW := 11      // Y-axis speed label width e.g. " 143.91 Mbps"
	sepW := 3         // " | " separator
	safetyMargin := 2 // Margin to prevent auto-line-wrap on wide terminals
	prefixW := labelW + sepW + safetyMargin

	cols = termWidth - prefixW
	if cols < 20 {
		cols = 20
	}

	// Responsive height: scales smoothly with terminal height, bounded between 6 and 14 rows
	height = termHeight - 14
	if height < 6 {
		height = 6
	} else if height > 14 {
		height = 14
	}

	return cols, height
}

// RenderSparkline compresses a sequence of samples into a single-line sparkline of fixed character width.
func RenderSparkline(samples []SpeedSample, width int) string {
	if width <= 0 {
		width = 12
	}
	if len(samples) == 0 {
		return strings.Repeat("-", width)
	}

	var clean []SpeedSample
	for _, s := range samples {
		if !math.IsNaN(s.Bps) && !math.IsInf(s.Bps, 0) && s.Bps >= 0 {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return strings.Repeat(" ", width)
	}

	allZero := true
	for _, s := range clean {
		if s.Bps > 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return strings.Repeat(" ", width)
	}

	bucketValues := resampleSamplesToColumns(clean, width)

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

// resampleValues projects a slice of float64 into exactly 'width' buckets.
// When n > width, it bucket-averages chunks.
// When n <= width, it smoothly linearly interpolates between data points to prevent blocky plateaus.
func resampleValues(values []float64, width int) []float64 {
	buckets := make([]float64, width)
	n := len(values)
	if n == 0 || width <= 0 {
		return buckets
	}
	if n == 1 {
		for i := range buckets {
			buckets[i] = values[0]
		}
		return buckets
	}

	if n <= width {
		for i := 0; i < width; i++ {
			pos := float64(i) * float64(n-1) / float64(width-1)
			idxLow := int(math.Floor(pos))
			idxHigh := int(math.Ceil(pos))
			if idxLow >= n {
				idxLow = n - 1
			}
			if idxHigh >= n {
				idxHigh = n - 1
			}
			if idxLow == idxHigh {
				buckets[i] = values[idxLow]
			} else {
				frac := pos - float64(idxLow)
				buckets[i] = values[idxLow] + frac*(values[idxHigh]-values[idxLow])
			}
		}
		return buckets
	}

	chunkSize := float64(n) / float64(width)
	for i := 0; i < width; i++ {
		start := int(float64(i) * chunkSize)
		end := int(float64(i+1) * chunkSize)
		if end > n {
			end = n
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

// resampleSamplesToColumns projects a time-series of SpeedSamples into exactly 'width' columns
// across the test duration using time-window bucketing and linear interpolation.
func resampleSamplesToColumns(samples []SpeedSample, width int) []float64 {
	cols := make([]float64, width)
	n := len(samples)
	if n == 0 || width <= 0 {
		return cols
	}
	if n == 1 {
		for i := range cols {
			cols[i] = samples[0].Bps
		}
		return cols
	}

	t0 := int64(0)
	tEnd := samples[n-1].ElapsedMs
	if tEnd <= 0 {
		tEnd = samples[0].ElapsedMs
	}

	// If timestamps are valid and increasing, use time-domain bucketing and interpolation
	if tEnd > t0 {
		duration := float64(tEnd - t0)
		for i := 0; i < width; i++ {
			tStart := float64(t0) + float64(i)*duration/float64(width)
			tStop := float64(t0) + float64(i+1)*duration/float64(width)
			tCenter := (tStart + tStop) / 2.0

			var sum float64
			var count int
			for _, s := range samples {
				t := float64(s.ElapsedMs)
				if i == width-1 {
					if t >= tStart && t <= tStop {
						sum += s.Bps
						count++
					}
				} else {
					if t >= tStart && t < tStop {
						sum += s.Bps
						count++
					}
				}
			}

			if count > 0 {
				cols[i] = sum / float64(count)
			} else {
				// Linear interpolation between the two nearest samples surrounding tCenter
				var prev, next *SpeedSample
				for idx := range samples {
					t := float64(samples[idx].ElapsedMs)
					if t <= tCenter {
						prev = &samples[idx]
					}
					if t >= tCenter && next == nil {
						next = &samples[idx]
					}
				}
				if prev != nil && next != nil && next.ElapsedMs > prev.ElapsedMs {
					ratio := (tCenter - float64(prev.ElapsedMs)) / float64(next.ElapsedMs-prev.ElapsedMs)
					cols[i] = prev.Bps + ratio*(next.Bps-prev.Bps)
				} else if prev != nil {
					cols[i] = prev.Bps
				} else if next != nil {
					cols[i] = next.Bps
				} else {
					cols[i] = samples[0].Bps
				}
			}
		}
		return cols
	}

	// Fallback when ElapsedMs are not populated or identical: index-based linear interpolation
	for i := 0; i < width; i++ {
		pos := float64(i) * float64(n-1) / float64(width-1)
		idxLow := int(math.Floor(pos))
		idxHigh := int(math.Ceil(pos))
		if idxLow >= n {
			idxLow = n - 1
		}
		if idxHigh >= n {
			idxHigh = n - 1
		}
		if idxLow == idxHigh {
			cols[i] = samples[idxLow].Bps
		} else {
			frac := pos - float64(idxLow)
			cols[i] = samples[idxLow].Bps + frac*(samples[idxHigh].Bps-samples[idxLow].Bps)
		}
	}
	return cols
}

// RenderWaveform generates a multi-line 2D ASCII/Unicode waveform chart of bandwidth over time.
// If width or height is <= 0, it dynamically sizes the chart to fill the user's terminal window.
func RenderWaveform(title string, samples []SpeedSample, avgBps float64, width int, height int, colorEnabled bool) string {
	if len(samples) == 0 {
		return ""
	}

	// Auto-detect responsive terminal dimensions if not explicitly provided
	if width <= 0 || height <= 0 {
		autoW, autoH := CalculateChartDimensions(0, 0)
		if width <= 0 {
			width = autoW
		}
		if height <= 0 {
			height = autoH
		}
	}

	var clean []SpeedSample
	for _, s := range samples {
		if !math.IsNaN(s.Bps) && !math.IsInf(s.Bps, 0) && s.Bps >= 0 {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return ""
	}

	cols := resampleSamplesToColumns(clean, width)

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
	colUnits := make([]int, width)
	for i, v := range cols {
		frac := v / yMax
		if frac < 0 {
			frac = 0
		} else if frac > 1 {
			frac = 1
		}
		colUnits[i] = int(math.Round(frac * float64(height*8)))
	}

	yAxisWidth := 11
	var sb strings.Builder

	if title != "" {
		sb.WriteString(title + ":\n")
	}

	// Calculate which row is closest to avgBps
	avgRow := -1
	if avgBps > 0 && avgBps <= yMax {
		avgRow = int(avgBps / (yMax / float64(height)))
		if avgRow >= height {
			avgRow = height - 1
		}
	}

	// Pre-generate row lines from top to bottom
	for r := height - 1; r >= 0; r-- {
		// Y-axis label
		var yLabel string
		switch {
		case r == height-1:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, FormatBitrate(peakBps))
		case r == avgRow:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, FormatBitrate(avgBps))
		case height >= 8 && r == height/2 && math.Abs(float64(avgRow-height/2)) >= 2:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, FormatBitrate(yMax*0.5))
		default:
			yLabel = fmt.Sprintf("%*s | ", yAxisWidth, "")
		}
		sb.WriteString(yLabel)

		// Render columns in row r
		var rowChars strings.Builder
		for c := 0; c < width; c++ {
			units := colUnits[c]
			fullRows := units / 8
			remainder := units % 8

			if r < fullRows {
				rowChars.WriteRune('█')
			} else if r == fullRows {
				if remainder > 0 {
					rowChars.WriteRune(sparklineBlocks[remainder-1])
				} else {
					rowChars.WriteRune(' ')
				}
			} else {
				rowChars.WriteRune(' ')
			}
		}

		lineStr := rowChars.String()
		if colorEnabled {
			lineStr = colorizeWaveformLine(lineStr, r, avgRow)
		}
		sb.WriteString(lineStr)
		sb.WriteString("\n")
	}

	// Baseline axis
	sb.WriteString(fmt.Sprintf("%*s +%s\n", yAxisWidth, FormatBitrate(0), strings.Repeat("-", width)))

	// X-axis time labels distributed across the full width
	totalElapsedMs := samples[len(samples)-1].ElapsedMs
	totalSec := float64(totalElapsedMs) / 1000.0
	if totalSec <= 0 {
		totalSec = 1.0
	}

	tickLine := make([]rune, width)
	for i := range tickLine {
		tickLine[i] = ' '
	}

	timeFractions := []float64{0.0, 0.25, 0.5, 0.75, 1.0}
	if width < 40 {
		timeFractions = []float64{0.0, 0.5, 1.0}
	}

	for _, frac := range timeFractions {
		timeVal := totalSec * frac
		var label string
		if totalSec >= 10 {
			label = fmt.Sprintf("%.0fs", timeVal)
		} else {
			label = fmt.Sprintf("%.1fs", timeVal)
		}

		pos := int(math.Round(frac * float64(width-1)))
		if pos+len(label) > width {
			pos = width - len(label)
		}
		if pos < 0 {
			pos = 0
		}

		for j, ch := range label {
			if pos+j < width {
				tickLine[pos+j] = ch
			}
		}
	}

	prefix := strings.Repeat(" ", yAxisWidth+3)
	sb.WriteString(fmt.Sprintf("%s%s\n", prefix, string(tickLine)))

	return sb.String()
}

func colorizeWaveformLine(line string, row int, avgRow int) string {
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
