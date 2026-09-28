package relayspeed

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// IsTerminal checks if the provided file descriptor is connected to a terminal.
func IsTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

// ProgressRenderer manages terminal animations, braille spinners, and clean non-TTY fallback.
type ProgressRenderer struct {
	mu           sync.Mutex
	out          io.Writer
	isTTY        bool
	disabled     bool
	colorEnabled bool

	activeNode   string
	lastUpdate   ProgressUpdate
	hasUpdate    bool
	frameIdx     int
	lastRenderAt time.Time

	ticker chan struct{}
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewProgressRenderer creates a new progress renderer.
func NewProgressRenderer(out io.Writer, isTTY bool, disabled bool) *ProgressRenderer {
	if out == nil {
		out = os.Stdout
	}
	r := &ProgressRenderer{
		out:          out,
		isTTY:        isTTY,
		disabled:     disabled,
		colorEnabled: isTTY && !disabled,
		stopCh:       make(chan struct{}),
	}

	if r.isTTY && !r.disabled {
		r.wg.Add(1)
		go r.animationLoop()
	}

	return r
}

func (r *ProgressRenderer) animationLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(90 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.mu.Lock()
			if r.activeNode != "" {
				r.frameIdx = (r.frameIdx + 1) % len(spinnerFrames)
				r.renderLocked()
			}
			r.mu.Unlock()
		}
	}
}

// StartNode begins tracking progress for a specific relay node.
func (r *ProgressRenderer) StartNode(alias string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.activeNode = alias
	r.hasUpdate = false
	r.lastUpdate = ProgressUpdate{Alias: alias}
	r.frameIdx = 0

	if r.disabled {
		return
	}

	if !r.isTTY {
		fmt.Fprintf(r.out, "[%s] Starting speed test...\n", alias)
		return
	}

	r.renderLocked()
}

// Update accepts an incremental progress update from the test engine.
func (r *ProgressRenderer) Update(u ProgressUpdate) {
	if r.disabled || !r.isTTY {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if u.Alias != "" {
		r.activeNode = u.Alias
	}
	r.lastUpdate = u
	r.hasUpdate = true

	// Limit direct render rate to avoid excessive I/O
	if time.Since(r.lastRenderAt) >= 90*time.Millisecond {
		r.renderLocked()
	}
}

// ProgressCallback returns a ProgressCallback function tied to this renderer.
func (r *ProgressRenderer) ProgressCallback() ProgressCallback {
	return func(u ProgressUpdate) {
		r.Update(u)
	}
}

// CompleteNode handles node completion, locking the line in place.
func (r *ProgressRenderer) CompleteNode(res *SpeedResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	alias := r.activeNode
	if res != nil && res.Alias != "" {
		alias = res.Alias
	}

	if r.disabled {
		r.activeNode = ""
		return
	}

	summary := formatDoneSummary(res)

	if !r.isTTY {
		if res != nil && res.Error != "" && res.Download == nil && res.Upload == nil {
			fmt.Fprintf(r.out, "[%s] Failed: %s\n", alias, res.Error)
		} else {
			fmt.Fprintf(r.out, "[%s] %s\n", alias, summary)
		}
		r.activeNode = ""
		return
	}

	// In TTY mode: overwrite current line in place and lock with newline
	var prefix string
	if res != nil && res.Error != "" && res.Download == nil && res.Upload == nil {
		if r.colorEnabled {
			prefix = "\033[31m✖\033[0m"
		} else {
			prefix = "✖"
		}
		fmt.Fprintf(r.out, "\r%s [%s] Failed: %s\033[K\n", prefix, alias, res.Error)
	} else {
		if r.colorEnabled {
			prefix = "\033[32m✔\033[0m"
		} else {
			prefix = "✔"
		}
		fmt.Fprintf(r.out, "\r%s [%s] %s\033[K\n", prefix, alias, summary)
	}

	r.activeNode = ""
}

// Stop cleanly terminates background animation tickers.
func (r *ProgressRenderer) Stop() {
	r.mu.Lock()
	if r.stopCh != nil {
		select {
		case <-r.stopCh:
		default:
			close(r.stopCh)
		}
	}
	r.mu.Unlock()

	r.wg.Wait()
}

func (r *ProgressRenderer) renderLocked() {
	if !r.isTTY || r.disabled || r.activeNode == "" {
		return
	}

	frame := spinnerFrames[r.frameIdx]
	line := r.formatCurrentLine(frame)

	fmt.Fprintf(r.out, "\r%s\033[K", line)
	r.lastRenderAt = time.Now()
}

func (r *ProgressRenderer) formatCurrentLine(frame string) string {
	u := r.lastUpdate
	alias := r.activeNode

	switch u.Phase {
	case "idle_ping":
		if u.Elapsed > 0 {
			ms := float64(u.Elapsed.Microseconds()) / 1000.0
			return fmt.Sprintf("%s [%s] Measuring idle latency... %.1f ms", frame, alias, ms)
		}
		return fmt.Sprintf("%s [%s] Measuring idle latency...", frame, alias)

	case "auto_probe":
		dirStr := string(u.Direction)
		if dirStr == "" {
			dirStr = "download"
		}
		return fmt.Sprintf("%s [%s] Probing %s baseline...", frame, alias, dirStr)

	case "auto_ramp":
		dirStr := string(u.Direction)
		if dirStr == "" {
			dirStr = "download"
		}
		return fmt.Sprintf("%s [%s] Ramping concurrency to %d stream(s)...", frame, alias, u.StepThreads)

	case "auto_sustaining":
		dirLabel := "Download"
		if u.Direction == DirectionUpload {
			dirLabel = "Upload"
		}
		label := dirLabel + ":"
		if u.StepThreads > 1 {
			label = fmt.Sprintf("%s (%d streams):", dirLabel, u.StepThreads)
		}
		totalBytes := u.TotalBytes
		if totalBytes <= 0 {
			totalBytes = MaxAutoTransferBytes
		}
		bar, pctInt := renderProgressBar(u.BytesDone, totalBytes, 18)
		doneStr := FormatDecimalBytes(u.BytesDone)
		totalStr := FormatDecimalBytes(totalBytes)
		bpsStr := FormatBitrate(u.CurrentBps)
		return fmt.Sprintf("%s [%s] %s [%s] %3d%%  %s / %s | %s (stability: %.0f%%)",
			frame, alias, label, bar, pctInt, doneStr, totalStr, bpsStr, u.StepGain)

	case "auto_converged":
		dirLabel := "Download"
		if u.Direction == DirectionUpload {
			dirLabel = "Upload"
		}
		label := dirLabel + ":"
		if u.StepThreads > 1 {
			label = fmt.Sprintf("%s (%d streams):", dirLabel, u.StepThreads)
		}
		totalBytes := u.TotalBytes
		if totalBytes <= 0 {
			totalBytes = MaxAutoTransferBytes
		}
		bar, pctInt := renderProgressBar(u.BytesDone, totalBytes, 18)
		doneStr := FormatDecimalBytes(u.BytesDone)
		totalStr := FormatDecimalBytes(totalBytes)
		bpsStr := FormatBitrate(u.CurrentBps)
		return fmt.Sprintf("%s [%s] %s [%s] %3d%%  %s / %s | %s (converged)",
			frame, alias, label, bar, pctInt, doneStr, totalStr, bpsStr)

	case "download", "upload":
		dirLabel := "Download"
		if u.Phase == "upload" || u.Direction == DirectionUpload {
			dirLabel = "Upload"
		}

		label := dirLabel + ":"
		if u.StepThreads > 1 {
			label = fmt.Sprintf("%s (%d streams):", dirLabel, u.StepThreads)
		}

		bar, pctInt := renderProgressBar(u.BytesDone, u.TotalBytes, 18)
		doneStr := FormatDecimalBytes(u.BytesDone)
		totalStr := FormatDecimalBytes(u.TotalBytes)
		bpsStr := FormatBitrate(u.CurrentBps)

		etaStr := ""
		if u.CurrentBps > 0 && u.TotalBytes > u.BytesDone {
			remBits := float64((u.TotalBytes - u.BytesDone) * 8)
			etaSec := remBits / u.CurrentBps
			etaStr = fmt.Sprintf(" (ETA: %.1fs)", etaSec)
		} else if u.TotalBytes > 0 && u.BytesDone < u.TotalBytes {
			etaStr = " (ETA: --)"
		}

		return fmt.Sprintf("%s [%s] %s [%s] %3d%%  %s / %s | %s%s",
			frame, alias, label, bar, pctInt, doneStr, totalStr, bpsStr, etaStr)

	default:
		return fmt.Sprintf("%s [%s] Preparing speed test...", frame, alias)
	}
}

func formatDoneSummary(res *SpeedResult) string {
	if res == nil {
		return "Done"
	}

	var parts []string
	if res.Download != nil {
		parts = append(parts, fmt.Sprintf("↓ %s", FormatBitrate(res.Download.AvgSpeedBps)))
	}
	if res.Upload != nil {
		parts = append(parts, fmt.Sprintf("↑ %s", FormatBitrate(res.Upload.AvgSpeedBps)))
	}

	var ping time.Duration
	if res.Download != nil && res.Download.IdleLatencyAvg > 0 {
		ping = res.Download.IdleLatencyAvg
	} else if res.Upload != nil && res.Upload.IdleLatencyAvg > 0 {
		ping = res.Upload.IdleLatencyAvg
	}

	if ping > 0 {
		parts = append(parts, fmt.Sprintf("Ping %s", FormatDurationMetric(ping)))
	}

	if len(parts) == 0 {
		return "Done"
	}
	return "Done: " + strings.Join(parts, " | ")
}

func renderProgressBar(bytesDone, totalBytes int64, width int) (bar string, pctInt int) {
	pct := 0.0
	if totalBytes > 0 {
		pct = float64(bytesDone) / float64(totalBytes)
	}
	if pct > 1.0 {
		pct = 1.0
	} else if pct < 0 {
		pct = 0
	}

	filled := int(math.Round(pct * float64(width)))
	if filled > width {
		filled = width
	}
	bar = strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	pctInt = int(pct * 100)
	return bar, pctInt
}

