package ui

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ProgressRenderer manages terminal animations, braille spinners, and clean non-TTY fallback.
type ProgressRenderer struct {
	mu           sync.Mutex
	out          io.Writer
	isTTY        bool
	disabled     bool
	colorEnabled bool

	activeNode   string
	phase        string
	frameIdx     int
	lastRenderAt time.Time

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
		colorEnabled: isTTY && !disabled && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb",
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

// Start begins tracking progress for a specific node/target.
func (r *ProgressRenderer) Start(alias, initialPhase string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.activeNode = alias
	r.phase = initialPhase
	r.frameIdx = 0

	if r.disabled {
		return
	}

	if !r.isTTY {
		if initialPhase != "" {
			fmt.Fprintf(r.out, "[%s] %s\n", alias, initialPhase)
		} else {
			fmt.Fprintf(r.out, "[%s] Starting...\n", alias)
		}
		return
	}

	r.renderLocked()
}

// Update changes the active phase message.
func (r *ProgressRenderer) Update(phase string) {
	if r.disabled || !r.isTTY {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.phase = phase
	if time.Since(r.lastRenderAt) >= 90*time.Millisecond {
		r.renderLocked()
	}
}

// Complete handles completion of the node, locking the line in place.
func (r *ProgressRenderer) Complete(alias string, success bool, summary string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if alias == "" {
		alias = r.activeNode
	}

	if r.disabled {
		r.activeNode = ""
		return
	}

	if !r.isTTY {
		fmt.Fprintf(r.out, "[%s] %s\n", alias, summary)
		r.activeNode = ""
		return
	}

	var symbol string
	if success {
		if r.colorEnabled {
			symbol = ColorGreen + SymCheck + ColorReset
		} else {
			symbol = SymCheck
		}
	} else {
		if r.colorEnabled {
			symbol = ColorRed + SymCross + ColorReset
		} else {
			symbol = SymCross
		}
	}

	fmt.Fprintf(r.out, "\r%s [%s] %s\033[K\n", symbol, alias, summary)
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
	fmt.Fprintf(r.out, "\r%s [%s] %s\033[K", frame, r.activeNode, r.phase)
	r.lastRenderAt = time.Now()
}
