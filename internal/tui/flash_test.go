package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestFlashManager(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	fm := NewFlashManager()
	if fm.IsActive("apply") {
		t.Fatal("expected apply to be inactive initially")
	}

	defaultStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
	rendered := fm.Render("apply", "[A] Apply", defaultStyle)
	if !strings.Contains(rendered, "[A] Apply") {
		t.Fatalf("expected rendered text to contain [A] Apply, got %s", rendered)
	}

	// Trigger success
	cmd := fm.Trigger("apply", FlashSuccess, 50*time.Millisecond)
	if cmd == nil {
		t.Fatal("expected non-nil tea.Cmd from Trigger")
	}
	if !fm.IsActive("apply") {
		t.Fatal("expected apply to be active immediately after Trigger")
	}
	if fm.GetType("apply") != FlashSuccess {
		t.Fatalf("expected FlashSuccess, got %v", fm.GetType("apply"))
	}

	flashRendered := fm.Render("apply", "[A] Apply", defaultStyle)
	if flashRendered == rendered {
		t.Fatal("expected flash rendered style to differ from default style")
	}

	// Wait for expiration
	time.Sleep(70 * time.Millisecond)
	if fm.IsActive("apply") {
		t.Fatal("expected apply to be expired after duration")
	}
	fm.Expire("apply")
	if fm.GetType("apply") != FlashNone {
		t.Fatal("expected FlashNone after Expire")
	}

	// Trigger error
	fm.Trigger("apply", FlashError, 100*time.Millisecond)
	if fm.GetType("apply") != FlashError {
		t.Fatalf("expected FlashError, got %v", fm.GetType("apply"))
	}
	fm.Clear("apply")
	if fm.IsActive("apply") {
		t.Fatal("expected apply to be inactive after Clear")
	}
}
