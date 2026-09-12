package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestDetailPaneHeaderWithBadges(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)

	badges := []string{"[A] Apply", "[U] Undo", "[+/-] Height", "[Q] Quit"}

	// 1. Wide terminal (80 cols) - all badges should fit
	h80 := detailPaneHeaderWithBadges("INFO", "INFO", badges, 80)
	if !strings.HasPrefix(h80, "┌─ INFO ") {
		t.Fatalf("expected prefix '┌─ INFO ', got: %q", h80)
	}
	if !strings.HasSuffix(h80, " ──┐") {
		t.Fatalf("expected suffix ' ──┐', got: %q", h80)
	}
	for _, b := range badges {
		if !strings.Contains(h80, b) {
			t.Fatalf("expected header to contain %q, got: %q", b, h80)
		}
	}

	// 2. Medium terminal (55 cols) - some badges dropped to fit
	h55 := detailPaneHeaderWithBadges("INFO", "INFO", badges, 55)
	if !strings.HasPrefix(h55, "┌─ INFO ") {
		t.Fatalf("expected prefix '┌─ INFO ', got: %q", h55)
	}
	if !strings.HasSuffix(h55, " ──┐") {
		t.Fatalf("expected suffix ' ──┐', got: %q", h55)
	}

	// 3. Very narrow terminal (25 cols) - falls back to plain header
	h25 := detailPaneHeaderWithBadges("INFO", "INFO", badges, 25)
	if !strings.HasPrefix(h25, "┌─ INFO ") {
		t.Fatalf("expected prefix '┌─ INFO ', got: %q", h25)
	}
	if !strings.HasSuffix(h25, "┐") {
		t.Fatalf("expected suffix '┐', got: %q", h25)
	}

	// 4. Empty badges (e.g. input / edit mode)
	hEmpty := detailPaneHeaderWithBadges("Setting Input", "Setting Input", nil, 60)
	if !strings.HasPrefix(hEmpty, "┌─ Setting Input ") {
		t.Fatalf("expected prefix '┌─ Setting Input ', got: %q", hEmpty)
	}
	if !strings.HasSuffix(hEmpty, "┐") {
		t.Fatalf("expected suffix '┐', got: %q", hEmpty)
	}
	if strings.Contains(hEmpty, "[Q] Quit") {
		t.Fatalf("expected no shortcuts in empty badge header, got: %q", hEmpty)
	}
}

func TestApplyAndUndoFlashIntegration(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)

	m := InitialModel()
	if m.flash == nil {
		t.Fatal("expected model.flash to be initialized")
	}

	// Test apply success flash
	cmd := m.getFlash().Trigger("apply", FlashSuccess, 50*time.Millisecond)
	if cmd == nil {
		t.Fatal("expected non-nil cmd")
	}
	if !m.getFlash().IsActive("apply") {
		t.Fatal("expected apply to be active")
	}
	if m.getFlash().GetType("apply") != FlashSuccess {
		t.Fatalf("expected FlashSuccess, got %v", m.getFlash().GetType("apply"))
	}

	// Test undo flash
	cmdUndo := m.getFlash().Trigger("undo", FlashSuccess, 50*time.Millisecond)
	if cmdUndo == nil {
		t.Fatal("expected non-nil cmdUndo")
	}
	if !m.getFlash().IsActive("undo") {
		t.Fatal("expected undo to be active")
	}

	// Test copy flash
	cmdCopy := m.getFlash().Trigger("copy", FlashSuccess, 50*time.Millisecond)
	if cmdCopy == nil {
		t.Fatal("expected non-nil cmdCopy")
	}
	if !m.getFlash().IsActive("copy") {
		t.Fatal("expected copy to be active")
	}
}
