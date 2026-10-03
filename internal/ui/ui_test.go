package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestStripANSIAndVisualWidth(t *testing.T) {
	colored := "\033[32mPASS\033[0m"
	if StripANSI(colored) != "PASS" {
		t.Errorf("StripANSI failed, got: %q", StripANSI(colored))
	}
	if VisualWidth(colored) != 4 {
		t.Errorf("VisualWidth failed, want 4, got: %d", VisualWidth(colored))
	}

	chinese := "香港节点"
	if VisualWidth(chinese) != 8 {
		t.Errorf("VisualWidth for Chinese wide runes failed, want 8, got: %d", VisualWidth(chinese))
	}
}

func TestTableMinimalist(t *testing.T) {
	table := NewTable("ALIAS", "STATUS", "TCP RTT", "UDP RTT", "IPV4 EXIT")
	table.SetAlignment(1, AlignCenter)
	table.SetAlignment(2, AlignRight)
	table.SetAlignment(3, AlignRight)

	table.AddRow("hk-01", "\033[32mPASS\033[0m", "42ms", "48ms", "103.21.244.12")
	table.AddRow("jp-02", "\033[33mWARN\033[0m", "76ms", "82ms", "153.121.45.2")
	table.AddSpannedRow("\033[31mFAIL:\033[0m dial tcp: connection refused", "us-01", "\033[31mFAIL\033[0m")

	out := table.Render()

	// Check headers and dividers
	if !strings.Contains(out, " ALIAS │ STATUS │ TCP RTT │ UDP RTT │ IPV4 EXIT") {
		t.Errorf("unexpected header in table:\n%s", out)
	}
	if !strings.Contains(out, "┼") {
		t.Errorf("expected ┼ intersect in divider:\n%s", out)
	}
	if !strings.Contains(out, "hk-01") || !strings.Contains(out, "103.21.244.12") {
		t.Errorf("missing row content:\n%s", out)
	}
	if !strings.Contains(out, "us-01") || !strings.Contains(out, "connection refused") {
		t.Errorf("missing spanned row content:\n%s", out)
	}
}

func TestProgressRenderer_NonTTY(t *testing.T) {
	var buf bytes.Buffer
	r := NewProgressRenderer(&buf, false, false)

	r.Start("hk-01", "Testing transport...")
	r.Complete("hk-01", true, "Done: TCP 42ms | UDP 48ms")
	r.Stop()

	out := buf.String()
	if !strings.Contains(out, "[hk-01] Testing transport...\n") {
		t.Errorf("expected non-TTY start output, got: %q", out)
	}
	if !strings.Contains(out, "[hk-01] Done: TCP 42ms | UDP 48ms\n") {
		t.Errorf("expected non-TTY complete output, got: %q", out)
	}
}

func TestProgressRenderer_TTY(t *testing.T) {
	var buf bytes.Buffer
	r := NewProgressRenderer(&buf, true, false)

	r.Start("hk-01", "Testing transport...")
	time.Sleep(20 * time.Millisecond)
	r.Update("Testing exit IP...")
	time.Sleep(20 * time.Millisecond)
	r.Complete("hk-01", true, "Done: TCP 42ms | UDP 48ms")
	r.Stop()

	out := buf.String()
	if !strings.Contains(out, "✔ [hk-01] Done: TCP 42ms | UDP 48ms") {
		t.Errorf("expected TTY complete output, got: %q", out)
	}
}

func TestBannersAndCallout(t *testing.T) {
	succ := Success("Operation completed")
	if !strings.Contains(succ, "✔") || !strings.Contains(succ, "Operation completed") {
		t.Errorf("unexpected Success output: %q", succ)
	}

	warn := Warning("Staging pending")
	if !strings.Contains(warn, "▲") || !strings.Contains(warn, "Staging pending") {
		t.Errorf("unexpected Warning output: %q", warn)
	}

	errOut := Error("Fatal error")
	if !strings.Contains(errOut, "✖") || !strings.Contains(errOut, "Fatal error") {
		t.Errorf("unexpected Error output: %q", errOut)
	}

	not := Notice("Info line")
	if !strings.Contains(not, "ℹ") || !strings.Contains(not, "Info line") {
		t.Errorf("unexpected Notice output: %q", not)
	}

	box := Callout("NOTICE", "Line 1", "Line 2 is longer")
	if !strings.Contains(box, "┌─ NOTICE") || !strings.Contains(box, "│ Line 1") || !strings.Contains(box, "└") {
		t.Errorf("unexpected Callout output:\n%s", box)
	}
}

func TestWrapVisual(t *testing.T) {
	// 1. Basic word wrap
	words := "direct ping to 10.0.82.20 timed out"
	wrapped := WrapVisual(words, 20)
	if len(wrapped) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(wrapped), wrapped)
	}
	for _, l := range wrapped {
		if VisualWidth(l) > 20 {
			t.Errorf("line %q exceeds visual width 20 (got %d)", l, VisualWidth(l))
		}
	}

	// 2. CJK wrapping without spaces
	cjk := "核心启动失败请检查配置"
	cjkWrapped := WrapVisual(cjk, 8)
	if len(cjkWrapped) != 3 {
		t.Fatalf("expected 3 lines for 12-char wide CJK with width 8, got %d: %v", len(cjkWrapped), cjkWrapped)
	}
	for _, l := range cjkWrapped {
		if VisualWidth(l) > 8 {
			t.Errorf("cjk line %q exceeds visual width 8 (got %d)", l, VisualWidth(l))
		}
	}

	// 3. Very long single word
	longWord := "http://example.com/a/very/long/path/that/cannot/be/broken/by/spaces"
	longWrapped := WrapVisual(longWord, 15)
	if len(longWrapped) < 4 {
		t.Fatalf("expected at least 4 chunks, got %d", len(longWrapped))
	}
	for _, l := range longWrapped {
		if VisualWidth(l) > 15 {
			t.Errorf("long word chunk %q exceeds 15 (got %d)", l, VisualWidth(l))
		}
	}

	// 4. ANSI color preservation
	colored := "\033[31mError: connection refused to remote host\033[0m"
	colWrapped := WrapVisual(colored, 20)
	if len(colWrapped) != 3 {
		t.Fatalf("expected 3 lines for colored text, got %d: %v", len(colWrapped), colWrapped)
	}
	for _, l := range colWrapped {
		if VisualWidth(l) > 20 {
			t.Errorf("colored line %q exceeds 20 (visual %d)", l, VisualWidth(l))
		}
	}
}

func TestTableMultilineWrapping(t *testing.T) {
	table := NewTable("CATEGORY", "CHECK ITEM", "STATUS", "DETAILS")
	table.SetAlignment(2, AlignCenter)
	table.SetMaxWidth(3, 30)

	longDetail := "Direct ping to 10.0.82.20 timed out (Fix: check remote firewall and default gateway)"
	table.AddRow("NETWORK", "Ping Check", "\033[31mFAIL\033[0m", longDetail)

	out := table.Render()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")

	// Table must have header (0), divider (1), and multiple row lines (2+)
	if len(lines) < 4 {
		t.Fatalf("expected multiline table with at least 4 lines, got %d lines:\n%s", len(lines), out)
	}

	// Check that visual width of all data rows is identical
	expectedWidth := VisualWidth(lines[0])
	for i, l := range lines {
		w := VisualWidth(l)
		if w != expectedWidth {
			t.Errorf("line %d width mismatch: want %d, got %d (line: %q)", i, expectedWidth, w, l)
		}
	}

	// Check that table contains borders on wrapped lines
	for i := 2; i < len(lines); i++ {
		if !strings.Contains(lines[i], "│") {
			t.Errorf("line %d missing vertical separator: %q", i, lines[i])
		}
	}

	// Test Box style with multiline
	table.SetStyle(StyleRounded)
	boxOut := table.Render()
	boxLines := strings.Split(strings.TrimSuffix(boxOut, "\n"), "\n")
	boxWidth := VisualWidth(boxLines[0])
	for i, l := range boxLines {
		if VisualWidth(l) != boxWidth {
			t.Errorf("box line %d width mismatch: want %d, got %d (line: %q)", i, boxWidth, VisualWidth(l), l)
		}
	}
}

