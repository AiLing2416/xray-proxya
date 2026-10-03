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

