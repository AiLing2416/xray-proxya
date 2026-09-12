package qrcode

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderTerminal_ValidContent(t *testing.T) {
	url := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@10.49.0.201:443?security=reality&sni=learn.microsoft.com&fp=chrome&pbk=xyz&sid=abc&type=tcp&flow=xtls-rprx-vision#Admin"
	qr, err := RenderTerminal(url, false)
	if err != nil {
		t.Fatalf("RenderTerminal failed: %v", err)
	}
	if len(qr) == 0 {
		t.Fatal("RenderTerminal returned empty string")
	}

	// Should contain block characters
	if !strings.Contains(qr, "█") || !strings.Contains(qr, "▀") {
		t.Errorf("expected block characters in QR output, got: %s", qr[:min(100, len(qr))])
	}

	lines := strings.Split(strings.TrimRight(qr, "\n"), "\n")
	if len(lines) < 10 {
		t.Errorf("expected at least 10 lines for QR code, got %d", len(lines))
	}
}

func TestRenderTerminal_EmptyContent(t *testing.T) {
	_, err := RenderTerminal("", false)
	if err == nil {
		t.Fatal("expected error for empty content, got nil")
	}

	_, err = RenderTerminal("   ", false)
	if err == nil {
		t.Fatal("expected error for whitespace-only content, got nil")
	}
}

func TestRenderTerminal_Inverse(t *testing.T) {
	url := "https://example.com/sub/admin?token=secret123"
	normal, err := RenderTerminal(url, false)
	if err != nil {
		t.Fatalf("RenderTerminal normal failed: %v", err)
	}
	inverted, err := RenderTerminal(url, true)
	if err != nil {
		t.Fatalf("RenderTerminal inverted failed: %v", err)
	}

	if normal == inverted {
		t.Fatal("normal and inverted QR codes should not be identical")
	}

	// Line counts should match
	normalLines := strings.Split(strings.TrimRight(normal, "\n"), "\n")
	invertedLines := strings.Split(strings.TrimRight(inverted, "\n"), "\n")
	if len(normalLines) != len(invertedLines) {
		t.Fatalf("line count mismatch: normal=%d, inverted=%d", len(normalLines), len(invertedLines))
	}
}

func TestPrintTerminal(t *testing.T) {
	var buf bytes.Buffer
	err := PrintTerminal(&buf, "http://10.49.0.201:8080/sub/guest/uuid-1234", false)
	if err != nil {
		t.Fatalf("PrintTerminal failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("PrintTerminal produced empty buffer")
	}
}
