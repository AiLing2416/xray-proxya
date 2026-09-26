package utils

import (
	"regexp"
	"testing"
)

func TestGenerateAlphanumericToken(t *testing.T) {
	tok1 := GenerateAlphanumericToken(16)
	if len(tok1) != 16 {
		t.Fatalf("expected 16-char token, got len %d: %q", len(tok1), tok1)
	}

	alphanumericRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !alphanumericRegex.MatchString(tok1) {
		t.Errorf("token %q contains non-alphanumeric characters", tok1)
	}

	tok2 := GenerateAlphanumericToken(16)
	if tok1 == tok2 {
		t.Errorf("expected two consecutive tokens to be different, got %q == %q", tok1, tok2)
	}

	if empty := GenerateAlphanumericToken(0); empty != "" {
		t.Errorf("expected empty token for length 0, got %q", empty)
	}
}
