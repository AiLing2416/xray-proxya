package sharelink

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// DecodeBase64Flexible decodes a base64 string using various URL/Std schemes and padding variations.
func DecodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Try standard
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try URL
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try raw URL
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try raw Std
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Pad with == and try again
	padLen := (4 - len(s)%4) % 4
	if padLen > 0 {
		padded := s + strings.Repeat("=", padLen)
		if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return b, nil
		}
		if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("failed to decode base64")
}

// DecodePayload extracts individual link lines from the raw subscription body bytes.
// It handles base64-encoded strings as well as plaintext line lists.
func DecodePayload(body []byte) ([]string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty subscription response")
	}

	var content string

	// Try base64 decoding
	decoded, err := DecodeBase64Flexible(trimmed)
	if err == nil && strings.Contains(string(decoded), "://") {
		content = string(decoded)
	} else if strings.Contains(trimmed, "://") {
		// Plain text list
		content = trimmed
	} else {
		return nil, fmt.Errorf("unrecognized subscription format (neither valid base64 nor plaintext proxy links)")
	}

	rawLines := strings.Split(content, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, l := range rawLines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		lines = append(lines, l)
	}

	return lines, nil
}
