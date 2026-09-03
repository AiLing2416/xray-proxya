package config

import (
	"testing"
)

func TestParseByteSizeBase10(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1000B", 1000},
		{"1KB", 1000},
		{"1k", 1000},
		{"2.5MB", 2500000},
		{"2.5m", 2500000},
		{"10GB", 10000000000},
		{"10g", 10000000000},
		{"10", 10000000000}, // pure number defaults to GB (Base 10)
		{"1TB", 1000000000000},
		{"1t", 1000000000000},
		{"0", 0},
		{"-1", -1},
	}

	for _, tc := range tests {
		got, err := ParseByteSize(tc.input)
		if err != nil {
			t.Fatalf("ParseByteSize(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseByteSize(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseByteSizeBase2(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1KiB", 1024},
		{"1kib", 1024},
		{"1MiB", 1048576},
		{"1mib", 1048576},
		{"1GiB", 1073741824},
		{"1gib", 1073741824},
		{"1TiB", 1099511627776},
		{"1tib", 1099511627776},
	}

	for _, tc := range tests {
		got, err := ParseByteSize(tc.input)
		if err != nil {
			t.Fatalf("ParseByteSize(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseByteSize(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseTriggersValidation(t *testing.T) {
	limitBytes := int64(10 * GigaByte) // 10 GB (10,000,000,000 bytes)

	// Valid mixed triggers
	raw, parsed, err := ParseTriggers("80p, 45P, 5G, 1GiB", limitBytes)
	if err != nil {
		t.Fatalf("ParseTriggers valid unexpected error: %v", err)
	}
	if len(raw) != 4 || len(parsed) != 4 {
		t.Fatalf("expected 4 triggers, got raw=%d parsed=%d", len(raw), len(parsed))
	}

	// Trigger exceeding 100% percentage rejected
	if _, _, err := ParseTriggers("105p", limitBytes); err == nil {
		t.Fatalf("expected error for percentage > 100%%")
	}

	// Trigger percentage <= 0 rejected
	if _, _, err := ParseTriggers("0p", limitBytes); err == nil {
		t.Fatalf("expected error for percentage <= 0%%")
	}

	// Trigger capacity exceeding Limit rejected
	if _, _, err := ParseTriggers("12GB", limitBytes); err == nil {
		t.Fatalf("expected error for capacity > limit")
	}

	// Valid trigger exactly equal to limit
	if _, _, err := ParseTriggers("10GB", limitBytes); err != nil {
		t.Fatalf("unexpected error for capacity == limit: %v", err)
	}

	// Clear trigger
	rawNone, parsedNone, err := ParseTriggers("none", limitBytes)
	if err != nil || rawNone != nil || parsedNone != nil {
		t.Fatalf("expected nil triggers for 'none'")
	}
}
