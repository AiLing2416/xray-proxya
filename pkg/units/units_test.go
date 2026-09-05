package units

import (
	"testing"
)

func TestFormatIEC(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.00 KiB"},
		{1536, "1.50 KiB"},
		{1048576, "1.00 MiB"},
		{20971520, "20.00 MiB"},
		{1073741824, "1.00 GiB"},
		{5368709120, "5.00 GiB"},
		{1099511627776, "1.00 TiB"},
		{1125899906842624, "1.00 PiB"},
		{1152921504606846976, "1.00 EiB"},
		{-10, "-10 B"},
	}

	for _, tc := range tests {
		got := FormatIEC(tc.input)
		if got != tc.want {
			t.Errorf("FormatIEC(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestFormatSI(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{-1, "Unlimited"},
		{-100, "Unlimited"},
		{0, "0B"},
		{500, "500B"},
		{1000, "1.00KB"},
		{1500, "1.50KB"},
		{1000000, "1.00MB"},
		{1000000000, "1.00GB"},
		{1500000000, "1.50GB"},
		{1000000000000, "1.00TB"},
		{1000000000000000, "1.00PB"},
	}

	for _, tc := range tests {
		got := FormatSI(tc.input)
		if got != tc.want {
			t.Errorf("FormatSI(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseBytes(t *testing.T) {
	// Base 10 tests
	testsSI := []struct {
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
		{"1PB", 1000000000000000},
		{"1p", 1000000000000000},
		{"0", 0},
		{"paused", 0},
		{"-1", -1},
		{"unlimited", -1},
	}

	for _, tc := range testsSI {
		got, err := ParseBytes(tc.input)
		if err != nil {
			t.Fatalf("ParseBytes(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseBytes(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}

	// Base 2 (IEC) tests with 'i'
	testsIEC := []struct {
		input string
		want  int64
	}{
		{"1KiB", 1024},
		{"1kib", 1024},
		{"1ki", 1024},
		{"1MiB", 1048576},
		{"1mib", 1048576},
		{"1mi", 1048576},
		{"1GiB", 1073741824},
		{"1gib", 1073741824},
		{"1gi", 1073741824},
		{"1TiB", 1099511627776},
		{"1tib", 1099511627776},
		{"1ti", 1099511627776},
		{"1PiB", 1125899906842624},
		{"1pib", 1125899906842624},
	}

	for _, tc := range testsIEC {
		got, err := ParseBytes(tc.input)
		if err != nil {
			t.Fatalf("ParseBytes(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseBytes(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}

	// Invalid cases
	invalid := []string{"", "   ", "abc", "10xyz", "12.34.56GB"}
	for _, inv := range invalid {
		if _, err := ParseBytes(inv); err == nil {
			t.Errorf("ParseBytes(%q) expected error, got nil", inv)
		}
	}
}
