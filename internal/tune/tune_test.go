package tune

import (
	"errors"
	"testing"
)

func TestNormalizeValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  123  ", "123"},
		{"10240\t65535\n", "10240 65535"},
		{"  abc   def  ghi  ", "abc def ghi"},
	}

	for _, tc := range tests {
		actual := normalizeValue(tc.input)
		if actual != tc.expected {
			t.Errorf("normalizeValue(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}

func TestProcPathForKey(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"},
		{"net.ipv6.conf.all.forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"},
	}

	for _, tc := range tests {
		actual := procPathForKey(tc.key)
		if actual != tc.expected {
			t.Errorf("procPathForKey(%q) = %q; want %q", tc.key, actual, tc.expected)
		}
	}
}

func TestReadSysctl(t *testing.T) {
	// Read a standard key that should exist on Linux
	val, err := ReadSysctl("net.ipv4.ip_forward")
	if err != nil {
		t.Logf("Skipping TestReadSysctl if net.ipv4.ip_forward is not readable (e.g. non-Linux / sandbox): %v", err)
		return
	}
	if val != "0" && val != "1" {
		t.Errorf("Unexpected value for net.ipv4.ip_forward: %q", val)
	}

	// Read a non-existent key
	_, err = ReadSysctl("net.invalid.nonexistent.key")
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Expected ErrUnsupported for invalid key, got: %v", err)
	}
}
