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

func TestNormalizeModuleName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"nf-tables", "nf_tables"},
		{"nft_tproxy", "nft_tproxy"},
		{"  tcp_bbr  ", "tcp_bbr"},
		{"nft-masq", "nft_masq"},
	}

	for _, tc := range tests {
		actual := NormalizeModuleName(tc.input)
		if actual != tc.expected {
			t.Errorf("NormalizeModuleName(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}

func TestIsIPv4ForwardingEnabled(t *testing.T) {
	// Should not panic and return boolean
	_ = IsIPv4ForwardingEnabled()
}

func TestInspectModules(t *testing.T) {
	registry := NewModuleRegistry()
	if registry == nil {
		t.Fatal("NewModuleRegistry returned nil")
	}

	// Non-existent fictitious module should be reported as missing
	info := registry.Inspect("non_existent_fake_module_12345")
	if info.Status != ModuleStatusMissing || info.Present {
		t.Errorf("expected non-existent module to be missing, got status=%s present=%v", info.Status, info.Present)
	}

	// InspectAll should return results for all keys
	batch := registry.InspectAll([]string{"tun", "non_existent_fake_module_12345"})
	if len(batch) != 2 {
		t.Errorf("expected 2 results, got %d", len(batch))
	}
}
