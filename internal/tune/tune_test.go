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

func TestApplyProfilePreservesInitialBaselineAcrossMultipleApplies(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	mockSysctl := map[string]string{
		"net.core.somaxconn":  "512",
		"net.ipv4.ip_forward": "0",
	}

	origRead := readSysctlFn
	origWrite := writeSysctlFn
	defer func() {
		readSysctlFn = origRead
		writeSysctlFn = origWrite
	}()

	readSysctlFn = func(key string) (string, error) {
		if val, ok := mockSysctl[key]; ok {
			return val, nil
		}
		return "", ErrUnsupported
	}
	writeSysctlFn = func(key, value string) error {
		mockSysctl[key] = value
		return nil
	}

	profile1 := Profile{
		Name: "profile1",
		Settings: []Setting{
			{Key: "net.core.somaxconn", Value: "1024"},
			{Key: "net.ipv4.ip_forward", Value: "1"},
		},
	}

	// 1. Apply profile 1
	state1, err := ApplyProfile(profile1)
	if err != nil {
		t.Fatalf("ApplyProfile(profile1) err = %v", err)
	}
	for _, entry := range state1.Entries {
		if entry.Key == "net.core.somaxconn" && entry.OldValue != "512" {
			t.Errorf("profile1 somaxconn OldValue = %s, want 512", entry.OldValue)
		}
	}
	if mockSysctl["net.core.somaxconn"] != "1024" || mockSysctl["net.ipv4.ip_forward"] != "1" {
		t.Fatalf("profile1 write failed: %v", mockSysctl)
	}

	// 2. Apply profile 2: modifies somaxconn to 2048, does not touch ip_forward
	profile2 := Profile{
		Name: "profile2",
		Settings: []Setting{
			{Key: "net.core.somaxconn", Value: "2048"},
		},
	}
	state2, err := ApplyProfile(profile2)
	if err != nil {
		t.Fatalf("ApplyProfile(profile2) err = %v", err)
	}

	var foundSomaxconn, foundIPForward bool
	for _, entry := range state2.Entries {
		if entry.Key == "net.core.somaxconn" {
			foundSomaxconn = true
			if entry.OldValue != "512" {
				t.Errorf("profile2 somaxconn OldValue = %s, want initial baseline 512 (was overwritten by profile1)", entry.OldValue)
			}
			if entry.NewValue != "2048" {
				t.Errorf("profile2 somaxconn NewValue = %s, want 2048", entry.NewValue)
			}
		}
		if entry.Key == "net.ipv4.ip_forward" {
			foundIPForward = true
			if entry.OldValue != "0" {
				t.Errorf("profile2 preserved ip_forward OldValue = %s, want 0", entry.OldValue)
			}
		}
	}
	if !foundSomaxconn {
		t.Errorf("somaxconn entry missing from state2")
	}
	if !foundIPForward {
		t.Errorf("ip_forward entry was dropped from state2 instead of preserved")
	}

	// 3. Rollback profile 2
	results, err := RollbackRuntimeState(state2)
	if err != nil {
		t.Fatalf("RollbackRuntimeState err = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Rollback results len = %d, want 2", len(results))
	}

	// Both parameters must be restored to their original system baselines (512 and 0)
	if mockSysctl["net.core.somaxconn"] != "512" {
		t.Errorf("somaxconn after rollback = %s, want 512", mockSysctl["net.core.somaxconn"])
	}
	if mockSysctl["net.ipv4.ip_forward"] != "0" {
		t.Errorf("ip_forward after rollback = %s, want 0", mockSysctl["net.ipv4.ip_forward"])
	}

	// Runtime state file must be cleared
	if _, err := LoadRuntimeState(); err == nil {
		t.Errorf("runtime state file should be deleted after successful rollback")
	}
}
