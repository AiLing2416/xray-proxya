package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHETunnelConfig_PreProduct(t *testing.T) {
	raw := `auto he-ipv6
iface he-ipv6 inet6 v4tunnel
        address 2001:470:1f0a:692::2
        netmask 64
        endpoint 216.66.80.30
        local 87.58.209.196
        ttl 255
        gateway 2001:470:1f0a:692::1
`
	spec, err := ParseHETunnelConfig(raw)
	if err != nil {
		t.Fatalf("ParseHETunnelConfig failed: %v", err)
	}

	if spec.Interface != "he-ipv6" {
		t.Errorf("expected interface 'he-ipv6', got '%s'", spec.Interface)
	}
	if spec.ServerIPv4 != "216.66.80.30" {
		t.Errorf("expected ServerIPv4 '216.66.80.30', got '%s'", spec.ServerIPv4)
	}
	if spec.ClientIPv4 != "87.58.209.196" {
		t.Errorf("expected ClientIPv4 '87.58.209.196', got '%s'", spec.ClientIPv4)
	}
	if spec.ClientIPv6 != "2001:470:1f0a:692::2" {
		t.Errorf("expected ClientIPv6 '2001:470:1f0a:692::2', got '%s'", spec.ClientIPv6)
	}
	if spec.PrefixLen != 64 {
		t.Errorf("expected PrefixLen 64, got %d", spec.PrefixLen)
	}
	if spec.GatewayIPv6 != "2001:470:1f0a:692::1" {
		t.Errorf("expected GatewayIPv6 '2001:470:1f0a:692::1', got '%s'", spec.GatewayIPv6)
	}
	if spec.RoutedSubnet != "2001:470:1f0a:692::/64" {
		t.Errorf("expected fallback RoutedSubnet '2001:470:1f0a:692::/64', got '%s'", spec.RoutedSubnet)
	}
}

func TestParseHETunnelConfig_WithRoutedComment(t *testing.T) {
	raw := `auto he-ipv6
iface he-ipv6 inet6 v4tunnel
        address 2001:470:1f10:123::2/64
        endpoint 216.66.80.30
        local 1.2.3.4
        gateway 2001:470:1f10:123::1
# Routed /64: 2001:470:1f11:123::/64
`
	spec, err := ParseHETunnelConfig(raw)
	if err != nil {
		t.Fatalf("ParseHETunnelConfig failed: %v", err)
	}

	if spec.ClientIPv6 != "2001:470:1f10:123::2" {
		t.Errorf("unexpected ClientIPv6: %s", spec.ClientIPv6)
	}
	if spec.PrefixLen != 64 {
		t.Errorf("unexpected PrefixLen: %d", spec.PrefixLen)
	}
	if spec.RoutedSubnet != "2001:470:1f11:123::/64" {
		t.Errorf("expected explicit RoutedSubnet '2001:470:1f11:123::/64', got '%s'", spec.RoutedSubnet)
	}
}

func TestParseHETunnelConfig_WithRouted48(t *testing.T) {
	raw := `iface he-ipv6 inet6 v4tunnel
        address 2001:470:1f10:123::2
        netmask 64
        endpoint 216.66.80.30
        local 10.0.0.5
        gateway 2001:470:1f10:123::1
# Routed /48: 2001:470:abcd::/48
`
	spec, err := ParseHETunnelConfig(raw)
	if err != nil {
		t.Fatalf("ParseHETunnelConfig failed: %v", err)
	}

	if spec.RoutedSubnet != "2001:470:abcd::/48" {
		t.Errorf("expected RoutedSubnet '2001:470:abcd::/48', got '%s'", spec.RoutedSubnet)
	}
}

func TestParseHETunnelConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "missing endpoint",
			content: `iface he-ipv6 inet6 v4tunnel
address 2001:470:1f0a:692::2
local 1.2.3.4`,
			wantErr: "missing ServerIPv4",
		},
		{
			name: "missing local",
			content: `iface he-ipv6 inet6 v4tunnel
address 2001:470:1f0a:692::2
endpoint 1.2.3.4`,
			wantErr: "missing ClientIPv4",
		},
		{
			name: "missing address",
			content: `iface he-ipv6 inet6 v4tunnel
endpoint 1.2.3.4
local 5.6.7.8`,
			wantErr: "missing ClientIPv6",
		},
		{
			name: "invalid IP",
			content: `iface he-ipv6 inet6 v4tunnel
endpoint not-an-ip
local 5.6.7.8
address 2001:470:1f0a:692::2`,
			wantErr: "invalid ServerIPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHETunnelConfig(tt.content)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestDetectAndFixNAT(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737), which won't match host interfaces.
	spec := &HETunnelSpec{
		Interface:  "he-ipv6",
		ServerIPv4: "216.66.80.30",
		ClientIPv4: "192.0.2.1",
		ClientIPv6: "2001:470:1f0a:692::2",
		PrefixLen:  64,
	}

	fixed, iface, orig := DetectAndFixNAT(spec)
	// If host has any local non-loopback IPv4 interface, fixed will be true.
	hostAddrs, _ := getHostIPv4Addresses()
	if len(hostAddrs) > 0 {
		if !fixed {
			t.Errorf("expected NAT auto-fix to trigger for RFC 5737 dummy IP")
		}
		if orig != "192.0.2.1" {
			t.Errorf("expected orig IP '192.0.2.1', got '%s'", orig)
		}
		if iface == "" {
			t.Errorf("expected non-empty detected iface name")
		}
		if spec.ClientIPv4 == "192.0.2.1" {
			t.Errorf("expected ClientIPv4 to be replaced with local interface IP")
		}
	}
}

func TestDoctorTunnelUp_RequiresArgument(t *testing.T) {
	cmd := doctorTunnelUpCmd
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Fatalf("expected error when doctor tunnel up is called without arguments, got nil")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg(s)") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDoctorTunnelDown_RequiresArgument(t *testing.T) {
	cmd := doctorTunnelDownCmd
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Fatalf("expected error when doctor tunnel down is called without arguments, got nil")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg(s)") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDoctorTunnelDown_WithConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	origSystemdDir := systemdDir
	systemdDir = tmpDir
	defer func() { systemdDir = origSystemdDir }()

	origRoot := tunnelRequireRoot
	tunnelRequireRoot = func(string) error { return nil }
	defer func() { tunnelRequireRoot = origRoot }()

	origRunner := tunnelCmdRunner
	tunnelCmdRunner = func(name string, arg ...string) ([]byte, error) { return []byte("ok"), nil }
	defer func() { tunnelCmdRunner = origRunner }()

	// Write mock config file
	confPath := filepath.Join(tmpDir, "interfaces-test")
	confContent := `auto he-ipv6
iface he-ipv6 inet6 v4tunnel
        address 2001:470:1f0a:692::2
        netmask 64
        endpoint 216.66.80.30
        local 87.58.209.196
        gateway 2001:470:1f0a:692::1
`
	if err := os.WriteFile(confPath, []byte(confContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create dummy service files that down should remove
	svcPath := filepath.Join(tmpDir, "he-tunnel-he-ipv6.service")
	_ = os.WriteFile(svcPath, []byte("[Unit]\nDescription=test\n"), 0644)
	legacyPath := filepath.Join(tmpDir, "he-tunnel.service")
	_ = os.WriteFile(legacyPath, []byte("[Unit]\nDescription=legacy\n"), 0644)

	err := doctorTunnelDownCmd.RunE(doctorTunnelDownCmd, []string{confPath})
	if err != nil {
		t.Fatalf("doctor tunnel down with config file failed: %v", err)
	}

	if _, err := os.Stat(svcPath); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted by down command", svcPath)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted by down command", legacyPath)
	}
}

func TestDoctorTunnelDown_WithInterface_Unverified(t *testing.T) {
	origRoot := tunnelRequireRoot
	tunnelRequireRoot = func(string) error { return nil }
	defer func() { tunnelRequireRoot = origRoot }()

	origFunc := findVerifiedTunnelConfigFunc
	findVerifiedTunnelConfigFunc = func(iface string) (bool, string) { return false, "" }
	defer func() { findVerifiedTunnelConfigFunc = origFunc }()

	err := doctorTunnelDownCmd.RunE(doctorTunnelDownCmd, []string{"eth0"})
	if err == nil {
		t.Fatalf("expected error when down is called on unverified interface eth0, got nil")
	}
	if !strings.Contains(err.Error(), "Cannot safely tear down interface 'eth0'") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDoctorTunnelDown_WithInterface_Verified(t *testing.T) {
	tmpDir := t.TempDir()
	origSystemdDir := systemdDir
	systemdDir = tmpDir
	defer func() { systemdDir = origSystemdDir }()

	origRoot := tunnelRequireRoot
	tunnelRequireRoot = func(string) error { return nil }
	defer func() { tunnelRequireRoot = origRoot }()

	origRunner := tunnelCmdRunner
	tunnelCmdRunner = func(name string, arg ...string) ([]byte, error) { return []byte("ok"), nil }
	defer func() { tunnelCmdRunner = origRunner }()

	origFunc := findVerifiedTunnelConfigFunc
	findVerifiedTunnelConfigFunc = func(iface string) (bool, string) {
		return true, "mock systemd service (he-tunnel-he-ipv6.service)"
	}
	defer func() { findVerifiedTunnelConfigFunc = origFunc }()

	svcPath := filepath.Join(tmpDir, "he-tunnel-he-ipv6.service")
	_ = os.WriteFile(svcPath, []byte("[Unit]\nDescription=test\n"), 0644)

	err := doctorTunnelDownCmd.RunE(doctorTunnelDownCmd, []string{"he-ipv6"})
	if err != nil {
		t.Fatalf("doctor tunnel down with verified interface failed: %v", err)
	}

	if _, err := os.Stat(svcPath); !os.IsNotExist(err) {
		t.Errorf("expected %s to be removed", svcPath)
	}
}

func TestDoctorTunnel_NoHardcodedDefaultConfig(t *testing.T) {
	content, err := os.ReadFile("doctor_tunnel_cmd.go")
	if err != nil {
		t.Fatalf("failed to read doctor_tunnel_cmd.go: %v", err)
	}
	if strings.Contains(string(content), "/root/interfaces-he") {
		t.Errorf("found hardcoded default path '/root/interfaces-he' in doctor_tunnel_cmd.go; should be purely config-driven")
	}
}
