package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHETunnelConfig_PreProduct(t *testing.T) {
	raw := `auto he-ipv6
iface he-ipv6 inet6 v4tunnel
        address 2001:db8:1f0a:692::2
        netmask 64
        endpoint 216.66.80.30
        local 198.51.100.87
        ttl 255
        gateway 2001:db8:1f0a:692::1
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
	if spec.ClientIPv4 != "198.51.100.87" {
		t.Errorf("expected ClientIPv4 '198.51.100.87', got '%s'", spec.ClientIPv4)
	}
	if spec.ClientIPv6 != "2001:db8:1f0a:692::2" {
		t.Errorf("expected ClientIPv6 '2001:db8:1f0a:692::2', got '%s'", spec.ClientIPv6)
	}
	if spec.PrefixLen != 64 {
		t.Errorf("expected PrefixLen 64, got %d", spec.PrefixLen)
	}
	if spec.GatewayIPv6 != "2001:db8:1f0a:692::1" {
		t.Errorf("expected GatewayIPv6 '2001:db8:1f0a:692::1', got '%s'", spec.GatewayIPv6)
	}
	if spec.RoutedSubnet != "2001:db8:1f0a:692::/64" {
		t.Errorf("expected fallback RoutedSubnet '2001:db8:1f0a:692::/64', got '%s'", spec.RoutedSubnet)
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
address 2001:db8:1f0a:692::2
local 1.2.3.4`,
			wantErr: "missing ServerIPv4",
		},
		{
			name: "missing local",
			content: `iface he-ipv6 inet6 v4tunnel
address 2001:db8:1f0a:692::2
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
address 2001:db8:1f0a:692::2`,
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
		ClientIPv6: "2001:db8:1f0a:692::2",
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
        address 2001:db8:1f0a:692::2
        netmask 64
        endpoint 216.66.80.30
        local 198.51.100.87
        gateway 2001:db8:1f0a:692::1
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

func setupMockTunnelEnvironment(t *testing.T) (systemdPath, sysfsPath string) {
	t.Helper()
	tmpDir := t.TempDir()
	sDir := filepath.Join(tmpDir, "systemd")
	sysDir := filepath.Join(tmpDir, "sysfs")
	_ = os.MkdirAll(sDir, 0755)
	_ = os.MkdirAll(sysDir, 0755)

	// Write mock managed service
	svcContent := `[Unit]
Description=Hurricane Electric 6in4 IPv6 Tunnel (he-ipv6)

[Service]
ExecStart=/sbin/ip tunnel add he-ipv6 mode sit remote 216.66.80.30 local 198.51.100.87 ttl 255
ExecStart=/sbin/ip link set he-ipv6 up mtu 1480
ExecStart=/sbin/ip -6 addr replace 2001:db8:1f0a:692::2/64 dev he-ipv6 nodad
`
	_ = os.WriteFile(filepath.Join(sDir, "he-tunnel-he-ipv6.service"), []byte(svcContent), 0644)

	// Setup mock sysfs for he-ipv6
	heStats := filepath.Join(sysDir, "he-ipv6", "statistics")
	_ = os.MkdirAll(heStats, 0755)
	_ = os.WriteFile(filepath.Join(sysDir, "he-ipv6", "type"), []byte("776\n"), 0644)
	_ = os.WriteFile(filepath.Join(heStats, "rx_bytes"), []byte("1048576\n"), 0644)
	_ = os.WriteFile(filepath.Join(heStats, "tx_bytes"), []byte("524288\n"), 0644)
	_ = os.WriteFile(filepath.Join(heStats, "rx_packets"), []byte("1200\n"), 0644)
	_ = os.WriteFile(filepath.Join(heStats, "tx_packets"), []byte("600\n"), 0644)

	// Setup mock sysfs for sit1 (unmanaged)
	sitStats := filepath.Join(sysDir, "sit1", "statistics")
	_ = os.MkdirAll(sitStats, 0755)
	_ = os.WriteFile(filepath.Join(sysDir, "sit1", "type"), []byte("776\n"), 0644)
	_ = os.WriteFile(filepath.Join(sitStats, "rx_bytes"), []byte("2048\n"), 0644)
	_ = os.WriteFile(filepath.Join(sitStats, "tx_bytes"), []byte("1024\n"), 0644)
	_ = os.WriteFile(filepath.Join(sitStats, "rx_packets"), []byte("20\n"), 0644)
	_ = os.WriteFile(filepath.Join(sitStats, "tx_packets"), []byte("10\n"), 0644)

	return sDir, sysDir
}

func TestDoctorTunnelStatus_TwoTier_ScanAndAsciiCards(t *testing.T) {
	sDir, sysDir := setupMockTunnelEnvironment(t)

	origSystemdDir := systemdDir
	systemdDir = sDir
	defer func() { systemdDir = origSystemdDir }()

	origSysfsDir := sysfsNetDir
	sysfsNetDir = sysDir
	defer func() { sysfsNetDir = origSysfsDir }()

	origRunner := tunnelCmdRunner
	tunnelCmdRunner = func(name string, arg ...string) ([]byte, error) {
		if len(arg) >= 2 && arg[0] == "is-active" {
			return []byte("active\n"), nil
		}
		if len(arg) >= 2 && arg[0] == "is-enabled" {
			return []byte("enabled\n"), nil
		}
		return []byte("ok"), nil
	}
	defer func() { tunnelCmdRunner = origRunner }()

	origIfaces := tunnelInterfacesLister
	tunnelInterfacesLister = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "he-ipv6", Flags: net.FlagUp, MTU: 1480},
			{Name: "sit1", Flags: net.FlagUp, MTU: 1480},
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, MTU: 65536},
		}, nil
	}
	defer func() { tunnelInterfacesLister = origIfaces }()

	origAddrs := tunnelAddrsLister
	tunnelAddrsLister = func(ifc net.Interface) ([]net.Addr, error) {
		if ifc.Name == "he-ipv6" {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("2001:db8:1f0a:692::2"), Mask: net.CIDRMask(64, 128)},
				&net.IPNet{IP: net.ParseIP("fe80::5054:ff:fe12:3456"), Mask: net.CIDRMask(64, 128)},
			}, nil
		}
		if ifc.Name == "sit1" {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
			}, nil
		}
		return nil, nil
	}
	defer func() { tunnelAddrsLister = origAddrs }()

	origProbe := tunnelProbeRunner
	tunnelProbeRunner = func(ip string, timeout time.Duration) (bool, time.Duration, error) {
		return true, 18 * time.Millisecond, nil
	}
	defer func() { tunnelProbeRunner = origProbe }()

	origJSON := doctorTunnelStatusJSON
	doctorTunnelStatusJSON = false
	defer func() { doctorTunnelStatusJSON = origJSON }()

	var buf bytes.Buffer
	doctorTunnelStatusCmd.SetOut(&buf)
	err := doctorTunnelStatusCmd.RunE(doctorTunnelStatusCmd, []string{})
	if err != nil {
		t.Fatalf("doctor tunnel status failed: %v", err)
	}

	out := buf.String()

	// Verify he-ipv6 is detected as Managed
	if !strings.Contains(out, "Tunnel Interface: he-ipv6 [UP]") {
		t.Errorf("expected he-ipv6 [UP] in output:\n%s", out)
	}
	if !strings.Contains(out, "Managed:        YES (via he-tunnel-he-ipv6.service, active, enabled)") {
		t.Errorf("expected he-ipv6 to be reported as managed:\n%s", out)
	}
	if !strings.Contains(out, "IPv6 (Global):  2001:db8:1f0a:692::2/64") {
		t.Errorf("expected global IPv6 in output:\n%s", out)
	}
	if !strings.Contains(out, "PASS (18ms)") {
		t.Errorf("expected probe PASS in output:\n%s", out)
	}

	// Verify sit1 is detected as Unmanaged
	if !strings.Contains(out, "Tunnel Interface: sit1 [UP]") {
		t.Errorf("expected sit1 [UP] in output:\n%s", out)
	}
	if !strings.Contains(out, "Managed:        NO (external/manual configuration)") {
		t.Errorf("expected sit1 to be unmanaged:\n%s", out)
	}
	if !strings.Contains(out, "Detected manual or external tunnel interface. Not managed by Xray-Proxya systemd service.") {
		t.Errorf("expected unmanaged diagnostic note for sit1:\n%s", out)
	}
}

func TestDoctorTunnelStatus_JSONOutput(t *testing.T) {
	sDir, sysDir := setupMockTunnelEnvironment(t)

	origSystemdDir := systemdDir
	systemdDir = sDir
	defer func() { systemdDir = origSystemdDir }()

	origSysfsDir := sysfsNetDir
	sysfsNetDir = sysDir
	defer func() { sysfsNetDir = origSysfsDir }()

	origRunner := tunnelCmdRunner
	tunnelCmdRunner = func(name string, arg ...string) ([]byte, error) {
		if len(arg) >= 2 && arg[0] == "is-active" {
			return []byte("active\n"), nil
		}
		if len(arg) >= 2 && arg[0] == "is-enabled" {
			return []byte("enabled\n"), nil
		}
		return []byte("ok"), nil
	}
	defer func() { tunnelCmdRunner = origRunner }()

	origIfaces := tunnelInterfacesLister
	tunnelInterfacesLister = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "he-ipv6", Flags: net.FlagUp, MTU: 1480},
			{Name: "sit1", Flags: net.FlagUp, MTU: 1480},
		}, nil
	}
	defer func() { tunnelInterfacesLister = origIfaces }()

	origAddrs := tunnelAddrsLister
	tunnelAddrsLister = func(ifc net.Interface) ([]net.Addr, error) {
		if ifc.Name == "he-ipv6" {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("2001:db8:1f0a:692::2"), Mask: net.CIDRMask(64, 128)},
				&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			}, nil
		}
		if ifc.Name == "sit1" {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
			}, nil
		}
		return nil, nil
	}
	defer func() { tunnelAddrsLister = origAddrs }()

	origProbe := tunnelProbeRunner
	tunnelProbeRunner = func(ip string, timeout time.Duration) (bool, time.Duration, error) {
		return true, 22 * time.Millisecond, nil
	}
	defer func() { tunnelProbeRunner = origProbe }()

	origJSON := doctorTunnelStatusJSON
	doctorTunnelStatusJSON = true
	defer func() { doctorTunnelStatusJSON = origJSON }()

	var buf bytes.Buffer
	doctorTunnelStatusCmd.SetOut(&buf)
	err := doctorTunnelStatusCmd.RunE(doctorTunnelStatusCmd, []string{})
	if err != nil {
		t.Fatalf("doctor tunnel status with --json failed: %v", err)
	}

	var report TunnelStatusReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v\nOutput: %s", err, buf.String())
	}

	if len(report.Tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(report.Tunnels))
	}

	tun0 := report.Tunnels[0]
	if tun0.Interface != "he-ipv6" {
		t.Errorf("expected tun0 to be he-ipv6, got %s", tun0.Interface)
	}
	if !tun0.Managed {
		t.Errorf("expected he-ipv6 to be Managed == true")
	}
	if tun0.ManagedBy != "he-tunnel-he-ipv6.service" {
		t.Errorf("unexpected ManagedBy: %s", tun0.ManagedBy)
	}
	if tun0.ServiceActive != "active" || tun0.ServiceEnabled != "enabled" {
		t.Errorf("unexpected service state: active=%s, enabled=%s", tun0.ServiceActive, tun0.ServiceEnabled)
	}
	if tun0.Traffic.RXBytes != 1048576 || tun0.Traffic.TXBytes != 524288 {
		t.Errorf("unexpected traffic stats: %+v", tun0.Traffic)
	}
	if len(tun0.Probes) != 1 || !tun0.Probes[0].Pass || tun0.Probes[0].RTTMs != 22 {
		t.Errorf("unexpected probes for he-ipv6: %+v", tun0.Probes)
	}

	tun1 := report.Tunnels[1]
	if tun1.Interface != "sit1" {
		t.Errorf("expected tun1 to be sit1, got %s", tun1.Interface)
	}
	if tun1.Managed {
		t.Errorf("expected sit1 to be Managed == false")
	}
	foundDiag := false
	for _, d := range tun1.Diagnostics {
		if strings.Contains(d, "Detected manual or external tunnel interface") {
			foundDiag = true
			break
		}
	}
	if !foundDiag {
		t.Errorf("expected unmanaged diagnostic in sit1: %+v", tun1.Diagnostics)
	}
}

func TestDoctorTunnelStatus_TargetInterfaceAndAbsent(t *testing.T) {
	sDir, sysDir := setupMockTunnelEnvironment(t)

	// Also add a service for an interface that is absent in kernel
	ghostSvc := `[Unit]
Description=Ghost Tunnel
[Service]
ExecStart=/sbin/ip tunnel add ghost-tun mode sit remote 1.1.1.1 local 2.2.2.2 ttl 255
ExecStart=/sbin/ip -6 addr replace 2001:db8:dead::2/64 dev ghost-tun
`
	_ = os.WriteFile(filepath.Join(sDir, "he-tunnel-ghost-tun.service"), []byte(ghostSvc), 0644)

	origSystemdDir := systemdDir
	systemdDir = sDir
	defer func() { systemdDir = origSystemdDir }()

	origSysfsDir := sysfsNetDir
	sysfsNetDir = sysDir
	defer func() { sysfsNetDir = origSysfsDir }()

	origRunner := tunnelCmdRunner
	tunnelCmdRunner = func(name string, arg ...string) ([]byte, error) {
		return []byte("inactive\n"), nil
	}
	defer func() { tunnelCmdRunner = origRunner }()

	origIfaces := tunnelInterfacesLister
	tunnelInterfacesLister = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "he-ipv6", Flags: net.FlagUp, MTU: 1480},
		}, nil
	}
	defer func() { tunnelInterfacesLister = origIfaces }()

	origAddrs := tunnelAddrsLister
	tunnelAddrsLister = func(ifc net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("2001:db8:1f0a:692::2"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	defer func() { tunnelAddrsLister = origAddrs }()

	origProbe := tunnelProbeRunner
	tunnelProbeRunner = func(ip string, timeout time.Duration) (bool, time.Duration, error) {
		return true, 10 * time.Millisecond, nil
	}
	defer func() { tunnelProbeRunner = origProbe }()

	origJSON := doctorTunnelStatusJSON
	doctorTunnelStatusJSON = true
	defer func() { doctorTunnelStatusJSON = origJSON }()

	// 1. Target single interface "he-ipv6"
	var buf1 bytes.Buffer
	doctorTunnelStatusCmd.SetOut(&buf1)
	if err := doctorTunnelStatusCmd.RunE(doctorTunnelStatusCmd, []string{"he-ipv6"}); err != nil {
		t.Fatalf("failed targeting he-ipv6: %v", err)
	}
	var rep1 TunnelStatusReport
	_ = json.Unmarshal(buf1.Bytes(), &rep1)
	if len(rep1.Tunnels) != 1 || rep1.Tunnels[0].Interface != "he-ipv6" {
		t.Errorf("expected only he-ipv6 in report, got: %+v", rep1.Tunnels)
	}

	// 2. Target absent interface "ghost-tun" (present in systemd, absent in kernel)
	var buf2 bytes.Buffer
	doctorTunnelStatusCmd.SetOut(&buf2)
	if err := doctorTunnelStatusCmd.RunE(doctorTunnelStatusCmd, []string{"ghost-tun"}); err != nil {
		t.Fatalf("failed targeting ghost-tun: %v", err)
	}
	var rep2 TunnelStatusReport
	_ = json.Unmarshal(buf2.Bytes(), &rep2)
	if len(rep2.Tunnels) != 1 {
		t.Fatalf("expected 1 tunnel for ghost-tun, got %d", len(rep2.Tunnels))
	}
	if rep2.Tunnels[0].State != "ABSENT" {
		t.Errorf("expected ghost-tun State to be ABSENT, got %s", rep2.Tunnels[0].State)
	}
	if !rep2.Tunnels[0].Managed {
		t.Errorf("expected ghost-tun to be Managed == true")
	}

	// 3. Target completely nonexistent interface
	err := doctorTunnelStatusCmd.RunE(doctorTunnelStatusCmd, []string{"totally-nonexistent"})
	if err == nil {
		t.Fatalf("expected error querying totally-nonexistent interface, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}
