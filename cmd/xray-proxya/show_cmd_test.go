package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

func TestShowResolveIPs_DefaultUsesIPv4(t *testing.T) {
	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
		showIPv4 = true
		showIPv6 = false
	}()

	getPublicIPv4Func = func() string { return "198.51.100.1" }
	getPublicIPv6Func = func() string { return "2001:db8::1" }
	getLocalIPFunc = func() string { return "10.0.0.2" }
	showAddr = ""

	cmd := &cobra.Command{}
	cmd.Flags().BoolVarP(&showIPv4, "ipv4", "4", true, "")
	cmd.Flags().BoolVarP(&showIPv6, "ipv6", "6", false, "")

	ips := resolveShowIPs(cmd)
	if len(ips) != 1 || ips[0] != "198.51.100.1" {
		t.Fatalf("resolveShowIPs() = %v, want [198.51.100.1]", ips)
	}
}

func TestShowResolveIPs_ExplicitIPv6Only(t *testing.T) {
	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
		showIPv4 = true
		showIPv6 = false
	}()

	getPublicIPv4Func = func() string { return "198.51.100.1" }
	getPublicIPv6Func = func() string { return "2001:db8::1" }
	getLocalIPFunc = func() string { return "10.0.0.2" }
	showAddr = ""

	cmd := &cobra.Command{}
	cmd.Flags().BoolVarP(&showIPv4, "ipv4", "4", true, "")
	cmd.Flags().BoolVarP(&showIPv6, "ipv6", "6", false, "")
	if err := cmd.Flags().Set("ipv6", "true"); err != nil {
		t.Fatalf("Set ipv6 error: %v", err)
	}

	ips := resolveShowIPs(cmd)
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("resolveShowIPs() with --ipv6 = %v, want [2001:db8::1]", ips)
	}
}

func TestShowResolveIPs_ExplicitIPv6NoFallbackToIPv4(t *testing.T) {
	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
		showIPv4 = true
		showIPv6 = false
	}()

	getPublicIPv4Func = func() string { return "198.51.100.1" }
	getPublicIPv6Func = func() string { return "" } // No public IPv6
	getLocalIPFunc = func() string { return "10.0.0.2" }
	showAddr = ""

	cmd := &cobra.Command{}
	cmd.Flags().BoolVarP(&showIPv4, "ipv4", "4", true, "")
	cmd.Flags().BoolVarP(&showIPv6, "ipv6", "6", false, "")
	if err := cmd.Flags().Set("ipv6", "true"); err != nil {
		t.Fatalf("Set ipv6 error: %v", err)
	}

	ips := resolveShowIPs(cmd)
	if len(ips) != 0 {
		t.Fatalf("resolveShowIPs() with missing IPv6 = %v, want empty (no fallback to IPv4)", ips)
	}
}

func TestShowResolveIPs_ExplicitDualStack(t *testing.T) {
	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
		showIPv4 = true
		showIPv6 = false
	}()

	getPublicIPv4Func = func() string { return "198.51.100.1" }
	getPublicIPv6Func = func() string { return "2001:db8::1" }
	getLocalIPFunc = func() string { return "10.0.0.2" }
	showAddr = ""

	cmd := &cobra.Command{}
	cmd.Flags().BoolVarP(&showIPv4, "ipv4", "4", true, "")
	cmd.Flags().BoolVarP(&showIPv6, "ipv6", "6", false, "")
	if err := cmd.Flags().Set("ipv4", "true"); err != nil {
		t.Fatalf("Set ipv4 error: %v", err)
	}
	if err := cmd.Flags().Set("ipv6", "true"); err != nil {
		t.Fatalf("Set ipv6 error: %v", err)
	}

	ips := resolveShowIPs(cmd)
	if len(ips) != 2 || ips[0] != "198.51.100.1" || ips[1] != "2001:db8::1" {
		t.Fatalf("resolveShowIPs() dual stack = %v, want [198.51.100.1, 2001:db8::1]", ips)
	}
}

func TestShowResolveIPs_AddressOverride(t *testing.T) {
	showAddr = "custom.example.com"
	defer func() { showAddr = "" }()

	ips := resolveShowIPs(nil)
	if len(ips) != 1 || ips[0] != "custom.example.com" {
		t.Fatalf("resolveShowIPs() with override = %v, want [custom.example.com]", ips)
	}
}

func TestShowCmd_ExecutionMultiIPAndHeaders(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-1234",
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "mock.com",
				Dest:    "mock.com:443",
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
		showIPv4 = true
		showIPv6 = false
		showCmd.Flags().Lookup("ipv4").Changed = false
		showCmd.Flags().Lookup("ipv6").Changed = false
	}()

	getPublicIPv4Func = func() string { return "198.51.100.1" }
	getPublicIPv6Func = func() string { return "2001:db8::1" }
	showAddr = ""
	showIPv4 = true
	showIPv6 = true
	showCmd.Flags().Lookup("ipv4").Changed = true
	showCmd.Flags().Lookup("ipv6").Changed = true

	// Capture stdout
	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := showCmd.RunE(showCmd, []string{})

	w.Close()
	os.Stdout = origStdout

	if err != nil {
		t.Fatalf("showCmd.RunE failed: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "=== Address: 198.51.100.1 ===") {
		t.Errorf("output missing IPv4 section header: %s", output)
	}
	if !strings.Contains(output, "=== Address: 2001:db8::1 ===") {
		t.Errorf("output missing IPv6 section header: %s", output)
	}
}

func TestShowCmd_NoIPError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-1234",
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
		showIPv4 = true
		showIPv6 = false
		showCmd.Flags().Lookup("ipv6").Changed = false
	}()

	getPublicIPv4Func = func() string { return "" }
	getPublicIPv6Func = func() string { return "" }
	getLocalIPFunc = func() string { return "" }
	showAddr = ""
	showIPv6 = true
	showCmd.Flags().Lookup("ipv6").Changed = true

	err := showCmd.RunE(showCmd, []string{})
	if err == nil {
		t.Fatal("expected error when no IP address found, got nil")
	}
}
