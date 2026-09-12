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

func TestShowResolveIPs_AddressOverride_IPv6_Bracketed(t *testing.T) {
	showAddr = "[2001:db8::1]"
	defer func() { showAddr = "" }()

	ips := resolveShowIPs(nil)
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("resolveShowIPs() with bracketed IPv6 = %v, want [2001:db8::1]", ips)
	}
}

func TestShowResolveIPs_AddressOverride_SkipsNetworkCalls(t *testing.T) {
	origV4 := getPublicIPv4Func
	origV6 := getPublicIPv6Func
	origLocal := getLocalIPFunc
	defer func() {
		getPublicIPv4Func = origV4
		getPublicIPv6Func = origV6
		getLocalIPFunc = origLocal
		showAddr = ""
	}()

	getPublicIPv4Func = func() string {
		t.Fatal("getPublicIPv4Func should not be called when -a is specified")
		return ""
	}
	getPublicIPv6Func = func() string {
		t.Fatal("getPublicIPv6Func should not be called when -a is specified")
		return ""
	}
	getLocalIPFunc = func() string {
		t.Fatal("getLocalIPFunc should not be called when -a is specified")
		return ""
	}

	showAddr = "custom.domain.com"
	ips := resolveShowIPs(nil)
	if len(ips) != 1 || ips[0] != "custom.domain.com" {
		t.Fatalf("resolveShowIPs() = %v, want [custom.domain.com]", ips)
	}
}

func TestShowCmd_AddressOverrideTitles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-addr",
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

	defer func() { showAddr = "" }()

	testCases := []struct {
		addrInput  string
		wantHeader string
	}{
		{"custom.domain.com", "Sharing Links for Admin, Using Hostname custom.domain.com"},
		{"87.229.95.124", "Sharing Links for Admin, Using IP 87.229.95.124"},
		{"2001:db8::1", "Sharing Links for Admin, Using IP [2001:db8::1]"},
		{"[2001:db8::1]", "Sharing Links for Admin, Using IP [2001:db8::1]"},
	}

	for _, tc := range testCases {
		showAddr = tc.addrInput
		origStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := showCmd.RunE(showCmd, []string{})
		w.Close()
		os.Stdout = origStdout

		if err != nil {
			t.Fatalf("showCmd.RunE failed for %s: %v", tc.addrInput, err)
		}
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		out := buf.String()
		if !strings.Contains(out, tc.wantHeader) {
			t.Errorf("for input %q, want header %q, got output:\n%s", tc.addrInput, tc.wantHeader, out)
		}
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

	if !strings.Contains(output, "Sharing Links for Admin, Using IP 198.51.100.1") {
		t.Errorf("output missing IPv4 atomic group header: %s", output)
	}
	if !strings.Contains(output, "Sharing Links for Admin, Using IP [2001:db8::1]") {
		t.Errorf("output missing IPv6 atomic group header: %s", output)
	}
	if !strings.Contains(output, showDivider) {
		t.Errorf("output missing 59-char divider: %s", output)
	}
	if strings.Contains(output, "🚀 SHARING LINKS") {
		t.Errorf("output should not contain old banner: %s", output)
	}
	if strings.Contains(output, "=== Address:") {
		t.Errorf("output should not contain nested address header: %s", output)
	}
	if strings.Contains(output, "# DIRECT") {
		t.Errorf("output should not contain old direct header: %s", output)
	}
}

func TestShowCmd_GuestAndRelayAtomicHeaders(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-5678",
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "mock.com",
				Dest:    "mock.com:443",
			},
		},
		Guests: []config.GuestConfig{
			{Alias: "Tom", UUID: "uuid-tom", Enabled: true},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "exti-1", Enabled: true, UserUUID: "uuid-relay", Config: map[string]interface{}{"protocol": "freedom"}},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	origV4 := getPublicIPv4Func
	defer func() {
		getPublicIPv4Func = origV4
		showGuest = ""
		showRelay = ""
	}()
	getPublicIPv4Func = func() string { return "87.229.95.124" }

	// Test Guest
	showGuest = "Tom"
	showRelay = ""
	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := showCmd.RunE(showCmd, []string{})
	w.Close()
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("showCmd.RunE guest failed: %v", err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	guestOut := buf.String()
	if !strings.Contains(guestOut, "Sharing Links for Guest Tom, Using IP 87.229.95.124") {
		t.Errorf("expected Guest Tom header, got: %s", guestOut)
	}

	// Test Relay
	showGuest = ""
	showRelay = "exti-1"
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	err = showCmd.RunE(showCmd, []string{})
	w2.Close()
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("showCmd.RunE relay failed: %v", err)
	}
	buf.Reset()
	_, _ = io.Copy(&buf, r2)
	relayOut := buf.String()
	if !strings.Contains(relayOut, "Sharing Links for Relay exti-1, Using IP 87.229.95.124") {
		t.Errorf("expected Relay exti-1 header, got: %s", relayOut)
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

func TestShowCmd_EndpointFlag(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-ep",
		Presets: []config.ModeInfo{{
			Mode:    config.ModeVLESSVision,
			Enabled: true,
			Port:    443,
			SNI:     "example.com",
			Settings: config.Settings{
				PublicKey: "pub",
				ShortID:   "abcd",
			},
		}},
		Endpoints: map[string]config.EndpointConfig{
			"my-domain": {
				Type: config.EndpointTypeStatic,
				Host: "test.example.com",
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	defer func() {
		showEndpoint = "default"
		showCmd.Flags().Lookup("endpoint").Changed = false
		_ = showCmd.Flags().Lookup("endpoint").Value.Set("default")
	}()

	showEndpoint = "my-domain"
	showCmd.Flags().Lookup("endpoint").Changed = true

	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := showCmd.RunE(showCmd, []string{})
	w.Close()
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("showCmd.RunE with --endpoint failed: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "@test.example.com:443?") {
		t.Errorf("expected @test.example.com:443? in output, got: %s", output)
	}
}

func TestShowCmd_DefaultEndpointAppliedWithoutFlag(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-def-ep",
		Presets: []config.ModeInfo{{
			Mode:    config.ModeVLESSVision,
			Enabled: true,
			Port:    443,
			SNI:     "example.com",
			Settings: config.Settings{
				PublicKey: "pub",
				ShortID:   "abcd",
			},
		}},
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type: config.EndpointTypeStatic,
				Host: "node.example.com",
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	defer func() {
		showEndpoint = "default"
		showCmd.Flags().Lookup("endpoint").Changed = false
		_ = showCmd.Flags().Lookup("endpoint").Value.Set("default")
	}()

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

	if !strings.Contains(output, "@node.example.com:443?") {
		t.Errorf("expected @node.example.com:443? in output without --endpoint flag, got: %s", output)
	}
}

func TestShowCmd_QRCodeFlag(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-show-qr",
		Presets: []config.ModeInfo{{
			Mode:    config.ModeVLESSVision,
			Enabled: true,
			Port:    443,
			SNI:     "example.com",
			Settings: config.Settings{
				PublicKey: "pub",
				ShortID:   "abcd",
			},
		}},
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type: config.EndpointTypeStatic,
				Host: "198.51.100.1",
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	defer func() {
		showQRCode = false
		showQRInvert = false
		showCmd.Flags().Lookup("qrcode").Changed = false
		_ = showCmd.Flags().Lookup("qrcode").Value.Set("false")
		showCmd.Flags().Lookup("qr-invert").Changed = false
		_ = showCmd.Flags().Lookup("qr-invert").Value.Set("false")
	}()

	// 1. Run with --qrcode
	showQRCode = true
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

	if !strings.Contains(output, "vless://test-uuid-show-qr@198.51.100.1:443") {
		t.Errorf("expected vless link in output, got: %s", output)
	}
	if !strings.Contains(output, "█") || !strings.Contains(output, "▀") {
		t.Errorf("expected QR code blocks in output when --qrcode is set, got: %s", output)
	}

	// 2. Run without --qrcode
	showQRCode = false
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	err = showCmd.RunE(showCmd, []string{})
	w2.Close()
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("showCmd.RunE without qrcode failed: %v", err)
	}

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	output2 := buf2.String()

	if !strings.Contains(output2, "vless://test-uuid-show-qr@198.51.100.1:443") {
		t.Errorf("expected vless link in output, got: %s", output2)
	}
	if strings.Contains(output2, "▀") {
		t.Errorf("unexpected QR code blocks in output when --qrcode is false, got: %s", output2)
	}
}


