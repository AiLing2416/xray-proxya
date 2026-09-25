package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestProxySetAndUnsetCmd(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Prepare config paths
	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "relay-test",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	cfgPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfgStagingPath := filepath.Join(configDir, "config.json.staging")
	if err := os.WriteFile(cfgStagingPath, cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// 1. Run "set" command flags
	proxySocksPort = 12000
	proxyHttpPort = 12001
	proxyListenIP = "192.168.1.5"
	defer func() {
		proxySocksPort = 0
		proxyHttpPort = 0
		proxyListenIP = ""
	}()

	proxySetCmd.Run(proxySetCmd, []string{"relay-test"})

	// Check staging config after set
	cfgAfterSet, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("LoadConfigEx staging error = %v", err)
	}
	if len(cfgAfterSet.CustomOutbounds) != 1 {
		t.Fatalf("expected 1 outbound, got %d", len(cfgAfterSet.CustomOutbounds))
	}
	co := cfgAfterSet.CustomOutbounds[0]
	if co.InternalProxyPort != 12000 {
		t.Fatalf("InternalProxyPort = %d, want 12000", co.InternalProxyPort)
	}
	if co.InternalHttpPort != 12001 {
		t.Fatalf("InternalHttpPort = %d, want 12001", co.InternalHttpPort)
	}
	if co.InternalListenAddr != "192.168.1.5" {
		t.Fatalf("InternalListenAddr = %q, want 192.168.1.5", co.InternalListenAddr)
	}

	// 2. Run "unset" command
	proxyUnsetCmd.Run(proxyUnsetCmd, []string{"relay-test"})

	// Check staging config after unset
	cfgAfterUnset, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("LoadConfigEx staging error = %v", err)
	}
	coAfter := cfgAfterUnset.CustomOutbounds[0]
	if coAfter.InternalProxyPort != 0 {
		t.Fatalf("InternalProxyPort = %d, want 0", coAfter.InternalProxyPort)
	}
	if coAfter.InternalHttpPort != 0 {
		t.Fatalf("InternalHttpPort = %d, want 0", coAfter.InternalHttpPort)
	}
	if coAfter.InternalListenAddr != "" {
		t.Fatalf("InternalListenAddr = %q, want empty", coAfter.InternalListenAddr)
	}
}

func TestProxySetIncrementalUpdate(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "relay-inc",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	cfgStagingPath := filepath.Join(configDir, "config.json.staging")
	if err := os.WriteFile(cfgStagingPath, cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	resetFlags := func() {
		_ = proxySetCmd.Flags().Set("port", "0")
		_ = proxySetCmd.Flags().Set("socks-port", "0")
		_ = proxySetCmd.Flags().Set("http-port", "0")
		_ = proxySetCmd.Flags().Set("listen", "127.0.0.1")
		proxySetCmd.Flags().Lookup("port").Changed = false
		proxySetCmd.Flags().Lookup("socks-port").Changed = false
		proxySetCmd.Flags().Lookup("http-port").Changed = false
		proxySetCmd.Flags().Lookup("listen").Changed = false
		proxySocksPort = 0
		proxyHttpPort = 0
		proxyListenIP = ""
	}
	defer resetFlags()

	// 1. Initial set: -p 10808
	resetFlags()
	_ = proxySetCmd.Flags().Set("port", "10808")
	if err := runProxySet(proxySetCmd, []string{"relay-inc"}); err != nil {
		t.Fatalf("runProxySet error: %v", err)
	}
	c1, _ := config.LoadConfigEx(true)
	if c1.CustomOutbounds[0].InternalProxyPort != 10808 {
		t.Fatalf("step 1: SOCKS port = %d, want 10808", c1.CustomOutbounds[0].InternalProxyPort)
	}
	if c1.CustomOutbounds[0].InternalHttpPort != 10809 {
		t.Fatalf("step 1: HTTP port = %d, want 10809", c1.CustomOutbounds[0].InternalHttpPort)
	}
	if c1.CustomOutbounds[0].InternalListenAddr != "127.0.0.1" {
		t.Fatalf("step 1: Listen = %q, want 127.0.0.1", c1.CustomOutbounds[0].InternalListenAddr)
	}

	// 2. Incremental set: -l 0.0.0.0 (ports must be preserved)
	resetFlags()
	_ = proxySetCmd.Flags().Set("listen", "0.0.0.0")
	if err := runProxySet(proxySetCmd, []string{"relay-inc"}); err != nil {
		t.Fatalf("runProxySet error: %v", err)
	}
	c2, _ := config.LoadConfigEx(true)
	if c2.CustomOutbounds[0].InternalProxyPort != 10808 {
		t.Fatalf("step 2: SOCKS port = %d, want 10808 (preserved)", c2.CustomOutbounds[0].InternalProxyPort)
	}
	if c2.CustomOutbounds[0].InternalHttpPort != 10809 {
		t.Fatalf("step 2: HTTP port = %d, want 10809 (preserved)", c2.CustomOutbounds[0].InternalHttpPort)
	}
	if c2.CustomOutbounds[0].InternalListenAddr != "0.0.0.0" {
		t.Fatalf("step 2: Listen = %q, want 0.0.0.0", c2.CustomOutbounds[0].InternalListenAddr)
	}

	// 3. Incremental set: --http-port 10815 (socks and listen preserved)
	resetFlags()
	_ = proxySetCmd.Flags().Set("http-port", "10815")
	if err := runProxySet(proxySetCmd, []string{"relay-inc"}); err != nil {
		t.Fatalf("runProxySet error: %v", err)
	}
	c3, _ := config.LoadConfigEx(true)
	if c3.CustomOutbounds[0].InternalProxyPort != 10808 {
		t.Fatalf("step 3: SOCKS port = %d, want 10808 (preserved)", c3.CustomOutbounds[0].InternalProxyPort)
	}
	if c3.CustomOutbounds[0].InternalHttpPort != 10815 {
		t.Fatalf("step 3: HTTP port = %d, want 10815", c3.CustomOutbounds[0].InternalHttpPort)
	}
	if c3.CustomOutbounds[0].InternalListenAddr != "0.0.0.0" {
		t.Fatalf("step 3: Listen = %q, want 0.0.0.0 (preserved)", c3.CustomOutbounds[0].InternalListenAddr)
	}

	// 4. Incremental set: -p 20808 (http links to socks+1 = 20809, listen preserved)
	resetFlags()
	_ = proxySetCmd.Flags().Set("port", "20808")
	if err := runProxySet(proxySetCmd, []string{"relay-inc"}); err != nil {
		t.Fatalf("runProxySet error: %v", err)
	}
	c4, _ := config.LoadConfigEx(true)
	if c4.CustomOutbounds[0].InternalProxyPort != 20808 {
		t.Fatalf("step 4: SOCKS port = %d, want 20808", c4.CustomOutbounds[0].InternalProxyPort)
	}
	if c4.CustomOutbounds[0].InternalHttpPort != 20809 {
		t.Fatalf("step 4: HTTP port = %d, want 20809 (linked)", c4.CustomOutbounds[0].InternalHttpPort)
	}
	if c4.CustomOutbounds[0].InternalListenAddr != "0.0.0.0" {
		t.Fatalf("step 4: Listen = %q, want 0.0.0.0 (preserved)", c4.CustomOutbounds[0].InternalListenAddr)
	}
}

func TestCheckProxyPortConflict(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSReality, Enabled: true, Port: 443},
		},
		AdminSub: config.AdminSubConfig{
			Port: 8443,
		},
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:              "node-a",
				Enabled:            true,
				InternalProxyPort:  10808,
				InternalHttpPort:   10809,
				InternalListenAddr: "127.0.0.1",
			},
			{
				Alias:              "node-lan",
				Enabled:            true,
				InternalProxyPort:  10810,
				InternalHttpPort:   10811,
				InternalListenAddr: "192.168.1.50",
			},
		},
	}

	// 1. SOCKS and HTTP port identical
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 10820, 10820); err == nil {
		t.Errorf("expected error when SOCKS port == HTTP port")
	}

	// 2. Conflict with other outbound on overlapping IP (127.0.0.1 vs 127.0.0.1)
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 10808, 10820); err == nil {
		t.Errorf("expected conflict with node-a SOCKS port")
	}
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 10820, 10809); err == nil {
		t.Errorf("expected conflict with node-a HTTP port")
	}

	// 3. Conflict with wildcard IP vs specific IP
	if err := checkProxyPortConflict(cfg, "node-new", "0.0.0.0", 10808, 10820); err == nil {
		t.Errorf("expected conflict between 0.0.0.0 and node-a on 127.0.0.1")
	}

	// 4. No conflict on distinct non-overlapping IPs
	if err := checkProxyPortConflict(cfg, "node-new", "192.168.1.60", 10810, 10811); err != nil {
		t.Errorf("expected no conflict on distinct IPs, got %v", err)
	}

	// 5. Conflict with presets (port 443)
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 443, 10820); err == nil {
		t.Errorf("expected conflict with preset port 443")
	}

	// 6. Conflict with AdminSub (port 8443)
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 10820, 8443); err == nil {
		t.Errorf("expected conflict with admin sub port 8443")
	}

	// 7. Same node updating itself should not conflict with its own old ports
	if err := checkProxyPortConflict(cfg, "node-a", "127.0.0.1", 10808, 10809); err != nil {
		t.Errorf("expected self update to not trigger conflict with itself, got %v", err)
	}

	// 8. Conflict with SkinPort (18443)
	cfg.SkinPort = 18443
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 18443, 10820); err == nil || !strings.Contains(err.Error(), "Web Camouflage Skin service") {
		t.Errorf("expected conflict with SkinPort on SOCKS port, got %v", err)
	}
	if err := checkProxyPortConflict(cfg, "node-new", "127.0.0.1", 10820, 18443); err == nil || !strings.Contains(err.Error(), "Web Camouflage Skin service") {
		t.Errorf("expected conflict with SkinPort on HTTP port, got %v", err)
	}
	if err := checkProxyPortConflict(cfg, "node-new", "192.168.1.60", 18443, 10820); err != nil {
		t.Errorf("expected no conflict on distinct non-overlapping IP with SkinPort, got %v", err)
	}
}

func TestProxySetActiveSelfOwnedPortExemption(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Find free test ports to bind
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l1.Close()
	testSocksPort := l1.Addr().(*net.TCPAddr).Port

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l2.Close()
	testHttpPort := l2.Addr().(*net.TCPAddr).Port

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:              "relay-self",
				Enabled:            true,
				InternalProxyPort:  testSocksPort,
				InternalHttpPort:   testHttpPort,
				InternalListenAddr: "127.0.0.1",
				Config:             map[string]interface{}{"protocol": "freedom"},
			},
			{
				Alias:   "relay-other",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile config.json error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json.staging"), cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile config.json.staging error = %v", err)
	}

	resetFlags := func() {
		_ = proxySetCmd.Flags().Set("port", "0")
		_ = proxySetCmd.Flags().Set("socks-port", "0")
		_ = proxySetCmd.Flags().Set("http-port", "0")
		_ = proxySetCmd.Flags().Set("listen", "127.0.0.1")
		proxySetCmd.Flags().Lookup("port").Changed = false
		proxySetCmd.Flags().Lookup("socks-port").Changed = false
		proxySetCmd.Flags().Lookup("http-port").Changed = false
		proxySetCmd.Flags().Lookup("listen").Changed = false
		proxySocksPort = 0
		proxyHttpPort = 0
		proxyListenIP = ""
	}
	defer resetFlags()

	// 1. Setting relay-self with its own occupied ports should SUCCEED
	resetFlags()
	_ = proxySetCmd.Flags().Set("socks-port", fmt.Sprintf("%d", testSocksPort))
	_ = proxySetCmd.Flags().Set("http-port", fmt.Sprintf("%d", testHttpPort))
	if err := runProxySet(proxySetCmd, []string{"relay-self"}); err != nil {
		t.Fatalf("expected relay-self to succeed on its own active ports, got %v", err)
	}

	// 2. Setting relay-other with the occupied ports must FAIL
	resetFlags()
	_ = proxySetCmd.Flags().Set("socks-port", fmt.Sprintf("%d", testSocksPort))
	_ = proxySetCmd.Flags().Set("http-port", fmt.Sprintf("%d", testHttpPort))
	if err := runProxySet(proxySetCmd, []string{"relay-other"}); err == nil {
		t.Fatalf("expected relay-other to fail with port in use, but it succeeded")
	}
}

func TestProxyRunPortLinkageAndValidation(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:              "relay-run",
				Enabled:            true,
				InternalProxyPort:  10808,
				InternalHttpPort:   10809,
				InternalListenAddr: "127.0.0.1",
				Config:             map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile config.json error = %v", err)
	}

	// 1. Non-existent relay
	err = runProxyRun(proxyRunCmd, []string{"non-existent"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}

	// 2. Occupy a port to test linkage
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()
	occupiedPort := l.Addr().(*net.TCPAddr).Port
	basePort := occupiedPort - 1

	// Test: running with -p basePort should link httpPort to basePort + 1 (occupiedPort)
	_ = proxyRunCmd.Flags().Set("port", fmt.Sprintf("%d", basePort))
	defer func() {
		_ = proxyRunCmd.Flags().Set("port", "0")
		_ = proxyRunCmd.Flags().Set("socks-port", "0")
		_ = proxyRunCmd.Flags().Set("http-port", "0")
		_ = proxyRunCmd.Flags().Set("listen", "")
		proxyRunCmd.Flags().Lookup("port").Changed = false
		proxyRunCmd.Flags().Lookup("socks-port").Changed = false
		proxyRunCmd.Flags().Lookup("http-port").Changed = false
		proxyRunCmd.Flags().Lookup("listen").Changed = false
		proxyRunSocksPort = 0
		proxyRunHttpPort = 0
		proxyRunListenIP = ""
	}()

	err = runProxyRun(proxyRunCmd, []string{"relay-run"})
	if err == nil {
		t.Fatalf("expected error due to occupied HTTP port %d, got nil", occupiedPort)
	}
	expectedMsg := fmt.Sprintf("HTTP Port %d is in use on the host.", occupiedPort)
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

func TestProxyListFilteringAndEmptyState(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// 1. Empty state when no outbounds configured
	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error = %v", err)
	}

	proxyListAll = false
	proxyListJSON = false
	t.Cleanup(func() {
		proxyListAll = false
		proxyListJSON = false
	})

	outEmpty := captureStdout(t, func() {
		if err := proxyListCmd.RunE(proxyListCmd, nil); err != nil {
			t.Fatalf("proxyListCmd error = %v", err)
		}
	})
	if !strings.Contains(outEmpty, "No local proxy listeners configured") {
		t.Errorf("expected empty message, got:\n%s", outEmpty)
	}

	// 2. Empty state when outbounds exist but none have InternalProxyPort > 0
	cfg.CustomOutbounds = []config.CustomOutbound{
		{Alias: "r1", Enabled: true, Config: map[string]interface{}{"protocol": "freedom"}},
		{Alias: "r2", Enabled: true, Config: map[string]interface{}{"protocol": "freedom"}},
		{Alias: "r3", Enabled: true, Config: map[string]interface{}{"protocol": "freedom"}},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error = %v", err)
	}

	outNoProxies := captureStdout(t, func() {
		if err := proxyListCmd.RunE(proxyListCmd, nil); err != nil {
			t.Fatalf("proxyListCmd error = %v", err)
		}
	})
	if !strings.Contains(outNoProxies, "No local proxy listeners configured") {
		t.Errorf("expected empty message when no proxy configured, got:\n%s", outNoProxies)
	}

	// 3. Configure proxy on r1 only in staging (unapplied / pending)
	cfgStaging := *cfg
	cfgStaging.CustomOutbounds[0].InternalProxyPort = 10808
	cfgStaging.CustomOutbounds[0].InternalHttpPort = 10809
	if err := cfgStaging.SaveEx(true); err != nil {
		t.Fatalf("SaveEx staging error = %v", err)
	}

	// Default: should ONLY show r1 (not r2, r3) and show PENDING and pending warning
	outDefault := captureStdout(t, func() {
		if err := proxyListCmd.RunE(proxyListCmd, nil); err != nil {
			t.Fatalf("proxyListCmd error = %v", err)
		}
	})
	if !strings.Contains(outDefault, "r1") {
		t.Errorf("expected r1 in default output, got:\n%s", outDefault)
	}
	if strings.Contains(outDefault, "r2") || strings.Contains(outDefault, "r3") {
		t.Errorf("expected r2 and r3 to be filtered out in default output, got:\n%s", outDefault)
	}
	if !strings.Contains(outDefault, "PENDING") {
		t.Errorf("expected PENDING state for unapplied proxy, got:\n%s", outDefault)
	}
	if !strings.Contains(outDefault, "Pending changes in STAGING") {
		t.Errorf("expected staging pending notice, got:\n%s", outDefault)
	}

	// 4. With -a (--all): should show r1, r2, and r3
	proxyListAll = true
	outAll := captureStdout(t, func() {
		if err := proxyListCmd.RunE(proxyListCmd, nil); err != nil {
			t.Fatalf("proxyListCmd error = %v", err)
		}
	})
	if !strings.Contains(outAll, "r1") || !strings.Contains(outAll, "r2") || !strings.Contains(outAll, "r3") {
		t.Errorf("expected r1, r2, r3 in -a output, got:\n%s", outAll)
	}
}

func TestNormalizeProbeListenIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "127.0.0.1"},
		{"0.0.0.0", "127.0.0.1"},
		{"::", "::1"},
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
		{"192.168.1.100", "192.168.1.100"},
	}
	for _, tc := range tests {
		got := normalizeProbeListenIP(tc.input)
		if got != tc.want {
			t.Errorf("normalizeProbeListenIP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestProxyTestUnappliedStagingHint(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Active config: no proxy configured
	activeCfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "test-node",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	activeBytes, _ := json.Marshal(activeCfg)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), activeBytes, 0600); err != nil {
		t.Fatalf("WriteFile config.json error: %v", err)
	}

	// Staging config: proxy configured with non-listening port
	// Find an unused local port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	freePort := l.Addr().(*net.TCPAddr).Port
	l.Close() // Close immediately so it's not listening

	stagingCfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:              "test-node",
				Enabled:            true,
				InternalProxyPort:  freePort,
				InternalHttpPort:   freePort + 1,
				InternalListenAddr: "127.0.0.1",
				Config:             map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	stagingBytes, _ := json.Marshal(stagingCfg)
	if err := os.WriteFile(filepath.Join(configDir, "config.json.staging"), stagingBytes, 0600); err != nil {
		t.Fatalf("WriteFile config.json.staging error: %v", err)
	}

	// Run proxy test - it should fail to connect and print the hint
	out := captureStdout(t, func() {
		err := runProxyTest(proxyTestCmd, []string{"test-node"})
		if err == nil {
			t.Fatal("expected runProxyTest to fail, but it succeeded")
		}
	})

	expectedHint := "💡 Hint: Local proxy for 'test-node' is in STAGING but not yet active. Run 'xray-proxya apply' to start it."
	if !strings.Contains(out, expectedHint) {
		t.Errorf("expected output to contain hint:\n%q\nGot:\n%s", expectedHint, out)
	}
}


