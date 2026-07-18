package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
