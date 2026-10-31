package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"xray-proxya/internal/config"
	"xray-proxya/internal/warp"
)

func TestRelayWarpCmd_Flags(t *testing.T) {
	if relayWarpCmd.Flags().Lookup("endpoint") == nil {
		t.Fatal("expected --endpoint flag")
	}
	if relayWarpCmd.Flags().Lookup("apply") == nil {
		t.Fatal("expected --apply flag")
	}
	if relayWarpCmd.Flags().Lookup("no-test") == nil {
		t.Fatal("expected --no-test flag")
	}
	if relayWarpCmd.Flags().Lookup("json") == nil {
		t.Fatal("expected --json flag")
	}
}

func TestRelayWarpCmd_RunE_AddAndOverwrite(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id": "mock-warp-cli-id",
			"config": map[string]interface{}{
				"client_id": "rUgi",
				"peers": []map[string]interface{}{
					{
						"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
						"endpoint": map[string]interface{}{
							"host": "engage.cloudflareclient.com:2408",
						},
					},
				},
				"interface": map[string]interface{}{
					"addresses": map[string]interface{}{
						"v4": "172.16.0.2",
						"v6": "2606:4700:110:8996:fd65:3885:4a6e:c2c4",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	cleanup := warp.SetRegistrationURLForTest(ts.URL)
	defer cleanup()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll error: %v", err)
	}

	initialCfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "existing-relay",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	initialBytes, _ := json.Marshal(initialCfg)
	if err := os.WriteFile(filepath.Join(configDir, "config.json.staging"), initialBytes, 0600); err != nil {
		t.Fatalf("WriteFile staging error: %v", err)
	}

	// 1. Run relay warp without test
	relayWarpNoTest = true
	relayWarpJSON = false
	relayWarpApply = false
	relayWarpEndpoint = ""

	if err := relayWarpCmd.RunE(relayWarpCmd, nil); err != nil {
		t.Fatalf("relayWarpCmd.RunE failed: %v", err)
	}

	// Verify staging configuration now contains CF_WARP
	loadedCfg, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("failed to load staging config: %v", err)
	}
	if len(loadedCfg.CustomOutbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(loadedCfg.CustomOutbounds))
	}
	var warpCO *config.CustomOutbound
	for _, co := range loadedCfg.CustomOutbounds {
		if co.Alias == warp.DefaultWarpAlias {
			warpCO = &co
			break
		}
	}
	if warpCO == nil {
		t.Fatalf("CF_WARP not found in CustomOutbounds")
	}
	if warpCO.Config["protocol"] != "wireguard" {
		t.Errorf("protocol = %v, want wireguard", warpCO.Config["protocol"])
	}

	// 2. Overwrite test: run with custom endpoint
	relayWarpEndpoint = "198.51.100.10:2408"
	if err := relayWarpCmd.RunE(relayWarpCmd, nil); err != nil {
		t.Fatalf("second relayWarpCmd.RunE failed: %v", err)
	}

	loadedCfg2, _ := config.LoadConfigEx(true)
	if len(loadedCfg2.CustomOutbounds) != 2 {
		t.Fatalf("expected still 2 outbounds after overwrite, got %d", len(loadedCfg2.CustomOutbounds))
	}
	var warpCO2 *config.CustomOutbound
	for _, co := range loadedCfg2.CustomOutbounds {
		if co.Alias == warp.DefaultWarpAlias {
			warpCO2 = &co
			break
		}
	}
	if warpCO2 == nil {
		t.Fatalf("CF_WARP not found after overwrite")
	}
	settings := warpCO2.Config["settings"].(map[string]interface{})
	peers := settings["peers"].([]interface{})
	peer := peers[0].(map[string]interface{})
	if peer["endpoint"] != "198.51.100.10:2408" {
		t.Errorf("endpoint not updated on overwrite: %v", peer["endpoint"])
	}

	// 3. JSON mode test
	relayWarpJSON = true
	relayWarpEndpoint = ""
	if err := relayWarpCmd.RunE(relayWarpCmd, nil); err != nil {
		t.Fatalf("JSON mode relayWarpCmd.RunE failed: %v", err)
	}
}
