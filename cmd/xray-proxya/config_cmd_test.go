package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestConfigUpgradeDryRunDoesNotModifyFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configPath := filepath.Join(tmpHome, ".config", "xray-proxya", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	original := `{"custom_outbounds":[{"alias":"relay-a","enabled":true,"config":{}}],"guests":[{"alias":"guest-a","reset_day":0}]}`
	if err := os.WriteFile(configPath, []byte(original), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configUpgradeStaging = false
	configUpgradeDryRun = true
	t.Cleanup(func() {
		configUpgradeStaging = false
		configUpgradeDryRun = false
	})

	output := captureStdout(t, func() {
		configUpgradeCmd.Run(configUpgradeCmd, nil)
	})

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(after) != original {
		t.Fatalf("config file changed during dry-run\nbefore: %s\nafter:  %s", original, string(after))
	}

	if !strings.Contains(output, "Dry run") {
		t.Fatalf("output = %q, want dry-run banner", output)
	}
	if !strings.Contains(output, "No files were modified.") {
		t.Fatalf("output = %q, want no-write confirmation", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w

	outC := make(chan []byte)
	go func() {
		data, _ := io.ReadAll(r)
		outC <- data
	}()

	fn()

	_ = w.Close()
	os.Stdout = oldStdout
	data := <-outC
	_ = r.Close()

	return string(data)
}

func resetCmdFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
}

func TestConfigPathCmd(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}

	activePath := config.GetConfigPathEx(false)
	stagingPath := config.GetConfigPathEx(true)

	// 1. Default text output
	resetCmdFlags(configPathCmd)
	out := captureStdout(t, func() {
		if err := configPathCmd.RunE(configPathCmd, nil); err != nil {
			t.Fatalf("config path failed: %v", err)
		}
	})
	if !strings.Contains(out, "Config Directory:") || !strings.Contains(out, "Active Config:") || !strings.Contains(out, "exists: true") || !strings.Contains(out, "exists: false") {
		t.Errorf("unexpected default config path output: %s", out)
	}

	// 2. --active / -a
	resetCmdFlags(configPathCmd)
	configPathCmd.Flags().Set("active", "true")
	out = captureStdout(t, func() {
		if err := configPathCmd.RunE(configPathCmd, nil); err != nil {
			t.Fatalf("config path -a failed: %v", err)
		}
	})
	if strings.TrimSpace(out) != activePath {
		t.Errorf("config path -a = %q, want %q", strings.TrimSpace(out), activePath)
	}

	// 3. --staging / -s
	resetCmdFlags(configPathCmd)
	configPathCmd.Flags().Set("staging", "true")
	out = captureStdout(t, func() {
		if err := configPathCmd.RunE(configPathCmd, nil); err != nil {
			t.Fatalf("config path -s failed: %v", err)
		}
	})
	if strings.TrimSpace(out) != stagingPath {
		t.Errorf("config path -s = %q, want %q", strings.TrimSpace(out), stagingPath)
	}

	// 4. --json
	resetCmdFlags(configPathCmd)
	configPathCmd.Flags().Set("json", "true")
	out = captureStdout(t, func() {
		if err := configPathCmd.RunE(configPathCmd, nil); err != nil {
			t.Fatalf("config path --json failed: %v", err)
		}
	})
	var pathJSON ConfigPathJSON
	if err := json.Unmarshal([]byte(out), &pathJSON); err != nil {
		t.Fatalf("unmarshal json: %v\nOutput: %s", err, out)
	}
	if !pathJSON.ActiveExists || pathJSON.StagingExists {
		t.Errorf("active_exists = %t, staging_exists = %t; want true, false", pathJSON.ActiveExists, pathJSON.StagingExists)
	}
	if pathJSON.ActivePath != activePath || pathJSON.StagingPath != stagingPath {
		t.Errorf("path mismatch in json: %+v", pathJSON)
	}

	// Now create staging and verify staging_exists becomes true
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}
	out = captureStdout(t, func() {
		if err := configPathCmd.RunE(configPathCmd, nil); err != nil {
			t.Fatalf("config path --json failed: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(out), &pathJSON); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if !pathJSON.StagingExists {
		t.Errorf("expected staging_exists = true after saving staging config")
	}
}

func TestConfigShowCmd(t *testing.T) {
	setupTestConfigDir(t)

	// 1. Uninitialized
	resetCmdFlags(configShowCmd)
	err := configShowCmd.RunE(configShowCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "has not been initialized") {
		t.Fatalf("expected uninitialized error, got: %v", err)
	}

	// 2. Active config formatted JSON
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tun",
			LANInterface: "eth0",
			LocalEnabled: true,
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}

	resetCmdFlags(configShowCmd)
	out := captureStdout(t, func() {
		if err := configShowCmd.RunE(configShowCmd, nil); err != nil {
			t.Fatalf("config show failed: %v", err)
		}
	})
	var parsedMap map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsedMap); err != nil {
		t.Fatalf("unmarshal config show json: %v\nOutput: %s", err, out)
	}
	if parsedMap["role"] != "gateway" {
		t.Errorf("role = %v, want gateway", parsedMap["role"])
	}

	// 3. Staging not found error
	resetCmdFlags(configShowCmd)
	configShowCmd.Flags().Set("staging", "true")
	err = configShowCmd.RunE(configShowCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "No staging config found.") {
		t.Fatalf("expected no staging error, got: %v", err)
	}

	// 4. Staging show
	stagedCfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	if err := stagedCfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}
	resetCmdFlags(configShowCmd)
	configShowCmd.Flags().Set("staging", "true")
	out = captureStdout(t, func() {
		if err := configShowCmd.RunE(configShowCmd, nil); err != nil {
			t.Fatalf("config show -s failed: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(out), &parsedMap); err != nil {
		t.Fatalf("unmarshal config show -s json: %v", err)
	}
	if parsedMap["role"] != "server" {
		t.Errorf("role = %v, want server", parsedMap["role"])
	}

	// 5. Filter section
	resetCmdFlags(configShowCmd)
	configShowCmd.Flags().Set("filter", "gateway")
	out = captureStdout(t, func() {
		if err := configShowCmd.RunE(configShowCmd, nil); err != nil {
			t.Fatalf("config show -f gateway failed: %v", err)
		}
	})
	var gwConfig config.GatewayConfig
	if err := json.Unmarshal([]byte(out), &gwConfig); err != nil {
		t.Fatalf("unmarshal filter section json: %v\nOutput: %s", err, out)
	}
	if gwConfig.Mode != "tun" || gwConfig.LANInterface != "eth0" || !gwConfig.LocalEnabled {
		t.Errorf("unexpected gateway section content: %+v", gwConfig)
	}

	// 6. Filter nonexistent section
	resetCmdFlags(configShowCmd)
	configShowCmd.Flags().Set("filter", "non_existent_section")
	err = configShowCmd.RunE(configShowCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "not found in configuration") {
		t.Fatalf("expected not found error for nonexistent filter, got: %v", err)
	}

	// 7. Raw output
	resetCmdFlags(configShowCmd)
	configShowCmd.Flags().Set("raw", "true")
	out = captureStdout(t, func() {
		if err := configShowCmd.RunE(configShowCmd, nil); err != nil {
			t.Fatalf("config show -r failed: %v", err)
		}
	})
	activeRaw, _ := os.ReadFile(config.GetConfigPathEx(false))
	if strings.TrimSpace(out) != strings.TrimSpace(string(activeRaw)) {
		t.Errorf("raw output did not match file content")
	}
}

func TestConfigUpgradeUpgradesEndpointsAndGateURL(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configPath := filepath.Join(tmpHome, ".config", "xray-proxya", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	legacyJSON := `{"role":"server","address_node":"old-node.example.com","address_sub":"https://old-sub.example.com"}`
	if err := os.WriteFile(configPath, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configUpgradeStaging = false
	configUpgradeDryRun = false
	t.Cleanup(func() {
		configUpgradeStaging = false
		configUpgradeDryRun = false
	})

	_ = captureStdout(t, func() {
		configUpgradeCmd.Run(configUpgradeCmd, nil)
	})

	upgraded, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if upgraded.GateURL != "https://old-sub.example.com" {
		t.Errorf("GateURL = %q, want https://old-sub.example.com", upgraded.GateURL)
	}
	ep, ok := upgraded.Endpoints["default"]
	if !ok {
		t.Fatal("missing default endpoint in upgraded config")
	}
	if ep.Type != config.EndpointTypeStatic || ep.Host != "old-node.example.com" {
		t.Errorf("ep = %+v, want static old-node.example.com", ep)
	}
}


