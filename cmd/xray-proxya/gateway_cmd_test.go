package main

import (
	"encoding/json"
	"strings"
	"testing"
	"xray-proxya/internal/applyops"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestGatewayCommandRejectsUnexpectedArguments(t *testing.T) {
	if err := gatewayCmd.Args(gatewayCmd, []string{"lan", "disable"}); err == nil {
		t.Fatal("gateway command accepted unexpected arguments")
	}
	if err := gatewayCmd.Args(gatewayCmd, nil); err != nil {
		t.Fatalf("gateway command rejected no arguments: %v", err)
	}
}

var _ cobra.PositionalArgs = gatewayCmd.Args

func TestGatewayRemovedSubcommands(t *testing.T) {
	removed := []string{
		"local-enable",
		"local-disable",
		"lan-enable",
		"lan-disable",
		"apply",
		"sync-firewall",
		"rollback",
		"verify",
	}

	for _, name := range removed {
		cmd, _, _ := gatewayCmd.Find([]string{name})
		if cmd != nil && cmd != gatewayCmd && cmd.Name() == name {
			t.Errorf("expected subcommand %q to be removed from gatewayCmd", name)
		}
	}
}

func TestGatewaySetFlagsLanLocalEnableDisable(t *testing.T) {
	setupTestConfigDir(t)

	testCases := []struct {
		name      string
		args      []string
		initLocal bool
		initLAN   bool
		wantLocal bool
		wantLAN   bool
	}{
		{
			name:      "enable LAN",
			args:      []string{"--lan-enable"},
			initLAN:   false,
			wantLAN:   true,
			initLocal: false,
			wantLocal: false,
		},
		{
			name:      "disable LAN",
			args:      []string{"--lan-disable"},
			initLAN:   true,
			wantLAN:   false,
			initLocal: false,
			wantLocal: false,
		},
		{
			name:      "enable Local",
			args:      []string{"--local-enable"},
			initLocal: false,
			wantLocal: true,
			initLAN:   false,
			wantLAN:   false,
		},
		{
			name:      "disable Local",
			args:      []string{"--local-disable"},
			initLocal: true,
			wantLocal: false,
			initLAN:   false,
			wantLAN:   false,
		},
		{
			name:      "enable both",
			args:      []string{"--lan-enable", "--local-enable"},
			initLAN:   false,
			initLocal: false,
			wantLAN:   true,
			wantLocal: true,
		},
		{
			name:      "concise enable LAN",
			args:      []string{"--lan"},
			initLAN:   false,
			wantLAN:   true,
			initLocal: false,
			wantLocal: false,
		},
		{
			name:      "concise disable LAN",
			args:      []string{"--no-lan"},
			initLAN:   true,
			wantLAN:   false,
			initLocal: false,
			wantLocal: false,
		},
		{
			name:      "concise enable Local",
			args:      []string{"--local"},
			initLocal: false,
			wantLocal: true,
			initLAN:   false,
			wantLAN:   false,
		},
		{
			name:      "concise disable Local",
			args:      []string{"--no-local"},
			initLocal: true,
			wantLocal: false,
			initLAN:   false,
			wantLAN:   false,
		},
		{
			name:      "concise enable both",
			args:      []string{"--lan", "--local"},
			initLAN:   false,
			initLocal: false,
			wantLAN:   true,
			wantLocal: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.UserConfig{
				Role: config.RoleGateway,
				Gateway: config.GatewayConfig{
					Mode:         "tun",
					LocalEnabled: tc.initLocal,
					LANEnabled:   tc.initLAN,
				},
			}
			if err := cfg.SaveEx(true); err != nil {
				t.Fatalf("save staging config: %v", err)
			}

			// Reset flags before parsing
			gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			})

			if err := gatewaySetCmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags error: %v", err)
			}
			if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err != nil {
				t.Fatalf("RunE error: %v", err)
			}

			updated, err := config.LoadConfigEx(true)
			if err != nil {
				t.Fatalf("load staging config: %v", err)
			}
			if updated.Gateway.LANEnabled != tc.wantLAN {
				t.Errorf("LANEnabled = %v, want %v", updated.Gateway.LANEnabled, tc.wantLAN)
			}
			if updated.Gateway.LocalEnabled != tc.wantLocal {
				t.Errorf("LocalEnabled = %v, want %v", updated.Gateway.LocalEnabled, tc.wantLocal)
			}
		})
	}
}

func TestGatewaySetEmptyFlagsError(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode: "tun",
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})

	err := gatewaySetCmd.RunE(gatewaySetCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "No parameter supplied") {
		t.Fatalf("expected 'No parameter supplied' error, got %v", err)
	}
}

func TestGatewaySetConflictingFlagsError(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode: "tun",
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	conflictCases := [][]string{
		{"--lan", "--no-lan"},
		{"--lan-enable", "--lan-disable"},
		{"--lan", "--lan-disable"},
		{"--local", "--no-local"},
		{"--local-enable", "--local-disable"},
		{"--local", "--local-disable"},
	}

	for _, args := range conflictCases {
		gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
		if err := gatewaySetCmd.ParseFlags(args); err != nil {
			t.Fatalf("ParseFlags error for %v: %v", args, err)
		}
		err := gatewaySetCmd.RunE(gatewaySetCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "Conflicting flags specified") {
			t.Errorf("args %v: expected 'Conflicting flags specified' error, got %v", args, err)
		}
	}
}

func TestGatewayEnableDisableNowFlags(t *testing.T) {
	setupTestConfigDir(t)

	// Verify flags registered
	if f := gatewayEnableCmd.Flags().Lookup("now"); f == nil {
		t.Fatal("expected --now flag on gateway enable")
	} else if f.DefValue != "false" {
		t.Fatalf("expected defValue 'false', got %q", f.DefValue)
	}

	if f := gatewayDisableCmd.Flags().Lookup("now"); f == nil {
		t.Fatal("expected --now flag on gateway disable")
	} else if f.DefValue != "false" {
		t.Fatalf("expected defValue 'false', got %q", f.DefValue)
	}

	// 1. Enable without --now
	initCfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tun",
			LocalEnabled: false,
			LANEnabled:   false,
		},
	}
	if err := initCfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	gatewayEnableCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	applyCalled := false
	mgmtOp := ""
	origApply := applyPendingFunc
	origMgmt := runGatewayManagementFunc
	defer func() {
		applyPendingFunc = origApply
		runGatewayManagementFunc = origMgmt
	}()
	applyPendingFunc = func(opts applyops.Options) ([]string, error) {
		applyCalled = true
		return []string{"applied"}, nil
	}
	runGatewayManagementFunc = func(op string) error {
		mgmtOp = op
		return nil
	}

	if err := gatewayEnableCmd.RunE(gatewayEnableCmd, nil); err != nil {
		t.Fatalf("runGatewayEnable failed: %v", err)
	}
	if applyCalled {
		t.Error("applyPendingFunc called when --now was not set")
	}
	loaded, err := config.LoadConfigEx(true)
	if err != nil || !loaded.Gateway.LocalEnabled || !loaded.Gateway.LANEnabled {
		t.Errorf("expected LocalEnabled and LANEnabled to be true, got %+v", loaded.Gateway)
	}

	// 2. Enable with --now
	gatewayEnableCmd.Flags().Set("now", "true")
	if err := gatewayEnableCmd.RunE(gatewayEnableCmd, nil); err != nil {
		t.Fatalf("runGatewayEnable with --now failed: %v", err)
	}
	if !applyCalled {
		t.Error("expected applyPendingFunc to be called with --now")
	}
	if mgmtOp != "system-up" {
		t.Errorf("expected mgmtOp 'system-up', got %q", mgmtOp)
	}

	// 3. Disable without --now
	applyCalled = false
	mgmtOp = ""
	gatewayDisableCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewayDisableCmd.RunE(gatewayDisableCmd, nil); err != nil {
		t.Fatalf("runGatewayDisable failed: %v", err)
	}
	if applyCalled {
		t.Error("applyPendingFunc called when --now was not set")
	}
	loaded, err = config.LoadConfigEx(true)
	if err != nil || loaded.Gateway.LocalEnabled || loaded.Gateway.LANEnabled {
		t.Errorf("expected LocalEnabled and LANEnabled to be false, got %+v", loaded.Gateway)
	}

	// 4. Disable with --now
	gatewayDisableCmd.Flags().Set("now", "true")
	if err := gatewayDisableCmd.RunE(gatewayDisableCmd, nil); err != nil {
		t.Fatalf("runGatewayDisable with --now failed: %v", err)
	}
	if !applyCalled {
		t.Error("expected applyPendingFunc to be called with --now")
	}
	if mgmtOp != "system-down" {
		t.Errorf("expected mgmtOp 'system-down', got %q", mgmtOp)
	}
}

func TestGatewayStatusJSON(t *testing.T) {
	setupTestConfigDir(t)

	if f := gatewayStatusCmd.Flags().Lookup("json"); f == nil {
		t.Fatal("expected --json flag on gateway status")
	}

	activeCfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tun",
			LocalEnabled: true,
			LANEnabled:   true,
			RelayAlias:   "hk-01",
			LANInterface: "eth0",
			State:        "proxy",
		},
	}
	if err := activeCfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}
	if err := activeCfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	gatewayStatusCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	gatewayStatusCmd.Flags().Set("json", "true")
	defer func() {
		gatewayStatusCmd.Flags().Set("json", "false")
	}()

	out := captureStdout(t, func() {
		if err := gatewayStatusCmd.RunE(gatewayStatusCmd, nil); err != nil {
			t.Fatalf("gatewayStatusCmd.RunE failed: %v", err)
		}
	})

	var parsed GatewayStatusJSON
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v\nOutput was: %s", err, out)
	}

	if parsed.Active == nil || !parsed.Active.LocalEnabled || !parsed.Active.LANEnabled {
		t.Errorf("unexpected active config: %+v", parsed.Active)
	}
	if parsed.Active.Relay != "hk-01" || parsed.Active.Interface != "eth0" || parsed.Active.State != "proxy" {
		t.Errorf("unexpected active fields: %+v", parsed.Active)
	}
	if parsed.Staging == nil || parsed.Staging.Relay != "hk-01" {
		t.Errorf("unexpected staging fields: %+v", parsed.Staging)
	}
	if parsed.Runtime.Problems == nil {
		t.Error("expected runtime.problems to not be nil (must be empty array or filled)")
	}

	// Also verify non-JSON output does not crash
	gatewayStatusCmd.Flags().Set("json", "false")
	humanOut := captureStdout(t, func() {
		if err := gatewayStatusCmd.RunE(gatewayStatusCmd, nil); err != nil {
			t.Fatalf("gatewayStatusCmd.RunE human readable failed: %v", err)
		}
	})
	if !strings.Contains(humanOut, "GATEWAY CONFIGURATION") || !strings.Contains(humanOut, "RUNTIME STATE") {
		t.Errorf("expected human readable headers in output, got: %s", humanOut)
	}
}

