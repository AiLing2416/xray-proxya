package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	origApply := applyPendingFunc
	defer func() {
		applyPendingFunc = origApply
	}()
	applyPendingFunc = func(opts applyops.Options) ([]string, error) {
		applyCalled = true
		return []string{"applied"}, nil
	}

	if err := gatewayEnableCmd.RunE(gatewayEnableCmd, nil); err != nil {
		t.Fatalf("runGatewayEnable failed: %v", err)
	}
	if applyCalled {
		t.Error("applyPendingFunc called when --now was not set")
	}
	loaded, err := config.LoadConfigEx(true)
	if err != nil || !loaded.Gateway.LocalEnabled || !loaded.Gateway.LANEnabled || loaded.Gateway.State != "proxy" {
		t.Errorf("expected LocalEnabled/LANEnabled true and State proxy, got %+v", loaded.Gateway)
	}

	// 2. Enable with --now
	gatewayEnableCmd.Flags().Set("now", "true")
	if err := gatewayEnableCmd.RunE(gatewayEnableCmd, nil); err != nil {
		t.Fatalf("runGatewayEnable with --now failed: %v", err)
	}
	if !applyCalled {
		t.Error("expected applyPendingFunc to be called with --now")
	}

	// 3. Disable without --now
	applyCalled = false
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
	if err != nil || loaded.Gateway.LocalEnabled || loaded.Gateway.LANEnabled || loaded.Gateway.State != "disabled" {
		t.Errorf("expected LocalEnabled/LANEnabled false and State disabled, got %+v", loaded.Gateway)
	}

	// 4. Disable with --now
	gatewayDisableCmd.Flags().Set("now", "true")
	if err := gatewayDisableCmd.RunE(gatewayDisableCmd, nil); err != nil {
		t.Fatalf("runGatewayDisable with --now failed: %v", err)
	}
	if !applyCalled {
		t.Error("expected applyPendingFunc to be called with --now")
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
			Mode:               "tun",
			LocalEnabled:       true,
			LANEnabled:         true,
			RelayAlias:         "hk-01",
			LANInterface:       "eth0",
			State:              "proxy",
			BypassCountries:    []string{"cn"},
			BypassDNS:          []string{"223.5.5.5"},
			IsolatedInterfaces: []string{"eth2"},
		},
	}
	if err := activeCfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}
	if err := activeCfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	confText := `def zone wan eth0
def zone lan eth1
def zone guest eth2 isolate
local -> hk-01
zone lan -> hk-01
set state proxy
set bypass_countries CN
set bypass_dns 223.5.5.5
`
	_ = os.WriteFile(config.GetGatewayConfPathEx(false), []byte(confText), 0600)
	_ = os.WriteFile(config.GetGatewayConfPathEx(true), []byte(confText), 0600)

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
	if parsed.Active.Relay != "hk-01" || parsed.Active.Interface != "eth1" || parsed.Active.State != "proxy" {
		t.Errorf("unexpected active fields: %+v", parsed.Active)
	}
	if len(parsed.Active.BypassCountries) != 1 || parsed.Active.BypassCountries[0] != "CN" {
		t.Errorf("unexpected active BypassCountries: %+v", parsed.Active.BypassCountries)
	}
	if len(parsed.Active.BypassDNS) != 1 || parsed.Active.BypassDNS[0] != "223.5.5.5" {
		t.Errorf("unexpected active BypassDNS: %+v", parsed.Active.BypassDNS)
	}
	if len(parsed.Active.IsolatedInterfaces) != 1 || parsed.Active.IsolatedInterfaces[0] != "eth2" {
		t.Errorf("unexpected active IsolatedInterfaces: %+v", parsed.Active.IsolatedInterfaces)
	}
	if parsed.Staging == nil || parsed.Staging.Relay != "hk-01" {
		t.Errorf("unexpected staging fields: %+v", parsed.Staging)
	}
	if parsed.Runtime.Problems == nil {
		t.Error("expected runtime.problems to not be nil (must be empty array or filled)")
	}

	// Also verify non-JSON output does not crash and displays Bypass DNS/Geo for ACTIVE
	gatewayStatusCmd.Flags().Set("json", "false")
	humanOut := captureStdout(t, func() {
		if err := gatewayStatusCmd.RunE(gatewayStatusCmd, nil); err != nil {
			t.Fatalf("gatewayStatusCmd.RunE human readable failed: %v", err)
		}
	})
	if !strings.Contains(humanOut, "GATEWAY CONFIGURATION") || !strings.Contains(humanOut, "RUNTIME STATE") {
		t.Errorf("expected human readable headers in output, got: %s", humanOut)
	}
	activeSection := humanOut
	if idx := strings.Index(humanOut, "STAGING:"); idx != -1 {
		activeSection = humanOut[:idx]
	}
	if !strings.Contains(activeSection, "Bypass DNS:  223.5.5.5") {
		t.Errorf("expected Bypass DNS in ACTIVE section, got:\n%s", activeSection)
	}
	if !strings.Contains(activeSection, "Bypass Geo:  CN") {
		t.Errorf("expected Bypass Geo in ACTIVE section, got:\n%s", activeSection)
	}
}

func TestProxyNodeExitConfigurationSuite(t *testing.T) {
	setupTestConfigDir(t)

	// Verify ProxyNode.txt links can be parsed and configured as relays for gateway
	proxyNodePath := filepath.Join("..", "..", "ProxyNode.txt")
	data, err := os.ReadFile(proxyNodePath)
	if err != nil {
		t.Skipf("ProxyNode.txt not found at %s, skipping test: %v", proxyNodePath, err)
		return
	}

	lines := strings.Split(string(data), "\n")
	var nodeLinks []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			nodeLinks = append(nodeLinks, l)
		}
	}
	if len(nodeLinks) < 2 {
		t.Fatalf("expected at least 2 proxy nodes in ProxyNode.txt, found %d", len(nodeLinks))
	}

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			State:        "proxy",
			LocalEnabled: true,
			LANEnabled:   true,
			LANInterface: "eth0",
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save initial staging config: %v", err)
	}

	// 1. Add JP-TK
	if err := addOutboundCmd.RunE(addOutboundCmd, []string{nodeLinks[0]}); err != nil {
		t.Fatalf("failed to add JP-TK relay node: %v", err)
	}

	// 2. Add DE-LM
	if err := addOutboundCmd.RunE(addOutboundCmd, []string{nodeLinks[1]}); err != nil {
		t.Fatalf("failed to add DE-LM relay node: %v", err)
	}

	// Verify both nodes are staged
	stagedCfg, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("failed to load staging config: %v", err)
	}
	if len(stagedCfg.CustomOutbounds) < 2 {
		t.Fatalf("expected at least 2 custom outbounds, got %d", len(stagedCfg.CustomOutbounds))
	}

	// 3. Bind gateway to JP-TK
	gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewaySetCmd.ParseFlags([]string{"--relay", "JP-TK", "--state", "proxy", "--local-enable"}); err != nil {
		t.Fatalf("failed to parse gateway set flags: %v", err)
	}
	if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err != nil {
		t.Fatalf("failed to set gateway relay to JP-TK: %v", err)
	}

	stagedCfg, _ = config.LoadConfigEx(true)
	if stagedCfg.Gateway.RelayAlias != "JP-TK" {
		t.Errorf("expected gateway relay alias JP-TK, got %s", stagedCfg.Gateway.RelayAlias)
	}

	// 4. Switch gateway to DE-LM
	gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewaySetCmd.ParseFlags([]string{"--relay", "DE-LM"}); err != nil {
		t.Fatalf("failed to parse gateway set flags: %v", err)
	}
	if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err != nil {
		t.Fatalf("failed to switch gateway relay to DE-LM: %v", err)
	}

	stagedCfg, _ = config.LoadConfigEx(true)
	if stagedCfg.Gateway.RelayAlias != "DE-LM" {
		t.Errorf("expected gateway relay alias DE-LM, got %s", stagedCfg.Gateway.RelayAlias)
	}
}

func TestGatewayFull6StateMatrixConfiguration(t *testing.T) {
	setupTestConfigDir(t)

	// Verify all 6 states in the state matrix can be configured and validated
	states := []struct {
		name      string
		args      []string
		wantState string
		wantLocal bool
		wantLAN   bool
	}{
		{
			name:      "Case 1: disabled",
			args:      []string{"--state", "disabled", "--no-local", "--no-lan"},
			wantState: "disabled",
			wantLocal: false,
			wantLAN:   false,
		},
		{
			name:      "Case 2: forward-only local-only",
			args:      []string{"--state", "forward-only", "--local", "--no-lan"},
			wantState: "forward-only",
			wantLocal: true,
			wantLAN:   false,
		},
		{
			name:      "Case 3: forward-only lan-only",
			args:      []string{"--state", "forward-only", "--no-local", "--lan"},
			wantState: "forward-only",
			wantLocal: false,
			wantLAN:   true,
		},
		{
			name:      "Case 4: proxy local-only",
			args:      []string{"--state", "proxy", "--local", "--no-lan"},
			wantState: "proxy",
			wantLocal: true,
			wantLAN:   false,
		},
		{
			name:      "Case 5: proxy lan-only",
			args:      []string{"--state", "proxy", "--no-local", "--lan"},
			wantState: "proxy",
			wantLocal: false,
			wantLAN:   true,
		},
		{
			name:      "Case 6: proxy dual",
			args:      []string{"--state", "proxy", "--local", "--lan"},
			wantState: "proxy",
			wantLocal: true,
			wantLAN:   true,
		},
	}

	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.UserConfig{
				Role: config.RoleGateway,
				Gateway: config.GatewayConfig{
					Mode:         "tun",
					LANInterface: "ens18",
				},
			}
			if err := cfg.SaveEx(true); err != nil {
				t.Fatalf("save staging config: %v", err)
			}
			gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			})
			if err := gatewaySetCmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags error for %v: %v", tc.args, err)
			}
			if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err != nil {
				t.Fatalf("RunE error: %v", err)
			}
			updated, err := config.LoadConfigEx(true)
			if err != nil {
				t.Fatalf("load staging config: %v", err)
			}
			if updated.Gateway.State != tc.wantState {
				t.Errorf("State = %s, want %s", updated.Gateway.State, tc.wantState)
			}
			if updated.Gateway.LocalEnabled != tc.wantLocal {
				t.Errorf("LocalEnabled = %v, want %v", updated.Gateway.LocalEnabled, tc.wantLocal)
			}
			if updated.Gateway.LANEnabled != tc.wantLAN {
				t.Errorf("LANEnabled = %v, want %v", updated.Gateway.LANEnabled, tc.wantLAN)
			}
		})
	}
}

func TestGatewaySetPositionalRelay(t *testing.T) {
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

	if err := gatewaySetCmd.RunE(gatewaySetCmd, []string{"my-positional-relay"}); err != nil {
		t.Fatalf("gatewaySetCmd with positional relay failed: %v", err)
	}

	updated, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("LoadConfigEx error: %v", err)
	}
	if updated.Gateway.RelayAlias != "my-positional-relay" {
		t.Fatalf("expected RelayAlias 'my-positional-relay', got %q", updated.Gateway.RelayAlias)
	}
}

func TestGatewaySetModeFlag(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tproxy",
			LocalEnabled: true,
			LANEnabled:   true,
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	// 1. Set mode tun
	gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewaySetCmd.ParseFlags([]string{"--mode", "tun"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err != nil {
		t.Fatalf("RunE error: %v", err)
	}
	updated, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staging config: %v", err)
	}
	if updated.Gateway.Mode != "tun" {
		t.Fatalf("Mode = %q, want tun", updated.Gateway.Mode)
	}

	// 2. Set mode tproxy
	gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewaySetCmd.ParseFlags([]string{"--mode", "tproxy"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err != nil {
		t.Fatalf("RunE error: %v", err)
	}
	updated, err = config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staging config: %v", err)
	}
	if updated.Gateway.Mode != "tproxy" {
		t.Fatalf("Mode = %q, want tproxy", updated.Gateway.Mode)
	}

	// 3. Set invalid mode
	gatewaySetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewaySetCmd.ParseFlags([]string{"--mode", "badmode"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	if err := gatewaySetCmd.RunE(gatewaySetCmd, nil); err == nil {
		t.Fatal("expected error for invalid mode badmode, got nil")
	}
}

func TestGatewayExportCmd(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:          "tproxy",
			WANInterface:  "eth0",
			LANInterfaces: []string{"eth1", "eth2"},
			LocalEnabled:  true,
			LANEnabled:    true,
			RelayAlias:    "relay-hk",
			Rules: []config.GatewayRule{
				{MAC: "52:54:00:84:00:11", Target: "direct"},
			},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-hk", Enabled: true},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}

	// 1. Export with --write
	gatewayExportCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewayExportCmd.ParseFlags([]string{"--write"}); err != nil {
		t.Fatalf("ParseFlags --write: %v", err)
	}
	if err := gatewayExportCmd.RunE(gatewayExportCmd, nil); err != nil {
		t.Fatalf("gateway export --write error: %v", err)
	}

	confPath := config.GetGatewayConfPath()
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("failed to read written gateway.conf: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "def zone wan eth0") || !strings.Contains(content, "52:54:00:84:00:11") {
		t.Errorf("exported content missing expected lines:\n%s", content)
	}

	// 2. Export to custom file path argument
	outFile := filepath.Join(t.TempDir(), "custom_gw.conf")
	gatewayExportCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := gatewayExportCmd.RunE(gatewayExportCmd, []string{outFile}); err != nil {
		t.Fatalf("gateway export <file> error: %v", err)
	}
	outData, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read exported file: %v", err)
	}
	if !strings.Contains(string(outData), "relay-hk") {
		t.Errorf("custom exported file missing relay-hk:\n%s", string(outData))
	}
}

func TestGatewayEditCmd(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:          "tproxy",
			WANInterface:  "eth0",
			LANInterfaces: []string{"eth1"},
			LocalEnabled:  true,
			LANEnabled:    true,
			RelayAlias:    "relay-hk",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-hk", Enabled: true},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}

	// Use 'true' as a dummy editor that exits 0 immediately without error
	t.Setenv("EDITOR", "true")

	if err := gatewayEditCmd.RunE(gatewayEditCmd, nil); err != nil {
		t.Fatalf("gateway edit with dummy editor error: %v", err)
	}

	// Confirm gateway.conf was created and valid
	confPath := config.GetGatewayConfPath()
	if !config.GatewayConfExists() {
		t.Fatalf("expected %s to exist after edit", confPath)
	}
}



