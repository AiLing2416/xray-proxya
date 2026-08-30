package main

import (
	"testing"
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
				f.Changed = false
				_ = f.Value.Set(f.DefValue)
			})

			if err := gatewaySetCmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags error: %v", err)
			}
			gatewaySetCmd.Run(gatewaySetCmd, nil)

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
