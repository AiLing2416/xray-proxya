package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

func TestListSubcommandsLsAlias(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Guests: []config.GuestConfig{
			{Alias: "g1", Enabled: true},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "r1", Enabled: true, InternalProxyPort: 10808},
		},
		RelaySubs: map[string]string{
			"sub1": "https://example.com/sub",
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("failed to save active config: %v", err)
	}

	tests := []struct {
		name        string
		args        []string
		expectedCmd string
	}{
		{"guests ls", []string{"guests", "ls"}, "list"},
		{"relay ls", []string{"relay", "ls"}, "list"},
		{"proxy ls", []string{"proxy", "ls"}, "list"},
		{"relay sub ls", []string{"relay", "sub", "ls"}, "list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetCmd, _, err := rootCmd.Find(tt.args)
			if err != nil {
				t.Fatalf("Find(%v) returned error: %v", tt.args, err)
			}
			if targetCmd.Name() != tt.expectedCmd {
				t.Fatalf("Find(%v) got command %q, want %q", tt.args, targetCmd.Name(), tt.expectedCmd)
			}

			// Verify ls is in Aliases
			hasLs := false
			for _, alias := range targetCmd.Aliases {
				if alias == "ls" {
					hasLs = true
					break
				}
			}
			if !hasLs {
				t.Fatalf("command %q does not contain 'ls' in Aliases: %v", targetCmd.Name(), targetCmd.Aliases)
			}

			// Run command directly and ensure it does not error or panic
			buf := new(bytes.Buffer)
			targetCmd.SetOut(buf)
			targetCmd.SetErr(buf)
			if targetCmd.RunE != nil {
				if err := targetCmd.RunE(targetCmd, []string{}); err != nil {
					t.Fatalf("RunE(%v) returned error: %v", tt.args, err)
				}
			} else {
				targetCmd.Run(targetCmd, []string{})
			}
		})
	}
}

func TestStandardizedCommandsAndFlags(t *testing.T) {
	if guestsInfoCmd.Use != "show <alias>" || !slices.Contains(guestsInfoCmd.Aliases, "info") {
		t.Errorf("guestsInfoCmd Use=%q Aliases=%v, want Use='show <alias>' and 'info' alias", guestsInfoCmd.Use, guestsInfoCmd.Aliases)
	}
	if slices.Contains(configShowCmd.Aliases, "view") {
		t.Errorf("configShowCmd.Aliases = %v, should not contain 'view'", configShowCmd.Aliases)
	}
	if !slices.Contains(presetsListCmd.Aliases, "ls") {
		t.Errorf("presetsListCmd.Aliases = %v, want 'ls'", presetsListCmd.Aliases)
	}
	if !slices.Contains(tuneProfilesCmd.Aliases, "list") || !slices.Contains(tuneProfilesCmd.Aliases, "ls") {
		t.Errorf("tuneProfilesCmd.Aliases = %v, want 'list' and 'ls'", tuneProfilesCmd.Aliases)
	}
	if purgeCmd.Use != "purge" {
		t.Errorf("purgeCmd.Use = %q, want 'purge'", purgeCmd.Use)
	}
	if !strings.HasSuffix(outboundCmd.Short, "(STAGING)") || !strings.HasSuffix(bindInterfaceCmd.Short, "(STAGING)") {
		t.Errorf("relay staging Short mismatch: outbound=%q bind=%q", outboundCmd.Short, bindInterfaceCmd.Short)
	}
	for _, cmd := range []*cobra.Command{guestsListCmd, testOutboundCmd, infoOutboundCmd, speedOutboundCmd, endpointListCmd} {
		f := cmd.Flags().Lookup("json")
		if f == nil {
			t.Fatalf("%s missing --json flag", cmd.Name())
		}
		if f.Shorthand != "" {
			t.Errorf("%s --json shorthand = %q, want empty", cmd.Name(), f.Shorthand)
		}
	}
}
