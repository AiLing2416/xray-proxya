package main

import (
	"bytes"
	"testing"
	"xray-proxya/internal/config"
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
			targetCmd.Run(targetCmd, []string{})
		})
	}
}
