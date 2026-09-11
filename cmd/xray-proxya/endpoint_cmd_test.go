package main

import (
	"encoding/json"
	"strings"
	"testing"

	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

func resetEndpointFlags(cmd *cobra.Command) {
	for _, name := range []string{"host", "auto", "v4", "v6"} {
		if f := cmd.Flags().Lookup(name); f != nil {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		}
	}
	endpointSetHost = ""
	endpointSetAuto = false
	endpointSetV4 = false
	endpointSetV6 = false
}

func TestEndpointSetStatic(t *testing.T) {
	setupTestConfigDir(t)
	cmd := endpointSetCmd
	resetEndpointFlags(cmd)
	defer resetEndpointFlags(cmd)

	cfg := &config.UserConfig{Role: config.RoleServer}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	_ = cmd.Flags().Set("host", "test.example.com")

	err := cmd.RunE(cmd, []string{"my-domain"})
	if err != nil {
		t.Fatalf("endpoint set failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	ep, ok := loaded.Endpoints["my-domain"]
	if !ok {
		t.Fatalf("expected endpoint 'my-domain' in staging")
	}
	if ep.Type != config.EndpointTypeStatic || ep.Host != "test.example.com" {
		t.Fatalf("unexpected ep content: %+v", ep)
	}
}

func TestEndpointSetAutoV6(t *testing.T) {
	setupTestConfigDir(t)
	cmd := endpointSetCmd
	resetEndpointFlags(cmd)
	defer resetEndpointFlags(cmd)

	cfg := &config.UserConfig{Role: config.RoleServer}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	_ = cmd.Flags().Set("auto", "true")
	_ = cmd.Flags().Set("v6", "true")

	err := cmd.RunE(cmd, []string{"my-auto"})
	if err != nil {
		t.Fatalf("endpoint set failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	ep, ok := loaded.Endpoints["my-auto"]
	if !ok {
		t.Fatalf("expected endpoint 'my-auto' in staging")
	}
	if ep.Type != config.EndpointTypeAuto || ep.Family != "v6" {
		t.Fatalf("unexpected ep content: %+v", ep)
	}
}

func TestEndpointSetValidation(t *testing.T) {
	setupTestConfigDir(t)
	cmd := endpointSetCmd
	resetEndpointFlags(cmd)
	defer resetEndpointFlags(cmd)

	cfg := &config.UserConfig{Role: config.RoleServer}
	_ = cfg.SaveEx(true)

	// 1. No parameter supplied
	err := cmd.RunE(cmd, []string{"foo"})
	if err == nil || !strings.Contains(err.Error(), "No parameter supplied") {
		t.Fatalf("expected 'No parameter supplied' error, got: %v", err)
	}

	// 2. Both host and auto
	resetEndpointFlags(cmd)
	_ = cmd.Flags().Set("host", "example.com")
	_ = cmd.Flags().Set("auto", "true")

	err = cmd.RunE(cmd, []string{"bar"})
	if err == nil || !strings.Contains(err.Error(), "Cannot specify both --host and --auto") {
		t.Fatalf("expected 'Cannot specify both --host and --auto' error, got: %v", err)
	}
}

func TestEndpointListJSON(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type:   config.EndpointTypeAuto,
				Family: "v4",
			},
			"hk-node": {
				Type: config.EndpointTypeStatic,
				Host: "hk.example.com",
			},
		},
		Guests: []config.GuestConfig{
			{Alias: "alice", Endpoint: "hk-node"},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	endpointListJSON = true
	defer func() { endpointListJSON = false }()

	out := captureStdout(t, func() {
		err := endpointListCmd.RunE(endpointListCmd, []string{})
		if err != nil {
			t.Fatalf("endpoint list failed: %v", err)
		}
	})

	var views []EndpointListView
	if err := json.Unmarshal([]byte(out), &views); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v\nOutput: %s", err, out)
	}
	if len(views) != 2 {
		t.Fatalf("expected 2 endpoints in JSON, got %d", len(views))
	}
	foundHK := false
	for _, v := range views {
		if v.Name == "hk-node" {
			foundHK = true
			if len(v.References) != 1 || v.References[0] != "guest:alice" {
				t.Fatalf("unexpected references for hk-node: %v", v.References)
			}
		}
	}
	if !foundHK {
		t.Fatalf("hk-node not found in JSON views")
	}
}

func TestEndpointRemoveAndDefaultProtection(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type:   config.EndpointTypeAuto,
				Family: "v4",
			},
			"custom": {
				Type: config.EndpointTypeStatic,
				Host: "custom.example.com",
			},
		},
		Guests: []config.GuestConfig{
			{Alias: "bob", Endpoint: "custom"},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	// 1. Try removing default -> must fail
	err := endpointRemoveCmd.RunE(endpointRemoveCmd, []string{"default"})
	if err == nil || !strings.Contains(err.Error(), "Cannot delete reserved 'default' endpoint") {
		t.Fatalf("expected error deleting default endpoint, got: %v", err)
	}

	// 2. Remove custom with warning
	out := captureStdout(t, func() {
		err := endpointRemoveCmd.RunE(endpointRemoveCmd, []string{"custom"})
		if err != nil {
			t.Fatalf("failed to remove custom endpoint: %v", err)
		}
	})
	if !strings.Contains(out, "Warning: Endpoint 'custom' is currently referenced") {
		t.Fatalf("expected warning for referenced endpoint, got: %s", out)
	}

	// Verify custom is gone
	loaded, _ := config.LoadConfigEx(true)
	if _, ok := loaded.Endpoints["custom"]; ok {
		t.Fatalf("custom endpoint was not removed from staging")
	}
}

func TestEndpointShow(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type: config.EndpointTypeStatic,
				Host: "show.example.com",
			},
		},
	}
	_ = cfg.SaveEx(true)

	out := captureStdout(t, func() {
		err := endpointShowCmd.RunE(endpointShowCmd, []string{"default"})
		if err != nil {
			t.Fatalf("endpoint show failed: %v", err)
		}
	})
	if !strings.Contains(out, "show.example.com") {
		t.Fatalf("expected show.example.com in output, got: %s", out)
	}
}

func TestEndpointCompletion(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"default": {Type: config.EndpointTypeAuto, Family: "v4"},
			"node-a":  {Type: config.EndpointTypeStatic, Host: "a.com"},
		},
	}
	_ = cfg.SaveEx(true)

	comps, _ := completeEndpointNames(endpointSetCmd, nil, "")
	if len(comps) != 2 {
		t.Fatalf("expected 2 completions, got %d: %v", len(comps), comps)
	}
}
