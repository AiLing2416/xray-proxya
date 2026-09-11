package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/endpoint"

	"github.com/spf13/cobra"
)

func resetEndpointFlags(cmd *cobra.Command) {
	for _, name := range []string{"host", "auto", "v4", "v6", "type", "subnet", "interface", "max", "ndp", "no-ndp", "profile", "ttl"} {
		if f := cmd.Flags().Lookup(name); f != nil {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		}
	}
	endpointSetHost = ""
	endpointSetAuto = false
	endpointSetV4 = false
	endpointSetV6 = false
	endpointSetType = ""
	endpointSetSubnet = ""
	endpointSetInterface = ""
	endpointSetMax = 6
	endpointSetNDP = false
	endpointSetNoNDP = false
	endpointSetProfile = ""
	endpointSetTTL = ""
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

func TestEndpointList_DynamicV6_TextOutput(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"he-pool": {
				Type:         config.EndpointTypeDynamicV6,
				Subnet:       "2001:470:1f0a:692::/64",
				Interface:    "he-ipv6",
				MaxAddresses: 6,
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	// Populate rotation state with a known address
	mockState := endpoint.RotationState{
		ActivePool: []endpoint.AddressEntry{
			{Address: "2001:470:1f0a:692:a7d7:2136:b3b0:11ea", State: "active"},
		},
	}
	_ = endpoint.SaveRotationState("he-pool", &mockState)

	out := captureStdout(t, func() {
		err := endpointListCmd.RunE(endpointListCmd, []string{})
		if err != nil {
			t.Fatalf("endpoint list failed: %v", err)
		}
	})

	if !strings.Contains(out, "2001:470:1f0a:692::/64") {
		t.Errorf("expected subnet '2001:470:1f0a:692::/64' in TARGET column, got: %s", out)
	}
	if !strings.Contains(out, "::a7d7:2136:b3b0:11ea") {
		t.Errorf("expected shortened rotatable IPv6 '::a7d7:2136:b3b0:11ea' in RESOLVED column, got: %s", out)
	}
	if strings.Contains(out, "dynamic-v6 (2001:470:1f0a:692::/64)") {
		t.Errorf("found redundant 'dynamic-v6 (2001:470...)' in TARGET column: %s", out)
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

func TestEndpointSetShorthandHViaRootCmd(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{Role: config.RoleServer}
	_ = cfg.SaveEx(true)

	rootCmd.SetArgs([]string{"endpoint", "set", "default", "-h", "hk.example.com"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	ep, ok := loaded.Endpoints["default"]
	if !ok {
		t.Fatalf("expected default endpoint")
	}
	if ep.Host != "hk.example.com" || ep.Type != config.EndpointTypeStatic {
		t.Fatalf("unexpected default endpoint: %+v", ep)
	}
}

func TestEndpointSetDynamicV6(t *testing.T) {
	setupTestConfigDir(t)
	cmd := endpointSetCmd
	resetEndpointFlags(cmd)
	defer resetEndpointFlags(cmd)

	cfg := &config.UserConfig{Role: config.RoleServer}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	_ = cmd.Flags().Set("type", "dynamic-v6")
	_ = cmd.Flags().Set("subnet", "2001:470:1f0b:692::/64")
	_ = cmd.Flags().Set("interface", "he-ipv6")
	_ = cmd.Flags().Set("max", "8")

	err := cmd.RunE(cmd, []string{"he-pool"})
	if err != nil {
		t.Fatalf("endpoint set dynamic-v6 failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	ep, ok := loaded.Endpoints["he-pool"]
	if !ok {
		t.Fatalf("expected endpoint 'he-pool' in staging")
	}
	if ep.Type != config.EndpointTypeDynamicV6 {
		t.Errorf("expected type dynamic-v6, got %s", ep.Type)
	}
	if ep.Subnet != "2001:470:1f0b:692::/64" {
		t.Errorf("expected subnet 2001:470:1f0b:692::/64, got %s", ep.Subnet)
	}
	if ep.Interface != "he-ipv6" {
		t.Errorf("expected interface he-ipv6, got %s", ep.Interface)
	}
	if ep.MaxAddresses != 8 {
		t.Errorf("expected max 8, got %d", ep.MaxAddresses)
	}
	if ep.EnableNDP {
		t.Errorf("expected EnableNDP to be false for he-ipv6 interface")
	}
}

func TestEndpointSetDynamicV6_AutoNDP(t *testing.T) {
	setupTestConfigDir(t)
	cmd := endpointSetCmd

	// Test 1: eth0 interface defaults to EnableNDP=true
	resetEndpointFlags(cmd)
	defer resetEndpointFlags(cmd)

	cfg := &config.UserConfig{Role: config.RoleServer}
	_ = cfg.SaveEx(true)

	_ = cmd.Flags().Set("type", "dynamic-v6")
	_ = cmd.Flags().Set("subnet", "2001:db8::/64")
	_ = cmd.Flags().Set("interface", "eth0")

	err := cmd.RunE(cmd, []string{"eth-pool"})
	if err != nil {
		t.Fatalf("endpoint set failed: %v", err)
	}

	loaded, _ := config.LoadConfigEx(true)
	if !loaded.Endpoints["eth-pool"].EnableNDP {
		t.Errorf("expected EnableNDP to be true for eth0 interface by default")
	}

	// Test 2: explicit --no-ndp
	resetEndpointFlags(cmd)
	_ = cmd.Flags().Set("type", "dynamic-v6")
	_ = cmd.Flags().Set("subnet", "2001:db8::/64")
	_ = cmd.Flags().Set("interface", "eth0")
	_ = cmd.Flags().Set("no-ndp", "true")

	err = cmd.RunE(cmd, []string{"eth-pool-no-ndp"})
	if err != nil {
		t.Fatalf("endpoint set failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if loaded.Endpoints["eth-pool-no-ndp"].EnableNDP {
		t.Errorf("expected EnableNDP to be false when --no-ndp is set")
	}
}

func TestEndpointShowDynamicV6_TextAndJSON(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"he-pool": {
				Type:         config.EndpointTypeDynamicV6,
				Subnet:       "2001:470:1f0b:692::/64",
				Interface:    "he-ipv6",
				MaxAddresses: 6,
				EnableNDP:    false,
			},
		},
	}
	_ = cfg.SaveEx(true)

	// Populate a mock rotation state file
	mockState := endpoint.RotationState{
		ActivePool: []endpoint.AddressEntry{
			{Address: "2001:470:1f0b:692::1234", State: "active", CreatedAt: time.Now()},
		},
		DeprecatedPool: []endpoint.AddressEntry{
			{Address: "2001:470:1f0b:692::5678", State: "deprecated", CreatedAt: time.Now().Add(-2 * time.Hour), DeprecatedAt: time.Now().Add(-10 * time.Minute)},
		},
	}
	_ = endpoint.SaveRotationState("he-pool", &mockState)

	// 1. Test text output
	out := captureStdout(t, func() {
		err := endpointShowCmd.RunE(endpointShowCmd, []string{"he-pool"})
		if err != nil {
			t.Fatalf("endpoint show failed: %v", err)
		}
	})
	if !strings.Contains(out, "2001:470:1f0b:692::1234") {
		t.Errorf("expected active IP in show output, got: %s", out)
	}
	if !strings.Contains(out, "2001:470:1f0b:692::5678") {
		t.Errorf("expected deprecated IP in show output, got: %s", out)
	}
	if !strings.Contains(out, "Subnet:      2001:470:1f0b:692::/64") {
		t.Errorf("expected subnet in show output, got: %s", out)
	}

	// 2. Test JSON output
	endpointShowJSON = true
	defer func() { endpointShowJSON = false }()

	jsonOut := captureStdout(t, func() {
		err := endpointShowCmd.RunE(endpointShowCmd, []string{"he-pool"})
		if err != nil {
			t.Fatalf("endpoint show --json failed: %v", err)
		}
	})

	var detail EndpointDetailView
	if err := json.Unmarshal([]byte(jsonOut), &detail); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v, out: %s", err, jsonOut)
	}
	if detail.Name != "he-pool" || detail.Type != "dynamic-v6" {
		t.Errorf("unexpected detail in JSON: %+v", detail)
	}
	if len(detail.ActivePool) != 1 || detail.ActivePool[0].Address != "2001:470:1f0b:692::1234" {
		t.Errorf("unexpected ActivePool in JSON: %+v", detail.ActivePool)
	}
	if len(detail.DeprecatedPool) != 1 || detail.DeprecatedPool[0].Address != "2001:470:1f0b:692::5678" {
		t.Errorf("unexpected DeprecatedPool in JSON: %+v", detail.DeprecatedPool)
	}
}

func TestEndpointTestCmd(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"static-test": {
				Type: config.EndpointTypeStatic,
				Host: "127.0.0.1",
			},
		},
	}
	_ = cfg.SaveEx(true)

	endpointTestJSON = true
	defer func() { endpointTestJSON = false }()

	jsonOut := captureStdout(t, func() {
		err := endpointTestCmd.RunE(endpointTestCmd, []string{"static-test"})
		if err != nil {
			t.Fatalf("endpoint test failed: %v", err)
		}
	})

	var results []EndpointTestResult
	if err := json.Unmarshal([]byte(jsonOut), &results); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v, out: %s", err, jsonOut)
	}
	if len(results) == 0 || results[0].Name != "static-test" {
		t.Fatalf("unexpected test results: %+v", results)
	}
}

func TestEndpointRotateCmd(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"he-pool": {
				Type:         config.EndpointTypeDynamicV6,
				Subnet:       "2001:470:1f0b:692::/64",
				Interface:    "he-ipv6",
				MaxAddresses: 4,
			},
			"static-node": {
				Type: config.EndpointTypeStatic,
				Host: "1.1.1.1",
			},
		},
	}
	_ = cfg.SaveEx(true)

	origRequireRoot := endpointRequireRoot
	endpointRequireRoot = func(string) error { return nil }
	defer func() { endpointRequireRoot = origRequireRoot }()

	restoreRunners := endpoint.SetTestRunners(
		func(name string, arg ...string) ([]byte, error) { return []byte("ok"), nil },
		func(sourceIPv6 string, timeout time.Duration) (bool, time.Duration, error) {
			return true, 5 * time.Millisecond, nil
		},
	)
	defer restoreRunners()

	// 1. Error on rotating non-dynamic-v6 endpoint
	err := endpointRotateCmd.RunE(endpointRotateCmd, []string{"static-node"})
	if err == nil || !strings.Contains(err.Error(), "rotation only applies to 'dynamic-v6'") {
		t.Fatalf("expected error rotating static endpoint, got: %v", err)
	}

	// 2. Rotate dynamic-v6 with --json
	endpointRotateJSON = true
	defer func() { endpointRotateJSON = false }()

	jsonOut := captureStdout(t, func() {
		// Mock initial active state
		st := endpoint.RotationState{
			ActivePool: []endpoint.AddressEntry{
				{Address: "2001:470:1f0b:692::1111", State: "active", CreatedAt: time.Now()},
			},
		}
		_ = endpoint.SaveRotationState("he-pool", &st)

		err := endpointRotateCmd.RunE(endpointRotateCmd, []string{"he-pool"})
		if err != nil {
			t.Fatalf("endpoint rotate failed: %v", err)
		}
	})

	var rotRes EndpointRotateResult
	if err := json.Unmarshal([]byte(jsonOut), &rotRes); err != nil {
		t.Fatalf("failed to unmarshal rotate JSON: %v, out: %s", err, jsonOut)
	}
	if rotRes.Name != "he-pool" || rotRes.RotatedAddress == "" {
		t.Errorf("unexpected rotate result: %+v", rotRes)
	}
}

func TestEndpointRotateProfilesCmd(t *testing.T) {
	out := captureStdout(t, func() {
		endpointRotateProfilesCmd.Run(endpointRotateProfilesCmd, []string{})
	})
	if !strings.Contains(out, "turtle") || !strings.Contains(out, "proactive") || !strings.Contains(out, "isolated") {
		t.Fatalf("expected rotate-profiles table to contain turtle, proactive, isolated, got:\n%s", out)
	}
	if !strings.Contains(out, "3600s") {
		t.Fatalf("expected retirement info 3600s in rotate-profiles table, got:\n%s", out)
	}
}

func TestEndpointSetProfileAndTTL(t *testing.T) {
	setupTestConfigDir(t)
	cmd := endpointSetCmd
	resetEndpointFlags(cmd)
	defer resetEndpointFlags(cmd)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"he-pool": {
				Type:      config.EndpointTypeDynamicV6,
				Subnet:    "2001:470:1f0a:692::/64",
				Interface: "he-ipv6",
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save staging config: %v", err)
	}

	// 1. Set turtle profile with TTL 6h
	_ = cmd.Flags().Set("profile", "turtle")
	_ = cmd.Flags().Set("ttl", "6h")
	if err := cmd.RunE(cmd, []string{"he-pool"}); err != nil {
		t.Fatalf("endpoint set -p turtle --ttl 6h failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	ep := loaded.Endpoints["he-pool"]
	if ep.Profile != "turtle" || ep.TTL != "6h" {
		t.Fatalf("expected profile=turtle, ttl=6h, got profile=%q, ttl=%q", ep.Profile, ep.TTL)
	}

	// 2. Reject invalid profile
	resetEndpointFlags(cmd)
	_ = cmd.Flags().Set("profile", "non-existent-profile")
	if err := cmd.RunE(cmd, []string{"he-pool"}); err == nil {
		t.Fatalf("expected error setting invalid profile, got nil")
	}

	// 3. Set isolated profile
	resetEndpointFlags(cmd)
	_ = cmd.Flags().Set("profile", "isolated")
	if err := cmd.RunE(cmd, []string{"he-pool"}); err != nil {
		t.Fatalf("endpoint set -p isolated failed: %v", err)
	}
	loaded2, _ := config.LoadConfigEx(true)
	if loaded2.Endpoints["he-pool"].Profile != "isolated" {
		t.Fatalf("expected profile=isolated, got %q", loaded2.Endpoints["he-pool"].Profile)
	}
}

