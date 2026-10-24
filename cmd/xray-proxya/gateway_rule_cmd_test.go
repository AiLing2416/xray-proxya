package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestGatewayRuleListTextAndJSON(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
			Rules: []config.GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{MAC: "52:54:00:83:00:11", Target: "block"},
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx(false) failed: %v", err)
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	// 1. Text output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	gatewayRuleListJSON = false
	err := gatewayRuleListCmd.RunE(gatewayRuleListCmd, []string{})

	_ = w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("gatewayRuleListCmd failed: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	textOutput := buf.String()

	if !strings.Contains(textOutput, "GATEWAY ROUTING RULES") {
		t.Errorf("expected header in output, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "52:54:00:83:00:11") {
		t.Errorf("expected MAC rule in output, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "eth1") {
		t.Errorf("expected interface rule in output, got:\n%s", textOutput)
	}

	// 2. JSON output
	r, w, _ = os.Pipe()
	os.Stdout = w

	gatewayRuleListJSON = true
	err = gatewayRuleListCmd.RunE(gatewayRuleListCmd, []string{})

	_ = w.Close()
	os.Stdout = oldStdout
	gatewayRuleListJSON = false

	if err != nil {
		t.Fatalf("gatewayRuleListCmd JSON failed: %v", err)
	}

	buf.Reset()
	_, _ = io.Copy(&buf, r)
	jsonOutput := buf.String()

	if !strings.Contains(jsonOutput, `"mac": "52:54:00:83:00:11"`) || !strings.Contains(jsonOutput, `"interface": "eth1"`) {
		t.Errorf("expected JSON output with MAC and interface, got:\n%s", jsonOutput)
	}
}

func TestGatewayRuleSetAndDel(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-us", Enabled: true},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	// 1. Add rule with invalid target
	ruleSetMAC = ""
	ruleSetInterface = "eth1"
	ruleSetTo = "nonexistent-relay"
	ruleSetTarget = ""
	err := gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err == nil || !strings.Contains(err.Error(), "not found in custom outbounds") {
		t.Errorf("expected error for nonexistent relay target, got: %v", err)
	}

	// 2. Add rule with valid relay target
	ruleSetInterface = "eth1"
	ruleSetTo = "relay-us"
	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("failed to set valid relay rule: %v", err)
	}

	stg, _ := config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].Interface != "eth1" || stg.Gateway.Rules[0].Target != "relay-us" {
		t.Fatalf("unexpected rules in staging: %+v", stg.Gateway.Rules)
	}

	// 3. Update existing rule in-place
	ruleSetInterface = "eth1"
	ruleSetTo = "direct"
	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("failed to update rule in-place: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].Target != "direct" {
		t.Fatalf("expected rule updated in-place to direct, got: %+v", stg.Gateway.Rules)
	}

	// 4. Add second rule with MAC
	ruleSetInterface = ""
	ruleSetMAC = "52-54-00-83-00-11"
	ruleSetTo = "block"
	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("failed to add MAC rule: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 2 || stg.Gateway.Rules[1].MAC != "52:54:00:83:00:11" || stg.Gateway.Rules[1].Target != "block" {
		t.Fatalf("expected 2 rules with normalized MAC, got: %+v", stg.Gateway.Rules)
	}

	// 5. Delete rule by index
	err = gatewayRuleDelCmd.RunE(gatewayRuleDelCmd, []string{"1"})
	if err != nil {
		t.Fatalf("failed to delete rule by index: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].MAC != "52:54:00:83:00:11" {
		t.Fatalf("expected rule 1 deleted, got: %+v", stg.Gateway.Rules)
	}

	// 6. Delete rule by MAC flag
	ruleDelMAC = "52:54:00:83:00:11"
	ruleDelInterface = ""
	gatewayRuleDelCmd.Flags().Lookup("mac").Changed = true
	err = gatewayRuleDelCmd.RunE(gatewayRuleDelCmd, []string{})
	gatewayRuleDelCmd.Flags().Lookup("mac").Changed = false
	ruleDelMAC = ""
	if err != nil {
		t.Fatalf("failed to delete rule by MAC flag: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 0 {
		t.Fatalf("expected rules to be empty, got: %+v", stg.Gateway.Rules)
	}
}

func TestGatewayRuleClear(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Rules: []config.GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{Interface: "eth2", Target: "block"},
			},
		},
	}
	_ = cfg.SaveEx(true)

	err := gatewayRuleClearCmd.RunE(gatewayRuleClearCmd, []string{})
	if err != nil {
		t.Fatalf("gatewayRuleClearCmd failed: %v", err)
	}

	stg, _ := config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 0 {
		t.Errorf("expected rules to be empty after clear, got: %+v", stg.Gateway.Rules)
	}
}

func TestGatewaySetRouterFlags(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
	}
	_ = cfg.SaveEx(true)

	// Set multi-interface, wan, and nat
	cmd := gatewaySetCmd
	resetCmdFlags(cmd)
	_ = cmd.Flags().Set("interface", "eth1,eth2")
	_ = cmd.Flags().Set("wan", "eth0")
	_ = cmd.Flags().Set("no-nat", "true")

	err := runGatewaySet(cmd, []string{})
	if err != nil {
		t.Fatalf("runGatewaySet failed: %v", err)
	}

	stg, _ := config.LoadConfigEx(true)
	if len(stg.Gateway.LANInterfaces) != 2 || stg.Gateway.LANInterfaces[0] != "eth1" || stg.Gateway.LANInterfaces[1] != "eth2" {
		t.Errorf("LANInterfaces = %v, want [eth1 eth2]", stg.Gateway.LANInterfaces)
	}
	if stg.Gateway.WANInterface != "eth0" {
		t.Errorf("WANInterface = %q, want eth0", stg.Gateway.WANInterface)
	}
	if !stg.Gateway.NATDisabled {
		t.Errorf("NATDisabled = %v, want true", stg.Gateway.NATDisabled)
	}

	// Test clearing WAN to auto and enabling NAT
	resetCmdFlags(cmd)
	_ = cmd.Flags().Set("wan", "auto")
	_ = cmd.Flags().Set("nat", "true")

	err = runGatewaySet(cmd, []string{})
	if err != nil {
		t.Fatalf("runGatewaySet failed: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if stg.Gateway.WANInterface != "" {
		t.Errorf("WANInterface should be empty after 'auto', got %q", stg.Gateway.WANInterface)
	}
	if stg.Gateway.NATDisabled {
		t.Errorf("NATDisabled = %v, want false after --nat", stg.Gateway.NATDisabled)
	}
}
