package main

import (
	"bytes"
	"fmt"
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
				{IP: "192.168.1.95", Target: "direct"},
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
	if !strings.Contains(textOutput, "192.168.1.95") {
		t.Errorf("expected IP rule in output, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "eth1") {
		t.Errorf("expected interface rule in output, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "IP / CIDR") {
		t.Errorf("expected IP / CIDR header in output, got:\n%s", textOutput)
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

	if !strings.Contains(jsonOutput, `"mac": "52:54:00:83:00:11"`) || !strings.Contains(jsonOutput, `"interface": "eth1"`) || !strings.Contains(jsonOutput, `"ip": "192.168.1.95"`) {
		t.Errorf("expected JSON output with MAC, interface, and IP, got:\n%s", jsonOutput)
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

	// Test WAN and LAN collision validation
	resetCmdFlags(cmd)
	_ = cmd.Flags().Set("interface", "eth1,eth2")
	_ = cmd.Flags().Set("wan", "eth1")
	err = runGatewaySet(cmd, []string{})
	if err == nil {
		t.Fatal("expected runGatewaySet to fail when WAN is configured as a LAN interface")
	}
	if !strings.Contains(err.Error(), `cannot also be configured as a LAN interface`) {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDetectLockoutRisk_NonBlock(t *testing.T) {
	rule := config.GatewayRule{
		Interface: "eth0",
		Target:    "direct",
	}
	hasRisk, msg := detectLockoutRisk(rule)
	if hasRisk {
		t.Errorf("expected no risk for non-block target, got true (%s)", msg)
	}

	ruleRelay := config.GatewayRule{
		Interface: "eth0",
		Target:    "relay-us",
	}
	hasRisk, msg = detectLockoutRisk(ruleRelay)
	if hasRisk {
		t.Errorf("expected no risk for relay target, got true (%s)", msg)
	}
}

func TestDetectLockoutRisk_NoSSH(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_CLIENT", "")

	// 1. Whole interface block without MAC -> risk
	rule1 := config.GatewayRule{
		Interface: "eth1",
		Target:    "block",
	}
	hasRisk, msg := detectLockoutRisk(rule1)
	if !hasRisk || !strings.Contains(msg, "without MAC filtering") {
		t.Errorf("expected risk for whole interface block without SSH, got %v (%s)", hasRisk, msg)
	}

	// 2. Specific MAC block without SSH -> no risk
	rule2 := config.GatewayRule{
		MAC:    "52:54:00:83:00:11",
		Target: "block",
	}
	hasRisk, msg = detectLockoutRisk(rule2)
	if hasRisk {
		t.Errorf("expected no risk for specific MAC without SSH, got true (%s)", msg)
	}
}

func TestDetectLockoutRisk_WithSSH(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.0.82.100 50000 10.0.82.21 22")
	t.Setenv("SSH_CLIENT", "10.0.82.100 50000 22")

	origLookupIface := lookupInterfaceByIP
	origLookupMAC := lookupMACByIP
	defer func() {
		lookupInterfaceByIP = origLookupIface
		lookupMACByIP = origLookupMAC
	}()

	lookupInterfaceByIP = func(ip string) (string, error) {
		if ip == "10.0.82.21" {
			return "eth0", nil
		}
		return "", fmt.Errorf("interface not found")
	}
	lookupMACByIP = func(ip string) (string, error) {
		if ip == "10.0.82.100" {
			return "52:54:00:82:00:99", nil
		}
		return "", fmt.Errorf("mac not found")
	}

	// a1. Block entire inbound interface (eth0) -> risk
	ruleA1 := config.GatewayRule{
		Interface: "eth0",
		Target:    "block",
	}
	hasRisk, msg := detectLockoutRisk(ruleA1)
	if !hasRisk || !strings.Contains(msg, "active SSH inbound interface") {
		t.Errorf("expected risk for blocking inbound interface eth0, got %v (%s)", hasRisk, msg)
	}

	// a2. Block inbound interface with matching client MAC -> risk
	ruleA2 := config.GatewayRule{
		Interface: "eth0",
		MAC:       "52:54:00:82:00:99",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleA2)
	if !hasRisk || !strings.Contains(msg, "matching your active SSH connection") {
		t.Errorf("expected risk for blocking inbound interface with client MAC, got %v (%s)", hasRisk, msg)
	}

	// a3. Block inbound interface with unknown client MAC -> risk
	lookupMACByIP = func(ip string) (string, error) {
		return "", fmt.Errorf("not found in arp")
	}
	ruleA3 := config.GatewayRule{
		Interface: "eth0",
		MAC:       "52:54:00:82:00:55",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleA3)
	if !hasRisk || !strings.Contains(msg, "client MAC could not be verified") {
		t.Errorf("expected risk when inbound interface matches and client MAC cannot be verified, got %v (%s)", hasRisk, msg)
	}

	// Reset lookupMACByIP for remaining tests
	lookupMACByIP = func(ip string) (string, error) {
		if ip == "10.0.82.100" {
			return "52:54:00:82:00:99", nil
		}
		return "", fmt.Errorf("mac not found")
	}

	// b. Block client MAC across any interface -> risk
	ruleB := config.GatewayRule{
		MAC:    "52:54:00:82:00:99",
		Target: "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleB)
	if !hasRisk || !strings.Contains(msg, "matching your active SSH client MAC") {
		t.Errorf("expected risk for blocking active SSH client MAC, got %v (%s)", hasRisk, msg)
	}

	// c. Block different interface with different MAC -> no risk
	ruleC := config.GatewayRule{
		Interface: "eth1",
		MAC:       "52:54:00:83:00:11",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleC)
	if hasRisk {
		t.Errorf("expected no risk for different interface and different MAC, got true (%s)", msg)
	}

	// d. Block different interface entirely while SSH inbound interface is known -> no risk to SSH
	ruleD := config.GatewayRule{
		Interface: "eth1",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleD)
	if hasRisk {
		t.Errorf("expected no risk for whole-block on non-SSH interface eth1 when SSH is on eth0, got true (%s)", msg)
	}

	// e. If SSH inbound interface cannot be resolved, whole interface block is flagged as risk
	lookupInterfaceByIP = func(ip string) (string, error) {
		return "", fmt.Errorf("cannot resolve")
	}
	ruleE := config.GatewayRule{
		Interface: "eth1",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleE)
	if !hasRisk || !strings.Contains(msg, "while an active SSH session is present") {
		t.Errorf("expected risk for whole-interface block when SSH interface unresolved, got %v (%s)", hasRisk, msg)
	}
}

func TestGatewayRuleSet_LockoutRisk_InteractiveAndForce(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	t.Setenv("SSH_CONNECTION", "10.0.82.100 50000 10.0.82.21 22")
	origLookupIface := lookupInterfaceByIP
	origLookupMAC := lookupMACByIP
	defer func() {
		lookupInterfaceByIP = origLookupIface
		lookupMACByIP = origLookupMAC
		gatewayRuleSetCmd.SetIn(nil)
		gatewayRuleSetCmd.SetOut(nil)
	}()

	lookupInterfaceByIP = func(ip string) (string, error) {
		if ip == "10.0.82.21" {
			return "eth0", nil
		}
		return "", fmt.Errorf("interface not found")
	}
	lookupMACByIP = func(ip string) (string, error) {
		if ip == "10.0.82.100" {
			return "52:54:00:82:00:99", nil
		}
		return "", fmt.Errorf("mac not found")
	}

	// 1. Interactive 'y': should succeed and save rule
	var outBuf bytes.Buffer
	gatewayRuleSetCmd.SetOut(&outBuf)
	gatewayRuleSetCmd.SetIn(strings.NewReader("y\n"))
	ruleSetInterface = "eth0"
	ruleSetMAC = ""
	ruleSetTo = "block"
	ruleSetTarget = ""
	ruleSetForce = false

	err := gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("expected interactive 'y' to succeed, got: %v", err)
	}
	if !strings.Contains(outBuf.String(), "[N/y]:") {
		t.Errorf("expected prompt [N/y]: in output, got:\n%s", outBuf.String())
	}
	stg, _ := config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].Interface != "eth0" || stg.Gateway.Rules[0].Target != "block" {
		t.Fatalf("expected rule saved to staging after 'y', got: %+v", stg.Gateway.Rules)
	}

	// Clear staging rules
	stg.Gateway.Rules = nil
	_ = stg.SaveEx(true)

	// 2. Interactive 'yes' (case-insensitive): should succeed
	outBuf.Reset()
	gatewayRuleSetCmd.SetIn(strings.NewReader("YES\n"))
	ruleSetInterface = "eth0"
	ruleSetMAC = ""
	ruleSetTo = "block"
	ruleSetForce = false

	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("expected interactive 'YES' to succeed, got: %v", err)
	}
	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 {
		t.Fatalf("expected rule saved after 'YES', got: %+v", stg.Gateway.Rules)
	}

	// Clear staging rules
	stg.Gateway.Rules = nil
	_ = stg.SaveEx(true)

	// 3. Interactive 'n': should cancel with error and NOT save rule
	outBuf.Reset()
	gatewayRuleSetCmd.SetIn(strings.NewReader("n\n"))
	ruleSetInterface = "eth0"
	ruleSetMAC = ""
	ruleSetTo = "block"
	ruleSetForce = false

	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err == nil || !strings.Contains(err.Error(), "Operation cancelled by user") {
		t.Fatalf("expected cancellation error for 'n', got: %v", err)
	}
	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 0 {
		t.Fatalf("expected rules to remain empty after cancellation, got: %+v", stg.Gateway.Rules)
	}

	// 4. Interactive default (enter key / newline): should cancel with error
	outBuf.Reset()
	gatewayRuleSetCmd.SetIn(strings.NewReader("\n"))
	ruleSetInterface = "eth0"
	ruleSetMAC = ""
	ruleSetTo = "block"
	ruleSetForce = false

	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err == nil || !strings.Contains(err.Error(), "Operation cancelled by user") {
		t.Fatalf("expected cancellation error for newline, got: %v", err)
	}
	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 0 {
		t.Fatalf("expected rules to remain empty after newline, got: %+v", stg.Gateway.Rules)
	}

	// 5. Non-interactive EOF: should cancel with error
	outBuf.Reset()
	gatewayRuleSetCmd.SetIn(strings.NewReader(""))
	ruleSetInterface = "eth0"
	ruleSetMAC = ""
	ruleSetTo = "block"
	ruleSetForce = false

	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err == nil || !strings.Contains(err.Error(), "failed to read confirmation") {
		t.Fatalf("expected cancellation error for EOF, got: %v", err)
	}
	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 0 {
		t.Fatalf("expected rules to remain empty after EOF, got: %+v", stg.Gateway.Rules)
	}

	// 6. With --force flag: should succeed without prompting
	outBuf.Reset()
	gatewayRuleSetCmd.SetIn(strings.NewReader("")) // EOF in stdin would fail if prompted
	ruleSetInterface = "eth0"
	ruleSetMAC = ""
	ruleSetTo = "block"
	ruleSetForce = true

	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("expected --force to succeed, got: %v", err)
	}
	if !strings.Contains(outBuf.String(), "⚠️  WARNING: High-risk block rule forced (--force specified):") {
		t.Errorf("expected force warning in output, got:\n%s", outBuf.String())
	}
	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].Interface != "eth0" || stg.Gateway.Rules[0].Target != "block" {
		t.Fatalf("expected rule saved to staging with force, got: %+v", stg.Gateway.Rules)
	}
}

func TestGatewayRuleSetForceFlag(t *testing.T) {
	flag := gatewayRuleSetCmd.Flags().Lookup("force")
	if flag == nil {
		t.Fatalf("expected --force flag on gateway rule set")
	}
	if flag.Shorthand != "f" {
		t.Errorf("expected shorthand 'f', got %q", flag.Shorthand)
	}
}

func TestGatewayRuleSet_TUNModeDisallowsRelay(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tun",
			State: "proxy",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-us", Enabled: true},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	// 1. Setting a relay target in TUN mode must fail
	ruleSetInterface = "eth1"
	ruleSetMAC = ""
	ruleSetTo = "relay-us"
	ruleSetForce = false
	err := gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err == nil || !strings.Contains(err.Error(), "TUN mode does not support per-client relay routing") {
		t.Fatalf("expected error setting relay target in TUN mode, got: %v", err)
	}

	// 2. Setting a direct target in TUN mode must succeed
	ruleSetTo = "direct"
	if err := gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{}); err != nil {
		t.Fatalf("expected direct target to succeed in TUN mode, got: %v", err)
	}

	// 3. Setting a block target in TUN mode must succeed
	ruleSetInterface = ""
	ruleSetMAC = "52:54:00:12:34:56"
	ruleSetTo = "block"
	if err := gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{}); err != nil {
		t.Fatalf("expected block target to succeed in TUN mode, got: %v", err)
	}
}

func TestGatewayRuleSetAndDel_IP(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-hk", Enabled: true},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	// 1. Add rule with single IP
	ruleSetMAC = ""
	ruleSetIP = "192.168.1.95"
	ruleSetInterface = ""
	ruleSetTo = "relay-hk"
	err := gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("failed to set IP rule: %v", err)
	}

	stg, _ := config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].IP != "192.168.1.95" || stg.Gateway.Rules[0].Target != "relay-hk" {
		t.Fatalf("unexpected rule in staging: %+v", stg.Gateway.Rules)
	}

	// 2. Add rule with CIDR (and host bit normalization)
	ruleSetIP = "10.0.0.5/24"
	ruleSetTo = "direct"
	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("failed to set CIDR rule: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 2 || stg.Gateway.Rules[1].IP != "10.0.0.0/24" || stg.Gateway.Rules[1].Target != "direct" {
		t.Fatalf("unexpected rule in staging: %+v", stg.Gateway.Rules)
	}

	// 3. Update IP rule in-place
	ruleSetIP = "192.168.1.95"
	ruleSetTo = "block"
	err = gatewayRuleSetCmd.RunE(gatewayRuleSetCmd, []string{})
	if err != nil {
		t.Fatalf("failed to update IP rule: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 2 || stg.Gateway.Rules[0].Target != "block" {
		t.Fatalf("expected rule 0 updated to block, got: %+v", stg.Gateway.Rules)
	}

	// 4. Delete rule by IP flag
	ruleDelIP = "192.168.1.95"
	ruleDelMAC = ""
	ruleDelInterface = ""
	gatewayRuleDelCmd.Flags().Lookup("ip").Changed = true
	err = gatewayRuleDelCmd.RunE(gatewayRuleDelCmd, []string{})
	gatewayRuleDelCmd.Flags().Lookup("ip").Changed = false
	ruleDelIP = ""
	if err != nil {
		t.Fatalf("failed to delete by IP: %v", err)
	}

	stg, _ = config.LoadConfigEx(true)
	if len(stg.Gateway.Rules) != 1 || stg.Gateway.Rules[0].IP != "10.0.0.0/24" {
		t.Fatalf("expected remaining CIDR rule, got: %+v", stg.Gateway.Rules)
	}

	// Cleanup
	ruleSetIP = ""
	ruleSetMAC = ""
	ruleSetInterface = ""
	ruleSetTo = ""
}

func TestDetectLockoutRisk_WithIP(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.0.82.100 50000 10.0.82.21 22")
	t.Setenv("SSH_CLIENT", "10.0.82.100 50000 22")

	origLookupIface := lookupInterfaceByIP
	origLookupMAC := lookupMACByIP
	defer func() {
		lookupInterfaceByIP = origLookupIface
		lookupMACByIP = origLookupMAC
	}()

	lookupInterfaceByIP = func(ip string) (string, error) {
		if ip == "10.0.82.21" {
			return "eth0", nil
		}
		return "", fmt.Errorf("interface not found")
	}
	lookupMACByIP = func(ip string) (string, error) {
		return "52:54:00:82:00:99", nil
	}

	// 1. Block client IP matching active SSH connection -> risk
	ruleClientIP := config.GatewayRule{
		IP:     "10.0.82.100",
		Target: "block",
	}
	hasRisk, msg := detectLockoutRisk(ruleClientIP)
	if !hasRisk || !strings.Contains(msg, "matching your active SSH client IP") {
		t.Errorf("expected risk for blocking active SSH client IP, got %v (%s)", hasRisk, msg)
	}

	// 2. Block CIDR subnet containing client IP -> risk
	ruleCIDR := config.GatewayRule{
		IP:     "10.0.82.0/24",
		Target: "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleCIDR)
	if !hasRisk || !strings.Contains(msg, "contains your active SSH client IP") {
		t.Errorf("expected risk for blocking CIDR containing SSH client IP, got %v (%s)", hasRisk, msg)
	}

	// 3. Block different IP -> no risk
	ruleOtherIP := config.GatewayRule{
		IP:     "10.0.82.200",
		Target: "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleOtherIP)
	if hasRisk {
		t.Errorf("expected no risk for different IP, got true (%s)", msg)
	}

	// 4. Block client IP on active SSH interface -> risk
	ruleIfaceAndIP := config.GatewayRule{
		Interface: "eth0",
		IP:        "10.0.82.100",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleIfaceAndIP)
	if !hasRisk || !strings.Contains(msg, "eth0") {
		t.Errorf("expected risk for blocking client IP on SSH interface eth0, got %v (%s)", hasRisk, msg)
	}

	// 5. Block client IP on different interface (eth1) -> no risk to active SSH on eth0
	ruleOtherIface := config.GatewayRule{
		Interface: "eth1",
		IP:        "10.0.82.100",
		Target:    "block",
	}
	hasRisk, msg = detectLockoutRisk(ruleOtherIface)
	if hasRisk {
		t.Errorf("expected no risk for client IP on different interface, got true (%s)", msg)
	}
}
