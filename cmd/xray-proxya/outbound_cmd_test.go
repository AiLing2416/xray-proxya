package main

import (
	"strings"
	"testing"

	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

func TestSetRelayPrivateTargets(t *testing.T) {
	cfg := &config.UserConfig{CustomOutbounds: []config.CustomOutbound{{Alias: "remote"}}}
	if !setRelayPrivateTargets(cfg, "remote", true) {
		t.Fatal("setRelayPrivateTargets() = false, want true")
	}
	if !cfg.CustomOutbounds[0].AllowPrivateTargets {
		t.Fatal("AllowPrivateTargets = false, want true")
	}
	if setRelayPrivateTargets(cfg, "missing", false) {
		t.Fatal("setRelayPrivateTargets() = true for missing relay")
	}
}

func TestNormalizeDNSFlagsRejectsResetCombination(t *testing.T) {
	_, _, err := normalizeDNSFlags("UseIPv4", []string{"1.1.1.1"}, true)
	if err == nil {
		t.Fatalf("normalizeDNSFlags() error = nil, want conflict error")
	}
}

func TestNormalizeDNSFlagsResetClearsWithoutError(t *testing.T) {
	strategy, servers, err := normalizeDNSFlags("", nil, true)
	if err != nil {
		t.Fatalf("normalizeDNSFlags() error = %v", err)
	}
	if strategy != "" {
		t.Fatalf("strategy = %q, want empty", strategy)
	}
	if servers != nil {
		t.Fatalf("servers = %v, want nil", servers)
	}
}

func TestNormalizeDNSFlagsNormalizesValues(t *testing.T) {
	strategy, servers, err := normalizeDNSFlags("useipv6", []string{" 1.1.1.1 ", "https://dns.google/dns-query", "1.1.1.1"}, false)
	if err != nil {
		t.Fatalf("normalizeDNSFlags() error = %v", err)
	}
	if strategy != "UseIPv6" {
		t.Fatalf("strategy = %q, want %q", strategy, "UseIPv6")
	}
	wantServers := []string{"1.1.1.1", "https://dns.google/dns-query"}
	if len(servers) != len(wantServers) {
		t.Fatalf("len(servers) = %d, want %d; servers=%v", len(servers), len(wantServers), servers)
	}
	for i := range wantServers {
		if servers[i] != wantServers[i] {
			t.Fatalf("servers[%d] = %q, want %q; servers=%v", i, servers[i], wantServers[i], servers)
		}
	}
}

func TestApplyDNSConfigUpdateResetClearsOverrides(t *testing.T) {
	co := config.CustomOutbound{
		Alias:       "relay-a",
		DNSStrategy: "UseIPv4",
		DNSServers:  []string{"1.1.1.1"},
	}

	applyDNSConfigUpdate(&co, "", nil, true)

	if co.DNSStrategy != "" {
		t.Fatalf("DNSStrategy = %q, want empty", co.DNSStrategy)
	}
	if co.DNSServers != nil {
		t.Fatalf("DNSServers = %v, want nil", co.DNSServers)
	}
}

func TestApplyDNSConfigUpdatePreservesUntouchedFields(t *testing.T) {
	co := config.CustomOutbound{
		Alias:       "relay-a",
		DNSStrategy: "UseIPv4",
		DNSServers:  []string{"1.1.1.1"},
	}

	applyDNSConfigUpdate(&co, "UseIPv6", nil, false)
	if co.DNSStrategy != "UseIPv6" {
		t.Fatalf("DNSStrategy = %q, want %q", co.DNSStrategy, "UseIPv6")
	}
	if len(co.DNSServers) != 1 || co.DNSServers[0] != "1.1.1.1" {
		t.Fatalf("DNSServers = %v, want original value", co.DNSServers)
	}

	applyDNSConfigUpdate(&co, "", []string{"8.8.8.8"}, false)
	if co.DNSStrategy != "UseIPv6" {
		t.Fatalf("DNSStrategy = %q, want %q", co.DNSStrategy, "UseIPv6")
	}
	if len(co.DNSServers) != 1 || co.DNSServers[0] != "8.8.8.8" {
		t.Fatalf("DNSServers = %v, want updated value", co.DNSServers)
	}
}

func TestProbeDNSViaTCPQueryFormat(t *testing.T) {
	// Verify the DNS query payload is well-formed
	query := buildDNSProbeQuery()
	if len(query) < 12 {
		t.Fatalf("DNS query too short: %d bytes", len(query))
	}
	// Check QDCOUNT = 1
	qdcount := int(query[4])<<8 | int(query[5])
	if qdcount != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", qdcount)
	}
}

func TestRelayRemoveAliases(t *testing.T) {
	if removeOutboundCmd.Name() != "remove" {
		t.Fatalf("expected command name 'remove', got %q", removeOutboundCmd.Name())
	}
	expectedAliases := map[string]bool{"rm": true, "del": true, "delete": true}
	if len(removeOutboundCmd.Aliases) != len(expectedAliases) {
		t.Fatalf("expected %d aliases, got %v", len(expectedAliases), removeOutboundCmd.Aliases)
	}
	for _, alias := range removeOutboundCmd.Aliases {
		if !expectedAliases[alias] {
			t.Errorf("unexpected alias %q", alias)
		}
	}

	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "r-rem", Enabled: true},
			{Alias: "r-rm", Enabled: true},
			{Alias: "r-del", Enabled: true},
			{Alias: "r-delete", Enabled: true},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	for _, aliasCmd := range []string{"remove", "rm", "del", "delete"} {
		cmd, _, err := rootCmd.Find([]string{"relay", aliasCmd})
		if err != nil || cmd != removeOutboundCmd {
			t.Fatalf("expected rootCmd.Find(relay, %s) to resolve to removeOutboundCmd, got %v (err: %v)", aliasCmd, cmd, err)
		}
	}

	removeOutboundCmd.Run(removeOutboundCmd, []string{"r-rem"})
	removeOutboundCmd.Run(removeOutboundCmd, []string{"r-rm"})
	removeOutboundCmd.Run(removeOutboundCmd, []string{"r-del"})
	removeOutboundCmd.Run(removeOutboundCmd, []string{"r-delete"})

	stagedFinal, _ := config.LoadConfigEx(true)
	if len(stagedFinal.CustomOutbounds) != 0 {
		t.Fatalf("expected 0 outbounds after all removals, got %d", len(stagedFinal.CustomOutbounds))
	}
}

func TestRelayHelpAndExamplesNoObsoleteOutbound(t *testing.T) {
	cmds := []*cobra.Command{resolveOutboundCmd, setDNSRelayCmd, setPrivateTargetsRelayCmd, setOutboundCmd}
	for _, cmd := range cmds {
		if strings.Contains(cmd.Example, "xray-proxya outbound") {
			t.Errorf("command %q Example contains obsolete 'xray-proxya outbound': %s", cmd.Name(), cmd.Example)
		}
		if strings.Contains(cmd.Long, "'outbound ") {
			t.Errorf("command %q Long contains obsolete ''outbound ': %s", cmd.Name(), cmd.Long)
		}
	}
}

func resetSetOutboundFlags() {
	_ = setOutboundCmd.Flags().Set("private", "false")
	setOutboundCmd.Flags().Lookup("private").Changed = false
	_ = setOutboundCmd.Flags().Set("no-private", "false")
	setOutboundCmd.Flags().Lookup("no-private").Changed = false
}

func TestSetPrivateTargetsHidden(t *testing.T) {
	if !setPrivateTargetsRelayCmd.Hidden {
		t.Errorf("expected setPrivateTargetsRelayCmd to be hidden")
	}
}

func TestRelaySetCommand(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "node1", AllowPrivateTargets: false},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	// 1. Test empty flags error
	resetSetOutboundFlags()
	err := setOutboundCmd.RunE(setOutboundCmd, []string{"node1"})
	if err == nil || !strings.Contains(err.Error(), "No parameter supplied") {
		t.Fatalf("expected 'No parameter supplied' error, got %v", err)
	}

	// 2. Test conflicting flags
	resetSetOutboundFlags()
	_ = setOutboundCmd.Flags().Set("private", "true")
	_ = setOutboundCmd.Flags().Set("no-private", "true")
	err = setOutboundCmd.RunE(setOutboundCmd, []string{"node1"})
	if err == nil || !strings.Contains(err.Error(), "Conflicting flags specified") {
		t.Fatalf("expected 'Conflicting flags specified' error, got %v", err)
	}

	// 3. Test -p / --private allows private targets
	resetSetOutboundFlags()
	_ = setOutboundCmd.Flags().Set("private", "true")
	err = setOutboundCmd.RunE(setOutboundCmd, []string{"node1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !loaded.CustomOutbounds[0].AllowPrivateTargets {
		t.Fatalf("expected AllowPrivateTargets == true")
	}

	// 4. Test --no-private blocks private targets
	resetSetOutboundFlags()
	_ = setOutboundCmd.Flags().Set("no-private", "true")
	err = setOutboundCmd.RunE(setOutboundCmd, []string{"node1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	loaded, err = config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.CustomOutbounds[0].AllowPrivateTargets {
		t.Fatalf("expected AllowPrivateTargets == false")
	}

	// 5. Test unknown node error
	resetSetOutboundFlags()
	_ = setOutboundCmd.Flags().Set("private", "true")
	err = setOutboundCmd.RunE(setOutboundCmd, []string{"missing-node"})
	if err == nil || !strings.Contains(err.Error(), "Relay 'missing-node' not found") {
		t.Fatalf("expected relay not found error, got %v", err)
	}
}

func TestRelayAddAutoAlias(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role:            config.RoleGateway,
		CustomOutbounds: []config.CustomOutbound{},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	linkWithRemark := "vless://a3f6c8d2-1111-4b1a-9a99-999999999999@1.2.3.4:443?security=none#HongKong-01"
	bareLink1 := "vless://a3f6c8d2-1111-4b1a-9a99-999999999999@1.2.3.4:443?security=none"
	bareLink2 := "vless://a3f6c8d2-2222-4b1a-9a99-999999999999@1.2.3.5:443?security=none"

	// 1. Single arg with remark -> alias = HongKong-01
	err := runAddOutbound(addOutboundCmd, []string{linkWithRemark})
	if err != nil {
		t.Fatalf("add with remark failed: %v", err)
	}
	loaded, err := config.LoadConfigEx(true)
	if err != nil || len(loaded.CustomOutbounds) != 1 {
		t.Fatalf("expected 1 outbound, got %d (err: %v)", len(loaded.CustomOutbounds), err)
	}
	if loaded.CustomOutbounds[0].Alias != "HongKong-01" {
		t.Fatalf("expected alias HongKong-01, got %q", loaded.CustomOutbounds[0].Alias)
	}

	// 2. Single arg bare link -> alias = Relay-1
	err = runAddOutbound(addOutboundCmd, []string{bareLink1})
	if err != nil {
		t.Fatalf("add bare link 1 failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.CustomOutbounds) != 2 || loaded.CustomOutbounds[1].Alias != "Relay-1" {
		t.Fatalf("expected alias Relay-1, got %v", loaded.CustomOutbounds[1].Alias)
	}

	// 3. Single arg bare link 2 -> alias = Relay-2
	err = runAddOutbound(addOutboundCmd, []string{bareLink2})
	if err != nil {
		t.Fatalf("add bare link 2 failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.CustomOutbounds) != 3 || loaded.CustomOutbounds[2].Alias != "Relay-2" {
		t.Fatalf("expected alias Relay-2, got %v", loaded.CustomOutbounds[2].Alias)
	}

	// 4. Two args explicit alias -> alias = explicit-node
	err = runAddOutbound(addOutboundCmd, []string{"explicit-node", bareLink1})
	if err != nil {
		t.Fatalf("add explicit alias failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.CustomOutbounds) != 4 || loaded.CustomOutbounds[3].Alias != "explicit-node" {
		t.Fatalf("expected alias explicit-node, got %v", loaded.CustomOutbounds[3].Alias)
	}

	// 5. Two args inverted (link first, alias second) -> alias = inverted-node
	err = runAddOutbound(addOutboundCmd, []string{bareLink1, "inverted-node"})
	if err != nil {
		t.Fatalf("add inverted args failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.CustomOutbounds) != 5 || loaded.CustomOutbounds[4].Alias != "inverted-node" {
		t.Fatalf("expected alias inverted-node, got %v", loaded.CustomOutbounds[4].Alias)
	}

	// 6. Explicit duplicate alias -> error
	err = runAddOutbound(addOutboundCmd, []string{"explicit-node", bareLink1})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already exists error, got %v", err)
	}

	// 7. Auto remark duplicate -> automatically appends -2
	err = runAddOutbound(addOutboundCmd, []string{linkWithRemark})
	if err != nil {
		t.Fatalf("add duplicate auto remark failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.CustomOutbounds) != 6 || loaded.CustomOutbounds[5].Alias != "HongKong-01-2" {
		t.Fatalf("expected alias HongKong-01-2, got %v", loaded.CustomOutbounds[5].Alias)
	}
}
