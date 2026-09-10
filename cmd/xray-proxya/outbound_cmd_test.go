package main

import (
	"testing"

	"xray-proxya/internal/config"
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
