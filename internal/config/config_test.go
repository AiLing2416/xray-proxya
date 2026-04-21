package config

import "testing"

func TestBackfillDefaultsPopulatesMissingFields(t *testing.T) {
	cfg := &UserConfig{
		CustomOutbounds: []CustomOutbound{
			{
				Alias:       "relay-a",
				DNSStrategy: "useipv4",
				DNSServers:  []string{" 1.1.1.1 ", "1.1.1.1", ""},
			},
		},
		Guests: []GuestConfig{
			{Alias: "guest-a", ResetDay: 0},
		},
	}

	changes := cfg.BackfillDefaults()
	if len(changes) == 0 {
		t.Fatalf("BackfillDefaults() returned no changes")
	}
	if cfg.Role != RoleServer {
		t.Fatalf("Role = %q, want %q", cfg.Role, RoleServer)
	}
	if cfg.UUID == "" {
		t.Fatalf("UUID was not generated")
	}
	if cfg.CustomOutbounds[0].UserUUID == "" {
		t.Fatalf("Custom outbound user UUID was not generated")
	}
	if cfg.CustomOutbounds[0].DNSStrategy != "UseIPv4" {
		t.Fatalf("DNSStrategy = %q, want UseIPv4", cfg.CustomOutbounds[0].DNSStrategy)
	}
	if len(cfg.CustomOutbounds[0].DNSServers) != 1 || cfg.CustomOutbounds[0].DNSServers[0] != "1.1.1.1" {
		t.Fatalf("DNSServers = %v, want [1.1.1.1]", cfg.CustomOutbounds[0].DNSServers)
	}
	if cfg.Guests[0].UUID == "" {
		t.Fatalf("Guest UUID was not generated")
	}
	if cfg.Guests[0].ResetDay != 1 {
		t.Fatalf("ResetDay = %d, want 1", cfg.Guests[0].ResetDay)
	}
	if cfg.CustomOutbounds[0].Config == nil {
		t.Fatalf("Custom outbound config was not initialized")
	}
	if cfg.Gateway.Blacklist == nil || cfg.Gateway.BlacklistIPs == nil {
		t.Fatalf("Gateway blacklist slices were not initialized")
	}
	if len(cfg.ActiveModes) != len(PresetOrder) {
		t.Fatalf("len(ActiveModes) = %d, want %d", len(cfg.ActiveModes), len(PresetOrder))
	}
}

func TestBackfillDefaultsGatewayMode(t *testing.T) {
	cfg := &UserConfig{
		Role:    RoleGateway,
		Gateway: GatewayConfig{},
	}

	cfg.BackfillDefaults()

	if cfg.Gateway.Mode != "tun" {
		t.Fatalf("Gateway.Mode = %q, want tun", cfg.Gateway.Mode)
	}
	if len(cfg.ActiveModes) != 0 {
		t.Fatalf("gateway config should not auto-expand active modes; got %d", len(cfg.ActiveModes))
	}
}
