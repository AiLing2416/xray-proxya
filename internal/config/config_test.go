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
	if cfg.Guests[0].DisabledReason != GuestDisabledQuotaZero {
		t.Fatalf("DisabledReason = %q, want %q", cfg.Guests[0].DisabledReason, GuestDisabledQuotaZero)
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

func TestBackfillDefaultsSetsDisabledReasonForDisabledGuest(t *testing.T) {
	cfg := &UserConfig{
		Guests: []GuestConfig{
			{Alias: "guest-a", Enabled: false, QuotaGB: 0},
			{Alias: "guest-b", Enabled: false, QuotaGB: 5},
		},
	}

	cfg.BackfillDefaults()

	if cfg.Guests[0].DisabledReason != GuestDisabledQuotaZero {
		t.Fatalf("guest-a DisabledReason = %q, want %q", cfg.Guests[0].DisabledReason, GuestDisabledQuotaZero)
	}
	if cfg.Guests[1].DisabledReason != GuestDisabledManual {
		t.Fatalf("guest-b DisabledReason = %q, want %q", cfg.Guests[1].DisabledReason, GuestDisabledManual)
	}
}

func TestBackfillDefaultsMigratesLegacyAdminSubscription(t *testing.T) {
	cfg := &UserConfig{
		Subscriptions: []Subscription{{
			Alias:       "admin",
			TargetType:  "direct",
			TargetAlias: "",
			Address:     "sub.example.com",
			Token:       "legacy-token",
		}},
		SubPort: 9443,
		IPv6Pool: IPv6Config{
			Enabled:      true,
			Subnet:       "2001:db8::/64",
			Interface:    "eth0",
			MaxAddresses: 6,
			EnableNDP:    true,
		},
	}

	cfg.BackfillDefaults()

	if !cfg.AdminSub.Enabled {
		t.Fatalf("expected admin_sub to be enabled")
	}
	if cfg.AdminSub.Token != "legacy-token" {
		t.Fatalf("token = %q, want legacy-token", cfg.AdminSub.Token)
	}
	if cfg.AdminSub.Address != "sub.example.com" {
		t.Fatalf("address = %q", cfg.AdminSub.Address)
	}
	if cfg.AdminSub.Port != 9443 {
		t.Fatalf("port = %d, want 9443", cfg.AdminSub.Port)
	}
	if cfg.AdminSub.Mode != AdminSubModeIPv6Rotate {
		t.Fatalf("mode = %q, want %q", cfg.AdminSub.Mode, AdminSubModeIPv6Rotate)
	}
	if cfg.AdminSub.IPv6Rotate.Subnet != "2001:db8::/64" {
		t.Fatalf("subnet = %q", cfg.AdminSub.IPv6Rotate.Subnet)
	}
	if len(cfg.Subscriptions) != 0 {
		t.Fatalf("expected legacy managed subscription to be removed from subscriptions, got %d", len(cfg.Subscriptions))
	}
}
