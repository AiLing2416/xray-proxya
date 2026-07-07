package main

import (
	"testing"
	"xray-proxya/internal/config"
)

func testApplyConfig() *config.UserConfig {
	return &config.UserConfig{
		Role:        config.RoleServer,
		UUID:        "root-uuid",
		APIInbound:  10001,
		TestInbound: 10002,
		Presets:     []config.ModeInfo{{Mode: config.ModeVLESSVision, Enabled: true, Port: 443}},
		CustomOutbounds: []config.CustomOutbound{{
			Alias:    "remote",
			Enabled:  true,
			UserUUID: "user-uuid",
			Config:   map[string]interface{}{"protocol": "socks"},
		}},
		Guests: []config.GuestConfig{{
			Alias:       "guest1",
			UUID:        "guest-uuid",
			Enabled:     true,
			QuotaGB:     1,
			ResetDay:    1,
			LastResetYM: "2026-05",
		}},
		Gateway: config.GatewayConfig{
			RelayAlias: "remote",
		},
		AdminSub: config.AdminSubConfig{
			Enabled:    true,
			Token:      "admin-token",
			Port:       8443,
			Mode:       config.AdminSubModeIPv6Rotate,
			TargetType: "direct",
			IPv6Rotate: config.IPv6Config{
				Enabled:      true,
				Subnet:       "2001:db8::/64",
				Interface:    "eth0",
				MaxAddresses: 6,
			},
		},
		Subscriptions: []config.Subscription{{
			Alias:       "sub1",
			TargetType:  "guest",
			TargetAlias: "guest1",
			Token:       "token1",
		}},
		SubPort:      8443,
		GuestSubPort: 9443,
		GuestSubBind: "127.0.0.1",
		IPv6Pool: config.IPv6Config{
			Enabled:      true,
			Subnet:       "2001:db8::/64",
			Interface:    "eth0",
			MaxAddresses: 6,
		},
	}
}

func TestBuildApplyImpactSubscriptionOnly(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.Subscriptions[0].Token = "token2"

	impact := buildApplyImpact(active, staging)
	if impact.XrayConfigChanged {
		t.Fatalf("expected subscription-only change to skip Xray restart")
	}
	if impact.SubListenerChanged {
		t.Fatalf("expected subscription-only change to skip sub listener restart")
	}
	if !impact.SubContentChanged {
		t.Fatalf("expected subscription-only change to be visible to sub content")
	}
}

func TestBuildApplyImpactSubPortChange(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.AdminSub.Port = 9443
	staging.SubPort = 9443

	impact := buildApplyImpact(active, staging)
	if impact.XrayConfigChanged {
		t.Fatalf("expected sub port change to avoid Xray restart")
	}
	if !impact.SubListenerChanged {
		t.Fatalf("expected sub port change to restart sub listener")
	}
}

func TestBuildApplyImpactGuestChange(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.Guests[0].Enabled = false

	impact := buildApplyImpact(active, staging)
	if !impact.XrayConfigChanged {
		t.Fatalf("expected guest change to restart Xray")
	}
	if !impact.SubContentChanged {
		t.Fatalf("expected guest change to affect generated subscriptions")
	}
}

func TestBuildApplyImpactGuestSubTokenChange(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.Guests[0].SubToken = "token-guest"

	impact := buildApplyImpact(active, staging)
	if impact.XrayConfigChanged {
		t.Fatalf("expected guest sub token change to skip Xray restart")
	}
	if !impact.SubContentChanged {
		t.Fatalf("expected guest sub token change to affect sub content")
	}
}

func TestBuildApplyImpactGatewayRuntimeOnly(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.Gateway.LocalEnabled = true

	impact := buildApplyImpact(active, staging)
	if impact.XrayConfigChanged {
		t.Fatalf("expected gateway runtime-only change to skip Xray restart")
	}
	if !impact.GatewayRuntimeChanged {
		t.Fatalf("expected gateway runtime-only change to be tracked")
	}
}

func TestBuildApplyImpactRelayAliasChange(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.Gateway.RelayAlias = "other"

	impact := buildApplyImpact(active, staging)
	if !impact.XrayConfigChanged {
		t.Fatalf("expected relay alias change to restart Xray")
	}
	if !impact.SubContentChanged {
		t.Fatalf("expected relay alias change to affect generated subscriptions")
	}
}

func TestBuildApplyImpactAdminSubTokenChange(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.AdminSub.Token = "admin-token-2"

	impact := buildApplyImpact(active, staging)
	if impact.XrayConfigChanged {
		t.Fatalf("expected admin sub token change to skip Xray restart")
	}
	if !impact.SubContentChanged {
		t.Fatalf("expected admin sub token change to affect sub content")
	}
	if impact.SubListenerChanged {
		t.Fatalf("expected admin sub token change to avoid listener restart")
	}
}

func TestBuildApplyImpactGuestSubListenerChange(t *testing.T) {
	active := testApplyConfig()
	staging := testApplyConfig()
	staging.GuestSubPort = 9555

	impact := buildApplyImpact(active, staging)
	if impact.XrayConfigChanged {
		t.Fatalf("expected guest sub listener change to skip Xray restart")
	}
	if !impact.SubListenerChanged {
		t.Fatalf("expected guest sub listener change to restart sub listener")
	}
}
