package config

import (
	"strings"
	"testing"
)

func TestDiffUserConfig(t *testing.T) {
	active := &UserConfig{
		Role: RoleServer,
		UUID: "uuid-1",
		Presets: []ModeInfo{
			{Mode: ModeVLESSVision, Enabled: false, Port: 443},
		},
		CustomOutbounds: []CustomOutbound{
			{Alias: "node-1", Config: map[string]interface{}{"protocol": "vless"}},
			{Alias: "node-2", Config: map[string]interface{}{"protocol": "vmess"}},
		},
		Guests: []GuestConfig{
			{Alias: "alice", QuotaGB: 100, ResetDay: 1, Enabled: true},
		},
		Gateway: GatewayConfig{
			RelayAlias:   "direct",
			LocalEnabled: false,
		},
	}

	staging := &UserConfig{
		Role: RoleServer,
		UUID: "uuid-1",
		Presets: []ModeInfo{
			{Mode: ModeVLESSVision, Enabled: true, Port: 8443},
		},
		CustomOutbounds: []CustomOutbound{
			{Alias: "node-1", AllowPrivateTargets: true, Config: map[string]interface{}{"protocol": "vless"}},
			{Alias: "node-3", Config: map[string]interface{}{"protocol": "trojan"}},
		},
		Guests: []GuestConfig{
			{Alias: "alice", QuotaGB: 200, ResetDay: 1, Enabled: true},
			{Alias: "bob", QuotaGB: 50, ResetDay: 15, Enabled: true},
		},
		Gateway: GatewayConfig{
			RelayAlias:   "node-3",
			LocalEnabled: true,
		},
	}

	diffs := DiffUserConfig(active, staging)
	if len(diffs) == 0 {
		t.Fatalf("expected non-empty diffs")
	}

	joined := strings.Join(diffs, "\n")

	// Check presets diff
	if !strings.Contains(joined, "Status OFF -> ON") || !strings.Contains(joined, "Port 443 -> 8443") {
		t.Errorf("expected preset diff, got:\n%s", joined)
	}

	// Check relays diff
	if !strings.Contains(joined, `Added relay "node-3"`) || !strings.Contains(joined, `Removed relay "node-2"`) || !strings.Contains(joined, `Private Targets false -> true`) {
		t.Errorf("expected relay diffs, got:\n%s", joined)
	}

	// Check guests diff
	if !strings.Contains(joined, `Quota 100.0 GB -> 200.0 GB`) || !strings.Contains(joined, `Added guest "bob"`) {
		t.Errorf("expected guest diffs, got:\n%s", joined)
	}

	// Check gateway diff
	if !strings.Contains(joined, "Relay: direct -> node-3") || !strings.Contains(joined, "Local Proxy: false -> true") {
		t.Errorf("expected gateway diffs, got:\n%s", joined)
	}
}

func TestDiffUserConfigClean(t *testing.T) {
	active := &UserConfig{
		Role: RoleGateway,
		UUID: "uuid-gw",
	}
	staging := &UserConfig{
		Role: RoleGateway,
		UUID: "uuid-gw",
	}
	diffs := DiffUserConfig(active, staging)
	if len(diffs) != 0 {
		t.Fatalf("expected empty diffs for identical configs, got: %v", diffs)
	}
}
