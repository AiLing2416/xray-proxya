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

func TestDiffUserConfigGatewayDNS(t *testing.T) {
	active := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			DNSListen:   "127.0.0.1:5353",
			DNSStrategy: "UseIP",
			DNSServers:  []string{"1.1.1.1"},
			DNSRecords:  map[string][]string{"router.lan": {"10.0.82.1"}},
		},
	}
	staging := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			DNSListen:   ":53",
			DNSStrategy: "UseIPv4",
			DNSServers:  []string{"8.8.8.8", "1.1.1.1"},
			DNSRecords:  map[string][]string{"router.lan": {"10.0.82.1", "fd00:82::1"}},
		},
	}

	diffs := DiffUserConfig(active, staging)
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, `DNS Listen: "127.0.0.1:5353" -> ":53"`) {
		t.Errorf("expected DNS Listen diff, got: %s", joined)
	}
	if !strings.Contains(joined, `DNS Strategy: "UseIP" -> "UseIPv4"`) {
		t.Errorf("expected DNS Strategy diff, got: %s", joined)
	}
	if !strings.Contains(joined, "DNS Servers") {
		t.Errorf("expected DNS Servers diff, got: %s", joined)
	}
	if !strings.Contains(joined, "DNS Records") {
		t.Errorf("expected DNS Records diff, got: %s", joined)
	}
}

func TestDiffUserConfigGatewayRouter(t *testing.T) {
	active := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			LANInterface: "eth1",
			WANInterface: "eth0",
			NATDisabled:  false,
			Rules:        []GatewayRule{{Interface: "eth1", Target: "direct"}},
		},
	}
	staging := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			LANInterface: "eth1,eth2",
			WANInterface: "eth3",
			NATDisabled:  true,
			Rules: []GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{MAC: "52:54:00:83:00:11", Target: "block"},
			},
		},
	}

	diffs := DiffUserConfig(active, staging)
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "LAN Interfaces") {
		t.Errorf("expected LAN Interfaces diff, got: %s", joined)
	}
	if !strings.Contains(joined, `WAN Interface: "eth0" -> "eth3"`) {
		t.Errorf("expected WAN Interface diff, got: %s", joined)
	}
	if !strings.Contains(joined, `NAT Masquerade: true -> false`) {
		t.Errorf("expected NAT Masquerade diff, got: %s", joined)
	}
	if !strings.Contains(joined, `Gateway Rules: 1 rule(s) -> 2 rule(s)`) {
		t.Errorf("expected Gateway Rules diff, got: %s", joined)
	}

	// Gateway rules diff when only IP changes
	activeIP := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{{IP: "192.168.1.95", Target: "direct"}},
		},
	}
	stagingIP := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{{IP: "192.168.1.96", Target: "direct"}},
		},
	}
	diffsIP := DiffUserConfig(activeIP, stagingIP)
	joinedIP := strings.Join(diffsIP, "\n")
	if !strings.Contains(joinedIP, "Gateway Rules") {
		t.Errorf("expected Gateway Rules diff for IP change, got: %s", joinedIP)
	}
}
