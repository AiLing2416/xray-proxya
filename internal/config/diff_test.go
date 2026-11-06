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

	// Port forward rules diff
	activePF := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			PortForwards: []PortForwardRule{{WANPort: 80, TargetIP: "192.168.1.100", TargetPort: 80, Proto: "tcp"}},
		},
	}
	stagingPF := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			PortForwards: []PortForwardRule{
				{WANPort: 80, TargetIP: "192.168.1.100", TargetPort: 80, Proto: "tcp"},
				{WANPort: 443, TargetIP: "192.168.1.100", TargetPort: 443, Proto: "tcp"},
			},
		},
	}
	diffsPF := DiffUserConfig(activePF, stagingPF)
	joinedPF := strings.Join(diffsPF, "\n")
	if !strings.Contains(joinedPF, "Port Forwarding: 1 rule(s) -> 2 rule(s)") {
		t.Errorf("expected Port Forwarding diff, got: %s", joinedPF)
	}

	// Isolated interfaces diff
	activeIso := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			IsolatedInterfaces: []string{"eth1"},
		},
	}
	stagingIso := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			IsolatedInterfaces: []string{"eth1", "eth2"},
		},
	}
	diffsIso := DiffUserConfig(activeIso, stagingIso)
	joinedIso := strings.Join(diffsIso, "\n")
	if !strings.Contains(joinedIso, "Isolated Interfaces: [eth1] -> [eth1 eth2]") {
		t.Errorf("expected Isolated Interfaces diff, got: %s", joinedIso)
	}
}

func TestDiffUserConfigGranularRulesAndForwards(t *testing.T) {
	// 1. Rules: modify target and remove rule
	active := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{MAC: "52:54:00:83:00:11", Target: "block"},
			},
			PortForwards: []PortForwardRule{
				{WANPort: 80, TargetIP: "192.168.1.100", TargetPort: 80, Proto: "tcp"},
				{WANPort: 2222, TargetIP: "192.168.1.20", TargetPort: 22, Proto: "tcp"},
			},
		},
	}
	staging := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{
				{Interface: "eth1", Target: "relay-us"},            // modified target
				{IP: "10.0.82.50", Target: "direct"},               // added
			},                                                       // MAC rule removed
			PortForwards: []PortForwardRule{
				{WANPort: 80, TargetIP: "192.168.1.101", TargetPort: 8080, Proto: "tcp"}, // modified target
				{WANPort: 443, TargetIP: "192.168.1.100", TargetPort: 443, Proto: "tcp"},  // added
			},                                                                              // WANPort 2222 removed
		},
	}

	diffs := DiffUserConfig(active, staging)
	joined := strings.Join(diffs, "\n")

	// Gateway Rules assertions
	if !strings.Contains(joined, "~ Rule: interface eth1 (target: direct -> relay-us)") {
		t.Errorf("expected modified rule diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "+ Rule: ip 10.0.82.50 -> direct") {
		t.Errorf("expected added rule diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "- Rule: mac 52:54:00:83:00:11 -> block") {
		t.Errorf("expected removed rule diff, got:\n%s", joined)
	}

	// Port Forwards assertions
	if !strings.Contains(joined, "~ Forward: wan:80 (proto: tcp): target 192.168.1.100:80 -> 192.168.1.101:8080") {
		t.Errorf("expected modified forward diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "+ Forward: wan:443 -> 192.168.1.100:443 (proto: tcp)") {
		t.Errorf("expected added forward diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "- Forward: wan:2222 -> 192.168.1.20:22 (proto: tcp)") {
		t.Errorf("expected removed forward diff, got:\n%s", joined)
	}
}

func TestDiffUserConfigNormalizedMatchingAndOrdering(t *testing.T) {
	// 1. MAC normalization with dash and lowercase/uppercase
	// 2. Proto normalization: udp,tcp should match tcp,udp or empty
	// 3. IPv6 target normalization: bracketed vs unbracketed
	active := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{
				{MAC: "52-54-00-83-00-11", Target: "direct"},
				{Interface: "eth1", Target: "relay-1"},
			},
			PortForwards: []PortForwardRule{
				{WANPort: 8080, TargetIP: "fd00::100", TargetPort: 80, Proto: "udp,tcp"},
			},
		},
	}
	staging := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{
				{MAC: "52:54:00:83:00:11", Target: "block"}, // target changed, MAC normalized
				{Interface: "eth1", Target: "relay-1"},       // unchanged
			},
			PortForwards: []PortForwardRule{
				{WANPort: 8080, TargetIP: "[fd00::100]", TargetPort: 8080, Proto: "tcp,udp"}, // target port changed, target IP format matches, proto normalized
			},
		},
	}

	diffs := DiffUserConfig(active, staging)
	joined := strings.Join(diffs, "\n")

	if !strings.Contains(joined, "~ Rule: mac 52:54:00:83:00:11 (target: direct -> block)") {
		t.Errorf("expected normalized MAC modified target diff, got:\n%s", joined)
	}
	if !strings.Contains(joined, "~ Forward: wan:8080 (proto: tcp,udp): target [fd00::100]:80 -> [fd00::100]:8080") {
		t.Errorf("expected normalized proto and bracketed IPv6 forward diff, got:\n%s", joined)
	}

	// 4. Test rule reordering
	stgReordered := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Rules: []GatewayRule{
				{Interface: "eth1", Target: "relay-1"},
				{MAC: "52:54:00:83:00:11", Target: "direct"},
			},
		},
	}
	reorderDiffs := DiffUserConfig(active, stgReordered)
	joinedReorder := strings.Join(reorderDiffs, "\n")
	if !strings.Contains(joinedReorder, "~ Rule order changed") {
		t.Errorf("expected rule order changed, got:\n%s", joinedReorder)
	}
}


