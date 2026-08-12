package gateway

import (
	"errors"
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func TestIsMissingKernelObject(t *testing.T) {
	if !isMissingKernelObject(errors.New("command failed"), []byte("Error: No such chain")) {
		t.Fatal("missing nft chain should be treated as an idempotent cleanup")
	}
	if isMissingKernelObject(errors.New("command failed"), []byte("permission denied")) {
		t.Fatal("permission errors must not be treated as missing objects")
	}
}

func TestParseDefaultInterface(t *testing.T) {
	iface, err := ParseDefaultInterface("default via 192.168.1.1 dev ens18 proto dhcp src 192.168.1.10 metric 100\n")
	if err != nil {
		t.Fatalf("ParseDefaultInterface() error = %v", err)
	}
	if iface != "ens18" {
		t.Fatalf("interface = %q, want ens18", iface)
	}
}

func TestParseDefaultInterfaceNoDefault(t *testing.T) {
	if _, err := ParseDefaultInterface("192.168.1.0/24 dev ens18 proto kernel\n"); err == nil {
		t.Fatal("ParseDefaultInterface() error = nil, want error")
	}
}

func TestBuildNFTUsesConfiguredLANInterface(t *testing.T) {
	rules := buildNFT(testGatewayConfig(true, true), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rules, `iifname != "ens18" return`) {
		t.Fatalf("rules should use configured LAN interface: %s", rules)
	}
	if !strings.Contains(rules, "ip daddr 192.168.50.0/24 return") {
		t.Fatalf("rules should exclude configured LAN subnet: %s", rules)
	}
	if !strings.Contains(rules, "ip saddr != 192.168.50.0/24 return") {
		t.Fatalf("rules should reject spoofed IPv4 LAN sources: %s", rules)
	}

	rulesIPv6 := buildNFT(testGatewayConfig(true, true), "ens18", "192.168.50.0/24", "fd00::/64")
	if !strings.Contains(rulesIPv6, "ip6 saddr != fd00::/64 return") {
		t.Fatalf("rules should reject spoofed IPv6 LAN sources: %s", rulesIPv6)
	}
	if !strings.Contains(rules, "ip6 saddr ::/0 return") {
		t.Fatalf("rules should bypass IPv6 LAN interception without a LAN IPv6 subnet: %s", rules)
	}
}

func TestBuildNFTConditionalChains(t *testing.T) {
	// Both enabled
	rulesBoth := buildNFT(testGatewayConfig(true, true), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesBoth, "chain prerouting") {
		t.Error("rules should contain prerouting chain when LANEnabled is true")
	}
	if !strings.Contains(rulesBoth, "chain output") {
		t.Error("rules should contain output chain when LocalEnabled is true")
	}

	// LAN only
	rulesLANOnly := buildNFT(testGatewayConfig(false, true), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesLANOnly, "chain prerouting") {
		t.Error("rules should contain prerouting chain when LANEnabled is true")
	}
	if strings.Contains(rulesLANOnly, "chain output") {
		t.Error("rules should not contain output chain when LocalEnabled is false")
	}

	// Local only
	rulesLocalOnly := buildNFT(testGatewayConfig(true, false), "ens18", "192.168.50.0/24", "")
	if strings.Contains(rulesLocalOnly, "chain prerouting") {
		t.Error("rules should not contain prerouting chain when LANEnabled is false")
	}
	if !strings.Contains(rulesLocalOnly, "chain output") {
		t.Error("rules should contain output chain when LocalEnabled is true")
	}
}

func TestBuildNFTProtectsSSHSourceAndDestinationPorts(t *testing.T) {
	rules := buildNFT(testGatewayConfig(true, false), "ens18", "192.168.50.0/24", "")
	for _, port := range getSSHPorts() {
		if !strings.Contains(rules, "tcp sport "+port+" return") {
			t.Fatalf("rules should protect SSH source port %s: %s", port, rules)
		}
		if !strings.Contains(rules, "tcp dport "+port+" return") {
			t.Fatalf("rules should protect SSH destination port %s: %s", port, rules)
		}
	}
}

func testGatewayConfig(local, lan bool) *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			LocalEnabled: local,
			LANEnabled:   lan,
			Mode:         "tun",
			RelayAlias:   "relay-a",
		},
	}
}

func TestBuildNFTWithBypassDNS(t *testing.T) {
	cfg := testGatewayConfig(true, true)
	cfg.Gateway.BypassDNS = []string{"8.8.8.8", "2001:4860:4860::8888"}
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "fd00::/64")
	if !strings.Contains(rules, "ip daddr 8.8.8.8 return") {
		t.Fatalf("rules should bypass IPv4 DNS 8.8.8.8: %s", rules)
	}
	if !strings.Contains(rules, "ip6 daddr 2001:4860:4860::8888 return") {
		t.Fatalf("rules should bypass IPv6 DNS 2001:4860:4860::8888: %s", rules)
	}
}

func TestBuildNFTRoutesPathLinkICMPToDedicatedMark(t *testing.T) {
	cfg := testGatewayConfig(true, true)
	cfg.Path.Enabled, cfg.Path.Token = true, "token"
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "fd00::/64")
	for _, expected := range []string{"icmp type echo-request meta mark set " + pathTunMark, "icmpv6 type echo-request meta mark set " + pathTunMark} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("missing %q in %s", expected, rules)
		}
	}
}

func TestPathTunnelEnabledForEitherGatewayMode(t *testing.T) {
	for _, mode := range []struct {
		name  string
		local bool
		lan   bool
	}{
		{name: "local only", local: true},
		{name: "lan only", lan: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			cfg := testGatewayConfig(mode.local, mode.lan)
			cfg.Path.Enabled, cfg.Path.Token = true, "token"
			if !pathTunnelEnabled(cfg) {
				t.Fatal("PathLink should be enabled when either gateway mode is enabled")
			}
		})
	}
	neither := testGatewayConfig(false, false)
	neither.Path.Enabled, neither.Path.Token = true, "token"
	if pathTunnelEnabled(neither) {
		t.Fatal("PathLink should be disabled when both gateway modes are disabled")
	}
	noRelay := testGatewayConfig(true, false)
	noRelay.Gateway.RelayAlias = ""
	noRelay.Path.Enabled, noRelay.Path.Token = true, "token"
	if pathTunnelEnabled(noRelay) {
		t.Fatal("PathLink should be disabled when no relay is configured")
	}
}

func TestPolicyRulesUseDedicatedPriorities(t *testing.T) {
	rules := policyRules("192.168.50.0/24", "fd00::/64", true)
	if len(rules) != 10 {
		t.Fatalf("policyRules returned %d rules, want 10", len(rules))
	}
	for _, rule := range rules {
		foundDedicatedPriority := false
		for _, arg := range rule.Args {
			if arg == prefXray || arg == prefLAN || arg == prefLoopback || arg == prefTun || arg == prefPathTun {
				foundDedicatedPriority = true
			}
		}
		if !foundDedicatedPriority {
			t.Fatalf("rule %v has no dedicated priority", rule.Args)
		}
	}
}
