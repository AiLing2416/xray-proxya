package gateway

import (
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

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

func testGatewayConfig(local, lan bool) *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			LocalEnabled: local,
			LANEnabled:   lan,
			Mode:         "tun",
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

func TestBuildNFTAddsSyntheticPingDropForLAN(t *testing.T) {
	cfg := testGatewayConfig(true, true)
	cfg.Gateway.SyntheticPing = true
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rules, `icmp type echo-request drop comment "xray-proxya synthetic-ping"`) {
		t.Fatalf("rules should drop LAN echo requests for synthetic replies: %s", rules)
	}
}

func TestPolicyRulesUseDedicatedPriorities(t *testing.T) {
	rules := policyRules("192.168.50.0/24", "fd00::/64", true)
	if len(rules) != 8 {
		t.Fatalf("policyRules returned %d rules, want 8", len(rules))
	}
	for _, rule := range rules {
		foundDedicatedPriority := false
		for _, arg := range rule.Args {
			if arg == prefXray || arg == prefLAN || arg == prefLoopback || arg == prefTun {
				foundDedicatedPriority = true
			}
		}
		if !foundDedicatedPriority {
			t.Fatalf("rule %v has no dedicated priority", rule.Args)
		}
	}
}
