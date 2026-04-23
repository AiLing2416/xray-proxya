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
	rules := buildNFT(testGatewayConfig(), "ens18", "192.168.50.0/24")
	if !strings.Contains(rules, `iifname != "ens18" return`) {
		t.Fatalf("rules should use configured LAN interface: %s", rules)
	}
	if !strings.Contains(rules, "ip daddr 192.168.50.0/24 return") {
		t.Fatalf("rules should exclude configured LAN subnet: %s", rules)
	}
}

func testGatewayConfig() *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			LocalEnabled: true,
			LANEnabled:   true,
			Mode:         "tun",
		},
	}
}
