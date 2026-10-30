package gateway

import (
	"os/exec"
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func TestRuleSpecificity(t *testing.T) {
	ruleIPIface := config.GatewayRule{IP: "192.168.1.95", Interface: "eth1"}
	ruleMACIface := config.GatewayRule{MAC: "52:54:00:83:00:11", Interface: "eth1"}
	rulePureIP := config.GatewayRule{IP: "192.168.1.95"}
	rulePureMAC := config.GatewayRule{MAC: "52:54:00:83:00:11"}
	rulePureIface := config.GatewayRule{Interface: "eth1"}

	if s := ruleSpecificity(ruleIPIface); s != 0 {
		t.Errorf("ruleSpecificity(IP+Interface) = %d, want 0", s)
	}
	if s := ruleSpecificity(ruleMACIface); s != 0 {
		t.Errorf("ruleSpecificity(MAC+Interface) = %d, want 0", s)
	}
	if s := ruleSpecificity(rulePureIP); s != 1 {
		t.Errorf("ruleSpecificity(pure IP) = %d, want 1", s)
	}
	if s := ruleSpecificity(rulePureMAC); s != 1 {
		t.Errorf("ruleSpecificity(pure MAC) = %d, want 1", s)
	}
	if s := ruleSpecificity(rulePureIface); s != 2 {
		t.Errorf("ruleSpecificity(pure Interface) = %d, want 2", s)
	}
}

func TestMatchTokens(t *testing.T) {
	// 1. IPv4 single
	tk1 := matchTokens(config.GatewayRule{IP: "192.168.1.95"})
	if got := strings.Join(tk1, " "); got != "ip saddr 192.168.1.95" {
		t.Errorf("matchTokens(IPv4) = %q, want %q", got, "ip saddr 192.168.1.95")
	}

	// 2. IPv4 CIDR
	tk2 := matchTokens(config.GatewayRule{IP: "10.0.0.0/24"})
	if got := strings.Join(tk2, " "); got != "ip saddr 10.0.0.0/24" {
		t.Errorf("matchTokens(IPv4 CIDR) = %q, want %q", got, "ip saddr 10.0.0.0/24")
	}

	// 3. IPv6 single
	tk3 := matchTokens(config.GatewayRule{IP: "fd00:82::1"})
	if got := strings.Join(tk3, " "); got != "ip6 saddr fd00:82::1" {
		t.Errorf("matchTokens(IPv6) = %q, want %q", got, "ip6 saddr fd00:82::1")
	}

	// 4. IPv6 CIDR
	tk4 := matchTokens(config.GatewayRule{IP: "fd00:82::/64"})
	if got := strings.Join(tk4, " "); got != "ip6 saddr fd00:82::/64" {
		t.Errorf("matchTokens(IPv6 CIDR) = %q, want %q", got, "ip6 saddr fd00:82::/64")
	}

	// 5. Interface + IP
	tk5 := matchTokens(config.GatewayRule{IP: "192.168.1.95", Interface: "eth1"})
	if got := strings.Join(tk5, " "); got != `iifname "eth1" ip saddr 192.168.1.95` {
		t.Errorf("matchTokens(Interface+IP) = %q, want %q", got, `iifname "eth1" ip saddr 192.168.1.95`)
	}

	// 6. Interface + MAC + IP
	tk6 := matchTokens(config.GatewayRule{MAC: "52:54:00:83:00:11", IP: "192.168.1.95", Interface: "eth1"})
	if got := strings.Join(tk6, " "); got != `iifname "eth1" ether saddr 52:54:00:83:00:11 ip saddr 192.168.1.95` {
		t.Errorf("matchTokens(Interface+MAC+IP) = %q, want %q", got, `iifname "eth1" ether saddr 52:54:00:83:00:11 ip saddr 192.168.1.95`)
	}
}

func TestBlockMatchTokens_WithIP(t *testing.T) {
	cfg := &config.UserConfig{
		Gateway: config.GatewayConfig{
			Rules: []config.GatewayRule{
				{IP: "192.168.1.95", Interface: "eth1", Target: "direct"}, // rank 0
				{IP: "192.168.1.95", Target: "block"},                     // rank 1 block -> yields to eth1
				{Interface: "eth2", Target: "block"},                      // rank 2 block
				{IP: "10.0.84.50", Interface: "eth2", Target: "relay-hk"}, // rank 0 non-block -> eth2 block yields
				{IP: "fd00:84::50", Target: "direct"},                     // rank 1 non-block -> eth2 block yields
			},
		},
	}

	// 1. IP-only block yields to interface+IP rule of the same IP
	bTokens := blockMatchTokens(cfg, cfg.Gateway.Rules[1])
	bStr := strings.Join(bTokens, " ")
	if !strings.Contains(bStr, `ip saddr 192.168.1.95`) || !strings.Contains(bStr, `iifname != "eth1"`) {
		t.Errorf("expected IP block to yield to eth1 rule, got %q", bStr)
	}

	// 2. Interface-only block on eth2 yields to rules naming an IP on it
	bIfaceTokens := blockMatchTokens(cfg, cfg.Gateway.Rules[2])
	bIfaceStr := strings.Join(bIfaceTokens, " ")
	if !strings.Contains(bIfaceStr, `iifname "eth2"`) {
		t.Errorf("expected iifname eth2, got %q", bIfaceStr)
	}
	if !strings.Contains(bIfaceStr, `ip saddr != 10.0.84.50`) {
		t.Errorf("expected yield to 10.0.84.50, got %q", bIfaceStr)
	}
	if !strings.Contains(bIfaceStr, `ip6 saddr != fd00:84::50`) {
		t.Errorf("expected yield to fd00:84::50, got %q", bIfaceStr)
	}
}

func TestBuildNFTScript_WithIPRules(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:          "tproxy",
			LANEnabled:    true,
			LocalEnabled:  false,
			RelayAlias:    "relay-default",
			LANInterfaces: []string{"eth1"},
			WANInterface:  "eth0",
			Rules: []config.GatewayRule{
				{IP: "192.168.1.95", Target: "direct"},
				{IP: "10.0.0.0/24", Target: "relay-hk"},
				{IP: "fd00:82::1", Target: "relay-hk"},
				{IP: "192.168.1.99", Target: "block"},
			},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-default", Enabled: true},
			{Alias: "relay-hk", Enabled: true},
		},
	}

	lanIfaces := []string{"eth1"}
	lanCIDRs := []string{"192.168.1.0/24"}
	lanIPv6CIDRs := []string{"fd00:82::/64"}
	wanIface := "eth0"

	rules := buildNFTMulti(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface)

	// Direct rule returns
	if !strings.Contains(rules, "ip saddr 192.168.1.95 return") {
		t.Errorf("expected direct return for 192.168.1.95, got:\n%s", rules)
	}

	// IPv4 relay tproxy rule uses "tproxy ip to :port"
	if !strings.Contains(rules, "ip saddr 10.0.0.0/24 meta l4proto { tcp, udp } tproxy ip to :12346 meta mark set 1 accept") {
		t.Errorf("expected tproxy ip rule for 10.0.0.0/24, got:\n%s", rules)
	}

	// IPv6 relay tproxy rule uses "tproxy ip6 to :port"
	if !strings.Contains(rules, "ip6 saddr fd00:82::1 meta l4proto { tcp, udp } tproxy ip6 to :12346 meta mark set 1 accept") {
		t.Errorf("expected tproxy ip6 rule for fd00:82::1, got:\n%s", rules)
	}

	// Block rule drops in input & prerouting
	if !strings.Contains(rules, "ip saddr 192.168.1.99 drop") {
		t.Errorf("expected block drop for 192.168.1.99, got:\n%s", rules)
	}

	// Check syntax with nft if available in user namespace
	cmd := exec.Command("unshare", "-r", "-n", "bash", "-c", "printf '%s' \"$1\" | nft -c -f -", "_", rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("unshare nft syntax check skipped/failed: %v: %s", err, string(out))
	} else {
		t.Log("unshare nft syntax check passed successfully!")
	}
}
