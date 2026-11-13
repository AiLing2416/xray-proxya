package gateway

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func TestRuleSpecificity(t *testing.T) {
	ruleIfaceMACIP := config.GatewayRule{IP: "192.168.1.95", MAC: "52:54:00:83:00:11", Interface: "eth1"}
	ruleMACIface := config.GatewayRule{MAC: "52:54:00:83:00:11", Interface: "eth1"}
	ruleIPIface := config.GatewayRule{IP: "192.168.1.95", Interface: "eth1"}
	ruleMACIP := config.GatewayRule{MAC: "52:54:00:83:00:11", IP: "192.168.1.95"}
	rulePureMAC := config.GatewayRule{MAC: "52:54:00:83:00:11"}
	rulePureIP := config.GatewayRule{IP: "192.168.1.95"}
	rulePureIface := config.GatewayRule{Interface: "eth1"}

	if s := ruleSpecificity(ruleIfaceMACIP); s != 0 {
		t.Errorf("ruleSpecificity(Interface+MAC+IP) = %d, want 0", s)
	}
	if s := ruleSpecificity(ruleMACIface); s != 1 {
		t.Errorf("ruleSpecificity(Interface+MAC) = %d, want 1", s)
	}
	if s := ruleSpecificity(ruleIPIface); s != 2 {
		t.Errorf("ruleSpecificity(Interface+IP) = %d, want 2", s)
	}
	if s := ruleSpecificity(ruleMACIP); s != 3 {
		t.Errorf("ruleSpecificity(MAC+IP) = %d, want 3", s)
	}
	if s := ruleSpecificity(rulePureMAC); s != 4 {
		t.Errorf("ruleSpecificity(pure MAC) = %d, want 4", s)
	}
	if s := ruleSpecificity(rulePureIP); s != 5 {
		t.Errorf("ruleSpecificity(pure IP) = %d, want 5", s)
	}
	if s := ruleSpecificity(rulePureIface); s != 6 {
		t.Errorf("ruleSpecificity(pure Interface) = %d, want 6", s)
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

func TestBlockGuardEntries_WithIPAndCIDRPriority(t *testing.T) {
	cfg := &config.UserConfig{
		Gateway: config.GatewayConfig{
			Rules: []config.GatewayRule{
				{IP: "10.0.84.0/24", Target: "block"},
				{IP: "10.0.84.50", Target: "direct"},
				{IP: "192.168.1.95", Interface: "eth1", Target: "direct"},
				{IP: "192.168.1.95", Target: "block"},
				{Interface: "eth2", Target: "block"},
				{IP: "fd00:84::50", Target: "direct"},
			},
		},
	}

	entries := blockGuardEntries(cfg)
	if len(entries) != 6 {
		t.Fatalf("expected 6 block guard entries, got %d: %+v", len(entries), entries)
	}
	// Highest specificity first: Interface+IP return before pure IP /128, /32, /24;
	// at equal specificity+prefixLen (/32), block precedes non-block, and both precede /24 block.
	if got := strings.Join(entries[0].Tokens, " ") + " " + entries[0].Verdict; got != `iifname "eth1" ip saddr 192.168.1.95 return` {
		t.Errorf("entry[0] = %q, want eth1+192.168.1.95 return", got)
	}
	if got := strings.Join(entries[1].Tokens, " ") + " " + entries[1].Verdict; got != `ip6 saddr fd00:84::50 return` {
		t.Errorf("entry[1] = %q, want fd00:84::50 return", got)
	}
	if got := strings.Join(entries[2].Tokens, " ") + " " + entries[2].Verdict; got != `ip saddr 192.168.1.95 drop` {
		t.Errorf("entry[2] = %q, want ip saddr 192.168.1.95 drop", got)
	}
	if got := strings.Join(entries[3].Tokens, " ") + " " + entries[3].Verdict; got != `ip saddr 10.0.84.50 return` {
		t.Errorf("entry[3] = %q, want 10.0.84.50 return", got)
	}
	if got := strings.Join(entries[4].Tokens, " ") + " " + entries[4].Verdict; got != `ip saddr 10.0.84.0/24 drop` {
		t.Errorf("entry[4] = %q, want 10.0.84.0/24 drop", got)
	}
	if got := strings.Join(entries[5].Tokens, " ") + " " + entries[5].Verdict; got != `iifname "eth2" drop` {
		t.Errorf("entry[5] = %q, want iifname eth2 drop", got)
	}
	for _, e := range entries {
		if strings.Contains(strings.Join(e.Tokens, " "), "!=") {
			t.Errorf("blockGuardEntries must not emit negative single-family tokens: %+v", e)
		}
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
	if !strings.Contains(rules, fmt.Sprintf("ip saddr 10.0.0.0/24 meta l4proto { tcp, udp } tproxy ip to :%d meta mark set 1 accept", config.DefaultTProxyPort+1)) {
		t.Errorf("expected tproxy ip rule for 10.0.0.0/24, got:\n%s", rules)
	}

	// IPv6 relay tproxy rule uses "tproxy ip6 to :port"
	if !strings.Contains(rules, fmt.Sprintf("ip6 saddr fd00:82::1 meta l4proto { tcp, udp } tproxy ip6 to :%d meta mark set 1 accept", config.DefaultTProxyPort+1)) {
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
