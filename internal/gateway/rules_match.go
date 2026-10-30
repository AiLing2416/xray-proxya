package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"xray-proxya/internal/config"
)

func quoteIface(name string) string { return `"` + name + `"` }

func isBlockRule(r config.GatewayRule) bool {
	return strings.EqualFold(strings.TrimSpace(r.Target), "block")
}

func isIPv6(ipOrCIDR string) bool {
	if strings.Contains(ipOrCIDR, "/") {
		if prefix, err := netip.ParsePrefix(ipOrCIDR); err == nil {
			return prefix.Addr().Is6()
		}
	}
	if addr, err := netip.ParseAddr(ipOrCIDR); err == nil {
		return addr.Is6()
	}
	return strings.Contains(ipOrCIDR, ":")
}

// ruleSpecificity ranks gateway rules: interface+MAC / interface+IP (0) beats
// MAC-only / IP-only (1) beats interface-only (2). Lower values are evaluated first.
func ruleSpecificity(r config.GatewayRule) int {
	switch {
	case (r.MAC != "" || r.IP != "") && r.Interface != "":
		return 0
	case r.MAC != "" || r.IP != "":
		return 1
	default:
		return 2
	}
}

// sortedGatewayRules returns the rules matching keep, ordered by specificity
// (stable with respect to configuration order within the same rank).
func sortedGatewayRules(cfg *config.UserConfig, block bool) []config.GatewayRule {
	var out []config.GatewayRule
	for _, r := range cfg.Gateway.Rules {
		if (r.MAC == "" && r.Interface == "" && r.IP == "") || isBlockRule(r) != block {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return ruleSpecificity(out[i]) < ruleSpecificity(out[j]) })
	return out
}

// matchTokens returns the nft match expression for a rule's selector.
func matchTokens(r config.GatewayRule) []string {
	var t []string
	if r.Interface != "" {
		t = append(t, "iifname", quoteIface(r.Interface))
	}
	if r.MAC != "" {
		t = append(t, "ether", "saddr", r.MAC)
	}
	if r.IP != "" {
		if isIPv6(r.IP) {
			t = append(t, "ip6", "saddr", r.IP)
		} else {
			t = append(t, "ip", "saddr", r.IP)
		}
	}
	return t
}

// blockMatchTokens returns the selector of a block rule, excluding clients that
// a strictly more specific non-block rule claims, so that specificity (not rule
// class) decides which rule wins.
func blockMatchTokens(cfg *config.UserConfig, r config.GatewayRule) []string {
	t := matchTokens(r)
	for _, o := range cfg.Gateway.Rules {
		if isBlockRule(o) || (o.MAC == "" && o.Interface == "" && o.IP == "") {
			continue
		}
		switch ruleSpecificity(r) {
		case 1: // MAC/IP-only block yields to interface+MAC/IP rules of the same MAC/IP.
			if r.MAC != "" && o.MAC == r.MAC && o.Interface != "" {
				t = append(t, "iifname", "!=", quoteIface(o.Interface))
			}
			if r.IP != "" && o.IP == r.IP && o.Interface != "" {
				t = append(t, "iifname", "!=", quoteIface(o.Interface))
			}
		case 2: // interface-only block yields to rules naming a MAC or IP on it.
			if o.MAC != "" && (o.Interface == "" || o.Interface == r.Interface) {
				t = append(t, "ether", "saddr", "!=", o.MAC)
			}
			if o.IP != "" && (o.Interface == "" || o.Interface == r.Interface) {
				if isIPv6(o.IP) {
					t = append(t, "ip6", "saddr", "!=", o.IP)
				} else {
					t = append(t, "ip", "saddr", "!=", o.IP)
				}
			}
		}
	}
	return t
}

// blockRuleTokens lists the match expressions of every block rule.
func blockRuleTokens(cfg *config.UserConfig) [][]string {
	var out [][]string
	for _, r := range sortedGatewayRules(cfg, true) {
		out = append(out, blockMatchTokens(cfg, r))
	}
	return out
}

// splitCIDRs splits a comma separated CIDR list (one element per interface may
// carry several prefixes) and drops empty items.
func splitCIDRs(list string) []string {
	var out []string
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func flattenCIDRs(lists []string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, splitCIDRs(l)...)
	}
	return out
}

// nftAddrSet renders a CIDR list as a single prefix or an anonymous set.
func nftAddrSet(list string) string {
	items := splitCIDRs(list)
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return "{ " + strings.Join(items, ", ") + " }"
}

// getInterfaceIPv6CIDRs returns every global (non link-local) IPv6 prefix of an
// interface, e.g. both a ULA and a GUA prefix.
func getInterfaceIPv6CIDRs(name string) ([]string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.To4() != nil || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsLoopback() {
			continue
		}
		cidr := (&net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask), Mask: ipNet.Mask}).String()
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv6 subnet found on %s", name)
	}
	return out, nil
}

// collectLANCIDRs gathers per-interface subnets, index-aligned with lanIfaces.
// IPv6 entries may carry several comma separated prefixes. A missing IPv4
// subnet is an error only when requireV4 is set.
func collectLANCIDRs(lanIfaces []string, requireV4 bool) (v4, v6 []string, err error) {
	for _, iface := range lanIfaces {
		c4, e := getInterfaceCIDR(iface)
		if e != nil {
			if requireV4 {
				return nil, nil, fmt.Errorf("detect LAN subnet for %s: %w", iface, e)
			}
			c4 = ""
		}
		v4 = append(v4, c4)
		c6s, _ := getInterfaceIPv6CIDRs(iface)
		v6 = append(v6, strings.Join(c6s, ","))
	}
	return v4, v6, nil
}

// filterRuleArgs converts match tokens into args for insertFilterRules.
func filterRuleArgs(tokens []string, verdict string) []string {
	return append(append([]string{}, tokens...), verdict)
}

// installBlockFilterRules installs the configured block rules into the system
// inet filter table (input + forward), for states where the managed table is
// not installed (forward-only, or proxy state with both Local and LAN off).
func installBlockFilterRules(cfg *config.UserConfig) error {
	blocks := blockRuleTokens(cfg)
	if len(blocks) == 0 {
		return nil
	}
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority filter; }")
	var rules [][]string
	for _, tk := range blocks {
		rules = append(rules, filterRuleArgs(tk, "drop"))
	}
	if err := insertFilterRules("forward", rules...); err != nil {
		return err
	}
	return insertFilterRules("input", rules...)
}
