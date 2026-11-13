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

func isDirectRule(r config.GatewayRule) bool {
	return strings.EqualFold(strings.TrimSpace(r.Target), "direct")
}

func isIPv6(ipOrCIDR string) bool {
	s := strings.TrimSpace(ipOrCIDR)
	if strings.Contains(s, "/") {
		if prefix, err := netip.ParsePrefix(s); err == nil {
			return prefix.Addr().Is6()
		}
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is6()
	}
	return strings.Contains(s, ":")
}

// ruleIPPrefixLen returns the prefix length of r.IP (32 for IPv4 host, 128 for
// IPv6 host, or CIDR bits), or 0 when r.IP is empty/unparseable.
func ruleIPPrefixLen(ipOrCIDR string) int {
	s := strings.TrimSpace(ipOrCIDR)
	if s == "" {
		return 0
	}
	if strings.Contains(s, "/") {
		if prefix, err := netip.ParsePrefix(s); err == nil {
			return prefix.Bits()
		}
		return 0
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Is6() {
			return 128
		}
		return 32
	}
	return 0
}

// ruleSpecificity ranks gateway client rules from most specific (0) to least
// specific (6):
//
//	0: Interface + MAC + IP
//	1: Interface + MAC
//	2: Interface + IP
//	3: MAC + IP
//	4: MAC
//	5: IP
//	6: Interface
func ruleSpecificity(r config.GatewayRule) int {
	hasIface := strings.TrimSpace(r.Interface) != ""
	hasMAC := strings.TrimSpace(r.MAC) != ""
	hasIP := strings.TrimSpace(r.IP) != ""

	switch {
	case hasIface && hasMAC && hasIP:
		return 0
	case hasIface && hasMAC:
		return 1
	case hasIface && hasIP:
		return 2
	case hasMAC && hasIP:
		return 3
	case hasMAC:
		return 4
	case hasIP:
		return 5
	default:
		return 6
	}
}

// sortedAllClientRules returns all non-empty client rules sorted by:
//  1. specificity rank ascending (most specific first)
//  2. IP prefix length descending (/32 or /128 before /28 before /24)
//  3. block rules before non-block rules at identical specificity
//  4. original configuration order (stable sort)
func sortedAllClientRules(cfg *config.UserConfig) []config.GatewayRule {
	if cfg == nil {
		return nil
	}
	var out []config.GatewayRule
	for _, r := range cfg.Gateway.Rules {
		if strings.TrimSpace(r.MAC) == "" && strings.TrimSpace(r.Interface) == "" && strings.TrimSpace(r.IP) == "" {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := ruleSpecificity(out[i]), ruleSpecificity(out[j])
		if si != sj {
			return si < sj
		}
		pi, pj := ruleIPPrefixLen(out[i].IP), ruleIPPrefixLen(out[j].IP)
		if pi != pj {
			return pi > pj
		}
		bi, bj := isBlockRule(out[i]), isBlockRule(out[j])
		if bi != bj {
			return bi
		}
		return false
	})
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

type blockGuardEntry struct {
	Tokens  []string
	Verdict string // "drop" or "return"
}

// blockGuardEntries builds the ordered sequence of return/drop rules up to the
// last block or dangling-relay rule in sortedAllClientRules. Placing
// higher-priority non-block exceptions as "return" before broader "drop" rules
// avoids negative single-family match tokens (e.g. `ip saddr != ...`) that
// would leak IPv6 in table inet.
func blockGuardEntries(cfg *config.UserConfig) []blockGuardEntry {
	all := sortedAllClientRules(cfg)
	tproxyPorts := config.GatewayTProxyPorts(cfg)
	isRuleDrop := func(r config.GatewayRule) bool {
		if isBlockRule(r) {
			return true
		}
		if isDirectRule(r) {
			return false
		}
		target := strings.TrimSpace(r.Target)
		return tproxyPorts[target] <= 0 || !config.GatewayRelayActive(cfg, target)
	}
	lastDropIdx := -1
	for i, r := range all {
		if isRuleDrop(r) {
			lastDropIdx = i
		}
	}
	if lastDropIdx < 0 {
		return nil
	}
	entries := make([]blockGuardEntry, 0, lastDropIdx+1)
	for i := 0; i <= lastDropIdx; i++ {
		r := all[i]
		tokens := matchTokens(r)
		if len(tokens) == 0 {
			continue
		}
		verdict := "return"
		if isRuleDrop(r) {
			verdict = "drop"
		}
		entries = append(entries, blockGuardEntry{Tokens: tokens, Verdict: verdict})
	}
	return entries
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

// getInterfaceCIDRs returns every non-loopback IPv4 subnet prefix of an interface.
func getInterfaceCIDRs(name string) ([]string, error) {
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
		if !ok || ipNet.IP == nil || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
			continue
		}
		cidr := (&net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask), Mask: ipNet.Mask}).String()
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 subnet found on %s", name)
	}
	return out, nil
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
// Both IPv4 and IPv6 entries may carry several comma-separated prefixes. A
// missing IPv4 subnet is an error only when requireV4 is set.
func collectLANCIDRs(lanIfaces []string, requireV4 bool) (v4, v6 []string, err error) {
	for _, iface := range lanIfaces {
		c4s, e := getInterfaceCIDRs(iface)
		if e != nil {
			if requireV4 {
				return nil, nil, fmt.Errorf("detect LAN subnet for %s: %w", iface, e)
			}
			v4 = append(v4, "")
		} else {
			v4 = append(v4, strings.Join(c4s, ","))
		}
		c6s, _ := getInterfaceIPv6CIDRs(iface)
		v6 = append(v6, strings.Join(c6s, ","))
	}
	return v4, v6, nil
}

// installBlockFilterRules installs the configured block guard chain into the
// system inet filter table (input + forward), for states where the managed
// xray_proxya table is not installed (forward-only, or proxy state with both
// Local and LAN off).
func installBlockFilterRules(cfg *config.UserConfig) error {
	entries := blockGuardEntries(cfg)
	if len(entries) == 0 {
		return nil
	}
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "block_guard")
	_ = run("nft", "flush", "chain", "inet", "filter", "block_guard")
	for _, e := range entries {
		args := append([]string{"add", "rule", "inet", "filter", "block_guard"}, e.Tokens...)
		args = append(args, e.Verdict, "comment", `"xray-proxya"`)
		if err := run("nft", args...); err != nil {
			return fmt.Errorf("install filter block_guard rule %q: %w", strings.Join(e.Tokens, " "), err)
		}
	}
	if err := insertFilterRules("forward", []string{"jump", "block_guard"}); err != nil {
		return err
	}
	return insertFilterRules("input", []string{"jump", "block_guard"})
}
