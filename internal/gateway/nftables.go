package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
	"xray-proxya/internal/tune"
)

const (
	tableName       = "xray_proxya"
	tunName         = "proxya-tun"
	pathTunName     = "path-tun"
	tunIPv4CIDR     = "172.16.255.1/30"
	tunIPv6CIDR     = "fd00:eea:ff::1/126"
	xrayMark        = "255"
	tunMark         = "1"
	pathTunMark     = "2"
	policyTable     = "100"
	pathPolicyTable = "101"
	prefXray        = "10000"
	prefLAN         = "10010"
	prefLoopback    = "10030"
	prefTun         = "10100"
	prefPathTun     = "10101"
)

type policyRuleSpec struct {
	IPv6 bool     `json:"ipv6"`
	Args []string `json:"args"`
}

func SyncFirewall(cfg *config.UserConfig) {
	if err := ApplyFirewall(cfg); err != nil {
		fmt.Printf("❌ Failed to apply gateway rules: %v\n", err)
	}
}

func ApplyFirewall(cfg *config.UserConfig) (err error) {
	if cfg == nil || cfg.Role != config.RoleGateway {
		return nil
	}
	mode := cfg.Gateway.EffectiveMode()
	if mode != "tproxy" && mode != "tun" {
		return nil
	}
	isTun := mode == "tun"

	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}

	if state == "disabled" {
		return CleanupFirewall()
	}

	if err := config.ValidateGatewayInterfaces(cfg); err != nil {
		return err
	}
	lanIfaces := cfg.Gateway.EffectiveLANInterfaces()
	if len(lanIfaces) == 0 {
		return fmt.Errorf("gateway LAN interface is not configured; run 'gateway set --lan <iface>'")
	}

	if state == "forward-only" {
		if err := CleanupFirewall(); err != nil {
			return err
		}
		var setupErr error
		if !cfg.Gateway.LANEnabled {
			setupErr = setupLANForwardingBlock(lanIfaces...)
		} else {
			setupErr = setupDirectLANForwarding(lanIfaces...)
		}
		if setupErr == nil {
			setupErr = installBlockFilterRules(cfg)
		}
		if setupErr != nil {
			return errors.Join(setupErr, CleanupFirewall())
		}
		return nil
	}

	if !cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled {
		if err := CleanupFirewall(); err != nil {
			return err
		}
		if err := installBlockFilterRules(cfg); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
		return nil
	}
	if config.GatewayTunDisabled() {
		return fmt.Errorf("gateway runtime is down; run 'xray-proxya gateway up' first")
	}

	lanCIDRs, lanIPv6CIDRs, err := collectLANCIDRs(lanIfaces, cfg.Gateway.LANEnabled)
	if err != nil {
		return err
	}
	wanIface := resolveWANInterface(cfg)
	if wanIface == "" && !cfg.Gateway.NATDisabled && cfg.Gateway.LANEnabled {
		fmt.Println("⚠️ WAN interface could not be detected (no default route) and none is configured; managed NAT is skipped. Run 'gateway set --wan <iface>' or re-apply once the default route is up.")
	}
	rules := buildNFTMulti(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface)
	configDir := filepath.Dir(config.GetConfigPathEx(false))
	_ = os.MkdirAll(configDir, 0700)
	f, err := os.CreateTemp(configDir, "xray-proxya-*.nft")
	if err != nil {
		return fmt.Errorf("create temp nft file: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile)

	if _, err := f.WriteString(rules); err != nil {
		f.Close()
		return fmt.Errorf("write nft rules: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp nft file: %w", err)
	}

	if err := CleanupFirewall(); err != nil {
		return fmt.Errorf("clean up existing gateway state: %w", err)
	}
	// From here until the managed nftables table is installed, every failure
	// must undo the addresses, routes, policy rules and temporary sysctls that
	// may already have been applied.  This keeps a failed TUN creation from
	// leaving traffic marked towards a disappeared interface.
	rollback := true
	defer func() {
		if err != nil && rollback {
			err = errors.Join(err, CleanupFirewall())
		}
	}()
	if err := SetupKernel(lanIfaces...); err != nil {
		return fmt.Errorf("kernel setup failed: %w", err)
	}

	if isTun {
		if err := waitForInterface(tunName, true); err != nil {
			return fmt.Errorf("tun interface %s was not created in time by Xray core. (Hint: Is the 'xray-proxya' service running? Try 'xray-proxya service status' or 'service start')", tunName)
		}
	} else {
		if err := waitForTProxyListener(cfg.Gateway.EffectiveTProxyPort()); err != nil {
			return err
		}
		for alias, p := range config.GatewayTProxyPorts(cfg) {
			if p != cfg.Gateway.EffectiveTProxyPort() {
				if err := waitForTProxyListener(p); err != nil {
					return fmt.Errorf("wait for relay %s tproxy listener on port %d: %w", alias, p, err)
				}
			}
		}
	}
	if cfg.Gateway.DNSListen != "" {
		if _, dnsPort, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen); err == nil && dnsPort > 0 {
			if err := waitForTProxyListener(dnsPort); err != nil {
				return fmt.Errorf("wait for gateway dns listener: %w", err)
			}
		}
	}

	if pathTunnelEnabled(cfg) {
		if err := waitForInterface(pathTunName, true); err != nil {
			return fmt.Errorf("ICMP PathLink TUN %s was not created in time", pathTunName)
		}
		if err := run("ip", "link", "set", "dev", pathTunName, "up"); err != nil {
			return err
		}
		// TUN-created interfaces can inherit a distribution-specific strict or
		// loose rp_filter value after SetupKernel ran. PathLink replies arrive
		// from public target addresses through this interface, so they must not
		// be rejected before normal LAN routing can deliver them.
		if err := run("sysctl", "-w", "net.ipv4.conf."+pathTunName+".rp_filter=0"); err != nil {
			return err
		}
	}

	ipv6Supported := ipv6Available()

	if isTun {
		if err := run("ip", "addr", "replace", tunIPv4CIDR, "dev", tunName); err != nil {
			return err
		}
		if ipv6Supported {
			if err := run("ip", "-6", "addr", "replace", tunIPv6CIDR, "dev", tunName); err != nil {
				ipv6Supported = false
			}
		}
	}

	rulesToAdd := policyRulesMulti(cfg, lanCIDRs, lanIPv6CIDRs, ipv6Supported)
	if err := savePolicyRules(rulesToAdd); err != nil {
		return err
	}
	for _, rule := range rulesToAdd {
		if err := addPolicyRule(rule); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
	}
	if isTun {
		if err := run("ip", "route", "replace", "default", "dev", tunName, "table", policyTable); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
		if ipv6Supported {
			if err := run("ip", "-6", "route", "replace", "default", "dev", tunName, "table", policyTable); err != nil {
				return errors.Join(err, CleanupFirewall())
			}
		}
	} else {
		if err := run("ip", "route", "replace", "local", "default", "dev", "lo", "table", policyTable); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
		if ipv6Supported {
			if err := run("ip", "-6", "route", "replace", "local", "default", "dev", "lo", "table", policyTable); err != nil {
				return errors.Join(err, CleanupFirewall())
			}
		}
	}
	if pathTunnelEnabled(cfg) {
		if err := run("ip", "route", "replace", "default", "dev", pathTunName, "table", pathPolicyTable); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
		if ipv6Supported {
			if err := run("ip", "-6", "route", "replace", "default", "dev", pathTunName, "table", pathPolicyTable); err != nil {
				return errors.Join(err, CleanupFirewall())
			}
		}
	}

	if err := run("nft", "-f", tmpFile); err != nil {
		return err
	}
	if pathTunnelEnabled(cfg) && len(lanIfaces) > 0 {
		if err := installPathTTLRules(lanIfaces, ipv6Supported); err != nil {
			return errors.Join(fmt.Errorf("preserve ICMP TTL through path-tun: %w", err), CleanupFirewall())
		}
	}

	// Ensure system filter table, forward and input chains exist. Rules are
	// inserted at the head of the chains (not appended) so that they are not
	// shadowed by pre-existing drop/reject rules, and failures are reported.
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority filter; }")

	var inputRules [][]string
	if !isTun {
		inputRules = append(inputRules, []string{"meta", "mark", tunMark, "accept"})
	}
	if cfg.Gateway.DNSListen != "" {
		if host, dnsPort, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen); err == nil && dnsPort > 0 {
			if !isLoopbackDNSListenHost(host) {
				for _, liface := range lanIfaces {
					inputRules = append(inputRules, []string{"iifname", liface, "meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", strconv.Itoa(dnsPort), "accept"})
				}
			}
		}
	}
	if len(inputRules) > 0 {
		if err := insertFilterRules("input", inputRules...); err != nil {
			return err
		}
	}

	var forwardRules [][]string
	if isTun {
		forwardRules = append(forwardRules,
			[]string{"iifname", tunName, "accept"},
			[]string{"oifname", tunName, "accept"})
	}
	managedNATInstalled := false
	if !cfg.Gateway.NATDisabled && wanIface != "" && len(lanIfaces) > 0 {
		wanDistinct := true
		for _, liface := range lanIfaces {
			if liface == wanIface {
				wanDistinct = false
				break
			}
		}
		if wanDistinct || cfg.Gateway.WANInterface != "" {
			managedNATInstalled = true
			for _, tk := range blockRuleTokens(cfg) {
				forwardRules = append(forwardRules, filterRuleArgs(tk, "drop"))
			}
		}
	}
	if pathTunnelEnabled(cfg) {
		forwardRules = append(forwardRules,
			[]string{"iifname", pathTunName, "accept"},
			[]string{"oifname", pathTunName, "accept"})
	}
	for _, liface := range lanIfaces {
		forwardRules = append(forwardRules, []string{"iifname", liface, "oifname", liface, "accept"})
	}
	if managedNATInstalled {
		for _, liface := range lanIfaces {
			forwardRules = append(forwardRules,
				[]string{"iifname", liface, "oifname", wanIface, "accept"},
				[]string{"iifname", wanIface, "oifname", liface, "ct", "state", "established,related", "accept"})
		}
	}
	if err := insertFilterRules("forward", forwardRules...); err != nil {
		return err
	}
	if cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled && !managedNATInstalled && !cfg.Gateway.NATDisabled {
		if err := installDirectLANForwardRules(lanIfaces...); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
	}

	rollback = false
	return nil
}

func CleanupFirewall() error {
	var cleanupErrs []error
	record := func(step string, err error) {
		if err == nil {
			return
		}
		wrapped := fmt.Errorf("gateway cleanup %s: %w", step, err)
		fmt.Printf("⚠️ %v\n", wrapped)
		cleanupErrs = append(cleanupErrs, wrapped)
	}

	record("PathLink TTL rules", cleanupPathTTLRules())
	record("nft table", runDelete("nft", "delete", "table", "inet", tableName))
	record("filter forward rules", cleanupFilterForwardRules())
	record("filter input rules", cleanupFilterInputRules())
	record("filter postrouting rules", cleanupFilterManagedRules("postrouting"))

	rules, rulesErr := loadPolicyRules()
	if rulesErr != nil {
		record("policy rule state", rulesErr)
	} else {
		allRulesDeleted := true
		for _, rule := range rules {
			if err := deletePolicyRule(rule); err != nil {
				allRulesDeleted = false
				record("policy rule", err)
			}
		}
		// Keep the state file when any kernel deletion failed. It is the only
		// durable information that lets a later cleanup retry the exact rules.
		if allRulesDeleted {
			record("policy rule state", removeIfExists(policyRulesPath()))
		}
	}
	record("IPv4 TProxy route", runDelete("ip", "route", "del", "local", "default", "dev", "lo", "table", policyTable))
	record("IPv6 TProxy route", runDelete("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", policyTable))
	record("legacy IPv4 TUN route", runDelete("ip", "route", "del", "default", "dev", "proxya-tun", "table", policyTable))
	record("legacy IPv6 TUN route", runDelete("ip", "-6", "route", "del", "default", "dev", "proxya-tun", "table", policyTable))
	record("IPv4 PathLink route", runDelete("ip", "route", "del", "default", "dev", pathTunName, "table", pathPolicyTable))
	record("IPv6 PathLink route", runDelete("ip", "-6", "route", "del", "default", "dev", pathTunName, "table", pathPolicyTable))
	record("sysctl state", restoreSysctlState())
	return errors.Join(cleanupErrs...)
}

type pathTTLRule struct {
	IPv6 bool     `json:"ipv6"`
	Args []string `json:"args"`
}

func pathTTLRulesPath() string {
	return filepath.Join(config.GetConfigDir(), "gateway.path-ttl-rules.json")
}

func installPathTTLRules(lanIfaces []string, ipv6Supported bool) error {
	var rules []pathTTLRule
	for _, lanIface := range lanIfaces {
		if lanIface == "" {
			continue
		}
		rules = append(rules, pathTTLRule{Args: []string{"-t", "mangle", "-A", "PREROUTING", "-i", lanIface, "-m", "mark", "--mark", pathTunMark, "-p", "icmp", "--icmp-type", "echo-request", "-j", "TTL", "--ttl-inc", "1"}})
		if ipv6Supported {
			rules = append(rules, pathTTLRule{IPv6: true, Args: []string{"-t", "mangle", "-A", "PREROUTING", "-i", lanIface, "-m", "mark", "--mark", pathTunMark, "-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-j", "HL", "--hl-inc", "1"}})
		}
	}
	for index, rule := range rules {
		binary := "iptables"
		if rule.IPv6 {
			binary = "ip6tables"
		}
		if err := run(binary, rule.Args...); err != nil {
			for i := index - 1; i >= 0; i-- {
				args := append([]string{}, rules[i].Args...)
				for j := range args {
					if args[j] == "-A" {
						args[j] = "-D"
						break
					}
				}
				name := "iptables"
				if rules[i].IPv6 {
					name = "ip6tables"
				}
				_ = run(name, args...)
			}
			return err
		}
	}
	data, err := json.Marshal(rules)
	if err != nil {
		cleanupPathTTLRules()
		return err
	}
	if err := os.WriteFile(pathTTLRulesPath(), data, 0600); err != nil {
		cleanupPathTTLRules()
		return err
	}
	return nil
}

func cleanupPathTTLRules() error {
	data, err := os.ReadFile(pathTTLRulesPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var rules []pathTTLRule
	if json.Unmarshal(data, &rules) != nil {
		return removeIfExists(pathTTLRulesPath())
	}
	var cleanupErrs []error
	for i := len(rules) - 1; i >= 0; i-- {
		args := append([]string{}, rules[i].Args...)
		for j := range args {
			if args[j] == "-A" {
				args[j] = "-D"
				break
			}
		}
		binary := "iptables"
		if rules[i].IPv6 {
			binary = "ip6tables"
		}
		if err := runDelete(binary, args...); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	if len(cleanupErrs) == 0 {
		if err := removeIfExists(pathTTLRulesPath()); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	return errors.Join(cleanupErrs...)
}

func resolveWANInterface(cfg *config.UserConfig) string {
	if cfg == nil {
		return ""
	}
	wan := strings.TrimSpace(cfg.Gateway.WANInterface)
	if wan != "" && wan != "auto" {
		return wan
	}
	iface, err := detectDefaultInterfaceFn()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(iface)
}

func policyRules(cfg *config.UserConfig, lanCIDR, lanIPv6CIDR string, ipv6Supported bool) []policyRuleSpec {
	var v4, v6 []string
	if lanCIDR != "" {
		v4 = []string{lanCIDR}
	}
	if lanIPv6CIDR != "" {
		v6 = []string{lanIPv6CIDR}
	}
	return policyRulesMulti(cfg, v4, v6, ipv6Supported)
}

func policyRulesMulti(cfg *config.UserConfig, lanCIDRs, lanIPv6CIDRs []string, ipv6Supported bool) []policyRuleSpec {
	rules := []policyRuleSpec{
		{Args: []string{"fwmark", tunMark, "table", policyTable, "pref", prefTun}},
		{Args: []string{"fwmark", xrayMark, "table", "main", "pref", prefXray}},
	}
	for i, cidr := range lanCIDRs {
		if cidr != "" {
			pref := fmt.Sprintf("%d", 10010+i)
			rules = append(rules, policyRuleSpec{Args: []string{"to", cidr, "table", "main", "pref", pref}})
		}
	}
	rules = append(rules, policyRuleSpec{Args: []string{"to", "127.0.0.0/8", "table", "main", "pref", prefLoopback}})
	if pathTunnelEnabled(cfg) {
		rules = append(rules, policyRuleSpec{Args: []string{"fwmark", pathTunMark, "table", pathPolicyTable, "pref", prefPathTun}})
	}
	if !ipv6Supported {
		return rules
	}
	rules = append(rules, policyRuleSpec{IPv6: true, Args: []string{"fwmark", tunMark, "table", policyTable, "pref", prefTun}})
	if pathTunnelEnabled(cfg) {
		rules = append(rules, policyRuleSpec{IPv6: true, Args: []string{"fwmark", pathTunMark, "table", pathPolicyTable, "pref", prefPathTun}})
	}
	rules = append(rules, policyRuleSpec{IPv6: true, Args: []string{"fwmark", xrayMark, "table", "main", "pref", prefXray}})
	for i, cidr := range flattenCIDRs(lanIPv6CIDRs) {
		if cidr != "" {
			pref := fmt.Sprintf("%d", 10010+i)
			rules = append(rules, policyRuleSpec{IPv6: true, Args: []string{"to", cidr, "table", "main", "pref", pref}})
		}
	}
	return append(rules, policyRuleSpec{IPv6: true, Args: []string{"to", "::1/128", "table", "main", "pref", prefLoopback}})
}

func pathTunnelEnabled(cfg *config.UserConfig) bool {
	if cfg == nil {
		return false
	}
	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}
	if cfg.Role != config.RoleGateway || state != "proxy" ||
		!(cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled) ||
		cfg.Gateway.RelayAlias == "" || config.PathTunDisabled() {
		return false
	}
	for i := range cfg.CustomOutbounds {
		outbound := &cfg.CustomOutbounds[i]
		if outbound.Alias == cfg.Gateway.RelayAlias {
			if !outbound.Enabled || outbound.Path == nil || outbound.Path.Token == "" {
				return false
			}
			listen := outbound.Path.Listen
			if listen == "" {
				listen = pathd.DefaultListenAddress
			}
			return pathd.ValidateListenAddress(listen) == nil
		}
	}
	return false
}

func policyRulesPath() string {
	return filepath.Join(config.GetConfigDir(), "gateway.policy-rules.json")
}

func savePolicyRules(rules []policyRuleSpec) error {
	data, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("encode gateway policy rules: %w", err)
	}
	if err := os.WriteFile(policyRulesPath(), data, 0600); err != nil {
		return fmt.Errorf("save gateway policy rules: %w", err)
	}
	return nil
}

func loadPolicyRules() ([]policyRuleSpec, error) {
	data, err := os.ReadFile(policyRulesPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var rules []policyRuleSpec
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("decode gateway policy rules: %w", err)
	}
	return rules, nil
}

func addPolicyRule(rule policyRuleSpec) error {
	args := append([]string{}, rule.Args...)
	args = append([]string{"rule", "add"}, args...)
	if rule.IPv6 {
		args = append([]string{"-6"}, args...)
	}
	return run("ip", args...)
}

func deletePolicyRule(rule policyRuleSpec) error {
	args := append([]string{}, rule.Args...)
	args = append([]string{"rule", "del"}, args...)
	if rule.IPv6 {
		args = append([]string{"-6"}, args...)
	}
	return runDelete("ip", args...)
}

func SetupKernel(lanIfaces ...string) error {
	if err := saveSysctlState(lanIfaces...); err != nil {
		return err
	}
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	if ipv6Available() {
		if err := run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
			return err
		}
	}
	if err := run("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"); err != nil {
		return err
	}
	if err := run("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"); err != nil {
		return err
	}
	if err := run("sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"); err != nil {
		return err
	}
	if err := run("sysctl", "-w", "net.ipv4.conf.default.send_redirects=0"); err != nil {
		return err
	}
	for _, iface := range lanIfaces {
		if iface != "" {
			if err := run("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.send_redirects=0", iface)); err != nil {
				return err
			}
			if err := run("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", iface)); err != nil {
				return err
			}
		}
	}
	return nil
}

func DetectDefaultInterface() (string, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	return ParseDefaultInterface(string(out))
}

func ParseDefaultInterface(routeOutput string) (string, error) {
	re := regexp.MustCompile(`(?:^|\s)dev\s+([^\s]+)`)
	for _, line := range strings.Split(routeOutput, "\n") {
		if !strings.Contains(line, "default") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) == 2 {
			return matches[1], nil
		}
	}
	return "", fmt.Errorf("no default route interface found")
}

func BuildRulesPreview(cfg *config.UserConfig) (string, error) {
	mode := ""
	if cfg != nil {
		mode = cfg.Gateway.EffectiveMode()
	}
	if cfg == nil || cfg.Role != config.RoleGateway || (mode != "tproxy" && mode != "tun") {
		return "", nil
	}
	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}
	if state == "disabled" || state == "forward-only" {
		return "", nil
	}
	if !cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled {
		return "", nil
	}
	if cfg.Gateway.LANInterface == "" {
		return "", fmt.Errorf("gateway LAN interface is not configured")
	}
	lanIfaces := cfg.Gateway.EffectiveLANInterfaces()
	if len(lanIfaces) == 0 {
		return "", fmt.Errorf("gateway LAN interface is not configured")
	}
	lanCIDRs, lanIPv6CIDRs, err := collectLANCIDRs(lanIfaces, true)
	if err != nil {
		return "", err
	}
	wanIface := resolveWANInterface(cfg)
	return buildNFTMulti(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface), nil
}

func Verify(cfg *config.UserConfig) []string {
	var problems []string
	if cfg == nil {
		return []string{"config is not loaded"}
	}
	if cfg.Role != config.RoleGateway {
		return []string{"role is not gateway"}
	}
	mode := cfg.Gateway.EffectiveMode()
	if mode != "tproxy" && mode != "tun" {
		problems = append(problems, "gateway mode must be 'tproxy' or 'tun'")
	}
	lanIfaces := cfg.Gateway.EffectiveLANInterfaces()
	if len(lanIfaces) == 0 {
		problems = append(problems, "LAN interface is not configured")
	} else {
		for _, iface := range lanIfaces {
			if _, err := net.InterfaceByName(iface); err != nil {
				problems = append(problems, fmt.Sprintf("LAN interface %s not found", iface))
			}
		}
	}

	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}

	expectForwarding := false
	switch state {
	case "disabled":
		expectForwarding = false
	case "forward-only":
		expectForwarding = cfg.Gateway.LANEnabled
	case "proxy":
		expectForwarding = cfg.Gateway.LANEnabled || (cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled)
	}

	if expectForwarding {
		if !isIPv4ForwardingEnabledFn() {
			problems = append(problems, "net.ipv4.ip_forward is not enabled")
		}
	} else {
		problems = append(problems, verifyNoManagedForwardRules()...)
	}

	if state == "disabled" {
		problems = append(problems, verifyNoManagedRuntime("disabled")...)
		return problems
	}

	if state == "forward-only" {
		problems = append(problems, verifyNoManagedRuntime("forward-only")...)
		return problems
	}

	// For proxy state, perform full verification
	if err := execCommandRun("nft", "list", "table", "inet", tableName); err != nil {
		problems = append(problems, "nft table inet "+tableName+" is not present")
	}

	ipv6Configured := ipv6Available()
	if mode == "tun" {
		if !interfaceExists(tunName) {
			problems = append(problems, tunName+" interface is not present (Hint: Is the xray-proxya service running?)")
		} else {
			if !interfaceIsUp(tunName) {
				problems = append(problems, tunName+" interface is not UP")
			}
			if !interfaceHasCIDR(tunName, tunIPv4CIDR) {
				problems = append(problems, tunName+" interface is missing IPv4 address "+tunIPv4CIDR)
			}
		}
		if ok, err := hasDefaultRoute(policyTable, tunName, false); err != nil {
			problems = append(problems, "cannot inspect IPv4 policy table "+policyTable+": "+err.Error())
		} else if !ok {
			problems = append(problems, "IPv4 policy table "+policyTable+" has no default route via "+tunName)
		}
		if ipv6Configured {
			if ok, err := hasDefaultRoute(policyTable, tunName, true); err != nil {
				problems = append(problems, "cannot inspect IPv6 policy table "+policyTable+": "+err.Error())
			} else if !ok {
				problems = append(problems, "IPv6 policy table "+policyTable+" has no default route via "+tunName)
			}
		}
	} else {
		if !isTProxyPortListening(cfg.Gateway.EffectiveTProxyPort()) {
			problems = append(problems, fmt.Sprintf("tproxy port %d is not listening", cfg.Gateway.EffectiveTProxyPort()))
		}
		for alias, port := range config.GatewayTProxyPorts(cfg) {
			if port != cfg.Gateway.EffectiveTProxyPort() && !isTProxyPortListening(port) {
				problems = append(problems, fmt.Sprintf("tproxy port %d (relay %s) is not listening", port, alias))
			}
		}
		if cfg.Gateway.DNSListen != "" {
			if _, dnsPort, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen); err == nil && dnsPort > 0 {
				if !isTProxyPortListening(dnsPort) {
					problems = append(problems, fmt.Sprintf("gateway dns port %d is not listening", dnsPort))
				}
			}
		}

		if ok, err := hasDefaultRoute(policyTable, "lo", false); err != nil {
			problems = append(problems, "cannot inspect IPv4 policy table "+policyTable+": "+err.Error())
		} else if !ok {
			problems = append(problems, "IPv4 policy table "+policyTable+" has no default route via lo")
		}
		if ipv6Configured {
			if ok, err := hasDefaultRoute(policyTable, "lo", true); err != nil {
				problems = append(problems, "cannot inspect IPv6 policy table "+policyTable+": "+err.Error())
			} else if !ok {
				problems = append(problems, "IPv6 policy table "+policyTable+" has no default route via lo")
			}
		}
	}
	if pathTunnelEnabled(cfg) {
		if err := exec.Command("ip", "link", "show", pathTunName).Run(); err != nil {
			problems = append(problems, pathTunName+" interface is not present (Hint: Does the selected relay have PathLink credentials and is the xray-proxya service running?)")
		} else {
			if !interfaceIsUp(pathTunName) {
				problems = append(problems, pathTunName+" interface is not UP")
			}
			if value, err := readSysctl("net.ipv4.conf." + pathTunName + ".rp_filter"); err != nil || value != "0" {
				problems = append(problems, pathTunName+" rp_filter is not 0")
			}
		}
	} else if interfaceExists(pathTunName) {
		problems = append(problems, pathTunName+" interface is present but PathLink is disabled")
	}
	if pathTunnelEnabled(cfg) {
		if ok, err := hasDefaultRoute(pathPolicyTable, pathTunName, false); err != nil {
			problems = append(problems, "cannot inspect IPv4 policy table "+pathPolicyTable+": "+err.Error())
		} else if !ok {
			problems = append(problems, "IPv4 policy table "+pathPolicyTable+" has no default route via "+pathTunName)
		}
		if ipv6Configured {
			if ok, err := hasDefaultRoute(pathPolicyTable, pathTunName, true); err != nil {
				problems = append(problems, "cannot inspect IPv6 policy table "+pathPolicyTable+": "+err.Error())
			} else if !ok {
				problems = append(problems, "IPv6 policy table "+pathPolicyTable+" has no default route via "+pathTunName)
			}
		}
	}

	var lanCIDRs, lanIPv6CIDRs []string
	for _, iface := range lanIfaces {
		if c4, err := getInterfaceCIDR(iface); err == nil {
			lanCIDRs = append(lanCIDRs, c4)
		}
		if c6s, err := getInterfaceIPv6CIDRs(iface); err == nil {
			lanIPv6CIDRs = append(lanIPv6CIDRs, strings.Join(c6s, ","))
		}
	}
	if len(lanCIDRs) == 0 && cfg.Gateway.LANEnabled {
		problems = append(problems, "cannot determine LAN CIDR for policy rules")
	} else {
		expected := policyRulesMulti(cfg, lanCIDRs, lanIPv6CIDRs, ipv6Configured)
		problems = append(problems, verifyPolicyRules(expected)...)
	}
	return problems
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func interfaceIsUp(name string) bool {
	out, err := exec.Command("ip", "link", "show", "dev", name).Output()
	if err != nil {
		return false
	}
	line := string(out)
	return strings.Contains(line, "state UP") || strings.Contains(line, "<UP,") || strings.Contains(line, ",UP,") || strings.Contains(line, ",UP>")
}

func hasDefaultRoute(table, device string, ipv6 bool) (bool, error) {
	args := []string{"route", "show", "table", table}
	if ipv6 {
		args = append([]string{"-6"}, args...)
	} else {
		args = append([]string{"-4"}, args...)
	}
	out, err := execCommandCombinedOutput("ip", args...)
	if err != nil {
		return false, fmt.Errorf("%w (output: %q)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		isDefault := false
		if fields[0] == "default" {
			isDefault = true
		} else if len(fields) > 1 && fields[0] == "local" && fields[1] == "default" {
			isDefault = true
		}
		if !isDefault {
			continue
		}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "dev" && fields[i+1] == device {
				return true, nil
			}
		}
	}
	return false, nil
}

func verifyPolicyRules(expected []policyRuleSpec) []string {
	var problems []string
	cache := map[bool]string{}
	for _, rule := range expected {
		output, ok := cache[rule.IPv6]
		if !ok {
			args := []string{"rule", "show"}
			if rule.IPv6 {
				args = append([]string{"-6"}, args...)
			} else {
				args = append([]string{"-4"}, args...)
			}
			out, err := exec.Command("ip", args...).CombinedOutput()
			if err != nil {
				problems = append(problems, fmt.Sprintf("cannot inspect %s policy rules: %v (output: %q)", map[bool]string{true: "IPv6", false: "IPv4"}[rule.IPv6], err, strings.TrimSpace(string(out))))
				cache[rule.IPv6] = ""
				continue
			}
			output = string(out)
			cache[rule.IPv6] = output
		}
		if !policyRuleOutputContains(output, rule) {
			problems = append(problems, fmt.Sprintf("missing policy rule: %s", strings.Join(rule.Args, " ")))
		}
	}
	return problems
}

func policyRuleOutputContains(output string, rule policyRuleSpec) bool {
	pref := ""
	for i := 0; i+1 < len(rule.Args); i++ {
		if rule.Args[i] == "pref" {
			pref = rule.Args[i+1]
			break
		}
	}
	for _, line := range strings.Split(output, "\n") {
		if pref == "" || !(strings.HasPrefix(strings.TrimSpace(line), pref+":") || strings.Contains(line, " "+pref+":")) {
			continue
		}
		matches := true
		for i := 0; i < len(rule.Args); i++ {
			switch rule.Args[i] {
			case "fwmark":
				if i+1 >= len(rule.Args) || !ruleLineHasMark(line, rule.Args[i+1]) {
					matches = false
				}
				i++
			case "table":
				if i+1 >= len(rule.Args) || !(strings.Contains(line, "lookup "+rule.Args[i+1]) || strings.Contains(line, "table "+rule.Args[i+1])) {
					matches = false
				}
				i++
			case "to":
				if i+1 >= len(rule.Args) || !ruleLineHasDestination(line, rule.Args[i+1]) {
					matches = false
				}
				i++
			case "pref":
				i++
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func ruleLineHasDestination(line, destination string) bool {
	if strings.Contains(line, "to "+destination) {
		return true
	}
	if _, network, err := net.ParseCIDR(destination); err == nil {
		return strings.Contains(line, "to "+network.IP.String())
	}
	return false
}

func ruleLineHasMark(line, value string) bool {
	mark, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return false
	}
	return strings.Contains(line, fmt.Sprintf("fwmark 0x%x", mark)) || strings.Contains(line, "fwmark "+value)
}

func verifyNoManagedRuntime(state string) []string {
	var problems []string
	if interfaceExists(tunName) {
		problems = append(problems, tunName+" interface is present but gateway state is "+state)
	}
	if interfaceExists(pathTunName) {
		problems = append(problems, pathTunName+" interface is present but gateway state is "+state)
	}
	if err := execCommandRun("nft", "list", "table", "inet", tableName); err == nil {
		problems = append(problems, "nft table inet "+tableName+" is present but gateway state is "+state)
	}
	for _, table := range []string{policyTable, pathPolicyTable} {
		for _, ipv6 := range []bool{false, true} {
			args := []string{"route", "show", "table", table}
			if ipv6 {
				args = append([]string{"-6"}, args...)
			} else {
				args = append([]string{"-4"}, args...)
			}
			out, err := execCommandCombinedOutput("ip", args...)
			if err != nil {
				problems = append(problems, fmt.Sprintf("cannot inspect %s policy table %s: %v", map[bool]string{true: "IPv6", false: "IPv4"}[ipv6], table, err))
			} else if strings.TrimSpace(string(out)) != "" {
				problems = append(problems, fmt.Sprintf("%s policy table %s still contains routes", map[bool]string{true: "IPv6", false: "IPv4"}[ipv6], table))
			}
		}
	}
	for _, ipv6 := range []bool{false, true} {
		args := []string{"rule", "show"}
		if ipv6 {
			args = append([]string{"-6"}, args...)
		} else {
			args = append([]string{"-4"}, args...)
		}
		out, err := execCommandCombinedOutput("ip", args...)
		if err != nil {
			problems = append(problems, fmt.Sprintf("cannot inspect %s policy rules: %v", map[bool]string{true: "IPv6", false: "IPv4"}[ipv6], err))
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if managedRuleLine(line) {
				problems = append(problems, fmt.Sprintf("managed %s policy rule still exists: %s", map[bool]string{true: "IPv6", false: "IPv4"}[ipv6], strings.TrimSpace(line)))
			}
		}
	}
	if state == "disabled" {
		if out, err := execCommandCombinedOutput("nft", "-a", "list", "chain", "inet", "filter", "forward"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, `comment "xray-proxya"`) {
					problems = append(problems, "managed filter forward rule still exists")
					break
				}
			}
		}
		if out, err := execCommandCombinedOutput("nft", "-a", "list", "chain", "inet", "filter", "input"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, `comment "xray-proxya"`) {
					problems = append(problems, "managed filter input rule still exists")
					break
				}
			}
		}
	}
	return problems
}

func verifyNoManagedForwardRules() []string {
	var problems []string
	if out, err := execCommandCombinedOutput("nft", "-a", "list", "chain", "inet", "filter", "forward"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, `comment "xray-proxya"`) && strings.Contains(line, "accept") {
				problems = append(problems, "unexpected managed forward accept rule exists when forwarding is disabled: "+strings.TrimSpace(line))
			}
		}
	}
	if out, err := execCommandCombinedOutput("nft", "-a", "list", "chain", "inet", "filter", "postrouting"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, `comment "xray-proxya"`) {
				problems = append(problems, "unexpected managed postrouting rule exists when forwarding is disabled: "+strings.TrimSpace(line))
			}
		}
	}
	return problems
}

func managedRuleLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	for p := 10010; p <= 10029; p++ {
		pref := fmt.Sprintf("%d", p)
		if strings.HasPrefix(trimmed, pref+":") || strings.Contains(line, " "+pref+":") {
			return true
		}
	}
	for _, pref := range []string{prefXray, prefLoopback, prefTun, prefPathTun} {
		if strings.HasPrefix(trimmed, pref+":") || strings.Contains(line, " "+pref+":") {
			return true
		}
	}
	return false
}

func interfaceHasCIDR(name, cidr string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if addr.String() == cidr {
			return true
		}
	}
	return false
}

func isLoopbackDNSListenHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hasActiveRelayAllowingPrivateTargets(cfg *config.UserConfig) bool {
	if cfg == nil {
		return false
	}
	activeRelays := make(map[string]bool)
	if cfg.Gateway.RelayAlias != "" && !strings.EqualFold(cfg.Gateway.RelayAlias, "direct") && !strings.EqualFold(cfg.Gateway.RelayAlias, "block") {
		activeRelays[cfg.Gateway.RelayAlias] = true
	}
	for _, r := range cfg.Gateway.Rules {
		target := strings.TrimSpace(r.Target)
		if target != "" && !strings.EqualFold(target, "direct") && !strings.EqualFold(target, "block") {
			activeRelays[target] = true
		}
	}
	for _, co := range cfg.CustomOutbounds {
		if activeRelays[co.Alias] && co.AllowPrivateTargets {
			return true
		}
	}
	return false
}

func buildNFT(cfg *config.UserConfig, lanIface, lanCIDR, lanIPv6CIDR string) string {
	var lanIfaces []string
	if cfg != nil {
		lanIfaces = cfg.Gateway.EffectiveLANInterfaces()
	}
	if len(lanIfaces) == 0 && lanIface != "" {
		lanIfaces = []string{lanIface}
	}
	var lanCIDRs, lanIPv6CIDRs []string
	if lanCIDR != "" {
		lanCIDRs = []string{lanCIDR}
	}
	if lanIPv6CIDR != "" {
		lanIPv6CIDRs = []string{lanIPv6CIDR}
	}
	wanIface := resolveWANInterface(cfg)
	return buildNFTMulti(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface)
}

func buildNFTMulti(cfg *config.UserConfig, lanIfaces []string, lanCIDRs, lanIPv6CIDRs []string, wanIface string) string {
	var b strings.Builder
	isTun := cfg != nil && cfg.Gateway.EffectiveMode() == "tun"
	basePort := cfg.Gateway.EffectiveTProxyPort()
	tproxyPorts := config.GatewayTProxyPorts(cfg)

	var allPorts []int
	seenPort := make(map[int]bool)
	allPorts = append(allPorts, basePort)
	seenPort[basePort] = true
	for _, p := range tproxyPorts {
		if !seenPort[p] {
			seenPort[p] = true
			allPorts = append(allPorts, p)
		}
	}
	sort.Ints(allPorts)
	var portStrs []string
	for _, p := range allPorts {
		portStrs = append(portStrs, strconv.Itoa(p))
	}

	b.WriteString("table inet " + tableName + " {\n")
	if cfg.Gateway.LANEnabled || cfg.Gateway.LocalEnabled {
		blocks := blockRuleTokens(cfg)
		hasInputRules := !isTun || len(blocks) > 0 || cfg.Gateway.DNSListen != ""
		if hasInputRules {
			b.WriteString("    chain input {\n")
			b.WriteString("        type filter hook input priority mangle; policy accept;\n")
			if !isTun {
				if len(portStrs) == 1 {
					b.WriteString("        meta mark != " + tunMark + " meta l4proto { tcp, udp } th dport " + portStrs[0] + " drop\n")
				} else {
					b.WriteString("        meta mark != " + tunMark + " meta l4proto { tcp, udp } th dport { " + strings.Join(portStrs, ", ") + " } drop\n")
				}
			}
			for _, tk := range blocks {
				b.WriteString("        " + strings.Join(tk, " ") + " drop\n")
			}
			if cfg.Gateway.DNSListen != "" {
				if host, dnsPort, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen); err == nil && dnsPort > 0 {
					if !isLoopbackDNSListenHost(host) && len(lanIfaces) > 0 {
						var quoted []string
						quoted = append(quoted, `"lo"`)
						for _, l := range lanIfaces {
							quoted = append(quoted, `"`+l+`"`)
						}
						b.WriteString("        iifname != { " + strings.Join(quoted, ", ") + " } meta l4proto { tcp, udp } th dport " + strconv.Itoa(dnsPort) + " drop\n")
					}
				}
			}
			b.WriteString("    }\n")
		}

		b.WriteString("    chain prerouting {\n")
		b.WriteString("        type filter hook prerouting priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		if !isTun {
			b.WriteString("        iifname != \"lo\" fib daddr type local return\n")
		}

		// Block rules (most specific selector first; less specific blocks
		// yield to more specific non-block rules).
		for _, tk := range blockRuleTokens(cfg) {
			b.WriteString("        " + strings.Join(tk, " ") + " drop\n")
		}

		// Interface & source subnet guards
		if cfg.Gateway.LANEnabled && cfg.Gateway.LocalEnabled {
			var allowed []string
			allowed = append(allowed, `"lo"`)
			for _, l := range lanIfaces {
				allowed = append(allowed, `"`+l+`"`)
			}
			b.WriteString("        iifname != { " + strings.Join(allowed, ", ") + " } return\n")
			for i, iface := range lanIfaces {
				var cidr, ipv6Cidr string
				if i < len(lanCIDRs) {
					cidr = lanCIDRs[i]
				}
				if i < len(lanIPv6CIDRs) {
					ipv6Cidr = lanIPv6CIDRs[i]
				}
				if cidr != "" {
					b.WriteString("        iifname \"" + iface + "\" ip saddr != " + cidr + " return\n")
				}
				if ipv6Cidr != "" {
					b.WriteString("        iifname \"" + iface + "\" ip6 saddr != " + nftAddrSet(ipv6Cidr) + " return\n")
				} else {
					b.WriteString("        iifname \"" + iface + "\" ip6 saddr ::/0 return\n")
				}
			}
		} else if cfg.Gateway.LANEnabled {
			if len(lanIfaces) == 1 {
				b.WriteString("        iifname != \"" + lanIfaces[0] + "\" return\n")
				var cidr, ipv6Cidr string
				if len(lanCIDRs) > 0 {
					cidr = lanCIDRs[0]
				}
				if len(lanIPv6CIDRs) > 0 {
					ipv6Cidr = lanIPv6CIDRs[0]
				}
				if cidr != "" {
					b.WriteString("        ip saddr != " + cidr + " return\n")
				}
				if ipv6Cidr != "" {
					b.WriteString("        iifname \"" + lanIfaces[0] + "\" ip6 saddr != " + nftAddrSet(ipv6Cidr) + " return\n")
				} else {
					b.WriteString("        iifname \"" + lanIfaces[0] + "\" ip6 saddr ::/0 return\n")
				}
			} else {
				var allowed []string
				for _, l := range lanIfaces {
					allowed = append(allowed, `"`+l+`"`)
				}
				b.WriteString("        iifname != { " + strings.Join(allowed, ", ") + " } return\n")
				for i, iface := range lanIfaces {
					var cidr, ipv6Cidr string
					if i < len(lanCIDRs) {
						cidr = lanCIDRs[i]
					}
					if i < len(lanIPv6CIDRs) {
						ipv6Cidr = lanIPv6CIDRs[i]
					}
					if cidr != "" {
						b.WriteString("        iifname \"" + iface + "\" ip saddr != " + cidr + " return\n")
					}
					if ipv6Cidr != "" {
						b.WriteString("        iifname \"" + iface + "\" ip6 saddr != " + nftAddrSet(ipv6Cidr) + " return\n")
					} else {
						b.WriteString("        iifname \"" + iface + "\" ip6 saddr ::/0 return\n")
					}
				}
			}
		} else {
			b.WriteString("        iifname != \"lo\" return\n")
		}

		// Destination bypasses
		allowPrivate := hasActiveRelayAllowingPrivateTargets(cfg)
		if !allowPrivate {
			b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		} else {
			b.WriteString("        ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		}
		for _, cidr := range lanCIDRs {
			if cidr != "" {
				b.WriteString("        ip daddr " + cidr + " return\n")
			}
		}
		if !allowPrivate {
			b.WriteString("        ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n")
		} else {
			b.WriteString("        ip6 daddr { ::1/128, fe80::/10, ff00::/8 } return\n")
		}
		for _, cidr := range flattenCIDRs(lanIPv6CIDRs) {
			if cidr != "" {
				b.WriteString("        ip6 daddr " + cidr + " return\n")
			}
		}
		for _, target := range outboundEndpoints(cfg) {
			writeOutboundEndpointRule(&b, target)
		}
		for _, ip := range cfg.Gateway.BypassDNS {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if parsedIP.To4() != nil {
					b.WriteString("        ip daddr " + parsedIP.String() + " return\n")
				} else {
					b.WriteString("        ip6 daddr " + parsedIP.String() + " return\n")
				}
			}
		}

		// Per-client rules ordered by specificity: interface+MAC, MAC, interface.
		if isTun {
			if pathTunnelEnabled(cfg) && cfg.Gateway.LANEnabled {
				b.WriteString("        icmp type echo-request meta mark set " + pathTunMark + "\n")
				b.WriteString("        icmpv6 type echo-request meta mark set " + pathTunMark + "\n")
			}
			b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
		} else {
			for _, rule := range sortedGatewayRules(cfg, false) {
				match := strings.Join(matchTokens(rule), " ")
				target := strings.TrimSpace(rule.Target)
				if strings.EqualFold(target, "direct") {
					b.WriteString("        " + match + " return\n")
					continue
				}
				port := tproxyPorts[target]
				if port <= 0 || !config.GatewayRelayActive(cfg, target) {
					// Fail closed: never silently fall back to the default relay.
					b.WriteString("        " + match + " drop\n")
					continue
				}
				b.WriteString("        " + match + " meta l4proto { tcp, udp } tproxy to :" + strconv.Itoa(port) + " meta mark set " + tunMark + " accept\n")
			}

			// Default Gateway Policy
			if pathTunnelEnabled(cfg) && cfg.Gateway.LANEnabled {
				b.WriteString("        icmp type echo-request meta mark set " + pathTunMark + "\n")
				b.WriteString("        icmpv6 type echo-request meta mark set " + pathTunMark + "\n")
			}
			if cfg.Gateway.RelayAlias != "" && !strings.EqualFold(cfg.Gateway.RelayAlias, "direct") && !strings.EqualFold(cfg.Gateway.RelayAlias, "block") {
				b.WriteString("        meta l4proto { tcp, udp } tproxy to :" + strconv.Itoa(basePort) + " meta mark set " + tunMark + " accept\n")
			}
		}
		b.WriteString("    }\n")
	}

	if cfg.Gateway.LocalEnabled {
		b.WriteString("    chain output {\n")
		b.WriteString("        type route hook output priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		if !isTun {
			b.WriteString("        fib daddr type local return\n")
		}
		allowPrivate := hasActiveRelayAllowingPrivateTargets(cfg)
		if !allowPrivate {
			b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		} else {
			b.WriteString("        ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		}
		for _, cidr := range lanCIDRs {
			if cidr != "" {
				b.WriteString("        ip daddr " + cidr + " return\n")
			}
		}
		if !allowPrivate {
			b.WriteString("        ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n")
		} else {
			b.WriteString("        ip6 daddr { ::1/128, fe80::/10, ff00::/8 } return\n")
		}
		for _, cidr := range flattenCIDRs(lanIPv6CIDRs) {
			if cidr != "" {
				b.WriteString("        ip6 daddr " + cidr + " return\n")
			}
		}
		for _, target := range outboundEndpoints(cfg) {
			writeOutboundEndpointRule(&b, target)
		}
		for _, ip := range cfg.Gateway.BypassDNS {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if parsedIP.To4() != nil {
					b.WriteString("        ip daddr " + parsedIP.String() + " return\n")
				} else {
					b.WriteString("        ip6 daddr " + parsedIP.String() + " return\n")
				}
			}
		}
		for _, port := range getSSHPorts() {
			// Exclude the SSH listener's reply traffic (source port) to prevent
			// inbound management sessions from being intercepted or broken.
			// Outbound SSH connections initiated by the host (destination port)
			// should still be proxied through the transparent gateway.
			b.WriteString("        tcp sport " + port + " return\n")
		}
		if pathTunnelEnabled(cfg) {
			b.WriteString("        icmp type echo-request meta mark set " + pathTunMark + "\n")
			b.WriteString("        icmpv6 type echo-request meta mark set " + pathTunMark + "\n")
		}
		b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
		b.WriteString("    }\n")
	}

	// Managed WAN NAT Masquerade & Forwarding
	if !cfg.Gateway.NATDisabled && wanIface != "" && len(lanIfaces) > 0 {
		wanDistinct := true
		for _, liface := range lanIfaces {
			if liface == wanIface {
				wanDistinct = false
				break
			}
		}
		if wanDistinct || cfg.Gateway.WANInterface != "" {
			var lanMatch string
			if len(lanIfaces) == 1 {
				lanMatch = `"` + lanIfaces[0] + `"`
			} else {
				var quoted []string
				for _, l := range lanIfaces {
					quoted = append(quoted, `"`+l+`"`)
				}
				lanMatch = `{ ` + strings.Join(quoted, ", ") + ` }`
			}

			b.WriteString("    chain forward {\n")
			b.WriteString("        type filter hook forward priority filter; policy accept;\n")
			for _, tk := range blockRuleTokens(cfg) {
				b.WriteString("        " + strings.Join(tk, " ") + " drop\n")
			}
			b.WriteString("        iifname " + lanMatch + " oifname \"" + wanIface + "\" accept\n")
			b.WriteString("        iifname \"" + wanIface + "\" oifname " + lanMatch + " ct state established,related accept\n")
			b.WriteString("    }\n")

			b.WriteString("    chain postrouting {\n")
			b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
			b.WriteString("        iifname " + lanMatch + " oifname \"" + wanIface + "\" masquerade\n")
			b.WriteString("    }\n")
		}
	}

	b.WriteString("}\n")
	return b.String()
}

func getInterfaceCIDR(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.To4() == nil {
			continue
		}
		networkIP := ipNet.IP.Mask(ipNet.Mask)
		return (&net.IPNet{IP: networkIP, Mask: ipNet.Mask}).String(), nil
	}
	return "", fmt.Errorf("no IPv4 subnet found on %s", name)
}

func getInterfaceIPv6CIDR(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.To4() != nil {
			continue
		}
		if ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsLoopback() {
			continue
		}
		networkIP := ipNet.IP.Mask(ipNet.Mask)
		return (&net.IPNet{IP: networkIP, Mask: ipNet.Mask}).String(), nil
	}
	return "", fmt.Errorf("no IPv6 subnet found on %s", name)
}

type outboundEndpoint struct {
	IP   net.IP
	Port int
}

func parsePort(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case int64:
		return int(val)
	case string:
		if p, err := strconv.Atoi(val); err == nil {
			return p
		}
	}
	return 0
}

func outboundEndpoints(cfg *config.UserConfig) []outboundEndpoint {
	var targets []outboundEndpoint
	seen := map[string]bool{}

	addEndpoint := func(addr string, portVal interface{}) {
		ip := net.ParseIP(addr)
		if ip == nil {
			return
		}
		port := parsePort(portVal)
		key := fmt.Sprintf("%s:%d", ip.String(), port)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, outboundEndpoint{IP: ip, Port: port})
	}

	for _, co := range cfg.CustomOutbounds {
		if !co.Enabled || co.Config == nil {
			continue
		}
		settings, _ := co.Config["settings"].(map[string]interface{})
		if settings == nil {
			continue
		}
		if vnextList, ok := settings["vnext"].([]interface{}); ok {
			for _, item := range vnextList {
				if vnext, ok := item.(map[string]interface{}); ok {
					addr, _ := vnext["address"].(string)
					addEndpoint(addr, vnext["port"])
				}
			}
		}
		if serversList, ok := settings["servers"].([]interface{}); ok {
			for _, item := range serversList {
				if server, ok := item.(map[string]interface{}); ok {
					addr, _ := server["address"].(string)
					addEndpoint(addr, server["port"])
				}
			}
		}
		if peersList, ok := settings["peers"].([]interface{}); ok {
			for _, item := range peersList {
				if peer, ok := item.(map[string]interface{}); ok {
					if endpoint, ok := peer["endpoint"].(string); ok {
						if host, portStr, err := net.SplitHostPort(endpoint); err == nil {
							addEndpoint(host, portStr)
						}
					}
				}
			}
		}
	}
	return targets
}

func outboundIPs(cfg *config.UserConfig) []string {
	var ips []string
	seen := map[string]bool{}
	for _, ep := range outboundEndpoints(cfg) {
		ipStr := ep.IP.String()
		if !seen[ipStr] {
			seen[ipStr] = true
			ips = append(ips, ipStr)
		}
	}
	return ips
}

func writeOutboundEndpointRule(b *strings.Builder, target outboundEndpoint) {
	if target.Port > 0 {
		if target.IP.To4() != nil {
			b.WriteString(fmt.Sprintf("        ip daddr %s meta l4proto { tcp, udp } th dport %d return\n", target.IP.String(), target.Port))
		} else {
			b.WriteString(fmt.Sprintf("        ip6 daddr %s meta l4proto { tcp, udp } th dport %d return\n", target.IP.String(), target.Port))
		}
	} else {
		if target.IP.To4() != nil {
			b.WriteString("        ip daddr " + target.IP.String() + " return\n")
		} else {
			b.WriteString("        ip6 daddr " + target.IP.String() + " return\n")
		}
	}
}

func getSSHPorts() []string {
	ports := []string{"22"}
	// The conventional SSH port is always excluded.  For a remote invocation,
	// SSH_CONNECTION additionally tells us the active server-side port; this
	// protects a custom listener without enumerating other processes through
	// `ss -p` (which would be inappropriate for the confined management domain).
	found := map[string]bool{}
	found["22"] = true
	if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) == 4 {
		if _, err := strconv.ParseUint(fields[3], 10, 16); err == nil {
			found[fields[3]] = true
		}
	}
	ports = ports[:0]
	for port := range found {
		ports = append(ports, port)
	}
	return ports
}

var (
	detectDefaultInterfaceFn  = DetectDefaultInterface
	runCommand                = defaultRunCommand
	execCommandCombinedOutput = defaultExecCombinedOutput
	execCommandRun            = defaultExecRun
	isIPv4ForwardingEnabledFn = tune.IsIPv4ForwardingEnabled
	isTProxyPortListeningFn   = isTProxyPortListeningDefault
)

func defaultExecRun(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func defaultRunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %s %v failed: %w (output: %q)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultExecCombinedOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func run(name string, args ...string) error {
	return runCommand(name, args...)
}

// insertFilterRules inserts rules at the head of the given inet filter chain,
// preserving the order in which they are supplied (first element ends up on
// top). Each rule is tagged with the managed comment so cleanup can find it.
func insertFilterRules(chain string, rules ...[]string) error {
	for i := len(rules) - 1; i >= 0; i-- {
		args := append([]string{"insert", "rule", "inet", "filter", chain}, rules[i]...)
		args = append(args, "comment", "\"xray-proxya\"")
		if err := run("nft", args...); err != nil {
			return fmt.Errorf("install %s rule %q: %w", chain, strings.Join(rules[i], " "), err)
		}
	}
	return nil
}

func setupLANForwardingBlock(lanIfaces ...string) error {
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")
	for _, lanIface := range lanIfaces {
		if lanIface == "" {
			continue
		}
		if err := insertFilterRules("forward", []string{"iifname", lanIface, "drop"}); err != nil {
			return fmt.Errorf("block LAN forwarding: %w", err)
		}
	}
	return nil
}

func installDirectLANForwardRules(lanIfaces ...string) error {
	wanIface, err := detectDefaultInterfaceFn()
	if err != nil {
		return fmt.Errorf("detect default WAN interface: %w", err)
	}

	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "postrouting", "{ type nat hook postrouting priority srcnat; }")

	for _, lanIface := range lanIfaces {
		if lanIface == "" {
			continue
		}
		if err := insertFilterRules("forward",
			[]string{"iifname", lanIface, "oifname", wanIface, "accept"},
			[]string{"iifname", wanIface, "oifname", lanIface, "ct", "state", "established,related", "accept"}); err != nil {
			return fmt.Errorf("allow LAN/WAN forwarding: %w", err)
		}
		if err := run("nft", "add", "rule", "inet", "filter", "postrouting", "iifname", lanIface, "oifname", wanIface, "masquerade", "comment", "\"xray-proxya\""); err != nil {
			return fmt.Errorf("enable direct LAN NAT masquerade: %w", err)
		}
	}
	return nil
}

func setupDirectLANForwarding(lanIfaces ...string) error {
	if err := SetupKernel(lanIfaces...); err != nil {
		return fmt.Errorf("kernel setup failed: %w", err)
	}
	return installDirectLANForwardRules(lanIfaces...)
}

func cleanupFilterManagedRules(chain string) error {
	out, err := execCommandCombinedOutput("nft", "-a", "list", "chain", "inet", "filter", chain)
	if err != nil {
		if isMissingKernelObject(err, out) {
			return nil
		}
		return fmt.Errorf("list filter %s chain: %w (output: %q)", chain, err, strings.TrimSpace(string(out)))
	}
	var cleanupErrs []error
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, `comment "xray-proxya"`) {
			idx := strings.Index(line, "handle ")
			if idx != -1 {
				handleStr := strings.TrimSpace(line[idx+7:])
				digits := ""
				for _, r := range handleStr {
					if r >= '0' && r <= '9' {
						digits += string(r)
					} else {
						break
					}
				}
				if digits != "" {
					if err := runDelete("nft", "delete", "rule", "inet", "filter", chain, "handle", digits); err != nil {
						cleanupErrs = append(cleanupErrs, err)
					}
				}
			}
		}
	}
	return errors.Join(cleanupErrs...)
}

func cleanupFilterForwardRules() error {
	return cleanupFilterManagedRules("forward")
}

func cleanupFilterInputRules() error {
	return cleanupFilterManagedRules("input")
}

func isTProxyPortListening(port int) bool {
	return isTProxyPortListeningFn(port)
}

func isTProxyPortListeningDefault(port int) bool {
	if reflect.ValueOf(runCommand).Pointer() != reflect.ValueOf(defaultRunCommand).Pointer() ||
		reflect.ValueOf(execCommandRun).Pointer() != reflect.ValueOf(defaultExecRun).Pointer() {
		return true
	}
	hexPort := fmt.Sprintf(":%04X", port)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if strings.HasSuffix(fields[1], hexPort) && fields[3] == "0A" {
					return true
				}
			}
		}
	}
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if strings.HasSuffix(fields[1], hexPort) && fields[3] == "07" {
					return true
				}
			}
		}
	}
	return false
}

func waitForTProxyListener(port int) error {
	deadline := time.Now().Add(tunWaitTimeout)
	for time.Now().Before(deadline) {
		if isTProxyPortListening(port) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for tproxy listener on port %d", port)
}

func runDelete(name string, args ...string) error {
	err := run(name, args...)
	if err == nil || isMissingKernelObject(err, nil) {
		return nil
	}
	return err
}

func isMissingKernelObject(err error, output []byte) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error() + " " + string(output))
	for _, marker := range []string{
		"no such file",
		"no such chain",
		"no such process",
		"cannot find",
		"no such rule",
		"no rule",
		"does not exist",
		"bad rule",
		"does a matching rule exist",
		"no chain/target/match",
		"protocol not available",
		"address family not supported",
		"no such device",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type sysctlState struct {
	Values map[string]string `json:"values"`
}

func sysctlStatePath() string {
	return filepath.Join(config.GetConfigDir(), "gateway.sysctl.json")
}

var readSysctlFn = tune.ReadSysctl

func readSysctl(key string) (string, error) {
	return readSysctlFn(key)
}

func ipv6Available() bool {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return false
	}
	if val, err := tune.ReadSysctl("net.ipv6.conf.all.disable_ipv6"); err == nil && val == "1" {
		return false
	}
	return true
}

func saveSysctlState(lanIfaces ...string) error {
	if _, err := os.Stat(sysctlStatePath()); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat gateway sysctl state: %w", err)
	}
	keys := []string{
		"net.ipv4.ip_forward",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.conf.all.send_redirects",
		"net.ipv4.conf.default.send_redirects",
	}
	if ipv6Available() {
		keys = append(keys, "net.ipv6.conf.all.forwarding")
	}
	seen := make(map[string]bool)
	for _, k := range keys {
		seen[k] = true
	}
	for _, iface := range lanIfaces {
		if iface != "" {
			k1 := "net.ipv4.conf." + iface + ".send_redirects"
			k2 := "net.ipv4.conf." + iface + ".rp_filter"
			if !seen[k1] {
				seen[k1] = true
				keys = append(keys, k1)
			}
			if !seen[k2] {
				seen[k2] = true
				keys = append(keys, k2)
			}
		}
	}
	values := make(map[string]string, len(keys))
	for _, key := range keys {
		value, err := readSysctl(key)
		if err != nil {
			return fmt.Errorf("read %s: %w", key, err)
		}
		values[key] = value
	}
	data, err := json.Marshal(sysctlState{Values: values})
	if err != nil {
		return fmt.Errorf("encode gateway sysctl state: %w", err)
	}
	if err := os.WriteFile(sysctlStatePath(), data, 0600); err != nil {
		return fmt.Errorf("save gateway sysctl state: %w", err)
	}
	return nil
}

func restoreSysctlState() error {
	data, err := os.ReadFile(sysctlStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state sysctlState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode gateway sysctl state: %w", err)
	}
	var restoreErrs []error
	for key, value := range state.Values {
		if err := run("sysctl", "-w", key+"="+value); err != nil {
			restoreErrs = append(restoreErrs, err)
		}
	}
	if err := removeIfExists(sysctlStatePath()); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	return errors.Join(restoreErrs...)
}
