package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	if (state == "forward-only" || cfg.Gateway.LANEnabled) && len(lanIfaces) == 0 {
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
			setupErr = setupDirectLANForwardingWithConfig(cfg, lanIfaces...)
		}
		if setupErr == nil {
			setupErr = installBlockFilterRules(cfg)
		}
		if setupErr == nil {
			setupErr = installIsolatedFilterRules(cfg, lanIfaces)
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
		if err := installIsolatedFilterRules(cfg, lanIfaces); err != nil {
			return errors.Join(err, CleanupFirewall())
		}
		return nil
	}
	if config.GatewayTunDisabled() {
		return fmt.Errorf("gateway runtime is down; run 'xray-proxya gateway up' first")
	}

	if cfg.Gateway.EffectiveMode() == "tun" {
		if err := CleanupFirewall(); err != nil {
			return fmt.Errorf("clean up existing gateway state: %w", err)
		}
		rollback := true
		defer func() {
			if err != nil && rollback {
				err = errors.Join(err, CleanupFirewall())
			}
		}()
		if err := SetupKernel(lanIfaces...); err != nil {
			return fmt.Errorf("kernel setup failed: %w", err)
		}
		if err := waitForInterface(tunName, true); err != nil {
			return fmt.Errorf("tun interface %s was not created in time by Xray core: %w", tunName, err)
		}
		ipv6Supported := ipv6Available()
		if err := run("ip", "addr", "replace", tunIPv4CIDR, "dev", tunName); err != nil {
			return err
		}
		if ipv6Supported {
			_ = run("ip", "-6", "addr", "replace", tunIPv6CIDR, "dev", tunName)
		}
		if err := run("ip", "link", "set", "dev", tunName, "up"); err != nil {
			return err
		}
		rollback = false
		return nil
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

	// Atomically replace firewall rules without clearing existing protection
	// beforehand. On error, default Fail-Closed mode installs/retains strict
	// drop protection instead of leaking traffic direct; FailOpen cleans up.
	failGuard := func() error {
		if !cfg.Gateway.FailOpen {
			return applyFailClosedFirewall(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface)
		}
		return CleanupFirewall()
	}
	rollback := true
	defer func() {
		if err != nil && rollback {
			err = errors.Join(err, failGuard())
		}
	}()
	if err := SetupKernel(lanIfaces...); err != nil {
		return fmt.Errorf("kernel setup failed: %w", err)
	}

	// 1. Primary TProxy Listeners
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

	// 2. Pure TUN Adapter (if enabled)
	if cfg.Gateway.EffectiveTUNEnabled() {
		if err := waitForInterface(tunName, true); err != nil {
			return fmt.Errorf("tun interface %s was not created in time by Xray core: %w", tunName, err)
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

	// Pure TUN Interface Addressing (operates purely as an addressable virtual adapter without policy routes)
	if cfg.Gateway.EffectiveTUNEnabled() {
		if err := run("ip", "addr", "replace", tunIPv4CIDR, "dev", tunName); err != nil {
			return err
		}
		if ipv6Supported {
			if err := run("ip", "-6", "addr", "replace", tunIPv6CIDR, "dev", tunName); err != nil {
				ipv6Supported = false
			}
		}
		if err := run("ip", "link", "set", "dev", tunName, "up"); err != nil {
			return err
		}
	}

	oldRules, _ := loadPolicyRules()
	rulesToAdd := policyRulesMulti(cfg, lanCIDRs, lanIPv6CIDRs, ipv6Supported)
	if err := savePolicyRules(rulesToAdd); err != nil {
		return err
	}
	if err := syncPolicyRules(oldRules, rulesToAdd); err != nil {
		return err
	}

	// Table 100 default destination is always local dev lo for primary TProxy socket redirection
	if err := run("ip", "route", "replace", "local", "default", "dev", "lo", "table", policyTable); err != nil {
		return err
	}
	if ipv6Supported {
		if err := run("ip", "-6", "route", "replace", "local", "default", "dev", "lo", "table", policyTable); err != nil {
			return err
		}
	}

	if pathTunnelEnabled(cfg) {
		if err := run("ip", "route", "replace", "default", "dev", pathTunName, "table", pathPolicyTable); err != nil {
			return err
		}
		if ipv6Supported {
			if err := run("ip", "-6", "route", "replace", "default", "dev", pathTunName, "table", pathPolicyTable); err != nil {
				return err
			}
		}
	} else {
		_ = runDelete("ip", "route", "del", "default", "dev", pathTunName, "table", pathPolicyTable)
		_ = runDelete("ip", "-6", "route", "del", "default", "dev", pathTunName, "table", pathPolicyTable)
	}

	oldForwardHandles, _ := listFilterManagedHandles("forward")
	oldInputHandles, _ := listFilterManagedHandles("input")
	oldPostroutingHandles, _ := listFilterManagedHandles("postrouting")

	if err := run("nft", "-f", tmpFile); err != nil {
		return err
	}
	if err := cleanupPathTTLRules(); err != nil {
		return err
	}
	if pathTunnelEnabled(cfg) && len(lanIfaces) > 0 {
		if err := installPathTTLRules(lanIfaces, ipv6Supported); err != nil {
			return fmt.Errorf("preserve ICMP TTL through path-tun: %w", err)
		}
	}

	// Ensure system filter table, forward and input chains exist. New rules are
	// inserted ahead of previous managed handles and old handles removed
	// afterwards so firewall updates never leave an unprotected window.
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority filter; }")

	var inputRules [][]string
	inputRules = append(inputRules, []string{"meta", "mark", tunMark, "accept"})
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

	isoSet := make(map[string]bool)
	isoIfaces := cfg.Gateway.EffectiveIsolatedInterfaces()
	for _, iso := range isoIfaces {
		isoSet[iso] = true
	}

	var forwardRules [][]string
	if cfg.Gateway.EffectiveTUNEnabled() {
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
		if wanDistinct {
			managedNATInstalled = true
		}
	}
	if pathTunnelEnabled(cfg) {
		forwardRules = append(forwardRules,
			[]string{"iifname", pathTunName, "accept"},
			[]string{"oifname", pathTunName, "accept"})
	}
	for _, liface := range lanIfaces {
		if isoSet[liface] {
			forwardRules = append(forwardRules, []string{"iifname", liface, "oifname", liface, "drop"})
		} else {
			forwardRules = append(forwardRules, []string{"iifname", liface, "oifname", liface, "accept"})
		}
	}
	if len(isoIfaces) > 0 {
		for _, iso := range isoIfaces {
			for _, liface := range lanIfaces {
				if liface != iso {
					forwardRules = append(forwardRules,
						[]string{"iifname", iso, "oifname", liface, "drop"},
						[]string{"iifname", liface, "oifname", iso, "ct", "state", "new", "drop"})
				}
			}
		}
		forwardRules = append(forwardRules, []string{"ct", "state", "established,related", "accept"})
	}
	if managedNATInstalled {
		for _, liface := range lanIfaces {
			forwardRules = append(forwardRules,
				[]string{"iifname", liface, "oifname", wanIface, "accept"},
				[]string{"iifname", wanIface, "oifname", liface, "ct", "state", "established,related", "accept"})
		}
	}
	if len(forwardRules) > 0 {
		if err := insertFilterRules("forward", forwardRules...); err != nil {
			return err
		}
	}
	if cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled && !managedNATInstalled && !cfg.Gateway.NATDisabled && len(lanIfaces) > 0 {
		if err := installDirectLANForwardRulesWithConfig(cfg, lanIfaces...); err != nil {
			return err
		}
	}

	_ = deleteFilterHandles("forward", oldForwardHandles)
	_ = deleteFilterHandles("input", oldInputHandles)
	_ = deleteFilterHandles("postrouting", oldPostroutingHandles)
	_ = runDelete("nft", "delete", "chain", "inet", "filter", "block_guard")

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
	record("filter block_guard chain", runDelete("nft", "delete", "chain", "inet", "filter", "block_guard"))

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
	for i, cidr := range flattenCIDRs(lanCIDRs) {
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
	if cfg == nil || cfg.Role != config.RoleGateway || mode != "tproxy" {
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
	lanIfaces := cfg.Gateway.EffectiveLANInterfaces()
	if cfg.Gateway.LANEnabled && len(lanIfaces) == 0 {
		return "", fmt.Errorf("gateway LAN interface is not configured")
	}
	lanCIDRs, lanIPv6CIDRs, err := collectLANCIDRs(lanIfaces, cfg.Gateway.LANEnabled)
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
	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}
	lanIfaces := cfg.Gateway.EffectiveLANInterfaces()
	if len(lanIfaces) == 0 {
		if cfg.Gateway.LANEnabled || state == "forward-only" {
			problems = append(problems, "LAN interface is not configured")
		}
	} else {
		for _, iface := range lanIfaces {
			if _, err := net.InterfaceByName(iface); err != nil {
				problems = append(problems, fmt.Sprintf("LAN interface %s not found", iface))
			}
		}
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

	ipv6Configured := ipv6Available()

	// 1. TProxy Policy Table & Listener Verification (only in tproxy mode)
	if mode == "tproxy" {
		if err := execCommandRun("nft", "list", "table", "inet", tableName); err != nil {
			problems = append(problems, "nft table inet "+tableName+" is not present")
		}
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

		lanCIDRs, lanIPv6CIDRs, cidrsErr := collectLANCIDRs(lanIfaces, cfg.Gateway.LANEnabled)
		if cidrsErr != nil && cfg.Gateway.LANEnabled {
			problems = append(problems, "cannot determine LAN CIDR for policy rules")
		} else {
			expected := policyRulesMulti(cfg, lanCIDRs, lanIPv6CIDRs, ipv6Configured)
			problems = append(problems, verifyPolicyRules(expected)...)
		}
	}

	// 2. Pure TUN Adapter Verification (if enabled or mode == tun)
	if cfg.Gateway.EffectiveTUNEnabled() {
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
		/*
		RESERVED AS FALLBACK: Standalone TUN Table 100 verification
		if ok, err := hasDefaultRoute(policyTable, tunName, false); err != nil {
			problems = append(problems, "cannot inspect IPv4 policy table "+policyTable+": "+err.Error())
		} else if !ok {
			problems = append(problems, "IPv4 policy table "+policyTable+" has no default route via "+tunName)
		}
		*/
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
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return false, nil
		}
		if strings.Contains(string(out), "FIB table does not exist") {
			return false, nil
		}
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
				var exitErr *exec.ExitError
				if (errors.As(err, &exitErr) && exitErr.ExitCode() == 2) || strings.Contains(string(out), "FIB table does not exist") {
					continue
				}
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

func resolveLocalProxyPort(cfg *config.UserConfig, tproxyPorts map[string]int, basePort int) (int, bool) {
	if cfg == nil || !cfg.Gateway.LocalEnabled {
		return 0, false
	}
	localRelay := cfg.Gateway.EffectiveLocalRelay()
	if localRelay == "" || !config.GatewayRelayActive(cfg, localRelay) {
		return 0, false
	}
	port := tproxyPorts[localRelay]
	if port <= 0 && localRelay == strings.TrimSpace(cfg.Gateway.RelayAlias) {
		port = basePort
	}
	if port <= 0 {
		return 0, false
	}
	return port, true
}

func resolveZoneDNSPort(cfg *config.UserConfig, iface string, tproxyPorts map[string]int, basePort int) int {
	if cfg == nil {
		return 0
	}
	if zRelay := cfg.Gateway.EffectiveRelayForInterface(iface); zRelay != "" && config.GatewayRelayActive(cfg, zRelay) {
		if p := tproxyPorts[zRelay]; p > 0 {
			return p
		}
		if zRelay == strings.TrimSpace(cfg.Gateway.RelayAlias) {
			return basePort
		}
	}
	if gRelay := strings.TrimSpace(cfg.Gateway.RelayAlias); gRelay != "" &&
		!strings.EqualFold(gRelay, "direct") && !strings.EqualFold(gRelay, "block") &&
		config.GatewayRelayActive(cfg, gRelay) {
		if p := tproxyPorts[gRelay]; p > 0 {
			return p
		}
		return basePort
	}
	if cfg.Gateway.DNSListen != "" {
		if _, dnsPort, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen); err == nil && dnsPort > 0 {
			return dnsPort
		}
	}
	return 0
}

func nftIfaceList(ifaces []string) string {
	if len(ifaces) == 1 {
		return quoteIface(ifaces[0])
	}
	quoted := make([]string, len(ifaces))
	for i, iface := range ifaces {
		quoted[i] = quoteIface(iface)
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func writeBlockGuardChain(b *strings.Builder, entries []blockGuardEntry) {
	if len(entries) == 0 {
		return
	}
	b.WriteString("    chain block_guard {\n")
	for _, e := range entries {
		b.WriteString("        " + strings.Join(e.Tokens, " ") + " " + e.Verdict + "\n")
	}
	b.WriteString("    }\n")
}

func writeIsolatedInputRules(b *strings.Builder, isoIfaces []string, allowTProxyMark bool) {
	for _, iso := range isoIfaces {
		if allowTProxyMark {
			b.WriteString(fmt.Sprintf("        iifname %q meta mark %s accept\n", iso, tunMark))
		}
		b.WriteString(fmt.Sprintf("        iifname %q udp dport { 67, 68, 546, 547 } accept\n", iso))
		if allowTProxyMark {
			b.WriteString(fmt.Sprintf("        iifname %q meta l4proto { tcp, udp } th dport 53 accept\n", iso))
		}
		b.WriteString(fmt.Sprintf("        iifname %q icmp type { echo-request, destination-unreachable, time-exceeded } accept\n", iso))
		b.WriteString(fmt.Sprintf("        iifname %q icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n", iso))
		b.WriteString(fmt.Sprintf("        iifname %q drop\n", iso))
	}
}

func writeIsolatedForwardRules(b *strings.Builder, isoIfaces, lanIfaces []string) {
	if len(isoIfaces) == 0 {
		return
	}
	for _, iso := range isoIfaces {
		b.WriteString(fmt.Sprintf("        iifname %q oifname %q drop\n", iso, iso))
		seenOther := map[string]bool{iso: true}
		var others []string
		for _, liface := range lanIfaces {
			if liface != "" && !seenOther[liface] {
				seenOther[liface] = true
				others = append(others, liface)
			}
		}
		for _, otherIso := range isoIfaces {
			if otherIso != "" && !seenOther[otherIso] {
				seenOther[otherIso] = true
				others = append(others, otherIso)
			}
		}
		if len(others) > 0 {
			otherExpr := nftIfaceList(others)
			b.WriteString(fmt.Sprintf("        iifname %q oifname %s drop\n", iso, otherExpr))
			b.WriteString(fmt.Sprintf("        iifname %s oifname %q ct state new drop\n", otherExpr, iso))
		}
	}
	b.WriteString("        ct state established,related accept\n")
}

func writeCommonDestinationBypasses(b *strings.Builder, cfg *config.UserConfig, lanCIDRs, lanIPv6CIDRs []string) {
	b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
	for _, cidr := range flattenCIDRs(lanCIDRs) {
		if cidr != "" {
			b.WriteString("        ip daddr " + cidr + " return\n")
		}
	}
	b.WriteString("        ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n")
	for _, cidr := range flattenCIDRs(lanIPv6CIDRs) {
		if cidr != "" {
			b.WriteString("        ip6 daddr " + cidr + " return\n")
		}
	}
	for _, target := range outboundEndpoints(cfg) {
		writeOutboundEndpointRule(b, target)
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
}

func ruleTProxyFamily(r config.GatewayRule) string {
	if r.IP == "" {
		return ""
	}
	if isIPv6(r.IP) {
		return "ip6 "
	}
	return "ip "
}

func buildNFTMulti(cfg *config.UserConfig, lanIfaces []string, lanCIDRs, lanIPv6CIDRs []string, wanIface string) string {
	var b strings.Builder
	basePort := cfg.Gateway.EffectiveTProxyPort()
	tproxyPorts := config.GatewayTProxyPorts(cfg)
	isoIfaces := cfg.Gateway.EffectiveIsolatedInterfaces()
	localPort, localProxyActive := resolveLocalProxyPort(cfg, tproxyPorts, basePort)
	blockEntries := blockGuardEntries(cfg)
	sortedRules := sortedAllClientRules(cfg)

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

	b.WriteString("table inet " + tableName + "\n")
	b.WriteString("delete table inet " + tableName + "\n")
	b.WriteString("table inet " + tableName + " {\n")
	writeBlockGuardChain(&b, blockEntries)

	if cfg.Gateway.LANEnabled || cfg.Gateway.LocalEnabled {
		b.WriteString("    chain input {\n")
		b.WriteString("        type filter hook input priority mangle; policy accept;\n")
		if len(portStrs) == 1 {
			b.WriteString("        meta mark != " + tunMark + " meta l4proto { tcp, udp } th dport " + portStrs[0] + " drop\n")
		} else {
			b.WriteString("        meta mark != " + tunMark + " meta l4proto { tcp, udp } th dport { " + strings.Join(portStrs, ", ") + " } drop\n")
		}
		if len(blockEntries) > 0 {
			b.WriteString("        jump block_guard\n")
		}
		writeIsolatedInputRules(&b, isoIfaces, true)
		if cfg.Gateway.DNSListen != "" {
			if host, dnsPort, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen); err == nil && dnsPort > 0 {
				if !isLoopbackDNSListenHost(host) && len(lanIfaces) > 0 {
					allowed := append([]string{"lo"}, lanIfaces...)
					b.WriteString("        iifname != " + nftIfaceList(allowed) + " meta l4proto { tcp, udp } th dport " + strconv.Itoa(dnsPort) + " drop\n")
				}
			}
		}
		b.WriteString("    }\n")

		b.WriteString("    chain prerouting {\n")
		b.WriteString("        type filter hook prerouting priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		b.WriteString("        ct status dnat return\n")

		// Handle host-originated loopback traffic redirected by policy table 100
		// before LAN rules so host local_relay never hits LAN client rules.
		if localProxyActive {
			b.WriteString("        iifname \"lo\" meta mark " + tunMark + " meta l4proto { tcp, udp } tproxy to :" + strconv.Itoa(localPort) + " meta mark set " + tunMark + " accept\n")
		}
		b.WriteString("        iifname \"lo\" return\n")

		if !cfg.Gateway.LANEnabled {
			if len(blockEntries) > 0 {
				b.WriteString("        jump block_guard\n")
			}
			b.WriteString("        iifname != \"lo\" return\n")
		} else {
			if len(blockEntries) > 0 {
				b.WriteString("        jump block_guard\n")
			}
			if len(lanIfaces) > 0 {
				b.WriteString("        iifname != " + nftIfaceList(lanIfaces) + " return\n")
			} else {
				b.WriteString("        return\n")
			}
			b.WriteString("        iifname != \"lo\" fib daddr type local meta l4proto != { tcp, udp } return\n")
			b.WriteString("        iifname != \"lo\" fib daddr type local th dport != 53 return\n")

			// Step 2: Port 53 DNS hijacking BEFORE LAN source subnet guards so IPv6
			// fe80:: link-local DNS works; blocked devices were already dropped above.
			for _, rule := range sortedRules {
				if isBlockRule(rule) {
					continue
				}
				match := strings.Join(matchTokens(rule), " ")
				tproxyFamily := ruleTProxyFamily(rule)
				if !isDirectRule(rule) {
					target := strings.TrimSpace(rule.Target)
					port := tproxyPorts[target]
					if port <= 0 || !config.GatewayRelayActive(cfg, target) {
						// Already dropped in block_guard before DNS hijacking.
						continue
					}
					b.WriteString("        " + match + " meta l4proto { tcp, udp } th dport 53 tproxy " + tproxyFamily + "to :" + strconv.Itoa(port) + " meta mark set " + tunMark + " accept\n")
					continue
				}
				// Direct devices still resolve DNS through zone/global relay to avoid poisoning.
				if rule.Interface != "" || len(lanIfaces) <= 1 {
					iface := rule.Interface
					if iface == "" && len(lanIfaces) == 1 {
						iface = lanIfaces[0]
					}
					port := resolveZoneDNSPort(cfg, iface, tproxyPorts, basePort)
					if port > 0 {
						b.WriteString("        " + match + " meta l4proto { tcp, udp } th dport 53 tproxy " + tproxyFamily + "to :" + strconv.Itoa(port) + " meta mark set " + tunMark + " accept\n")
					} else {
						b.WriteString("        " + match + " meta l4proto { tcp, udp } th dport 53 return\n")
					}
					continue
				}
				// Multi-LAN rule without explicit interface: coalesce if all zones use same DNS port.
				firstPort := resolveZoneDNSPort(cfg, lanIfaces[0], tproxyPorts, basePort)
				uniform := true
				for _, liface := range lanIfaces[1:] {
					if resolveZoneDNSPort(cfg, liface, tproxyPorts, basePort) != firstPort {
						uniform = false
						break
					}
				}
				if uniform {
					if firstPort > 0 {
						b.WriteString("        " + match + " meta l4proto { tcp, udp } th dport 53 tproxy " + tproxyFamily + "to :" + strconv.Itoa(firstPort) + " meta mark set " + tunMark + " accept\n")
					} else {
						b.WriteString("        " + match + " meta l4proto { tcp, udp } th dport 53 return\n")
					}
				} else {
					for _, liface := range lanIfaces {
						p := resolveZoneDNSPort(cfg, liface, tproxyPorts, basePort)
						if p > 0 {
							b.WriteString("        iifname " + quoteIface(liface) + " " + match + " meta l4proto { tcp, udp } th dport 53 tproxy " + tproxyFamily + "to :" + strconv.Itoa(p) + " meta mark set " + tunMark + " accept\n")
						} else {
							b.WriteString("        iifname " + quoteIface(liface) + " " + match + " meta l4proto { tcp, udp } th dport 53 return\n")
						}
					}
				}
			}
			// Default LAN :53 hijacking per zone or uniform across all LAN interfaces.
			if len(lanIfaces) > 0 {
				firstDNSPort := resolveZoneDNSPort(cfg, lanIfaces[0], tproxyPorts, basePort)
				firstExplicitBlock := strings.EqualFold(strings.TrimSpace(cfg.Gateway.ZoneDefaultRelays[lanIfaces[0]]), "block")
				uniformDNS := !firstExplicitBlock
				for _, liface := range lanIfaces[1:] {
					if strings.EqualFold(strings.TrimSpace(cfg.Gateway.ZoneDefaultRelays[liface]), "block") ||
						resolveZoneDNSPort(cfg, liface, tproxyPorts, basePort) != firstDNSPort {
						uniformDNS = false
						break
					}
				}
				if uniformDNS {
					if firstDNSPort > 0 {
						b.WriteString("        meta l4proto { tcp, udp } th dport 53 tproxy to :" + strconv.Itoa(firstDNSPort) + " meta mark set " + tunMark + " accept\n")
					}
				} else {
					for _, liface := range lanIfaces {
						if strings.EqualFold(strings.TrimSpace(cfg.Gateway.ZoneDefaultRelays[liface]), "block") {
							b.WriteString("        iifname " + quoteIface(liface) + " meta l4proto { tcp, udp } th dport 53 drop\n")
							continue
						}
						if p := resolveZoneDNSPort(cfg, liface, tproxyPorts, basePort); p > 0 {
							b.WriteString("        iifname " + quoteIface(liface) + " meta l4proto { tcp, udp } th dport 53 tproxy to :" + strconv.Itoa(p) + " meta mark set " + tunMark + " accept\n")
						}
					}
				}
			}

			// Step 3: Multi-subnet LAN source guards and non-LL IPv6 leak prevention.
			for i, iface := range lanIfaces {
				var cidr, ipv6Cidr string
				if i < len(lanCIDRs) {
					cidr = lanCIDRs[i]
				}
				if i < len(lanIPv6CIDRs) {
					ipv6Cidr = lanIPv6CIDRs[i]
				}
				if cidr != "" {
					b.WriteString("        iifname " + quoteIface(iface) + " ip saddr != " + nftAddrSet(cidr) + " return\n")
				}
				if ipv6Cidr != "" {
					b.WriteString("        iifname " + quoteIface(iface) + " ip6 saddr != " + nftAddrSet(ipv6Cidr) + " return\n")
				} else {
					b.WriteString("        iifname " + quoteIface(iface) + " ip6 saddr != { ::/128, fe80::/10 } drop\n")
					b.WriteString("        iifname " + quoteIface(iface) + " ip6 saddr { ::/128, fe80::/10 } return\n")
				}
			}

			// Destination bypasses (always bypass RFC1918/ULA + LAN CIDRs + outbound endpoints)
			writeCommonDestinationBypasses(&b, cfg, lanCIDRs, lanIPv6CIDRs)

			// Per-client non-DNS rules ordered by unified specificity
			for _, rule := range sortedRules {
				if isBlockRule(rule) {
					continue
				}
				match := strings.Join(matchTokens(rule), " ")
				if isDirectRule(rule) {
					b.WriteString("        " + match + " return\n")
					continue
				}
				target := strings.TrimSpace(rule.Target)
				port := tproxyPorts[target]
				if port <= 0 || !config.GatewayRelayActive(cfg, target) {
					b.WriteString("        " + match + " drop\n")
					continue
				}
				tproxyFamily := ruleTProxyFamily(rule)
				b.WriteString("        " + match + " meta l4proto { tcp, udp } tproxy " + tproxyFamily + "to :" + strconv.Itoa(port) + " meta mark set " + tunMark + " accept\n")
			}

			// Default Gateway Policy
			if pathTunnelEnabled(cfg) {
				b.WriteString("        icmp type echo-request meta mark set " + pathTunMark + "\n")
				b.WriteString("        icmpv6 type echo-request meta mark set " + pathTunMark + "\n")
			}
			if len(cfg.Gateway.ZoneDefaultRelays) == 0 {
				if cfg.Gateway.RelayAlias != "" && !strings.EqualFold(cfg.Gateway.RelayAlias, "direct") && !strings.EqualFold(cfg.Gateway.RelayAlias, "block") {
					if port := tproxyPorts[cfg.Gateway.RelayAlias]; port > 0 && config.GatewayRelayActive(cfg, cfg.Gateway.RelayAlias) {
						b.WriteString("        meta l4proto { tcp, udp } tproxy to :" + strconv.Itoa(port) + " meta mark set " + tunMark + " accept\n")
					}
				}
			} else {
				for _, liface := range lanIfaces {
					explicit := strings.TrimSpace(cfg.Gateway.ZoneDefaultRelays[liface])
					switch {
					case strings.EqualFold(explicit, "block"):
						b.WriteString("        iifname " + quoteIface(liface) + " drop\n")
					case strings.EqualFold(explicit, "direct"):
						b.WriteString("        iifname " + quoteIface(liface) + " return\n")
					default:
						zRelay := cfg.Gateway.EffectiveRelayForInterface(liface)
						if explicit != "" && !config.GatewayRelayActive(cfg, explicit) {
							b.WriteString("        iifname " + quoteIface(liface) + " drop\n")
						} else if zRelay != "" && config.GatewayRelayActive(cfg, zRelay) && tproxyPorts[zRelay] > 0 {
							b.WriteString("        iifname " + quoteIface(liface) + " meta l4proto { tcp, udp } tproxy to :" + strconv.Itoa(tproxyPorts[zRelay]) + " meta mark set " + tunMark + " accept\n")
						}
					}
				}
			}
		}
		b.WriteString("    }\n")
	}

	if cfg.Gateway.LocalEnabled {
		b.WriteString("    chain output {\n")
		b.WriteString("        type route hook output priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		b.WriteString("        fib daddr type local return\n")
		writeCommonDestinationBypasses(&b, cfg, lanCIDRs, lanIPv6CIDRs)
		for _, port := range getSSHPorts() {
			// Exclude the SSH listener's reply traffic (source port) to prevent
			// inbound management sessions from being intercepted or broken.
			b.WriteString("        tcp sport " + port + " return\n")
		}
		if pathTunnelEnabled(cfg) {
			b.WriteString("        icmp type echo-request meta mark set " + pathTunMark + "\n")
			b.WriteString("        icmpv6 type echo-request meta mark set " + pathTunMark + "\n")
		}
		if localProxyActive {
			b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
		}
		b.WriteString("    }\n")
	}

	// Managed WAN NAT Masquerade, Port Forwarding & Forwarding
	hasPortForwards := wanIface != "" && len(cfg.Gateway.PortForwards) > 0
	hasManagedNAT := !cfg.Gateway.NATDisabled && wanIface != "" && len(lanIfaces) > 0

	wanDistinct := true
	if hasManagedNAT {
		for _, liface := range lanIfaces {
			if liface == wanIface {
				wanDistinct = false
				break
			}
		}
		if !wanDistinct {
			fmt.Printf("⚠️ WAN interface %q overlaps with LAN interface; managed masquerade skipped to prevent loop\n", wanIface)
			hasManagedNAT = false
		}
	}

	if hasPortForwards {
		b.WriteString("    chain nat_prerouting {\n")
		b.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
		for _, pf := range cfg.Gateway.PortForwards {
			targetIP := strings.TrimSpace(pf.TargetIP)
			isV6 := strings.Contains(targetIP, ":")
			if addr, err := netip.ParseAddr(targetIP); err == nil {
				isV6 = addr.Is6()
			}
			nfProto := "meta nfproto ipv4 "
			dnatVerb := "dnat ip to "
			target := fmt.Sprintf("%s:%d", targetIP, pf.TargetPort)
			if isV6 {
				nfProto = "meta nfproto ipv6 "
				dnatVerb = "dnat ip6 to "
				target = fmt.Sprintf("[%s]:%d", targetIP, pf.TargetPort)
			}
			proto := strings.ToLower(strings.TrimSpace(pf.Proto))
			switch proto {
			case "tcp":
				b.WriteString(fmt.Sprintf("        iifname %q %stcp dport %d %s%s\n", wanIface, nfProto, pf.WANPort, dnatVerb, target))
			case "udp":
				b.WriteString(fmt.Sprintf("        iifname %q %sudp dport %d %s%s\n", wanIface, nfProto, pf.WANPort, dnatVerb, target))
			default:
				b.WriteString(fmt.Sprintf("        iifname %q %smeta l4proto { tcp, udp } th dport %d %s%s\n", wanIface, nfProto, pf.WANPort, dnatVerb, target))
			}
		}
		b.WriteString("    }\n")
	}

	var noV6Ifaces []string
	if cfg.Gateway.LANEnabled {
		for i, iface := range lanIfaces {
			if i >= len(lanIPv6CIDRs) || strings.TrimSpace(lanIPv6CIDRs[i]) == "" {
				noV6Ifaces = append(noV6Ifaces, iface)
			}
		}
	}

	hasIsolated := len(isoIfaces) > 0

	if hasManagedNAT || hasPortForwards || hasIsolated || len(blockEntries) > 0 || len(noV6Ifaces) > 0 {
		b.WriteString("    chain forward {\n")
		b.WriteString("        type filter hook forward priority filter; policy accept;\n")
		if len(blockEntries) > 0 {
			b.WriteString("        jump block_guard\n")
		}
		if hasPortForwards {
			b.WriteString("        ct status dnat accept\n")
		}
		writeIsolatedForwardRules(&b, isoIfaces, lanIfaces)
		for _, iface := range noV6Ifaces {
			b.WriteString("        iifname " + quoteIface(iface) + " ip6 saddr != { ::/128, fe80::/10 } drop\n")
		}
		if hasManagedNAT {
			lanMatch := nftIfaceList(lanIfaces)
			b.WriteString("        iifname " + lanMatch + " oifname \"" + wanIface + "\" accept\n")
			b.WriteString("        iifname \"" + wanIface + "\" oifname " + lanMatch + " ct state established,related accept\n")
		}
		b.WriteString("    }\n")

		if hasManagedNAT {
			lanMatch := nftIfaceList(lanIfaces)
			b.WriteString("    chain postrouting {\n")
			b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
			b.WriteString("        iifname " + lanMatch + " oifname \"" + wanIface + "\" masquerade\n")
			b.WriteString("    }\n")
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// buildFailClosedNFT constructs a fail-closed protection table installed when
// TProxy startup fails and FailOpen is false. It preserves client block/isolate
// policies and host SSH management while dropping traffic that would have been
// routed through a proxy relay so real IPs cannot leak on proxy failure.
func buildFailClosedNFT(cfg *config.UserConfig, lanIfaces, lanCIDRs, lanIPv6CIDRs []string, wanIface string) string {
	var b strings.Builder
	blockEntries := blockGuardEntries(cfg)
	isoIfaces := cfg.Gateway.EffectiveIsolatedInterfaces()
	sortedRules := sortedAllClientRules(cfg)
	localRelay := ""
	if cfg != nil {
		localRelay = cfg.Gateway.EffectiveLocalRelay()
	}

	b.WriteString("table inet " + tableName + "\n")
	b.WriteString("delete table inet " + tableName + "\n")
	b.WriteString("table inet " + tableName + " {\n")
	writeBlockGuardChain(&b, blockEntries)

	if len(blockEntries) > 0 || len(isoIfaces) > 0 {
		b.WriteString("    chain input {\n")
		b.WriteString("        type filter hook input priority mangle; policy accept;\n")
		if len(blockEntries) > 0 {
			b.WriteString("        jump block_guard\n")
		}
		writeIsolatedInputRules(&b, isoIfaces, false)
		b.WriteString("    }\n")
	}

	if cfg != nil && cfg.Gateway.LANEnabled && len(lanIfaces) > 0 {
		b.WriteString("    chain prerouting {\n")
		b.WriteString("        type filter hook prerouting priority mangle; policy accept;\n")
		b.WriteString("        iifname \"lo\" return\n")
		if len(blockEntries) > 0 {
			b.WriteString("        jump block_guard\n")
		}
		b.WriteString("        iifname != " + nftIfaceList(lanIfaces) + " return\n")
		b.WriteString("        iifname != \"lo\" fib daddr type local meta l4proto != { tcp, udp } return\n")
		b.WriteString("        iifname != \"lo\" fib daddr type local th dport != 53 return\n")
		// Drop proxied DNS (:53) even for direct clients while proxy DNS is down.
		b.WriteString("        meta l4proto { tcp, udp } th dport 53 drop\n")
		writeCommonDestinationBypasses(&b, cfg, lanCIDRs, lanIPv6CIDRs)
		for _, rule := range sortedRules {
			if isBlockRule(rule) {
				continue
			}
			match := strings.Join(matchTokens(rule), " ")
			if isDirectRule(rule) {
				b.WriteString("        " + match + " return\n")
			} else {
				b.WriteString("        " + match + " drop\n")
			}
		}
		for _, liface := range lanIfaces {
			explicit := strings.TrimSpace(cfg.Gateway.ZoneDefaultRelays[liface])
			if strings.EqualFold(explicit, "direct") {
				b.WriteString("        iifname " + quoteIface(liface) + " return\n")
			} else {
				b.WriteString("        iifname " + quoteIface(liface) + " drop\n")
			}
		}
		b.WriteString("    }\n")
	}

	if len(blockEntries) > 0 || len(isoIfaces) > 0 || (cfg != nil && cfg.Gateway.LANEnabled && len(lanIfaces) > 0) {
		b.WriteString("    chain forward {\n")
		b.WriteString("        type filter hook forward priority filter; policy accept;\n")
		if len(blockEntries) > 0 {
			b.WriteString("        jump block_guard\n")
		}
		writeIsolatedForwardRules(&b, isoIfaces, lanIfaces)
		if cfg != nil && cfg.Gateway.LANEnabled && len(lanIfaces) > 0 {
			b.WriteString("        meta l4proto { tcp, udp } th dport 53 drop\n")
			b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } accept\n")
			b.WriteString("        ip6 daddr { ::1/128, fc00::/7, fe80::/10 } accept\n")
			for _, rule := range sortedRules {
				if isBlockRule(rule) {
					continue
				}
				match := strings.Join(matchTokens(rule), " ")
				if isDirectRule(rule) {
					b.WriteString("        " + match + " accept\n")
				} else {
					b.WriteString("        " + match + " drop\n")
				}
			}
			for _, liface := range lanIfaces {
				if strings.EqualFold(strings.TrimSpace(cfg.Gateway.ZoneDefaultRelays[liface]), "direct") {
					b.WriteString("        iifname " + quoteIface(liface) + " accept\n")
				} else {
					b.WriteString("        iifname " + quoteIface(liface) + " drop\n")
				}
			}
		}
		b.WriteString("    }\n")
	}

	if cfg != nil && cfg.Gateway.LocalEnabled && localRelay != "" {
		b.WriteString("    chain output {\n")
		b.WriteString("        type route hook output priority mangle; policy accept;\n")
		b.WriteString("        fib daddr type local return\n")
		writeCommonDestinationBypasses(&b, cfg, lanCIDRs, lanIPv6CIDRs)
		for _, port := range getSSHPorts() {
			b.WriteString("        tcp sport " + port + " return\n")
		}
		b.WriteString("        meta l4proto { tcp, udp } drop\n")
		b.WriteString("    }\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func applyFailClosedFirewall(cfg *config.UserConfig, lanIfaces, lanCIDRs, lanIPv6CIDRs []string, wanIface string) error {
	rules := buildFailClosedNFT(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface)
	configDir := filepath.Dir(config.GetConfigPathEx(false))
	_ = os.MkdirAll(configDir, 0700)
	f, err := os.CreateTemp(configDir, "xray-proxya-failclosed-*.nft")
	if err != nil {
		return fmt.Errorf("create fail-closed nft file: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile)
	if _, err := f.WriteString(rules); err != nil {
		f.Close()
		return fmt.Errorf("write fail-closed nft rules: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close fail-closed nft file: %w", err)
	}

	var errs []error
	if err := run("nft", "-f", tmpFile); err != nil {
		errs = append(errs, err)
	}
	// Remove TProxy redirection policy rules so traffic doesn't loop to dead sockets,
	// while the fail-closed table blocks public leak.
	if oldRules, loadErr := loadPolicyRules(); loadErr == nil {
		allDeleted := true
		for _, r := range oldRules {
			if delErr := deletePolicyRule(r); delErr != nil {
				allDeleted = false
				errs = append(errs, delErr)
			}
		}
		if allDeleted {
			_ = removeIfExists(policyRulesPath())
		}
	}
	_ = runDelete("ip", "route", "del", "local", "default", "dev", "lo", "table", policyTable)
	_ = runDelete("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", policyTable)
	return errors.Join(errs...)
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

var sshdConfigMainPath = "/etc/ssh/sshd_config"
var sshdConfigDirPath = "/etc/ssh/sshd_config.d"

func parseSSHDConfigPorts(path string, found map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var portStr string
		if strings.EqualFold(fields[0], "port") && len(fields) >= 2 {
			portStr = fields[1]
		} else if len(fields[0]) > 5 && strings.EqualFold(fields[0][:5], "port=") {
			portStr = fields[0][5:]
		}
		if portStr != "" {
			if p, err := strconv.ParseUint(portStr, 10, 16); err == nil && p > 0 {
				found[strconv.FormatUint(p, 10)] = true
			}
		}
	}
}

func getSSHPorts() []string {
	// Always protect port 22, the active SSH_CONNECTION port, and any ports
	// configured in sshd_config / sshd_config.d/*.conf. Sort deterministically
	// so generated nftables rules are idempotent.
	found := map[string]bool{"22": true}
	if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) == 4 {
		if p, err := strconv.ParseUint(fields[3], 10, 16); err == nil && p > 0 {
			found[strconv.FormatUint(p, 10)] = true
		}
	}
	if sshdConfigMainPath != "" {
		parseSSHDConfigPorts(sshdConfigMainPath, found)
	}
	if sshdConfigDirPath != "" {
		if matches, err := filepath.Glob(filepath.Join(sshdConfigDirPath, "*.conf")); err == nil {
			sort.Strings(matches)
			for _, m := range matches {
				parseSSHDConfigPorts(m, found)
			}
		}
	}
	ports := make([]string, 0, len(found))
	for port := range found {
		ports = append(ports, port)
	}
	sort.Strings(ports)
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
	return installDirectLANForwardRulesWithConfig(nil, lanIfaces...)
}

func installDirectLANForwardRulesWithConfig(cfg *config.UserConfig, lanIfaces ...string) error {
	var wanIface string
	if cfg != nil {
		wanIface = resolveWANInterface(cfg)
	} else {
		var err error
		wanIface, err = detectDefaultInterfaceFn()
		if err != nil {
			return fmt.Errorf("detect default WAN interface: %w", err)
		}
	}
	if wanIface == "" {
		if cfg != nil && cfg.Gateway.NATDisabled {
			return nil
		}
		return fmt.Errorf("detect default WAN interface: no default route interface found")
	}
	for _, lanIface := range lanIfaces {
		if lanIface != "" && lanIface == wanIface {
			fmt.Printf("⚠️ WAN interface %q overlaps with LAN interface; managed masquerade skipped to prevent loop\n", wanIface)
			return nil
		}
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
		if cfg != nil && cfg.Gateway.NATDisabled {
			continue
		}
		// In the inet table, masquerade performs dual-stack NAT (NAT44 and NAT66).
		if err := run("nft", "add", "rule", "inet", "filter", "postrouting", "iifname", lanIface, "oifname", wanIface, "masquerade", "comment", "\"xray-proxya\""); err != nil {
			return fmt.Errorf("enable direct LAN NAT masquerade: %w", err)
		}
	}
	return nil
}

func setupDirectLANForwarding(lanIfaces ...string) error {
	return setupDirectLANForwardingWithConfig(nil, lanIfaces...)
}

func setupDirectLANForwardingWithConfig(cfg *config.UserConfig, lanIfaces ...string) error {
	if err := SetupKernel(lanIfaces...); err != nil {
		return fmt.Errorf("kernel setup failed: %w", err)
	}
	return installDirectLANForwardRulesWithConfig(cfg, lanIfaces...)
}

func installIsolatedFilterRules(cfg *config.UserConfig, lanIfaces []string) error {
	if cfg == nil {
		return nil
	}
	isoIfaces := cfg.Gateway.EffectiveIsolatedInterfaces()
	if len(isoIfaces) == 0 {
		return nil
	}
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority filter; }")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")

	var inputRules [][]string
	for _, iso := range isoIfaces {
		inputRules = append(inputRules,
			[]string{"iifname", iso, "udp", "dport", "{", "67,", "68,", "546,", "547", "}", "accept"},
			[]string{"iifname", iso, "icmp", "type", "{", "echo-request,", "destination-unreachable,", "time-exceeded", "}", "accept"},
			[]string{"iifname", iso, "icmpv6", "type", "{", "echo-request,", "destination-unreachable,", "packet-too-big,", "time-exceeded,", "parameter-problem,", "nd-router-solicit,", "nd-router-advert,", "nd-neighbor-solicit,", "nd-neighbor-advert", "}", "accept"},
			[]string{"iifname", iso, "drop"},
		)
	}
	if err := insertFilterRules("input", inputRules...); err != nil {
		return err
	}

	var forwardRules [][]string
	for _, iso := range isoIfaces {
		forwardRules = append(forwardRules, []string{"iifname", iso, "oifname", iso, "drop"})
		for _, liface := range lanIfaces {
			if liface != "" && liface != iso {
				forwardRules = append(forwardRules,
					[]string{"iifname", iso, "oifname", liface, "drop"},
					[]string{"iifname", liface, "oifname", iso, "ct", "state", "new", "drop"})
			}
		}
	}
	return insertFilterRules("forward", forwardRules...)
}

func policyRuleKey(r policyRuleSpec) string {
	return fmt.Sprintf("%v|%s", r.IPv6, strings.Join(r.Args, " "))
}

func syncPolicyRules(oldRules, newRules []policyRuleSpec) error {
	oldMap := make(map[string]policyRuleSpec, len(oldRules))
	for _, r := range oldRules {
		oldMap[policyRuleKey(r)] = r
	}
	newMap := make(map[string]policyRuleSpec, len(newRules))
	for _, r := range newRules {
		newMap[policyRuleKey(r)] = r
	}
	for _, r := range newRules {
		if _, exists := oldMap[policyRuleKey(r)]; !exists {
			if err := addPolicyRule(r); err != nil {
				return err
			}
		}
	}
	for _, r := range oldRules {
		if _, keep := newMap[policyRuleKey(r)]; !keep {
			_ = deletePolicyRule(r)
		}
	}
	return nil
}

func listFilterManagedHandles(chain string) ([]string, error) {
	out, err := execCommandCombinedOutput("nft", "-a", "list", "chain", "inet", "filter", chain)
	if err != nil {
		if isMissingKernelObject(err, out) {
			return nil, nil
		}
		return nil, fmt.Errorf("list filter %s chain: %w (output: %q)", chain, err, strings.TrimSpace(string(out)))
	}
	var handles []string
	for _, line := range strings.Split(string(out), "\n") {
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
					handles = append(handles, digits)
				}
			}
		}
	}
	return handles, nil
}

func deleteFilterHandles(chain string, handles []string) error {
	var errs []error
	for _, h := range handles {
		if err := runDelete("nft", "delete", "rule", "inet", "filter", chain, "handle", h); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func cleanupFilterManagedRules(chain string) error {
	handles, err := listFilterManagedHandles(chain)
	if err != nil {
		return err
	}
	return deleteFilterHandles(chain, handles)
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
