package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"xray-proxya/internal/config"
)

const (
	tableName   = "xray_proxya"
	tunName     = "proxya-tun"
	tunIPv4CIDR = "172.16.255.1/30"
	tunIPv6CIDR = "fd00:eea:ff::1/126"
	xrayMark    = "255"
	tunMark     = "1"
	policyTable = "100"
	prefXray    = "10000"
	prefLAN     = "10010"
	prefLoopback = "10011"
	prefTun     = "10100"
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

func ApplyFirewall(cfg *config.UserConfig) error {
	if cfg == nil || cfg.Role != config.RoleGateway {
		return nil
	}
	if cfg.Gateway.Mode != "tun" {
		return nil
	}

	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}

	if state == "disabled" {
		CleanupFirewall()
		return nil
	}

	lanIface := cfg.Gateway.LANInterface
	if lanIface == "" {
		return fmt.Errorf("gateway LAN interface is not configured; run 'gateway set --lan <iface>'")
	}

	if state == "forward-only" {
		CleanupFirewall()
		if err := SetupKernel(lanIface); err != nil {
			return fmt.Errorf("kernel setup failed: %w", err)
		}
		return nil
	}

	if !cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled {
		CleanupFirewall()
		if err := SetupKernel(lanIface); err != nil {
			return fmt.Errorf("kernel setup failed: %w", err)
		}
		return nil
	}
	if config.GatewayTunDisabled() {
		return fmt.Errorf("gateway runtime is down; run 'xray-proxya gateway up' first")
	}

	lanCIDR, err := getInterfaceCIDR(lanIface)
	if err != nil {
		return fmt.Errorf("detect LAN subnet for %s: %w", lanIface, err)
	}
	lanIPv6CIDR, _ := getInterfaceIPv6CIDR(lanIface)
	rules := buildNFT(cfg, lanIface, lanCIDR, lanIPv6CIDR)
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

	CleanupFirewall()
	if err := SetupKernel(lanIface); err != nil {
		return fmt.Errorf("kernel setup failed: %w", err)
	}

	// Wait for tun interface to be created by Xray (which runs asynchronously)
	var found bool
	for i := 0; i < 40; i++ {
		if _, err := net.InterfaceByName(tunName); err == nil {
			found = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		return fmt.Errorf("tun interface %s was not created in time by Xray core. (Hint: Is the 'xray-proxya' service running? Try 'xray-proxya service status' or 'service start')", tunName)
	}

	if err := run("ip", "addr", "replace", tunIPv4CIDR, "dev", tunName); err != nil {
		return err
	}
	if err := run("ip", "-6", "addr", "replace", tunIPv6CIDR, "dev", tunName); err != nil {
		return err
	}

	ipv6Supported := false
	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		ipv6Supported = true
	}

	rulesToAdd := policyRules(lanCIDR, lanIPv6CIDR, ipv6Supported)
	if err := savePolicyRules(rulesToAdd); err != nil {
		return err
	}
	for _, rule := range rulesToAdd {
		if err := addPolicyRule(rule); err != nil {
			CleanupFirewall()
			return err
		}
	}
	if err := run("ip", "route", "replace", "default", "dev", tunName, "table", policyTable); err != nil {
		CleanupFirewall()
		return err
	}
	if ipv6Supported {
		if err := run("ip", "-6", "route", "replace", "default", "dev", tunName, "table", policyTable); err != nil {
			CleanupFirewall()
			return err
		}
	}

	if err := run("nft", "-f", tmpFile); err != nil {
		return err
	}

	// Ensure system filter table and forward chain exist
	_ = run("nft", "add", "table", "inet", "filter")
	_ = run("nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority filter; }")

	// Add forward rules to allow traffic to/from proxya-tun and bypassed local interface traffic
	_ = run("nft", "add", "rule", "inet", "filter", "forward", "iifname", tunName, "accept", "comment", "\"xray-proxya\"")
	_ = run("nft", "add", "rule", "inet", "filter", "forward", "oifname", tunName, "accept", "comment", "\"xray-proxya\"")
	if lanIface != "" {
		_ = run("nft", "add", "rule", "inet", "filter", "forward", "iifname", lanIface, "oifname", lanIface, "accept", "comment", "\"xray-proxya\"")
	}

	return nil
}

func CleanupFirewall() {
	_ = run("nft", "delete", "table", "inet", tableName)
	cleanupFilterForwardRules()

	for _, rule := range loadPolicyRules() {
		_ = deletePolicyRule(rule)
	}
	_ = os.Remove(policyRulesPath())
	_ = run("ip", "route", "del", "default", "dev", tunName, "table", policyTable)
	_ = run("ip", "-6", "route", "del", "default", "dev", tunName, "table", policyTable)
}

func policyRules(lanCIDR, lanIPv6CIDR string, ipv6Supported bool) []policyRuleSpec {
	rules := []policyRuleSpec{
		{Args: []string{"fwmark", tunMark, "table", policyTable, "pref", prefTun}},
		{Args: []string{"fwmark", xrayMark, "table", "main", "pref", prefXray}},
		{Args: []string{"to", lanCIDR, "table", "main", "pref", prefLAN}},
		{Args: []string{"to", "127.0.0.0/8", "table", "main", "pref", prefLoopback}},
	}
	if !ipv6Supported {
		return rules
	}
	rules = append(rules,
		policyRuleSpec{IPv6: true, Args: []string{"fwmark", tunMark, "table", policyTable, "pref", prefTun}},
		policyRuleSpec{IPv6: true, Args: []string{"fwmark", xrayMark, "table", "main", "pref", prefXray}},
	)
	if lanIPv6CIDR != "" {
		rules = append(rules, policyRuleSpec{IPv6: true, Args: []string{"to", lanIPv6CIDR, "table", "main", "pref", prefLAN}})
	}
	return append(rules, policyRuleSpec{IPv6: true, Args: []string{"to", "::1/128", "table", "main", "pref", prefLoopback}})
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

func loadPolicyRules() []policyRuleSpec {
	data, err := os.ReadFile(policyRulesPath())
	if err != nil {
		return nil
	}
	var rules []policyRuleSpec
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil
	}
	return rules
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
	return run("ip", args...)
}

func SetupKernel(lanIface string) error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	if err := run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return err
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
	if lanIface != "" {
		if err := run("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.send_redirects=0", lanIface)); err != nil {
			return err
		}
		if err := run("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", lanIface)); err != nil {
			return err
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
	if cfg == nil || cfg.Role != config.RoleGateway || cfg.Gateway.Mode != "tun" {
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
	lanCIDR, err := getInterfaceCIDR(cfg.Gateway.LANInterface)
	if err != nil {
		return "", err
	}
	lanIPv6CIDR, _ := getInterfaceIPv6CIDR(cfg.Gateway.LANInterface)
	return buildNFT(cfg, cfg.Gateway.LANInterface, lanCIDR, lanIPv6CIDR), nil
}

func Verify(cfg *config.UserConfig) []string {
	var problems []string
	if cfg == nil {
		return []string{"config is not loaded"}
	}
	if cfg.Role != config.RoleGateway {
		return []string{"role is not gateway"}
	}
	if cfg.Gateway.Mode != "tun" {
		problems = append(problems, "gateway mode is not tun")
	}
	if cfg.Gateway.LANInterface == "" {
		problems = append(problems, "LAN interface is not configured")
	} else if _, err := net.InterfaceByName(cfg.Gateway.LANInterface); err != nil {
		problems = append(problems, fmt.Sprintf("LAN interface %s not found", cfg.Gateway.LANInterface))
	}

	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}

	if state == "disabled" {
		if err := exec.Command("nft", "list", "table", "inet", tableName).Run(); err == nil {
			problems = append(problems, "nft table inet "+tableName+" is still present but gateway state is disabled")
		}
		return problems
	}

	// For both forward-only and proxy, check IP forwarding is enabled
	if out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output(); err != nil || strings.TrimSpace(string(out)) != "1" {
		problems = append(problems, "net.ipv4.ip_forward is not enabled")
	}

	if state == "forward-only" {
		if err := exec.Command("nft", "list", "table", "inet", tableName).Run(); err == nil {
			problems = append(problems, "nft table inet "+tableName+" is present but gateway state is forward-only")
		}
		return problems
	}

	// For proxy state, perform full verification
	if err := exec.Command("ip", "link", "show", tunName).Run(); err != nil {
		problems = append(problems, tunName+" interface is not present (Hint: Is the 'xray-proxya' service running?)")
	} else {
		if !interfaceHasCIDR(tunName, tunIPv4CIDR) {
			problems = append(problems, tunName+" is missing IPv4 address "+tunIPv4CIDR)
		}
		ipv6Supported := false
		if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
			ipv6Supported = true
		}
		if ipv6Supported && !interfaceHasCIDR(tunName, tunIPv6CIDR) {
			problems = append(problems, tunName+" is missing IPv6 address "+tunIPv6CIDR)
		}
	}
	if err := exec.Command("nft", "list", "table", "inet", tableName).Run(); err != nil {
		problems = append(problems, "nft table inet "+tableName+" is not present")
	}
	return problems
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

func buildNFT(cfg *config.UserConfig, lanIface, lanCIDR, lanIPv6CIDR string) string {
	var b strings.Builder
	b.WriteString("table inet " + tableName + " {\n")
	if cfg.Gateway.LANEnabled {
		b.WriteString("    chain prerouting {\n")
		b.WriteString("        type filter hook prerouting priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		b.WriteString("        iifname != \"" + lanIface + "\" return\n")
		b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		b.WriteString("        ip daddr " + lanCIDR + " return\n")
		b.WriteString("        ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n")
		if lanIPv6CIDR != "" {
			b.WriteString("        ip6 daddr " + lanIPv6CIDR + " return\n")
		}
		for _, ip := range outboundIPs(cfg) {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if parsedIP.To4() != nil {
					b.WriteString("        ip daddr " + ip + " return\n")
				} else {
					b.WriteString("        ip6 daddr " + ip + " return\n")
				}
			}
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
		b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
		b.WriteString("    }\n")
	}

	if cfg.Gateway.LocalEnabled {
		b.WriteString("    chain output {\n")
		b.WriteString("        type route hook output priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		b.WriteString("        ip daddr " + lanCIDR + " return\n")
		b.WriteString("        ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n")
		if lanIPv6CIDR != "" {
			b.WriteString("        ip6 daddr " + lanIPv6CIDR + " return\n")
		}
		for _, ip := range outboundIPs(cfg) {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if parsedIP.To4() != nil {
					b.WriteString("        ip daddr " + ip + " return\n")
				} else {
					b.WriteString("        ip6 daddr " + ip + " return\n")
				}
			}
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
			b.WriteString("        tcp dport " + port + " return\n")
		}
		b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
		b.WriteString("    }\n")
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

func outboundIPs(cfg *config.UserConfig) []string {
	var ips []string
	seen := map[string]bool{}
	for _, co := range cfg.CustomOutbounds {
		if !co.Enabled {
			continue
		}
		settings, _ := co.Config["settings"].(map[string]interface{})
		vnextList, _ := settings["vnext"].([]interface{})
		for _, item := range vnextList {
			vnext, _ := item.(map[string]interface{})
			addr, _ := vnext["address"].(string)
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			if seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			ips = append(ips, ip.String())
		}
	}
	return ips
}

func getSSHPorts() []string {
	ports := []string{"22"}
	out, err := exec.Command("sh", "-c", "ss -tlnp | grep sshd").Output()
	if err != nil {
		return ports
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		hostPort := fields[3]
		idx := strings.LastIndex(hostPort, ":")
		if idx < 0 || idx+1 >= len(hostPort) {
			continue
		}
		port := hostPort[idx+1:]
		if port != "" {
			found[port] = true
		}
	}
	if len(found) == 0 {
		return ports
	}
	ports = ports[:0]
	for port := range found {
		ports = append(ports, port)
	}
	return ports
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %s %v failed: %w (output: %q)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cleanupFilterForwardRules() {
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", "filter", "forward").Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "xray-proxya") || strings.Contains(line, "proxya-tun") {
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
					_ = run("nft", "delete", "rule", "inet", "filter", "forward", "handle", digits)
				}
			}
		}
	}
}
