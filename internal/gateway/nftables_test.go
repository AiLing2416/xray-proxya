package gateway

import (
	"errors"
	"os"
	"strings"
	"testing"

	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
)

func TestIsMissingKernelObject(t *testing.T) {
	if !isMissingKernelObject(errors.New("command failed"), []byte("Error: No such chain")) {
		t.Fatal("missing nft chain should be treated as an idempotent cleanup")
	}
	if !isMissingKernelObject(errors.New("command failed"), []byte("Error: FIB table does not exist.")) {
		t.Fatal("missing policy-routing table should be treated as an idempotent cleanup")
	}
	if !isMissingKernelObject(errors.New("command failed"), []byte("iptables: Bad rule (does a matching rule exist in that chain?).")) {
		t.Fatal("missing iptables rule should be treated as an idempotent cleanup")
	}
	if !isMissingKernelObject(errors.New("command failed"), []byte("ip6tables: Bad rule (does a matching rule exist in that chain?).")) {
		t.Fatal("missing ip6tables rule should be treated as an idempotent cleanup")
	}
	if !isMissingKernelObject(errors.New("command failed"), []byte("iptables: No chain/target/match by that name.")) {
		t.Fatal("missing iptables target or match should be treated as an idempotent cleanup")
	}
	if !isMissingKernelObject(errors.New("command failed"), []byte("ip6tables: Protocol not available")) {
		t.Fatal("disabled IPv6 stack should be treated as an idempotent cleanup")
	}
	if !isMissingKernelObject(errors.New("command failed"), []byte("iptables: No such device")) {
		t.Fatal("removed/renamed network interface should be treated as an idempotent cleanup")
	}
	if isMissingKernelObject(errors.New("command failed"), []byte("permission denied")) {
		t.Fatal("permission errors must not be treated as missing objects")
	}
}

func TestPolicyRuleOutputContains(t *testing.T) {
	rule := policyRuleSpec{Args: []string{"fwmark", tunMark, "table", policyTable, "pref", prefTun}}
	if !policyRuleOutputContains("10100: from all fwmark 0x1 lookup 100\n", rule) {
		t.Fatal("expected IPv4 fwmark policy rule to be recognized")
	}
	if policyRuleOutputContains("10100: from all fwmark 0x2 lookup 101\n", rule) {
		t.Fatal("different mark/table must not satisfy policy rule")
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
	if !strings.Contains(rules, `iifname != { "lo", "ens18" } return`) {
		t.Fatalf("rules should allow lo and configured LAN interface: %s", rules)
	}
	if !strings.Contains(rules, "ip daddr 192.168.50.0/24 return") {
		t.Fatalf("rules should exclude configured LAN subnet: %s", rules)
	}
	if !strings.Contains(rules, `iifname "ens18" ip saddr != 192.168.50.0/24 return`) {
		t.Fatalf("rules should reject spoofed IPv4 LAN sources: %s", rules)
	}

	rulesIPv6 := buildNFT(testGatewayConfig(true, true), "ens18", "192.168.50.0/24", "fd00::/64")
	if !strings.Contains(rulesIPv6, `iifname "ens18" ip6 saddr != fd00::/64 return`) {
		t.Fatalf("rules should reject spoofed IPv6 LAN sources: %s", rulesIPv6)
	}
	if !strings.Contains(rules, `iifname "ens18" ip6 saddr ::/0 return`) {
		t.Fatalf("rules should bypass IPv6 LAN interception without a LAN IPv6 subnet: %s", rules)
	}

	// LAN only
	rulesLANOnly := buildNFT(testGatewayConfig(false, true), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesLANOnly, `iifname != "ens18" return`) {
		t.Fatalf("LAN-only rules should filter on LAN interface: %s", rulesLANOnly)
	}
	if !strings.Contains(rulesLANOnly, "ip saddr != 192.168.50.0/24 return") {
		t.Fatalf("LAN-only rules should reject spoofed IPv4 sources: %s", rulesLANOnly)
	}

	// Local only
	rulesLocalOnly := buildNFT(testGatewayConfig(true, false), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesLocalOnly, `iifname != "lo" return`) {
		t.Fatalf("local-only rules should filter on lo interface in prerouting: %s", rulesLocalOnly)
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
	if !strings.Contains(rulesBoth, "chain input") {
		t.Error("rules should contain input chain when gateway is enabled")
	}
	if !strings.Contains(rulesBoth, "meta mark != 1 meta l4proto { tcp, udp } th dport 12345 drop") {
		t.Error("input chain should contain tproxy port guard")
	}
	if !strings.Contains(rulesBoth, "fib daddr type local return") {
		t.Error("output chain should contain fib daddr type local return")
	}
	if !strings.Contains(rulesBoth, "tproxy to :12345 meta mark set 1 accept") {
		t.Error("prerouting should contain tproxy interception rule")
	}

	// LAN only
	rulesLANOnly := buildNFT(testGatewayConfig(false, true), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesLANOnly, "chain prerouting") {
		t.Error("rules should contain prerouting chain when LANEnabled is true")
	}
	if strings.Contains(rulesLANOnly, "chain output") {
		t.Error("rules should not contain output chain when LocalEnabled is false")
	}

	// Local only: prerouting is required for lo loopback tproxy
	rulesLocalOnly := buildNFT(testGatewayConfig(true, false), "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesLocalOnly, "chain prerouting") {
		t.Error("rules must contain prerouting chain for lo redirection when LocalEnabled is true")
	}
	if !strings.Contains(rulesLocalOnly, "chain output") {
		t.Error("rules should contain output chain when LocalEnabled is true")
	}
}

func TestBuildNFT_Proxy_LocalOnly_GeneratesPreroutingAndOutput(t *testing.T) {
	cfg := testGatewayConfig(true, false)
	cfg.Gateway.State = "proxy"
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rules, "chain prerouting") {
		t.Error("rules must contain prerouting chain when LocalEnabled is true in proxy state")
	}
	if !strings.Contains(rules, `iifname != "lo" return`) {
		t.Error("rules must filter on lo in prerouting for local-only")
	}
	if !strings.Contains(rules, "chain output") {
		t.Error("rules must contain output chain when LocalEnabled is true in proxy state")
	}
	if !strings.Contains(rules, "tproxy to :12345 meta mark set 1 accept") {
		t.Error("rules must contain tproxy rule in prerouting")
	}
}

func TestBuildNFT_Proxy_LANOnly_GeneratesPreroutingOnly(t *testing.T) {
	cfg := testGatewayConfig(false, true)
	cfg.Gateway.State = "proxy"
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rules, "chain prerouting") {
		t.Error("rules must contain prerouting chain when LANEnabled is true in proxy state")
	}
	if strings.Contains(rules, "chain output") {
		t.Error("rules should not contain output chain when LocalEnabled is false in proxy state")
	}
}

func TestBuildNFT_Proxy_TunMode(t *testing.T) {
	cfg := testGatewayConfig(true, true)
	cfg.Gateway.Mode = "tun"
	cfg.Gateway.State = "proxy"
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "")

	if !strings.Contains(rules, "chain prerouting") {
		t.Error("rules must contain prerouting chain")
	}
	if !strings.Contains(rules, "chain output") {
		t.Error("rules must contain output chain")
	}
	if strings.Contains(rules, "tproxy to :") {
		t.Error("tun mode rules must NOT contain tproxy to :<port>")
	}
	if !strings.Contains(rules, "meta l4proto { tcp, udp } meta mark set 1\n") {
		t.Error("tun mode rules must contain meta mark set 1")
	}
	if strings.Contains(rules, "fib daddr type local return") {
		t.Error("tun mode rules should not return on fib daddr type local")
	}
}

func TestBuildNFTProtectsSSHSourcePortOnly(t *testing.T) {
	rules := buildNFT(testGatewayConfig(true, false), "ens18", "192.168.50.0/24", "")
	for _, port := range getSSHPorts() {
		if !strings.Contains(rules, "tcp sport "+port+" return") {
			t.Fatalf("rules should protect SSH source port %s: %s", port, rules)
		}
		if strings.Contains(rules, "tcp dport "+port+" return") {
			t.Fatalf("rules should not exclude outbound SSH destination port %s: %s", port, rules)
		}
	}
}

func testGatewayConfig(local, lan bool) *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			LocalEnabled: local,
			LANEnabled:   lan,
			Mode:         "tproxy",
			RelayAlias:   "relay-a",
		},
		CustomOutbounds: []config.CustomOutbound{{Alias: "relay-a", Enabled: true}},
	}
}

func TestHasDefaultRoute_Parsing(t *testing.T) {
	origExecCombined := execCommandCombinedOutput
	defer func() { execCommandCombinedOutput = origExecCombined }()

	// Case 1: IPv4 local default route via lo
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		return []byte("local default dev lo scope host\n"), nil
	}
	ok, err := hasDefaultRoute("100", "lo", false)
	if err != nil || !ok {
		t.Fatalf("expected IPv4 local default route via lo to match: ok=%v, err=%v", ok, err)
	}

	// Case 2: IPv6 local default route via lo
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		return []byte("local default dev lo metric 1024 pref medium\n"), nil
	}
	ok, err = hasDefaultRoute("100", "lo", true)
	if err != nil || !ok {
		t.Fatalf("expected IPv6 local default route via lo to match: ok=%v, err=%v", ok, err)
	}

	// Case 3: Path-tun default route
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		return []byte("default dev path-tun scope link\n"), nil
	}
	ok, err = hasDefaultRoute("101", "path-tun", false)
	if err != nil || !ok {
		t.Fatalf("expected default dev path-tun to match: ok=%v, err=%v", ok, err)
	}

	// Case 4: Mismatched device
	ok, err = hasDefaultRoute("101", "other-dev", false)
	if err != nil || ok {
		t.Fatalf("expected mismatch for other-dev: ok=%v, err=%v", ok, err)
	}
}

func configurePathRelay(cfg *config.UserConfig) {
	cfg.CustomOutbounds[0].Path = &config.PathConfig{Listen: pathd.DefaultListenAddress, Token: "token", IdleSeconds: 20}
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

func TestBuildNFTOutboundEndpointsProxyPortOnly(t *testing.T) {
	cfg := testGatewayConfig(true, true)
	cfg.CustomOutbounds = []config.CustomOutbound{
		{
			Alias:   "vless-node",
			Enabled: true,
			Config: map[string]interface{}{
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": "87.58.209.196",
							"port":    443,
						},
					},
				},
			},
		},
		{
			Alias:   "ss-node-v6",
			Enabled: true,
			Config: map[string]interface{}{
				"settings": map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{
							"address": "2001:db8::1",
							"port":    8388,
						},
					},
				},
			},
		},
		{
			Alias:   "no-port-node",
			Enabled: true,
			Config: map[string]interface{}{
				"settings": map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{
							"address": "198.51.100.1",
						},
					},
				},
			},
		},
	}
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "fd00::/64")

	expectedV4 := "ip daddr 87.58.209.196 meta l4proto { tcp, udp } th dport 443 return"
	if !strings.Contains(rules, expectedV4) {
		t.Fatalf("rules should bypass proxy port 443 for 87.58.209.196: %s", rules)
	}
	if strings.Contains(rules, "ip daddr 87.58.209.196 return") {
		t.Fatalf("rules should not bypass whole IP 87.58.209.196 without port: %s", rules)
	}

	expectedV6 := "ip6 daddr 2001:db8::1 meta l4proto { tcp, udp } th dport 8388 return"
	if !strings.Contains(rules, expectedV6) {
		t.Fatalf("rules should bypass proxy port 8388 for 2001:db8::1: %s", rules)
	}
	if strings.Contains(rules, "ip6 daddr 2001:db8::1 return") {
		t.Fatalf("rules should not bypass whole IPv6 2001:db8::1 without port: %s", rules)
	}

	expectedFallback := "ip daddr 198.51.100.1 return"
	if !strings.Contains(rules, expectedFallback) {
		t.Fatalf("rules should fallback to whole IP bypass for node without port: %s", rules)
	}
}

func TestBuildNFTRoutesPathLinkICMPToDedicatedMark(t *testing.T) {
	cfg := testGatewayConfig(true, true)
	configurePathRelay(cfg)
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
			configurePathRelay(cfg)
			if !pathTunnelEnabled(cfg) {
				t.Fatal("PathLink should be enabled when either gateway mode is enabled")
			}
		})
	}
	neither := testGatewayConfig(false, false)
	configurePathRelay(neither)
	if pathTunnelEnabled(neither) {
		t.Fatal("PathLink should be disabled when both gateway modes are disabled")
	}
	noRelay := testGatewayConfig(true, false)
	noRelay.Gateway.RelayAlias = ""
	configurePathRelay(noRelay)
	if pathTunnelEnabled(noRelay) {
		t.Fatal("PathLink should be disabled when no relay is configured")
	}
}

func TestPolicyRulesUseDedicatedPriorities(t *testing.T) {
	rules := policyRules(testGatewayConfig(true, true), "192.168.50.0/24", "fd00::/64", true)
	if len(rules) != 8 {
		t.Fatalf("policyRules returned %d rules, want 8", len(rules))
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
	pathCfg := testGatewayConfig(true, true)
	configurePathRelay(pathCfg)
	if got := len(policyRules(pathCfg, "192.168.50.0/24", "fd00::/64", true)); got != 10 {
		t.Fatalf("PathLink policyRules returned %d rules, want 10", got)
	}
}

func TestSaveSysctlState_DoesNotOverwriteExistingBaseline(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	baselinePath := sysctlStatePath()
	initialData := `{"values":{"net.ipv4.ip_forward":"0","custom.test":"baseline"}}`
	if err := os.WriteFile(baselinePath, []byte(initialData), 0600); err != nil {
		t.Fatalf("failed to write initial sysctl baseline: %v", err)
	}

	if err := saveSysctlState(""); err != nil {
		t.Fatalf("saveSysctlState() returned error: %v", err)
	}

	content, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("failed to read baseline: %v", err)
	}
	if string(content) != initialData {
		t.Fatalf("saveSysctlState() overwrote existing baseline; got %s, want %s", string(content), initialData)
	}
}

func TestForwardOnly_LANDisabled_BlocksForwarding(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	var recordedCmds [][]string
	origRun := runCommand
	origExec := execCommandCombinedOutput
	origDetect := detectDefaultInterfaceFn
	defer func() {
		runCommand = origRun
		execCommandCombinedOutput = origExec
		detectDefaultInterfaceFn = origDetect
	}()

	runCommand = func(name string, args ...string) error {
		cmd := append([]string{name}, args...)
		recordedCmds = append(recordedCmds, cmd)
		return nil
	}
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		return []byte(""), errors.New("Error: No such chain")
	}
	detectDefaultInterfaceFn = func() (string, error) {
		return "eth0", nil
	}

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tun",
			State:        "forward-only",
			LANInterface: "eth1",
			LocalEnabled: true,
			LANEnabled:   false,
		},
	}

	if err := ApplyFirewall(cfg); err != nil {
		t.Fatalf("ApplyFirewall() error = %v", err)
	}

	hasDropRule := false
	hasIPForwardSysctl := false
	hasAcceptRule := false

	for _, cmd := range recordedCmds {
		cmdStr := strings.Join(cmd, " ")
		if strings.Contains(cmdStr, "sysctl") && strings.Contains(cmdStr, "net.ipv4.ip_forward=1") {
			hasIPForwardSysctl = true
		}
		if strings.Contains(cmdStr, "iifname eth1 drop") {
			hasDropRule = true
		}
		if strings.Contains(cmdStr, "accept") {
			hasAcceptRule = true
		}
	}

	if hasIPForwardSysctl {
		t.Error("expected net.ipv4.ip_forward=1 NOT to be called when LAN is disabled in forward-only")
	}
	if !hasDropRule {
		t.Error("expected drop rule for eth1 in forward chain, but none was recorded")
	}
	if hasAcceptRule {
		t.Error("expected no forward accept rules when LAN is disabled in forward-only")
	}
}

func TestForwardOnly_LANEnabled_EnablesForwarding(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	var recordedCmds [][]string
	origRun := runCommand
	origExec := execCommandCombinedOutput
	origDetect := detectDefaultInterfaceFn
	origReadSysctl := readSysctlFn
	defer func() {
		runCommand = origRun
		execCommandCombinedOutput = origExec
		detectDefaultInterfaceFn = origDetect
		readSysctlFn = origReadSysctl
	}()

	readSysctlFn = func(key string) (string, error) {
		return "0", nil
	}

	runCommand = func(name string, args ...string) error {
		cmd := append([]string{name}, args...)
		recordedCmds = append(recordedCmds, cmd)
		return nil
	}
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		return []byte(""), errors.New("Error: No such chain")
	}
	detectDefaultInterfaceFn = func() (string, error) {
		return "eth0", nil
	}

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tun",
			State:        "forward-only",
			LANInterface: "eth1",
			LocalEnabled: false,
			LANEnabled:   true,
		},
	}

	if err := ApplyFirewall(cfg); err != nil {
		t.Fatalf("ApplyFirewall() error = %v", err)
	}

	hasDropRule := false
	hasIPForwardSysctl := false
	hasLANToWANAccept := false
	hasWANToLANAccept := false
	hasMasquerade := false

	for _, cmd := range recordedCmds {
		cmdStr := strings.Join(cmd, " ")
		if strings.Contains(cmdStr, "sysctl") && strings.Contains(cmdStr, "net.ipv4.ip_forward=1") {
			hasIPForwardSysctl = true
		}
		if strings.Contains(cmdStr, "iifname eth1 drop") {
			hasDropRule = true
		}
		if strings.Contains(cmdStr, "iifname eth1 oifname eth0 accept") {
			hasLANToWANAccept = true
		}
		if strings.Contains(cmdStr, "iifname eth0 oifname eth1") && strings.Contains(cmdStr, "ct state established,related accept") {
			hasWANToLANAccept = true
		}
		if strings.Contains(cmdStr, "postrouting") && strings.Contains(cmdStr, "iifname eth1 oifname eth0 masquerade") {
			hasMasquerade = true
		}
	}

	if !hasIPForwardSysctl {
		t.Error("expected net.ipv4.ip_forward=1 to be set when LAN is enabled in forward-only")
	}
	if hasDropRule {
		t.Error("expected NO drop rule when LAN is enabled in forward-only")
	}
	if !hasLANToWANAccept {
		t.Error("expected LAN to WAN accept rule")
	}
	if !hasWANToLANAccept {
		t.Error("expected WAN to LAN established accept rule")
	}
	if !hasMasquerade {
		t.Error("expected postrouting masquerade rule")
	}
}

func TestVerify_StateMatrix(t *testing.T) {
	origForwarding := isIPv4ForwardingEnabledFn
	origExecCombined := execCommandCombinedOutput
	origExecRun := execCommandRun
	defer func() {
		isIPv4ForwardingEnabledFn = origForwarding
		execCommandCombinedOutput = origExecCombined
		execCommandRun = origExecRun
	}()

	execCommandRun = func(name string, args ...string) error {
		// Mock kernel objects: tun/nft table absent for disabled/forward-only
		return errors.New("not found")
	}
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}

	tests := []struct {
		name             string
		state            string
		localEnabled     bool
		lanEnabled       bool
		expectForwarding bool
	}{
		{
			name:             "disabled",
			state:            "disabled",
			localEnabled:     false,
			lanEnabled:       false,
			expectForwarding: false,
		},
		{
			name:             "forward-only_local_only",
			state:            "forward-only",
			localEnabled:     true,
			lanEnabled:       false,
			expectForwarding: false,
		},
		{
			name:             "forward-only_lan_only",
			state:            "forward-only",
			localEnabled:     false,
			lanEnabled:       true,
			expectForwarding: true,
		},
		{
			name:             "proxy_local_only",
			state:            "proxy",
			localEnabled:     true,
			lanEnabled:       false,
			expectForwarding: true,
		},
		{
			name:             "proxy_lan_only",
			state:            "proxy",
			localEnabled:     false,
			lanEnabled:       true,
			expectForwarding: true,
		},
		{
			name:             "proxy_both",
			state:            "proxy",
			localEnabled:     true,
			lanEnabled:       true,
			expectForwarding: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.UserConfig{
				Role: config.RoleGateway,
				Gateway: config.GatewayConfig{
					Mode:         "tun",
					State:        tc.state,
					LANInterface: "lo",
					LocalEnabled: tc.localEnabled,
					LANEnabled:   tc.lanEnabled,
				},
			}

			// Sub-case 1: Kernel ip_forward is DISABLED (0)
			isIPv4ForwardingEnabledFn = func() bool { return false }
			problems := Verify(cfg)
			hasForwardErr := false
			for _, p := range problems {
				if strings.Contains(p, "net.ipv4.ip_forward is not enabled") {
					hasForwardErr = true
					break
				}
			}
			if tc.expectForwarding && !hasForwardErr {
				t.Errorf("expected forwarding error when ip_forward=0, but got none; problems: %v", problems)
			}
			if !tc.expectForwarding && hasForwardErr {
				t.Errorf("did not expect forwarding error when expectForwarding=false, but got: %v", problems)
			}

			// Sub-case 2: Kernel ip_forward is ENABLED (1)
			isIPv4ForwardingEnabledFn = func() bool { return true }
			problems = Verify(cfg)
			for _, p := range problems {
				if strings.Contains(p, "net.ipv4.ip_forward is not enabled") {
					t.Errorf("unexpected forwarding error when ip_forward=1: %v", p)
				}
			}
		})
	}
}

func TestVerify_DetectsUnauthorizedForwardingRules(t *testing.T) {
	origExecCombined := execCommandCombinedOutput
	origExecRun := execCommandRun
	defer func() {
		execCommandCombinedOutput = origExecCombined
		execCommandRun = origExecRun
	}()

	execCommandRun = func(name string, args ...string) error {
		return errors.New("not found")
	}
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) {
		if name == "nft" && len(args) >= 6 && args[5] == "forward" {
			return []byte("table inet filter {\nchain forward {\niifname \"eth1\" oifname \"eth0\" accept comment \"xray-proxya\"\n}\n}"), nil
		}
		return []byte(""), nil
	}

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tun",
			State:        "forward-only",
			LANInterface: "lo",
			LocalEnabled: true,
			LANEnabled:   false, // expectForwarding = false
		},
	}

	problems := Verify(cfg)
	foundUnauthorized := false
	for _, p := range problems {
		if strings.Contains(p, "unexpected managed forward accept rule exists") {
			foundUnauthorized = true
			break
		}
	}
	if !foundUnauthorized {
		t.Fatalf("expected unauthorized forward rule detection, but got: %v", problems)
	}
}

func TestTProxyPortListening(t *testing.T) {
	origFn := isTProxyPortListeningFn
	defer func() { isTProxyPortListeningFn = origFn }()

	isTProxyPortListeningFn = func(port int) bool {
		return port == 12345
	}

	if !isTProxyPortListening(12345) {
		t.Fatal("expected port 12345 to report listening")
	}
	if isTProxyPortListening(54321) {
		t.Fatal("expected port 54321 to report not listening")
	}
	if err := waitForTProxyListener(12345); err != nil {
		t.Fatalf("waitForTProxyListener(12345) failed: %v", err)
	}
}

func TestBuildNFTWithDNSListen(t *testing.T) {
	// 1. Wildcard listen ":53"
	cfgWildcard := testGatewayConfig(true, true)
	cfgWildcard.Gateway.DNSListen = ":53"
	rules := buildNFT(cfgWildcard, "ens18", "192.168.50.0/24", "")
	expectedRule := `iifname != { "lo", "ens18" } meta l4proto { tcp, udp } th dport 53 drop`
	if !strings.Contains(rules, expectedRule) {
		t.Fatalf("expected wildcard dns drop rule %q, got:\n%s", expectedRule, rules)
	}
	if !strings.Contains(rules, `iifname != "lo" fib daddr type local return`) {
		t.Fatalf("expected prerouting local fib return rule, got:\n%s", rules)
	}

	// 2. Specific LAN IP listen "10.0.82.21:53"
	cfgSpecific := testGatewayConfig(true, true)
	cfgSpecific.Gateway.DNSListen = "10.0.82.21:53"
	rulesSpecific := buildNFT(cfgSpecific, "ens18", "192.168.50.0/24", "")
	if !strings.Contains(rulesSpecific, expectedRule) {
		t.Fatalf("expected specific non-loopback dns drop rule %q, got:\n%s", expectedRule, rulesSpecific)
	}

	// 3. Loopback-only listen "127.0.0.1:5353"
	cfgLoopback := testGatewayConfig(true, true)
	cfgLoopback.Gateway.DNSListen = "127.0.0.1:5353"
	rulesLoopback := buildNFT(cfgLoopback, "ens18", "192.168.50.0/24", "")
	if strings.Contains(rulesLoopback, "th dport 5353 drop") {
		t.Fatalf("unexpected dns drop rule for loopback listen, got:\n%s", rulesLoopback)
	}
}

func TestBuildNFT_LocalLANDNSInterception(t *testing.T) {
	// Case 1: TProxy mode, LANEnabled == true, DNSListen == ""
	// Should allow local port 53 through prerouting and intercept it before destination bypasses
	cfgTProxy := testGatewayConfig(true, true)
	cfgTProxy.Gateway.DNSListen = ""
	rulesTProxy := buildNFT(cfgTProxy, "ens18", "192.168.50.0/24", "")

	if !strings.Contains(rulesTProxy, `iifname != "lo" fib daddr type local meta l4proto != { tcp, udp } return`) {
		t.Fatalf("expected non-tcp/udp local fib return in prerouting, got:\n%s", rulesTProxy)
	}
	if !strings.Contains(rulesTProxy, `iifname != "lo" fib daddr type local th dport != 53 return`) {
		t.Fatalf("expected non-53 local fib return in prerouting, got:\n%s", rulesTProxy)
	}
	if strings.Contains(rulesTProxy, `iifname != "lo" fib daddr type local return`) {
		t.Fatalf("did not expect blanket local return in prerouting when DNSListen is empty and LANEnabled is true, got:\n%s", rulesTProxy)
	}
	expectedTProxyCapture := `fib daddr type local meta l4proto { tcp, udp } th dport 53 tproxy to :12345 meta mark set 1 accept`
	if !strings.Contains(rulesTProxy, expectedTProxyCapture) {
		t.Fatalf("expected local DNS tproxy capture rule %q in prerouting, got:\n%s", expectedTProxyCapture, rulesTProxy)
	}
	// Verify capture occurs before LAN subnet return
	idxCapture := strings.Index(rulesTProxy, expectedTProxyCapture)
	idxBypass := strings.Index(rulesTProxy, "ip daddr 192.168.50.0/24 return")
	if idxCapture == -1 || idxBypass == -1 || idxCapture > idxBypass {
		t.Fatalf("local DNS capture rule must appear before LAN subnet bypass, capture=%d, bypass=%d", idxCapture, idxBypass)
	}

	// Case 2: Configured DNSListen != ""
	// Should retain the original direct local return in prerouting, without special tproxy rule
	cfgDNSListen := testGatewayConfig(true, true)
	cfgDNSListen.Gateway.DNSListen = ":53"
	rulesDNSListen := buildNFT(cfgDNSListen, "ens18", "192.168.50.0/24", "")

	if !strings.Contains(rulesDNSListen, `iifname != "lo" fib daddr type local return`) {
		t.Fatalf("expected blanket local fib return in prerouting when DNSListen is configured, got:\n%s", rulesDNSListen)
	}
	if strings.Contains(rulesDNSListen, `fib daddr type local th dport != 53 return`) {
		t.Fatalf("unexpected non-53 local fib return when DNSListen is configured, got:\n%s", rulesDNSListen)
	}
	if strings.Contains(rulesDNSListen, expectedTProxyCapture) {
		t.Fatalf("unexpected local DNS tproxy capture rule when DNSListen is configured, got:\n%s", rulesDNSListen)
	}

	// Case 3: TUN mode, LANEnabled == true, DNSListen == ""
	// Should mark DNS traffic destined to local LAN IP with tunMark
	cfgTun := testGatewayConfig(true, true)
	cfgTun.Gateway.Mode = "tun"
	cfgTun.Gateway.DNSListen = ""
	rulesTun := buildNFT(cfgTun, "ens18", "192.168.50.0/24", "")

	if strings.Contains(rulesTun, "fib daddr type local return") {
		t.Fatalf("tun mode should not contain fib daddr type local return, got:\n%s", rulesTun)
	}
	expectedTunCapture := "fib daddr type local meta l4proto { tcp, udp } th dport 53 meta mark set 1\n"
	if !strings.Contains(rulesTun, expectedTunCapture) {
		t.Fatalf("expected local DNS mark rule in tun mode, got:\n%s", rulesTun)
	}
	// TUN mode local DNS rule should appear before LAN subnet return
	idxTunCapture := strings.Index(rulesTun, expectedTunCapture)
	idxTunBypass := strings.Index(rulesTun, "ip daddr 192.168.50.0/24 return")
	if idxTunCapture == -1 || idxTunBypass == -1 || idxTunCapture > idxTunBypass {
		t.Fatalf("tun mode local DNS capture rule must appear before LAN subnet bypass, capture=%d, bypass=%d", idxTunCapture, idxTunBypass)
	}

	// Case 4: LANEnabled == false (LocalEnabled only)
	// Should use standard local return and not capture
	cfgLocalOnly := testGatewayConfig(true, false)
	rulesLocalOnly := buildNFT(cfgLocalOnly, "ens18", "192.168.50.0/24", "")

	if !strings.Contains(rulesLocalOnly, `iifname != "lo" fib daddr type local return`) {
		t.Fatalf("expected standard local fib return in local-only mode, got:\n%s", rulesLocalOnly)
	}
	if strings.Contains(rulesLocalOnly, `fib daddr type local meta l4proto { tcp, udp } th dport 53`) {
		t.Fatalf("unexpected local DNS capture in local-only mode, got:\n%s", rulesLocalOnly)
	}
}

func TestVerify_GatewayDNSListening(t *testing.T) {
	origListening := isTProxyPortListeningFn
	origForwarding := isIPv4ForwardingEnabledFn
	origExecCombined := execCommandCombinedOutput
	origExecRun := execCommandRun
	defer func() {
		isTProxyPortListeningFn = origListening
		isIPv4ForwardingEnabledFn = origForwarding
		execCommandCombinedOutput = origExecCombined
		execCommandRun = origExecRun
	}()

	isIPv4ForwardingEnabledFn = func() bool { return true }
	execCommandRun = func(name string, args ...string) error { return nil }
	execCommandCombinedOutput = func(name string, args ...string) ([]byte, error) { return []byte(""), nil }

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tproxy",
			State:        "proxy",
			LANInterface: "lo",
			LocalEnabled: true,
			LANEnabled:   true,
			DNSListen:    ":53",
		},
	}

	// Case 1: Port 53 NOT listening
	isTProxyPortListeningFn = func(port int) bool {
		return port == 12345 // only tproxy port listening, not 53
	}
	problems := Verify(cfg)
	foundDNSProblem := false
	for _, p := range problems {
		if strings.Contains(p, "gateway dns port 53 is not listening") {
			foundDNSProblem = true
			break
		}
	}
	if !foundDNSProblem {
		t.Fatalf("expected 'gateway dns port 53 is not listening' problem, got: %v", problems)
	}

	// Case 2: Port 53 listening
	isTProxyPortListeningFn = func(port int) bool {
		return port == 12345 || port == 53
	}
	problems = Verify(cfg)
	for _, p := range problems {
		if strings.Contains(p, "gateway dns port 53 is not listening") {
			t.Fatalf("unexpected dns port 53 problem when listening: %v", problems)
		}
	}
}

func TestBuildNFTMultiRouterCapabilities(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:          "tproxy",
			State:         "proxy",
			LANEnabled:    true,
			LocalEnabled:  true,
			TProxyPort:    12345,
			RelayAlias:    "relay-default",
			LANInterfaces: []string{"eth1", "eth2"},
			WANInterface:  "eth0",
			NATDisabled:   false,
			Rules: []config.GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{Interface: "eth2", Target: "block"},
				{MAC: "52:54:00:83:00:11", Target: "block"},
				{MAC: "52:54:00:83:00:12", Target: "direct"},
				{MAC: "52:54:00:83:00:13", Target: "relay-extra"},
			},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-default", Enabled: true, AllowPrivateTargets: false},
			{Alias: "relay-extra", Enabled: true, AllowPrivateTargets: true},
		},
	}

	lanIfaces := []string{"eth1", "eth2"}
	lanCIDRs := []string{"10.0.83.0/24", "10.0.84.0/24"}
	lanIPv6CIDRs := []string{"fd00:83::/64", "fd00:84::/64"}
	wanIface := "eth0"

	rules := buildNFTMulti(cfg, lanIfaces, lanCIDRs, lanIPv6CIDRs, wanIface)

	// 1. Input chain guards
	if !strings.Contains(rules, `th dport { 12345, 12346 } drop`) {
		t.Errorf("expected multi-port tproxy guard in input chain, got:\n%s", rules)
	}
	if !strings.Contains(rules, `iifname "eth2" ether saddr != 52:54:00:83:00:12 ether saddr != 52:54:00:83:00:13 drop`) {
		t.Errorf("expected interface eth2 block (yielding to more specific MAC rules) in input chain, got:\n%s", rules)
	}
	if !strings.Contains(rules, `ether saddr 52:54:00:83:00:11 drop`) {
		t.Errorf("expected MAC block in input chain, got:\n%s", rules)
	}

	// 2. Prerouting local fib return
	if !strings.Contains(rules, `iifname != "lo" fib daddr type local meta l4proto != { tcp, udp } return`) ||
		!strings.Contains(rules, `iifname != "lo" fib daddr type local th dport != 53 return`) {
		t.Errorf("expected local fib return for non-DNS in prerouting, got:\n%s", rules)
	}
	if !strings.Contains(rules, `fib daddr type local meta l4proto { tcp, udp } th dport 53 tproxy to :12345 meta mark set 1 accept`) {
		t.Errorf("expected local DNS tproxy interception in prerouting, got:\n%s", rules)
	}

	// 3. Multi-LAN interface guards
	if !strings.Contains(rules, `iifname != { "lo", "eth1", "eth2" } return`) {
		t.Errorf("expected multi-lan guard in prerouting, got:\n%s", rules)
	}
	if !strings.Contains(rules, `iifname "eth1" ip saddr != 10.0.83.0/24 return`) {
		t.Errorf("expected eth1 IPv4 source guard, got:\n%s", rules)
	}
	if !strings.Contains(rules, `iifname "eth2" ip saddr != 10.0.84.0/24 return`) {
		t.Errorf("expected eth2 IPv4 source guard, got:\n%s", rules)
	}

	// 4. Private targets NOT globally bypassed in prerouting because relay-extra has AllowPrivateTargets == true
	if strings.Contains(rules, "10.0.0.0/8") {
		t.Errorf("RFC1918 10.0.0.0/8 should NOT be globally bypassed when AllowPrivateTargets is active, got:\n%s", rules)
	}
	// But local LAN CIDRs ARE bypassed
	if !strings.Contains(rules, "ip daddr 10.0.83.0/24 return") {
		t.Errorf("expected eth1 subnet bypass, got:\n%s", rules)
	}
	if !strings.Contains(rules, "ip daddr 10.0.84.0/24 return") {
		t.Errorf("expected eth2 subnet bypass, got:\n%s", rules)
	}

	// 5. Per-MAC rules
	if !strings.Contains(rules, `ether saddr 52:54:00:83:00:12 return`) {
		t.Errorf("expected MAC direct return rule, got:\n%s", rules)
	}
	if !strings.Contains(rules, `ether saddr 52:54:00:83:00:13 meta l4proto { tcp, udp } tproxy to :12346 meta mark set 1 accept`) {
		t.Errorf("expected MAC relay-extra tproxy rule to :12346, got:\n%s", rules)
	}

	// 6. Per-Interface rules
	if !strings.Contains(rules, `iifname "eth1" return`) {
		t.Errorf("expected interface eth1 direct rule, got:\n%s", rules)
	}

	// 7. Default Gateway Policy
	if !strings.Contains(rules, `meta l4proto { tcp, udp } tproxy to :12345 meta mark set 1 accept`) {
		t.Errorf("expected default relay policy to :12345, got:\n%s", rules)
	}

	// 8. Forward and Postrouting NAT chains
	if !strings.Contains(rules, `chain forward {`) {
		t.Errorf("expected chain forward, got:\n%s", rules)
	}
	if !strings.Contains(rules, `iifname { "eth1", "eth2" } oifname "eth0" accept`) {
		t.Errorf("expected LAN to WAN accept in forward chain, got:\n%s", rules)
	}
	if !strings.Contains(rules, `iifname "eth0" oifname { "eth1", "eth2" } ct state established,related accept`) {
		t.Errorf("expected WAN to LAN established accept in forward chain, got:\n%s", rules)
	}
	if !strings.Contains(rules, `chain postrouting {`) {
		t.Errorf("expected chain postrouting, got:\n%s", rules)
	}
	if !strings.Contains(rules, `iifname { "eth1", "eth2" } oifname "eth0" masquerade`) {
		t.Errorf("expected LAN to WAN masquerade in postrouting chain, got:\n%s", rules)
	}

	// 9. Policy rules check
	policyList := policyRulesMulti(cfg, lanCIDRs, lanIPv6CIDRs, true)
	var foundPref10010, foundPref10011 bool
	for _, pr := range policyList {
		argsStr := strings.Join(pr.Args, " ")
		if strings.Contains(argsStr, "to 10.0.83.0/24 table main pref 10010") {
			foundPref10010 = true
		}
		if strings.Contains(argsStr, "to 10.0.84.0/24 table main pref 10011") {
			foundPref10011 = true
		}
	}
	if !foundPref10010 || !foundPref10011 {
		t.Errorf("expected multi-LAN policy rules with pref 10010 and 10011, got: %v", policyList)
	}

	// 10. managedRuleLine check
	if !managedRuleLine("10010: from all to 10.0.83.0/24 lookup main") {
		t.Error("managedRuleLine should match pref 10010")
	}
	if !managedRuleLine("10015: from all to 10.0.85.0/24 lookup main") {
		t.Error("managedRuleLine should match pref 10015")
	}
	if !managedRuleLine("10029: from all to 10.0.99.0/24 lookup main") {
		t.Error("managedRuleLine should match pref 10029")
	}
	if !managedRuleLine("10030: from all to 127.0.0.0/8 lookup main") {
		t.Error("managedRuleLine should match pref 10030 (prefLoopback)")
	}
	if managedRuleLine("10031: from all to 10.0.99.0/24 lookup main") {
		t.Error("managedRuleLine should NOT match pref 10031")
	}
}

func TestBuildNFTMulti_DanglingRelayRuleFailsClosed(t *testing.T) {
	cfg := &config.UserConfig{Role: config.RoleGateway}
	cfg.Gateway.LANEnabled = true
	cfg.Gateway.RelayAlias = "main"
	cfg.CustomOutbounds = []config.CustomOutbound{
		{Alias: "main", Enabled: true},
		{Alias: "gone", Enabled: false},
	}
	cfg.Gateway.Rules = []config.GatewayRule{
		{Interface: "eth2", Target: "gone"},
		{MAC: "aa:bb:cc:dd:ee:01", Target: "missing"},
	}
	out := buildNFTMulti(cfg, []string{"eth1", "eth2"}, nil, nil, "")
	if !strings.Contains(out, "iifname \"eth2\" drop") {
		t.Fatalf("disabled relay interface rule must drop, got:\n%s", out)
	}
	if !strings.Contains(out, "ether saddr aa:bb:cc:dd:ee:01 drop") {
		t.Fatalf("missing relay MAC rule must drop, got:\n%s", out)
	}
	if strings.Contains(out, "iifname \"eth2\" meta l4proto") || strings.Contains(out, "ether saddr aa:bb:cc:dd:ee:01 meta l4proto") {
		t.Fatalf("dangling rule must not fall back to a tproxy port:\n%s", out)
	}
}

func TestBuildNFTMulti_WANOverlapSkipsMasquerade(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			LANEnabled:   true,
			LANInterface: "eth0",
			WANInterface: "eth0",
		},
	}
	lanIfaces := []string{"eth0"}
	wanIface := "eth0"

	rules := buildNFTMulti(cfg, lanIfaces, []string{"192.168.1.0/24"}, nil, wanIface)
	if strings.Contains(rules, "masquerade") {
		t.Fatalf("expected masquerade to be skipped when WAN interface overlaps with LAN interface, got:\n%s", rules)
	}
	if strings.Contains(rules, "chain postrouting") {
		t.Fatalf("expected postrouting chain to be skipped when WAN interface overlaps with LAN interface, got:\n%s", rules)
	}

	// When distinct, masquerade should be present
	wanDistinct := "eth1"
	rulesDistinct := buildNFTMulti(cfg, lanIfaces, []string{"192.168.1.0/24"}, nil, wanDistinct)
	if !strings.Contains(rulesDistinct, "masquerade") {
		t.Fatalf("expected masquerade to be present when WAN is distinct, got:\n%s", rulesDistinct)
	}
	if !strings.Contains(rulesDistinct, `iifname "eth0" oifname "eth1" masquerade`) {
		t.Fatalf("expected specific masquerade rule, got:\n%s", rulesDistinct)
	}
}

func TestValidateGatewayRuleTargets(t *testing.T) {
	cfg := &config.UserConfig{CustomOutbounds: []config.CustomOutbound{{Alias: "a", Enabled: true}, {Alias: "b"}}}
	cfg.Gateway.Rules = []config.GatewayRule{{Interface: "eth1", Target: "a"}, {Interface: "eth2", Target: "direct"}}
	if err := config.ValidateGatewayRuleTargets(cfg); err != nil {
		t.Fatalf("valid targets rejected: %v", err)
	}
	cfg.Gateway.Rules = append(cfg.Gateway.Rules, config.GatewayRule{Interface: "eth3", Target: "b"})
	if err := config.ValidateGatewayRuleTargets(cfg); err == nil {
		t.Fatal("disabled relay target must be rejected")
	}
}

func TestInsertFilterRulesPreservesOrder(t *testing.T) {
	var calls []string
	orig := runCommand
	runCommand = func(name string, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	defer func() { runCommand = orig }()
	if err := insertFilterRules("forward", []string{"drop1"}, []string{"accept2"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "accept2") || !strings.Contains(calls[1], "drop1") || !strings.HasPrefix(calls[0], "insert rule inet filter forward") {
		t.Fatalf("rules must be inserted in reverse so first ends on top: %v", calls)
	}
}

func TestRuleSpecificityOrdering(t *testing.T) {
	cfg := &config.UserConfig{Role: config.RoleGateway}
	cfg.Gateway.LANEnabled = true
	cfg.Gateway.RelayAlias = "main"
	cfg.CustomOutbounds = []config.CustomOutbound{{Alias: "main", Enabled: true}, {Alias: "x", Enabled: true}}
	const mac = "aa:bb:cc:dd:ee:01"
	cfg.Gateway.Rules = []config.GatewayRule{
		{Interface: "eth1", Target: "direct"},
		{MAC: mac, Target: "block"},
		{MAC: mac, Interface: "eth1", Target: "x"},
	}
	out := buildNFTMulti(cfg, []string{"eth1"}, []string{"10.0.1.0/24"}, nil, "")
	idxSpecific := strings.Index(out, `iifname "eth1" ether saddr `+mac+` meta l4proto`)
	idxIface := strings.Index(out, `iifname "eth1" return`)
	if idxSpecific < 0 || idxIface < 0 || idxSpecific > idxIface {
		t.Fatalf("interface+MAC rule must precede interface-only rule:\n%s", out)
	}
	if !strings.Contains(out, `ether saddr `+mac+` iifname != "eth1" drop`) {
		t.Fatalf("MAC-only block must yield to the interface+MAC relay rule:\n%s", out)
	}
}

func TestBuildNFTMulti_MultiPrefixIPv6(t *testing.T) {
	cfg := &config.UserConfig{Role: config.RoleGateway}
	cfg.Gateway.LANEnabled = true
	cfg.Gateway.RelayAlias = "main"
	cfg.CustomOutbounds = []config.CustomOutbound{{Alias: "main", Enabled: true}}
	out := buildNFTMulti(cfg, []string{"eth1"}, []string{"10.0.1.0/24"}, []string{"fd00:1::/64,2001:db8:1::/64"}, "")
	if !strings.Contains(out, `ip6 saddr != { fd00:1::/64, 2001:db8:1::/64 } return`) {
		t.Fatalf("all IPv6 prefixes must be in the source guard:\n%s", out)
	}
	if !strings.Contains(out, "ip6 daddr fd00:1::/64 return") || !strings.Contains(out, "ip6 daddr 2001:db8:1::/64 return") {
		t.Fatalf("all IPv6 prefixes must bypass:\n%s", out)
	}
	rules := policyRulesMulti(cfg, nil, []string{"fd00:1::/64,2001:db8:1::/64"}, true)
	n := 0
	for _, r := range rules {
		if r.IPv6 && len(r.Args) > 0 && r.Args[0] == "to" && r.Args[1] != "::1/128" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("expected a policy rule per IPv6 prefix, got %d", n)
	}
}

func TestInstallBlockFilterRules(t *testing.T) {
	var calls []string
	orig := runCommand
	runCommand = func(name string, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	defer func() { runCommand = orig }()
	cfg := &config.UserConfig{}
	cfg.Gateway.Rules = []config.GatewayRule{{Interface: "eth2", Target: "block"}, {Interface: "eth1", Target: "direct"}}
	if err := installBlockFilterRules(cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, `insert rule inet filter forward iifname "eth2" drop`) || !strings.Contains(joined, `insert rule inet filter input iifname "eth2" drop`) {
		t.Fatalf("block rules must be installed in forward and input:\n%s", joined)
	}
	calls = nil
	cfg.Gateway.Rules = []config.GatewayRule{{Interface: "eth1", Target: "direct"}}
	_ = installBlockFilterRules(cfg)
	if len(calls) != 0 {
		t.Fatalf("no block rules means no nft calls: %v", calls)
	}
}

func TestValidateInterfaceNameAndPorts(t *testing.T) {
	for _, bad := range []string{"", "a b", `e"th`, "eth0;", "averyveryverylongname", "..", "a\nb"} {
		if config.ValidateInterfaceName(bad) == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	for _, ok := range []string{"eth0", "br-lan", "eth0.10", "wg_0"} {
		if err := config.ValidateInterfaceName(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	if _, err := config.ValidateGatewayRule(config.GatewayRule{Interface: `e"th`, Target: "direct"}); err == nil {
		t.Error("rule with unsafe interface must be rejected")
	}
	cfg := &config.UserConfig{Role: config.RoleGateway, APIInbound: 12346}
	cfg.Gateway.RelayAlias = "a"
	cfg.Gateway.Rules = []config.GatewayRule{{Interface: "eth1", Target: "b"}}
	cfg.CustomOutbounds = []config.CustomOutbound{{Alias: "a", Enabled: true}, {Alias: "b", Enabled: true}}
	if err := config.ValidateGatewayPorts(cfg); err == nil {
		t.Error("tproxy relay port colliding with api inbound must be rejected")
	}
	cfg.APIInbound = 20000
	if err := config.ValidateGatewayPorts(cfg); err != nil {
		t.Errorf("non-conflicting ports rejected: %v", err)
	}
}

func TestBuildNFTMulti_TUNModeDirectRules(t *testing.T) {
	cfg := &config.UserConfig{Role: config.RoleGateway}
	cfg.Gateway.Mode = "tun"
	cfg.Gateway.LANEnabled = true
	cfg.Gateway.RelayAlias = "main"
	cfg.Gateway.Rules = []config.GatewayRule{
		{Interface: "eth1", Target: "direct"},
		{MAC: "aa:bb:cc:dd:ee:02", Target: "relay-other"},
	}
	out := buildNFTMulti(cfg, []string{"eth1"}, []string{"10.0.1.0/24"}, nil, "")
	if !strings.Contains(out, `iifname "eth1" return`) {
		t.Fatalf("expected direct rule return in TUN mode, got:\n%s", out)
	}
	if !strings.Contains(out, `ether saddr aa:bb:cc:dd:ee:02 drop`) {
		t.Fatalf("expected fail-closed drop for unsupported relay rule in TUN mode, got:\n%s", out)
	}
	if !strings.Contains(out, `meta l4proto { tcp, udp } meta mark set 1`) {
		t.Fatalf("expected default TUN mark rule in TUN mode, got:\n%s", out)
	}
}
