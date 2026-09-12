package gateway

import (
	"errors"
	"os"
	"strings"
	"testing"

	"xray-proxya/internal/config"
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
	if !strings.Contains(rules, `iifname != "ens18" return`) {
		t.Fatalf("rules should use configured LAN interface: %s", rules)
	}
	if !strings.Contains(rules, "ip daddr 192.168.50.0/24 return") {
		t.Fatalf("rules should exclude configured LAN subnet: %s", rules)
	}
	if !strings.Contains(rules, "ip saddr != 192.168.50.0/24 return") {
		t.Fatalf("rules should reject spoofed IPv4 LAN sources: %s", rules)
	}

	rulesIPv6 := buildNFT(testGatewayConfig(true, true), "ens18", "192.168.50.0/24", "fd00::/64")
	if !strings.Contains(rulesIPv6, "ip6 saddr != fd00::/64 return") {
		t.Fatalf("rules should reject spoofed IPv6 LAN sources: %s", rulesIPv6)
	}
	if !strings.Contains(rules, "ip6 saddr ::/0 return") {
		t.Fatalf("rules should bypass IPv6 LAN interception without a LAN IPv6 subnet: %s", rules)
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

func TestBuildNFT_Proxy_LocalOnly_GeneratesOutputOnly(t *testing.T) {
	cfg := testGatewayConfig(true, false)
	cfg.Gateway.State = "proxy"
	rules := buildNFT(cfg, "ens18", "192.168.50.0/24", "")
	if strings.Contains(rules, "chain prerouting") {
		t.Error("rules should not contain prerouting chain when LANEnabled is false in proxy state")
	}
	if !strings.Contains(rules, "chain output") {
		t.Error("rules must contain output chain when LocalEnabled is true in proxy state")
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

func TestBuildNFTProtectsSSHSourceAndDestinationPorts(t *testing.T) {
	rules := buildNFT(testGatewayConfig(true, false), "ens18", "192.168.50.0/24", "")
	for _, port := range getSSHPorts() {
		if !strings.Contains(rules, "tcp sport "+port+" return") {
			t.Fatalf("rules should protect SSH source port %s: %s", port, rules)
		}
		if !strings.Contains(rules, "tcp dport "+port+" return") {
			t.Fatalf("rules should protect SSH destination port %s: %s", port, rules)
		}
	}
}

func testGatewayConfig(local, lan bool) *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			LocalEnabled: local,
			LANEnabled:   lan,
			Mode:         "tun",
			RelayAlias:   "relay-a",
		},
		CustomOutbounds: []config.CustomOutbound{{Alias: "relay-a", Enabled: true}},
	}
}

func configurePathRelay(cfg *config.UserConfig) {
	cfg.CustomOutbounds[0].Path = &config.PathConfig{Listen: "127.0.0.1:39091", Token: "token", IdleSeconds: 20}
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
