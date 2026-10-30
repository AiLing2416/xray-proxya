package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/applyops"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/gatewayconf"
	proxyaSELinux "xray-proxya/internal/selinux"
	"xray-proxya/internal/tune"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	gatewayEnableNow  bool
	gatewayDisableNow bool
	gatewayStatusJSON bool

	applyPendingFunc         = applyops.ApplyPending
	runGatewayManagementFunc = runGatewayManagement
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Manage transparent proxy gateway (STAGING)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return utils.RequireRootShell("gateway")
	},
}

type GatewayConfigJSON struct {
	Mode          string               `json:"mode,omitempty"`
	TUNEnabled    bool                 `json:"tun_enabled"`
	LocalEnabled  bool                 `json:"local_enabled"`
	LANEnabled    bool                 `json:"lan_enabled"`
	Relay         string               `json:"relay"`
	Interface     string               `json:"interface"`
	LANInterfaces []string             `json:"lan_interfaces,omitempty"`
	WANInterface  string               `json:"wan_interface,omitempty"`
	NATDisabled   bool                 `json:"nat_disabled,omitempty"`
	Rules         []config.GatewayRule `json:"rules,omitempty"`
	State         string               `json:"state"`
	DNSListen     string               `json:"dns_listen,omitempty"`
	DNSStrategy   string               `json:"dns_strategy,omitempty"`
	DNSServers    []string                 `json:"dns_servers,omitempty"`
	DNSRecords    map[string][]string      `json:"dns_records,omitempty"`
	PortForwards  []config.PortForwardRule `json:"port_forwards,omitempty"`
}

type GatewayRuntimeJSON struct {
	TunPresent bool     `json:"tun_present"`
	TunUp      bool     `json:"tun_up"`
	IPForward  bool     `json:"ip_forward"`
	Problems   []string `json:"problems"`
}

type GatewayStatusJSON struct {
	Active  *GatewayConfigJSON `json:"active"`
	Staging *GatewayConfigJSON `json:"staging"`
	Runtime GatewayRuntimeJSON `json:"runtime"`
}

func toGatewayConfigJSON(cfg *config.UserConfig) *GatewayConfigJSON {
	if cfg == nil {
		return nil
	}
	state := cfg.Gateway.State
	if state == "" {
		state = "proxy"
	}
	effectiveLANs := cfg.Gateway.EffectiveLANInterfaces()
	lanInterface := cfg.Gateway.LANInterface
	if lanInterface == "" && len(effectiveLANs) > 0 {
		lanInterface = strings.Join(effectiveLANs, ",")
	}
	return &GatewayConfigJSON{
		Mode:          cfg.Gateway.EffectiveMode(),
		TUNEnabled:    cfg.Gateway.EffectiveTUNEnabled(),
		LocalEnabled:  cfg.Gateway.LocalEnabled,
		LANEnabled:    cfg.Gateway.LANEnabled,
		Relay:         cfg.Gateway.RelayAlias,
		Interface:     lanInterface,
		LANInterfaces: effectiveLANs,
		WANInterface:  cfg.Gateway.WANInterface,
		NATDisabled:   cfg.Gateway.NATDisabled,
		Rules:         cfg.Gateway.Rules,
		State:         state,
		DNSListen:     cfg.Gateway.DNSListen,
		DNSStrategy:   cfg.Gateway.DNSStrategy,
		DNSServers:    cfg.Gateway.DNSServers,
		DNSRecords:    cfg.Gateway.DNSRecords,
		PortForwards:  cfg.Gateway.PortForwards,
	}
}

func formatGatewayBoolState(enabled bool) string {
	if enabled {
		return "ENABLED"
	}
	return "DISABLED"
}

func getEffectiveGatewayState(cfg *config.UserConfig) string {
	if cfg == nil {
		return ""
	}
	if cfg.Gateway.State != "" {
		return cfg.Gateway.State
	}
	return "proxy"
}

var gatewayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway configuration and system state",
	RunE:  runGatewayStatus,
}

func runGatewayStatus(cmd *cobra.Command, args []string) error {
	activeCfg, _ := config.LoadConfigEx(false)
	stagingCfg, _ := config.LoadConfigEx(true)
	if activeCfg == nil && stagingCfg == nil {
		return fmt.Errorf("❌ Failed to load gateway configuration")
	}

	iface, err := net.InterfaceByName("proxya-tun")
	tunPresentReal := (err == nil)
	tunUpReal := tunPresentReal && (iface.Flags&net.FlagUp != 0)

	nftActive := exec.Command("nft", "list", "table", "inet", "xray_proxya").Run() == nil
	var problems []string
	if activeCfg != nil {
		problems = gateway.Verify(activeCfg)
	} else if stagingCfg != nil {
		problems = gateway.Verify(stagingCfg)
	}
	if problems == nil {
		problems = []string{}
	}

	hasRoute := false
	if out, err := exec.Command("ip", "route", "show", "table", "100").Output(); err == nil {
		if strings.Contains(string(out), "local default dev lo") || strings.Contains(string(out), "default") {
			hasRoute = true
		}
	}
	tproxyActive := nftActive && (hasRoute || len(problems) == 0)
	tunPresent := tunPresentReal
	tunUp := tunUpReal
	ipForward := tune.IsIPv4ForwardingEnabled()

	if gatewayStatusJSON {
		out := GatewayStatusJSON{
			Active:  toGatewayConfigJSON(activeCfg),
			Staging: toGatewayConfigJSON(stagingCfg),
			Runtime: GatewayRuntimeJSON{
				TunPresent: tunPresent,
				TunUp:      tunUp,
				IPForward:  ipForward,
				Problems:   problems,
			},
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("\n🛰️ GATEWAY CONFIGURATION")
	fmt.Println("--------------------------------------------------")
	if activeCfg != nil {
		fmt.Println("ACTIVE:")
		fmt.Printf("  Mode:        %s\n", activeCfg.Gateway.EffectiveMode())
		fmt.Printf("  Local Proxy: %s\n", formatGatewayBoolState(activeCfg.Gateway.LocalEnabled))
		fmt.Printf("  LAN Gateway: %s\n", formatGatewayBoolState(activeCfg.Gateway.LANEnabled))
		fmt.Printf("  Relay:       %s\n", activeCfg.Gateway.RelayAlias)
		lanStr := activeCfg.Gateway.LANInterface
		if len(activeCfg.Gateway.EffectiveLANInterfaces()) > 0 {
			lanStr = strings.Join(activeCfg.Gateway.EffectiveLANInterfaces(), ", ")
		}
		fmt.Printf("  LAN Iface:   %s\n", lanStr)
		wanStr := activeCfg.Gateway.WANInterface
		if wanStr == "" {
			wanStr = "(auto)"
		}
		fmt.Printf("  WAN Iface:   %s\n", wanStr)
		natStr := "ENABLED"
		if activeCfg.Gateway.NATDisabled {
			natStr = "DISABLED"
		}
		fmt.Printf("  NAT:         %s\n", natStr)
		if len(activeCfg.Gateway.Rules) > 0 {
			fmt.Printf("  Rules:       %d rule(s)\n", len(activeCfg.Gateway.Rules))
		}
		fmt.Printf("  State:       %s\n", getEffectiveGatewayState(activeCfg))
		if activeCfg.Gateway.DNSListen != "" {
			fmt.Printf("  DNS Listen:  %s\n", activeCfg.Gateway.DNSListen)
		}
		if len(activeCfg.Gateway.DNSServers) > 0 {
			fmt.Printf("  DNS Upstream:%s\n", strings.Join(activeCfg.Gateway.DNSServers, ", "))
		}
		if len(activeCfg.Gateway.DNSRecords) > 0 {
			fmt.Printf("  DNS Records: %d domain(s)\n", len(activeCfg.Gateway.DNSRecords))
		}
	} else {
		fmt.Println("ACTIVE:      (not initialized)")
	}
	if stagingCfg != nil {
		fmt.Println("STAGING:")
		fmt.Printf("  Mode:        %s\n", stagingCfg.Gateway.EffectiveMode())
		fmt.Printf("  Local Proxy: %s\n", formatGatewayBoolState(stagingCfg.Gateway.LocalEnabled))
		fmt.Printf("  LAN Gateway: %s\n", formatGatewayBoolState(stagingCfg.Gateway.LANEnabled))
		fmt.Printf("  Relay:       %s\n", stagingCfg.Gateway.RelayAlias)
		lanStr := stagingCfg.Gateway.LANInterface
		if len(stagingCfg.Gateway.EffectiveLANInterfaces()) > 0 {
			lanStr = strings.Join(stagingCfg.Gateway.EffectiveLANInterfaces(), ", ")
		}
		fmt.Printf("  LAN Iface:   %s\n", lanStr)
		wanStr := stagingCfg.Gateway.WANInterface
		if wanStr == "" {
			wanStr = "(auto)"
		}
		fmt.Printf("  WAN Iface:   %s\n", wanStr)
		natStr := "ENABLED"
		if stagingCfg.Gateway.NATDisabled {
			natStr = "DISABLED"
		}
		fmt.Printf("  NAT:         %s\n", natStr)
		if len(stagingCfg.Gateway.Rules) > 0 {
			fmt.Printf("  Rules:       %d rule(s)\n", len(stagingCfg.Gateway.Rules))
		}
		fmt.Printf("  State:       %s\n", getEffectiveGatewayState(stagingCfg))
		if stagingCfg.Gateway.DNSListen != "" {
			fmt.Printf("  DNS Listen:  %s\n", stagingCfg.Gateway.DNSListen)
		}
		if len(stagingCfg.Gateway.DNSServers) > 0 {
			fmt.Printf("  DNS Upstream:%s\n", strings.Join(stagingCfg.Gateway.DNSServers, ", "))
		}
		if len(stagingCfg.Gateway.DNSRecords) > 0 {
			fmt.Printf("  DNS Records: %d domain(s)\n", len(stagingCfg.Gateway.DNSRecords))
		}
		if len(stagingCfg.Gateway.BypassDNS) > 0 {
			fmt.Printf("  Bypass DNS:  %s\n", strings.Join(stagingCfg.Gateway.BypassDNS, ", "))
		}
		if len(stagingCfg.Gateway.BypassCountries) > 0 {
			fmt.Printf("  Bypass Geo:  %s\n", strings.Join(stagingCfg.Gateway.BypassCountries, ", "))
		}
	}

	fmt.Println("\n🛰️ RUNTIME STATE")
	fmt.Println("--------------------------------------------------")
	tproxyPort := config.DefaultTProxyPort
	if activeCfg != nil {
		tproxyPort = activeCfg.Gateway.EffectiveTProxyPort()
	} else if stagingCfg != nil {
		tproxyPort = stagingCfg.Gateway.EffectiveTProxyPort()
	}

	tproxyStatus := "INACTIVE"
	if tproxyActive {
		tproxyStatus = fmt.Sprintf(":%d (ACTIVE)", tproxyPort)
	}
	fmt.Printf("TProxy Port:   %s\n", tproxyStatus)

	nftStatus := "INACTIVE"
	if nftActive {
		nftStatus = "ACTIVE (table inet xray_proxya)"
	}
	fmt.Printf("nftables:      %s\n", nftStatus)

	routeStatus := "INACTIVE"
	if tproxyActive {
		routeStatus = "ACTIVE (lo table 100)"
	}
	fmt.Printf("TProxy Routing: %s\n", routeStatus)

	tunStatus := "DISABLED"
	tunEnabled := false
	if activeCfg != nil && activeCfg.Gateway.EffectiveTUNEnabled() {
		tunEnabled = true
	} else if stagingCfg != nil && stagingCfg.Gateway.EffectiveTUNEnabled() {
		tunEnabled = true
	}
	if tunEnabled || tunPresentReal {
		tunStatus = "NOT FOUND"
		if tunPresentReal {
			if tunUpReal {
				tunStatus = "UP (172.16.255.1)"
			} else {
				tunStatus = "DOWN"
			}
		}
	}
	fmt.Printf("TUN Adapter:   proxya-tun (%s)\n", tunStatus)

	forwardStatus := "DISABLED"
	if ipForward {
		forwardStatus = "ENABLED"
	}
	fmt.Printf("IPv4 Forward:  %s\n", forwardStatus)

	if len(problems) == 0 {
		fmt.Println("Verification:  OK (Ready)")
	} else {
		fmt.Println("Verification:  Issues Found:")
		for _, p := range problems {
			fmt.Printf("  - %s\n", p)
		}
	}
	fmt.Println()
	return nil
}

var gatewayEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Turn on transparent gateway (local & lan) in staging",
	RunE:  runGatewayEnable,
}

func runGatewayEnable(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("failed to load staging config: %v", err)
	}
	cfg.Gateway.LocalEnabled = true
	cfg.Gateway.LANEnabled = true
	if cfg.Gateway.Mode == "" {
		cfg.Gateway.Mode = "tproxy"
	}
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("failed to save staging config: %w", err)
	}

	if !gatewayEnableNow {
		fmt.Println("✅ Gateway ENABLED in STAGING. Run 'apply' to commit, then 'gateway up' to update runtime rules.")
		return nil
	}

	lines, err := applyPendingFunc(applyops.Options{Start: true})
	for _, line := range lines {
		fmt.Println(line)
	}
	if err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}
	if err := runGatewayManagementFunc("system-up"); err != nil {
		return fmt.Errorf("failed to bring gateway runtime up: %w", err)
	}
	fmt.Println("✅ Gateway ENABLED and runtime rules are UP.")
	return nil
}

var gatewayDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Turn off transparent gateway (local & lan) in staging",
	RunE:  runGatewayDisable,
}

func runGatewayDisable(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("failed to load staging config: %v", err)
	}
	cfg.Gateway.LocalEnabled = false
	cfg.Gateway.LANEnabled = false
	if cfg.Gateway.Mode == "" {
		cfg.Gateway.Mode = "tproxy"
	}
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("failed to save staging config: %w", err)
	}

	if !gatewayDisableNow {
		fmt.Println("✅ Gateway DISABLED in STAGING. Run 'apply' to commit, then 'gateway down' to remove runtime rules.")
		return nil
	}

	lines, err := applyPendingFunc(applyops.Options{})
	for _, line := range lines {
		fmt.Println(line)
	}
	if err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}
	if err := runGatewayManagementFunc("system-down"); err != nil {
		return fmt.Errorf("failed to bring gateway runtime down: %w", err)
	}
	fmt.Println("✅ Gateway DISABLED and runtime rules are DOWN.")
	return nil
}

var gatewaySetCmd = &cobra.Command{
	Use:               "set [relay]",
	Short:             "Configure gateway parameters in STAGING",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE:              runGatewaySet,
}

func runGatewaySet(cmd *cobra.Command, args []string) error {
	var positionalRelay string
	if len(args) == 1 {
		positionalRelay = strings.TrimSpace(args[0])
	}

	hasChanged := positionalRelay != ""
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			hasChanged = true
		}
	})
	if !hasChanged {
		return fmt.Errorf("❌ Error: No parameter supplied")
	}

	lanEnable := cmd.Flags().Changed("lan-enable") && cmd.Flags().Lookup("lan-enable").Value.String() == "true"
	lanDisable := cmd.Flags().Changed("lan-disable") && cmd.Flags().Lookup("lan-disable").Value.String() == "true"
	if cmd.Flags().Changed("lan") {
		val, _ := cmd.Flags().GetBool("lan")
		if val {
			lanEnable = true
		} else {
			lanDisable = true
		}
	}
	if cmd.Flags().Changed("no-lan") {
		val, _ := cmd.Flags().GetBool("no-lan")
		if val {
			lanDisable = true
		} else {
			lanEnable = true
		}
	}

	localEnable := cmd.Flags().Changed("local-enable") && cmd.Flags().Lookup("local-enable").Value.String() == "true"
	localDisable := cmd.Flags().Changed("local-disable") && cmd.Flags().Lookup("local-disable").Value.String() == "true"
	if cmd.Flags().Changed("local") {
		val, _ := cmd.Flags().GetBool("local")
		if val {
			localEnable = true
		} else {
			localDisable = true
		}
	}
	if cmd.Flags().Changed("no-local") {
		val, _ := cmd.Flags().GetBool("no-local")
		if val {
			localDisable = true
		} else {
			localEnable = true
		}
	}

	if lanEnable && lanDisable {
		return fmt.Errorf("❌ Error: Conflicting flags specified")
	}
	if localEnable && localDisable {
		return fmt.Errorf("❌ Error: Conflicting flags specified")
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}

	if cmd.Flags().Changed("tun") {
		tunVal, _ := cmd.Flags().GetBool("tun")
		cfg.Gateway.TUNEnabled = tunVal
		if tunVal {
			cfg.Gateway.Mode = ""
		}
	}
	if cmd.Flags().Changed("no-tun") {
		cfg.Gateway.TUNEnabled = false
		cfg.Gateway.Mode = ""
	}

	if cmd.Flags().Changed("mode") {
		modeVal, _ := cmd.Flags().GetString("mode")
		modeVal = strings.ToLower(strings.TrimSpace(modeVal))
		if modeVal != "tproxy" && modeVal != "tun" {
			return fmt.Errorf("❌ Invalid mode %q; valid options are 'tproxy' and 'tun'", modeVal)
		}
		if modeVal == "tun" {
			cfg.Gateway.TUNEnabled = true
		} else {
			cfg.Gateway.TUNEnabled = false
		}
		cfg.Gateway.Mode = modeVal
		if err := config.ValidateGatewayRulesForMode(cfg); err != nil {
			return fmt.Errorf("❌ %w", err)
		}
	} else if cfg.Gateway.Mode == "" {
		cfg.Gateway.Mode = "tproxy"
	}
	if cmd.Flags().Changed("relay") {
		relay, _ := cmd.Flags().GetString("relay")
		if positionalRelay != "" && relay != positionalRelay {
			return fmt.Errorf("❌ Error: Positional relay %q conflicts with --relay flag %q", positionalRelay, relay)
		}
		cfg.Gateway.RelayAlias = relay
	} else if positionalRelay != "" {
		cfg.Gateway.RelayAlias = positionalRelay
	}

	var iface string
	if cmd.Flags().Changed("interface") {
		iface, _ = cmd.Flags().GetString("interface")
	} else if cmd.Flags().Changed("lan-interface") {
		iface, _ = cmd.Flags().GetString("lan-interface")
	}
	if iface != "" {
		parts := strings.Split(iface, ",")
		var validIfaces []string
		seen := make(map[string]bool)
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			if err := config.ValidateInterfaceName(trimmed); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			if !seen[trimmed] {
				seen[trimmed] = true
				validIfaces = append(validIfaces, trimmed)
			}
		}
		if len(validIfaces) == 0 {
			return fmt.Errorf("❌ Invalid interface parameter: empty interface name")
		}
		cfg.Gateway.LANInterfaces = validIfaces
		cfg.Gateway.LANInterface = strings.Join(validIfaces, ",")
	}

	if cmd.Flags().Changed("wan") {
		wan, _ := cmd.Flags().GetString("wan")
		wanTrimmed := strings.TrimSpace(wan)
		if wanTrimmed == "" || strings.EqualFold(wanTrimmed, "auto") {
			cfg.Gateway.WANInterface = ""
		} else {
			if err := config.ValidateInterfaceName(wanTrimmed); err != nil {
				return fmt.Errorf("❌ WAN %w", err)
			}
			cfg.Gateway.WANInterface = wanTrimmed
		}
	}

	natEnable := cmd.Flags().Changed("nat")
	natDisable := cmd.Flags().Changed("no-nat")
	if natEnable && natDisable {
		return fmt.Errorf("❌ Error: Conflicting flags specified: cannot use both --nat and --no-nat")
	}
	if natEnable {
		cfg.Gateway.NATDisabled = false
	} else if natDisable {
		cfg.Gateway.NATDisabled = true
	}

	if cmd.Flags().Changed("state") {
		state, _ := cmd.Flags().GetString("state")
		stateLower := strings.ToLower(strings.TrimSpace(state))
		if stateLower != "disabled" && stateLower != "forward-only" && stateLower != "proxy" {
			return fmt.Errorf("❌ Invalid state: %s (must be one of: disabled, forward-only, proxy)", state)
		}
		cfg.Gateway.State = stateLower
		if stateLower == "forward-only" {
			fmt.Println("⚠️  forward-only is experimental: it enables kernel forwarding only, without NAT or transparent proxying.")
		}
	}

	if lanEnable {
		cfg.Gateway.LANEnabled = true
	} else if lanDisable {
		cfg.Gateway.LANEnabled = false
	}

	if localEnable {
		cfg.Gateway.LocalEnabled = true
	} else if localDisable {
		cfg.Gateway.LocalEnabled = false
	}

	if cmd.Flags().Changed("bypass-dns") {
		bypassDNS, _ := cmd.Flags().GetStringSlice("bypass-dns")
		cfg.Gateway.BypassDNS = bypassDNS
	}
	if cmd.Flags().Changed("bypass-countries") {
		bypassCountries, _ := cmd.Flags().GetStringSlice("bypass-countries")
		cfg.Gateway.BypassCountries = bypassCountries
	}

	if err := config.ValidateGatewayInterfaces(cfg); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	if err := config.ValidateGatewayRulesForMode(cfg); err != nil {
		return fmt.Errorf("❌ %w", err)
	}

	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Println("✅ Gateway parameters updated in STAGING.")
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var gatewayUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Restart Xray with TUN and bring gateway runtime rules up",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayManagement("system-up")
	},
}

var gatewaySystemUpCmd = &cobra.Command{
	Use:    "system-up",
	Short:  "Apply Gateway runtime from the SELinux management domain",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active config: %w", err)
		}
		if err := gateway.Up(cfg); err != nil {
			return fmt.Errorf("apply gateway runtime: %w", err)
		}
		fmt.Println("✅ Gateway runtime rules are up.")
		return nil
	},
}


var gatewayDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show gateway runtime rules that would be applied",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			return
		}
		rules, err := gateway.BuildRulesPreview(cfg)
		if err != nil {
			fmt.Printf("❌ Failed: %v\n", err)
			return
		}
		fmt.Println("# nftables")
		if rules == "" {
			fmt.Println("(no gateway rules needed)")
		} else {
			fmt.Print(rules)
		}
		fmt.Println("# policy routing")
		fmt.Println("ip rule add fwmark 1 table 100 pref 10100")
		fmt.Println("ip rule add fwmark 255 table main pref 10000")
		if cfg.Gateway.EffectiveMode() == "tun" {
			fmt.Println("ip route replace default dev proxya-tun table 100")
		} else {
			fmt.Println("ip route replace local default dev lo table 100")
		}
	},
}

var gatewayCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check gateway runtime state",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if config.GatewayConfExists() {
			confPath := config.GetGatewayConfPath()
			data, err := os.ReadFile(confPath)
			if err != nil {
				fmt.Printf("⚠️  Failed to read gateway.conf: %v\n", err)
			} else if ast, parseErr := gatewayconf.Parse(string(data)); parseErr != nil {
				fmt.Printf("❌ gateway.conf syntax error: %v\n", parseErr)
			} else {
				if _, compileErr := gatewayconf.Compile(ast, gatewayconf.WithUserConfig(cfg)); compileErr != nil {
					fmt.Printf("⚠️  gateway.conf semantic warning: %v\n", compileErr)
				} else {
					fmt.Println("✅ gateway.conf declarative configuration syntax is valid.")
				}
			}
		}

		problems := gateway.Verify(cfg)
		if len(problems) == 0 {
			fmt.Println("✅ Gateway runtime state looks ready.")
			return
		}
		fmt.Println("❌ Gateway verification found issues:")
		for _, problem := range problems {
			fmt.Printf("- %s\n", problem)
		}
		os.Exit(1)
	},
}


var gatewayDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Remove gateway rules and restart Xray without TUN",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayManagement("system-down")
	},
}

var gatewaySystemDownCmd = &cobra.Command{
	Use:    "system-down",
	Short:  "Remove Gateway runtime from the SELinux management domain",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := gateway.Down(); err != nil {
			return fmt.Errorf("remove gateway runtime: %w", err)
		}
		fmt.Println("✅ Gateway runtime rules are down and Xray restarted without TUN.")
		return nil
	},
}

var gatewaySystemSyncCmd = &cobra.Command{
	Use:    "system-sync",
	Short:  "Synchronize Gateway runtime from the SELinux management domain",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active config: %w", err)
		}
		var syncErr error
		if os.Getenv(proxyaSELinux.GatewayLifecycleLockHeldEnv()) == "1" {
			syncErr = gateway.SyncDesiredLocked(cfg)
		} else {
			syncErr = gateway.SyncDesired(cfg)
		}
		if syncErr != nil {
			return fmt.Errorf("synchronize gateway runtime: %w", syncErr)
		}
		return nil
	},
}

var gatewaySystemRestoreCmd = &cobra.Command{
	Use:    "system-restore",
	Short:  "Restore Gateway runtime from the SELinux management domain",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active config: %w", err)
		}
		if os.Getenv(proxyaSELinux.GatewayLifecycleLockHeldEnv()) == "1" {
			err = gateway.RestoreTunStateLocked(cfg)
		} else {
			err = gateway.RestoreTunState(cfg)
		}
		if err != nil {
			return fmt.Errorf("restore gateway runtime: %w", err)
		}
		return nil
	},
}

func runGatewayManagement(operation string) error {
	if !proxyaSELinux.IsEnforcing() || proxyaSELinux.InGatewayDomain() {
		if operation == "system-up" {
			return gatewaySystemUpCmd.RunE(gatewaySystemUpCmd, nil)
		}
		return gatewaySystemDownCmd.RunE(gatewaySystemDownCmd, nil)
	}
	if _, err := exec.LookPath("runcon"); err != nil {
		return fmt.Errorf("SELinux is enforcing but runcon is unavailable: %w", err)
	}
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate xray-proxya binary: %w", err)
	}
	cmd := exec.Command("runcon", "-r", "system_r", "-t", "xray_proxya_gateway_t", bin, "gateway", operation)
	// The restricted manager is non-interactive.  Keeping SSH/terminal file
	// descriptors out of that domain avoids granting it access to a caller's
	// labelled pipes merely to print diagnostics.
	cmd.Env = append(os.Environ(), proxyaSELinux.GatewayManagementEnv()+"=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run Gateway SELinux management domain: %w", err)
	}
	if operation == "system-up" {
		fmt.Println("✅ Gateway runtime rules are up.")
	} else {
		fmt.Println("✅ Gateway runtime rules are down and Xray restarted without TUN.")
	}
	return nil
}

var gatewayTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Observe enabled gateway paths through non-bypassed endpoints",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load active config: %v\n", err)
			return
		}

		if cfg.Gateway.State == "disabled" {
			fmt.Printf("ℹ️  Gateway transparent tests skipped: active state is %q.\n", cfg.Gateway.State)
			fmt.Println("   Hint: xray-proxya gateway set --state proxy && xray-proxya apply")
			return
		}

		if cfg.Gateway.LocalEnabled {
			fmt.Println("🔍 Running Local Proxy Route Test (observing public IP through a non-bypassed endpoint)...")
			localIP, err := gateway.RunLocalProxyTest(cfg)
			if err != nil {
				fmt.Printf("❌ Local Proxy Test Failed: %v\n   (Hint: Is the 'xray-proxya' service running and gateway rules up?)\n", err)
			} else {
				fmt.Printf("ℹ️  Local Proxy Test observed public IP: %s\n", localIP)
			}
		} else {
			fmt.Println("ℹ️  Local Proxy Test skipped: Local Proxy is disabled.")
		}

		if cfg.Gateway.LANEnabled {
			fmt.Println("\n🔍 Running Simulated LAN Gateway Route Test (observing public IP through a non-bypassed endpoint)...")
			lanIP, err := gateway.RunSimulatedLANTest(cfg)
			if err != nil {
				fmt.Printf("❌ Simulated LAN Test Failed: %v\n   (Hint: Is the 'xray-proxya' service running and gateway rules up?)\n", err)
			} else {
				fmt.Printf("ℹ️  Simulated LAN Gateway Test observed public IP: %s\n", lanIP)
			}
		} else {
			fmt.Println("ℹ️  Simulated LAN Gateway Test skipped: LAN Gateway is disabled; LAN clients are intentionally not served.")
		}
	},
}

var (
	gatewayExportWrite bool
	gatewayExportOut   string
)

var gatewayExportCmd = &cobra.Command{
	Use:     "export [file]",
	Aliases: []string{"dump"},
	Short:   "Export gateway configuration to declarative gateway.conf format",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			cfg, err = config.LoadConfigEx(false)
			if err != nil || cfg == nil {
				return fmt.Errorf("❌ Failed to load gateway configuration")
			}
		}

		content := gatewayconf.GenerateFromUserConfig(cfg)

		targetPath := gatewayExportOut
		if len(args) == 1 {
			targetPath = args[0]
		} else if gatewayExportWrite {
			targetPath = config.GetGatewayConfPath()
		}

		if targetPath == "" {
			fmt.Print(content)
			return nil
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
			return fmt.Errorf("❌ Failed to create directory: %w", err)
		}
		if err := os.WriteFile(targetPath, []byte(content), 0600); err != nil {
			return fmt.Errorf("❌ Failed to write %s: %w", targetPath, err)
		}
		fmt.Printf("✅ Gateway configuration exported to: %s\n", targetPath)
		return nil
	},
}

var gatewayEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit gateway.conf interactively with syntax validation",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		confPath := config.GetGatewayConfPath()

		if !config.GatewayConfExists() {
			cfg, _ := config.LoadConfigEx(true)
			if cfg == nil {
				cfg, _ = config.LoadConfigEx(false)
			}
			var content string
			if cfg != nil {
				content = gatewayconf.GenerateFromUserConfig(cfg)
			} else {
				content = gatewayconf.Generate(&config.GatewayConfig{
					Mode:         "tproxy",
					LocalEnabled: true,
					LANEnabled:   true,
				})
			}
			if err := os.MkdirAll(filepath.Dir(confPath), 0700); err != nil {
				return fmt.Errorf("❌ Failed to create config directory: %w", err)
			}
			if err := os.WriteFile(confPath, []byte(content), 0600); err != nil {
				return fmt.Errorf("❌ Failed to create initial %s: %w", confPath, err)
			}
			fmt.Printf("ℹ️  Created initial gateway.conf at %s\n", confPath)
		}

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = os.Getenv("VISUAL")
		}
		if editor == "" {
			for _, candidate := range []string{"nano", "vim", "vi"} {
				if _, err := exec.LookPath(candidate); err == nil {
					editor = candidate
					break
				}
			}
		}
		if editor == "" {
			return fmt.Errorf("❌ No editor found. Please set $EDITOR or install nano/vim")
		}

		isTerm := false
		if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			isTerm = true
		}

		for {
			c := exec.Command(editor, confPath)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("❌ Editor %q exited with error: %w", editor, err)
			}

			data, err := os.ReadFile(confPath)
			if err != nil {
				return fmt.Errorf("❌ Failed to read %s: %w", confPath, err)
			}

			ast, parseErr := gatewayconf.Parse(string(data))
			if parseErr != nil {
				fmt.Printf("\n❌ Syntax error in gateway.conf:\n   %v\n", parseErr)
				if !isTerm {
					return parseErr
				}
				fmt.Print("Press 'e' to re-edit, or 'q' to quit (changes kept on disk): ")
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) == "q" {
					return parseErr
				}
				continue
			}

			userCfg, _ := config.LoadConfigEx(true)
			if userCfg == nil {
				userCfg, _ = config.LoadConfigEx(false)
			}
			if _, compileErr := gatewayconf.Compile(ast, gatewayconf.WithUserConfig(userCfg)); compileErr != nil {
				fmt.Printf("\n⚠️  Compilation warning in gateway.conf:\n   %v\n", compileErr)
				if !isTerm {
					return compileErr
				}
				fmt.Print("Press 'e' to re-edit, or 'q' to keep and exit: ")
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "e" {
					break
				}
				continue
			}

			fmt.Println("✅ gateway.conf syntax validated successfully.")
			fmt.Println("ℹ️  Run 'xray-proxya apply' to compile and apply changes.")
			break
		}

		return nil
	},
}

func init() {
	gatewayEnableCmd.Flags().BoolVar(&gatewayEnableNow, "now", false, "Immediately commit changes and bring gateway runtime up")
	gatewayDisableCmd.Flags().BoolVar(&gatewayDisableNow, "now", false, "Immediately commit changes and bring gateway runtime down")
	gatewayStatusCmd.Flags().BoolVar(&gatewayStatusJSON, "json", false, "Output in JSON format")

	gatewaySetCmd.Flags().Bool("tun", false, "Enable standalone pure TUN adapter (proxya-tun) in staging")
	gatewaySetCmd.Flags().Bool("no-tun", false, "Disable standalone pure TUN adapter in staging")
	gatewaySetCmd.Flags().StringP("mode", "m", "", "Interception mode: 'tproxy' (default) or 'tun'")
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("interface", "i", "", "LAN interface name (supports comma-separated multiple interfaces)")
	gatewaySetCmd.Flags().String("lan-interface", "", "LAN interface name")
	gatewaySetCmd.Flags().String("wan", "", "WAN interface name ('auto' or empty to auto-detect)")
	gatewaySetCmd.Flags().Bool("nat", false, "Enable WAN NAT masquerade in staging")
	gatewaySetCmd.Flags().Bool("no-nat", false, "Disable WAN NAT masquerade in staging")
	gatewaySetCmd.Flags().StringSliceP("bypass-dns", "d", nil, "DNS server IPs to bypass transparent proxy hijacking")
	gatewaySetCmd.Flags().StringSliceP("bypass-countries", "c", nil, "Country codes to bypass (e.g. CN)")
	gatewaySetCmd.Flags().StringP("state", "s", "", "Gateway state (disabled, proxy, or experimental forward-only)")
	gatewaySetCmd.Flags().Bool("lan", false, "Enable or disable LAN gateway forwarding in staging")
	gatewaySetCmd.Flags().Bool("no-lan", false, "Disable LAN gateway in staging")
	gatewaySetCmd.Flags().Bool("lan-enable", false, "Enable LAN gateway (IP forwarding) in staging")
	gatewaySetCmd.Flags().Bool("lan-disable", false, "Disable LAN gateway in staging")
	gatewaySetCmd.Flags().Bool("local", false, "Enable or disable local machine transparent proxy in staging")
	gatewaySetCmd.Flags().Bool("no-local", false, "Disable local machine transparent proxy in staging")
	gatewaySetCmd.Flags().Bool("local-enable", false, "Enable local machine transparent proxy in staging")
	gatewaySetCmd.Flags().Bool("local-disable", false, "Disable local machine transparent proxy in staging")

	gatewaySetCmd.RegisterFlagCompletionFunc("mode", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"tproxy\tTransparent proxy using socket redirect (default)", "tun\tTransparent proxy using proxya-tun device"}, cobra.ShellCompDirectiveNoFileComp
	})

	gatewaySetCmd.RegisterFlagCompletionFunc("state", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"disabled", "forward-only", "proxy"}, cobra.ShellCompDirectiveNoFileComp
	})

	gatewaySetCmd.RegisterFlagCompletionFunc("bypass-countries", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"CN", "US", "HK", "SG", "JP", "TW", "GB", "DE"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Dynamic completions
	gatewaySetCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var aliases []string
		for _, co := range cfg.CustomOutbounds {
			aliases = append(aliases, co.Alias)
		}
		return aliases, cobra.ShellCompDirectiveNoFileComp
	})
	gatewaySetCmd.RegisterFlagCompletionFunc("lan", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
	})
	gatewaySetCmd.RegisterFlagCompletionFunc("interface", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var names []string
		for _, iface := range ifaces {
			if iface.Name != "" {
				names = append(names, iface.Name)
			}
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	})
	gatewaySetCmd.RegisterFlagCompletionFunc("wan", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		ifaces, err := net.Interfaces()
		if err != nil {
			return []string{"auto"}, cobra.ShellCompDirectiveNoFileComp
		}
		names := []string{"auto"}
		for _, iface := range ifaces {
			if iface.Name != "" {
				names = append(names, iface.Name)
			}
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	})

	gatewayExportCmd.Flags().BoolVarP(&gatewayExportWrite, "write", "w", false, "Write directly to ~/.config/xray-proxya/gateway.conf")
	gatewayExportCmd.Flags().StringVarP(&gatewayExportOut, "output", "o", "", "Output file path")

	_ = gatewaySetCmd.Flags().MarkHidden("lan-interface")
	_ = gatewaySetCmd.Flags().MarkHidden("lan-enable")
	_ = gatewaySetCmd.Flags().MarkHidden("lan-disable")
	_ = gatewaySetCmd.Flags().MarkHidden("local-enable")
	_ = gatewaySetCmd.Flags().MarkHidden("local-disable")

	gatewayCmd.AddCommand(
		gatewayStatusCmd,
		gatewayEnableCmd,
		gatewayDisableCmd,
		gatewaySetCmd,
		gatewayUpCmd,
		gatewaySystemUpCmd,
		gatewayDownCmd,
		gatewaySystemDownCmd,
		gatewaySystemSyncCmd,
		gatewaySystemRestoreCmd,
		gatewayCheckCmd,
		gatewayDiffCmd,
		gatewayTestCmd,
		gatewayExportCmd,
		gatewayEditCmd,
	)
	rootCmd.AddCommand(gatewayCmd)
}
