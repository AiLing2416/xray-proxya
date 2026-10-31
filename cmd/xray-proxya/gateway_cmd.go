package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

	gatewayStateProxy       bool
	gatewayStateForwardOnly bool
	gatewayStateDisabled    bool
	gatewayStateJSON        bool

	gatewayTProxyEnable          bool
	gatewayTProxyDisable         bool
	gatewayTProxyRelay           string
	gatewayTProxyLocal           bool
	gatewayTProxyNoLocal         bool
	gatewayTProxyLAN             bool
	gatewayTProxyNoLAN           bool
	gatewayTProxyInterface       string
	gatewayTProxyWAN             string
	gatewayTProxyNAT             bool
	gatewayTProxyNoNAT           bool
	gatewayTProxyBypassCountries []string
	gatewayTProxyBypassDNS       []string
	gatewayTProxyPort            int
	gatewayTProxyNow             bool
	gatewayTProxyJSON            bool

	gatewayTunEnable  bool
	gatewayTunDisable bool
	gatewayTunNow     bool
	gatewayTunJSON    bool

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
	Mode          string                   `json:"mode,omitempty"`
	TUNEnabled    bool                     `json:"tun_enabled"`
	LocalEnabled  bool                     `json:"local_enabled"`
	LANEnabled    bool                     `json:"lan_enabled"`
	Relay         string                   `json:"relay"`
	Interface     string                   `json:"interface"`
	LANInterfaces []string                 `json:"lan_interfaces,omitempty"`
	WANInterface  string                   `json:"wan_interface,omitempty"`
	NATDisabled   bool                     `json:"nat_disabled,omitempty"`
	Rules         []config.GatewayRule     `json:"rules,omitempty"`
	State         string                   `json:"state"`
	DNSListen     string                   `json:"dns_listen,omitempty"`
	DNSStrategy   string                   `json:"dns_strategy,omitempty"`
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
	Args:  cobra.NoArgs,
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

var gatewayStateCmd = &cobra.Command{
	Use:   "state",
	Short: "View or set gateway state (--proxy, --forward-only, --disabled)",
	Args:  cobra.NoArgs,
	RunE:  runGatewayState,
}

func runGatewayState(cmd *cobra.Command, args []string) error {
	defer func() {
		gatewayStateProxy = false
		gatewayStateForwardOnly = false
		gatewayStateDisabled = false
		gatewayStateJSON = false
	}()
	count := 0
	targetState := ""
	if gatewayStateProxy {
		count++
		targetState = "proxy"
	}
	if gatewayStateForwardOnly {
		count++
		targetState = "forward-only"
	}
	if gatewayStateDisabled {
		count++
		targetState = "disabled"
	}

	if count > 1 {
		return fmt.Errorf("❌ Conflicting state flags: only one of --proxy, --forward-only, or --disabled may be specified")
	}

	if count == 1 {
		err := gatewayconf.ModifyGatewayConf(func(content string) string {
			return gatewayconf.UpdateSet(content, "state", targetState)
		})
		if err != nil {
			return fmt.Errorf("❌ Failed to update gateway.conf: %w", err)
		}
		fmt.Printf("✅ Gateway state updated to '%s' in STAGING.\n", targetState)
		if targetState == "forward-only" {
			fmt.Println("⚠️  forward-only is experimental: it enables kernel forwarding only, without NAT or transparent proxying.")
		}
		fmt.Println("🚀 Run 'xray-proxya apply' to commit changes.")
		return nil
	}

	// Status display
	activeCfg, _ := config.LoadConfigEx(false)
	stagingCfg, _ := config.LoadConfigEx(true)
	if gatewayStateJSON {
		out := map[string]string{
			"active":  getEffectiveGatewayState(activeCfg),
			"staging": getEffectiveGatewayState(stagingCfg),
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("\n🛰️ GATEWAY STATE")
	fmt.Println("--------------------------------------------------")
	actState := "(not initialized)"
	if activeCfg != nil {
		actState = getEffectiveGatewayState(activeCfg)
	}
	stgState := "(not initialized)"
	if stagingCfg != nil {
		stgState = getEffectiveGatewayState(stagingCfg)
	}
	fmt.Printf("  ACTIVE:  %s\n", actState)
	fmt.Printf("  STAGING: %s\n", stgState)
	return nil
}

var gatewayTProxyCmd = &cobra.Command{
	Use:               "tproxy",
	Short:             "Configure or inspect TProxy transparent gateway settings",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE:              runGatewayTProxy,
}

func runGatewayTProxy(cmd *cobra.Command, args []string) error {
	defer func() {
		gatewayTProxyEnable = false
		gatewayTProxyDisable = false
		gatewayTProxyRelay = ""
		gatewayTProxyLocal = false
		gatewayTProxyNoLocal = false
		gatewayTProxyLAN = false
		gatewayTProxyNoLAN = false
		gatewayTProxyInterface = ""
		gatewayTProxyWAN = ""
		gatewayTProxyNAT = false
		gatewayTProxyNoNAT = false
		gatewayTProxyBypassCountries = nil
		gatewayTProxyBypassDNS = nil
		gatewayTProxyPort = 0
		gatewayTProxyNow = false
		gatewayTProxyJSON = false
		gatewayEnableNow = false
		gatewayDisableNow = false
	}()

	var positionalRelay string
	if len(args) == 1 {
		positionalRelay = strings.TrimSpace(args[0])
	}

	hasChanged := positionalRelay != ""
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if f.Changed && f.Name != "json" && f.Name != "now" {
			hasChanged = true
		}
	})

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
	if gatewayTProxyEnable && gatewayTProxyDisable {
		return fmt.Errorf("❌ Error: Conflicting flags specified: cannot use both --enable and --disable")
	}

	natEnable := cmd.Flags().Changed("nat")
	natDisable := cmd.Flags().Changed("no-nat")
	if natEnable && natDisable {
		return fmt.Errorf("❌ Error: Conflicting flags specified: cannot use both --nat and --no-nat")
	}

	if !hasChanged && !lanEnable && !lanDisable && !localEnable && !localDisable && !gatewayTProxyEnable && !gatewayTProxyDisable {
		if cmd.Name() == "set" {
			return fmt.Errorf("❌ Error: No parameter supplied")
		}
		return runGatewayStatus(cmd, args)
	}

	err := gatewayconf.ModifyGatewayConf(func(content string) string {
		if gatewayTProxyEnable {
			content = gatewayconf.UpdateSet(content, "local", "true")
			content = gatewayconf.UpdateSet(content, "lan", "true")
			content = gatewayconf.UpdateSet(content, "mode", "tproxy")
		}
		if gatewayTProxyDisable {
			content = gatewayconf.UpdateSet(content, "local", "false")
			content = gatewayconf.UpdateSet(content, "lan", "false")
		}
		if lanEnable {
			content = gatewayconf.UpdateSet(content, "lan", "true")
		} else if lanDisable {
			content = gatewayconf.UpdateSet(content, "lan", "false")
		}
		if localEnable {
			content = gatewayconf.UpdateSet(content, "local", "true")
		} else if localDisable {
			content = gatewayconf.UpdateSet(content, "local", "false")
		}

		if cmd.Flags().Changed("relay") {
			relay, _ := cmd.Flags().GetString("relay")
			content = gatewayconf.UpdateSet(content, "relay", relay)
		} else if positionalRelay != "" {
			content = gatewayconf.UpdateSet(content, "relay", positionalRelay)
		}

		if cmd.Flags().Changed("wan") {
			wan, _ := cmd.Flags().GetString("wan")
			wanTrimmed := strings.TrimSpace(wan)
			if wanTrimmed == "" || strings.EqualFold(wanTrimmed, "auto") {
				content = gatewayconf.UpdateSet(content, "wan", "auto")
			} else {
				content = gatewayconf.UpdateSet(content, "wan", wanTrimmed)
			}
		}

		var iface string
		if cmd.Flags().Changed("interface") {
			iface, _ = cmd.Flags().GetString("interface")
		} else if cmd.Flags().Changed("lan-interface") {
			iface, _ = cmd.Flags().GetString("lan-interface")
		}
		if iface != "" {
			content = gatewayconf.UpdateSet(content, "lan_interfaces", iface)
		}

		if natEnable {
			content = gatewayconf.UpdateSet(content, "nat", "true")
		} else if natDisable {
			content = gatewayconf.UpdateSet(content, "nat", "false")
		}

		if cmd.Flags().Changed("port") {
			port, _ := cmd.Flags().GetInt("port")
			content = gatewayconf.UpdateSet(content, "tproxy_port", strconv.Itoa(port))
		}

		if cmd.Flags().Changed("bypass-countries") {
			bypassCountries, _ := cmd.Flags().GetStringSlice("bypass-countries")
			content = gatewayconf.UpdateSet(content, "bypass_countries", strings.Join(bypassCountries, ","))
		}
		if cmd.Flags().Changed("bypass-dns") {
			bypassDNS, _ := cmd.Flags().GetStringSlice("bypass-dns")
			content = gatewayconf.UpdateSet(content, "bypass_dns", strings.Join(bypassDNS, ","))
		}

		if cmd.Flags().Changed("mode") {
			modeVal, _ := cmd.Flags().GetString("mode")
			modeVal = strings.ToLower(strings.TrimSpace(modeVal))
			content = gatewayconf.UpdateSet(content, "mode", modeVal)
		}
		if cmd.Flags().Changed("tun") {
			tunVal, _ := cmd.Flags().GetBool("tun")
			val := "false"
			if tunVal {
				val = "true"
			}
			content = gatewayconf.UpdateSet(content, "tun", val)
		}
		if cmd.Flags().Changed("no-tun") {
			content = gatewayconf.UpdateSet(content, "tun", "false")
		}
		if cmd.Flags().Changed("state") {
			stateVal, _ := cmd.Flags().GetString("state")
			content = gatewayconf.UpdateSet(content, "state", stateVal)
		}

		return content
	})
	if err != nil {
		return fmt.Errorf("❌ Failed to update gateway.conf: %w", err)
	}

	// Validate staging gateway
	stgCfg, err := config.LoadConfigEx(true)
	if err != nil {
		return fmt.Errorf("❌ Validation error in updated gateway: %w", err)
	}
	if stgCfg != nil {
		if err := config.ValidateGatewayInterfaces(stgCfg); err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		if err := config.ValidateGatewayRulesForMode(stgCfg); err != nil {
			return fmt.Errorf("❌ %w", err)
		}
	}

	now := gatewayTProxyNow || gatewayEnableNow || gatewayDisableNow
	if now {
		op := "system-up"
		if gatewayTProxyDisable || gatewayDisableNow {
			op = "system-down"
		}
		lines, err := applyPendingFunc(applyops.Options{Start: true})
		for _, line := range lines {
			fmt.Println(line)
		}
		if err != nil {
			return fmt.Errorf("failed to apply configuration: %w", err)
		}
		if err := runGatewayManagementFunc(op); err != nil {
			return fmt.Errorf("failed to sync gateway runtime: %w", err)
		}
		fmt.Printf("✅ Gateway parameters updated and runtime rules synced (%s).\n", op)
		return nil
	}

	fmt.Println("✅ Gateway parameters updated in STAGING.")
	fmt.Println("🚀 Run 'xray-proxya apply' to commit changes.")
	return nil
}

var gatewayTunCmd = &cobra.Command{
	Use:   "tun",
	Short: "Configure or inspect standalone TUN adapter settings",
	Args:  cobra.NoArgs,
	RunE:  runGatewayTun,
}

func runGatewayTun(cmd *cobra.Command, args []string) error {
	defer func() {
		gatewayTunEnable = false
		gatewayTunDisable = false
		gatewayTunNow = false
		gatewayTunJSON = false
	}()

	if gatewayTunEnable && gatewayTunDisable {
		return fmt.Errorf("❌ Error: Conflicting flags specified: cannot use both --enable and --disable")
	}

	if gatewayTunEnable || gatewayTunDisable {
		val := "false"
		if gatewayTunEnable {
			val = "true"
		}
		err := gatewayconf.ModifyGatewayConf(func(content string) string {
			return gatewayconf.UpdateSet(content, "tun", val)
		})
		if err != nil {
			return fmt.Errorf("❌ Failed to update gateway.conf: %w", err)
		}

		if gatewayTunNow {
			lines, err := applyPendingFunc(applyops.Options{Start: true})
			for _, line := range lines {
				fmt.Println(line)
			}
			if err != nil {
				return fmt.Errorf("failed to apply configuration: %w", err)
			}
			_ = runGatewayManagementFunc("system-up")
			fmt.Println("✅ Gateway TUN updated and runtime rules are UP.")
			return nil
		}

		fmt.Printf("✅ Gateway TUN set to %s in STAGING.\n", val)
		fmt.Println("🚀 Run 'xray-proxya apply' to commit changes.")
		return nil
	}

	activeCfg, _ := config.LoadConfigEx(false)
	stagingCfg, _ := config.LoadConfigEx(true)
	if gatewayTunJSON {
		out := map[string]bool{
			"active":  activeCfg != nil && activeCfg.Gateway.EffectiveTUNEnabled(),
			"staging": stagingCfg != nil && stagingCfg.Gateway.EffectiveTUNEnabled(),
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("\n🛰️ GATEWAY TUN ADAPTER")
	fmt.Println("--------------------------------------------------")
	actTUN := false
	if activeCfg != nil {
		actTUN = activeCfg.Gateway.EffectiveTUNEnabled()
	}
	stgTUN := false
	if stagingCfg != nil {
		stgTUN = stagingCfg.Gateway.EffectiveTUNEnabled()
	}
	fmt.Printf("  ACTIVE:  %s\n", formatGatewayBoolState(actTUN))
	fmt.Printf("  STAGING: %s\n", formatGatewayBoolState(stgTUN))
	return nil
}

var gatewayEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Turn on transparent gateway (local & lan) in staging",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		gatewayTProxyEnable = true
		gatewayTProxyNow = gatewayEnableNow
		return runGatewayTProxy(cmd, args)
	},
}

var gatewayDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Turn off transparent gateway (local & lan) in staging",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		gatewayTProxyDisable = true
		gatewayTProxyNow = gatewayDisableNow
		return runGatewayTProxy(cmd, args)
	},
}

var gatewaySetCmd = &cobra.Command{
	Use:               "set [relay]",
	Short:             "Configure gateway parameters in STAGING",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE:              runGatewayTProxy,
}

var gatewayUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring transparent gateway interception rules up and sync runtime",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayManagement("system-up")
	},
}

var gatewaySystemUpCmd = &cobra.Command{
	Use:    "system-up",
	Short:  "Apply Gateway runtime from the SELinux management domain",
	Args:   cobra.NoArgs,
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
	Args:  cobra.NoArgs,
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
		if cfg.Gateway.EffectiveMode() == "tun" {
			fmt.Println("(no policy routing rules in standalone tun mode)")
		} else {
			fmt.Println("ip rule add fwmark 1 table 100 pref 10100")
			fmt.Println("ip rule add fwmark 255 table main pref 10000")
			fmt.Println("ip route replace local default dev lo table 100")
		}
	},
}

var gatewayCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check gateway runtime state",
	Args:  cobra.NoArgs,
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
	Short: "Tear down transparent gateway interception rules and clear runtime",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayManagement("system-down")
	},
}

var gatewaySystemDownCmd = &cobra.Command{
	Use:    "system-down",
	Short:  "Remove Gateway runtime from the SELinux management domain",
	Args:   cobra.NoArgs,
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := gateway.Down(); err != nil {
			return fmt.Errorf("remove gateway runtime: %w", err)
		}
		fmt.Println("✅ Gateway runtime rules are down.")
		return nil
	},
}

var gatewaySystemSyncCmd = &cobra.Command{
	Use:    "system-sync",
	Short:  "Synchronize Gateway runtime from the SELinux management domain",
	Args:   cobra.NoArgs,
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
	Args:   cobra.NoArgs,
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
		fmt.Println("✅ Gateway runtime rules are down.")
	}
	return nil
}

var gatewayTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Observe enabled gateway paths through non-bypassed endpoints",
	Args:  cobra.NoArgs,
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

	gatewaySetCmd.Flags().Bool("tun", false, "Enable standalone TUN adapter (proxya-tun) in staging")
	gatewaySetCmd.Flags().Bool("no-tun", false, "Disable standalone TUN adapter in staging")
	gatewaySetCmd.Flags().StringP("mode", "m", "", "Gateway mode: 'tproxy' (default) or 'tun' (standalone virtual adapter only)")
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("interface", "i", "", "LAN interface name (supports comma-separated multiple interfaces)")
	gatewaySetCmd.Flags().String("lan-interface", "", "LAN interface name")
	gatewaySetCmd.Flags().String("wan", "", "WAN interface name ('auto' or empty to auto-detect)")
	gatewaySetCmd.Flags().Bool("nat", false, "Enable WAN NAT masquerade in staging")
	gatewaySetCmd.Flags().Bool("no-nat", false, "Disable WAN NAT masquerade in staging")
	gatewaySetCmd.Flags().StringSliceP("bypass-dns", "d", nil, "DNS server IPs to bypass transparent proxy hijacking")
	gatewaySetCmd.Flags().StringSliceP("bypass-countries", "c", nil, "Country codes to bypass (e.g. CN)")
	gatewaySetCmd.Flags().StringP("state", "s", "", "Gateway state (disabled, proxy, or experimental forward-only)")
	gatewaySetCmd.Flags().Int("port", 0, "TProxy listener port (e.g. 53905)")
	gatewaySetCmd.Flags().BoolVar(&gatewayTProxyNow, "now", false, "Immediately apply changes and update runtime rules")
	gatewaySetCmd.Flags().Bool("lan", false, "Enable LAN gateway forwarding in staging")
	gatewaySetCmd.Flags().Bool("no-lan", false, "Disable LAN gateway in staging")
	gatewaySetCmd.Flags().Bool("lan-enable", false, "Enable LAN gateway (IP forwarding) in staging")
	gatewaySetCmd.Flags().Bool("lan-disable", false, "Disable LAN gateway in staging")
	gatewaySetCmd.Flags().Bool("local", false, "Enable local machine transparent proxy in staging")
	gatewaySetCmd.Flags().Bool("no-local", false, "Disable local machine transparent proxy in staging")
	gatewaySetCmd.Flags().Bool("local-enable", false, "Enable local machine transparent proxy in staging")
	gatewaySetCmd.Flags().Bool("local-disable", false, "Disable local machine transparent proxy in staging")

	completeModeFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"tproxy\tTransparent proxy using socket redirect (default; combine with --tun for hybrid)",
			"tun\tStandalone proxya-tun virtual adapter only (no TProxy nftables/routing rules)",
		}, cobra.ShellCompDirectiveNoFileComp
	}
	completeStateFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"disabled", "forward-only", "proxy"}, cobra.ShellCompDirectiveNoFileComp
	}
	completeBypassCountriesFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"CN", "US", "HK", "SG", "JP", "TW", "GB", "DE"}, cobra.ShellCompDirectiveNoFileComp
	}
	completeBypassDNSFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "223.5.5.5", "119.29.29.29"}, cobra.ShellCompDirectiveNoFileComp
	}
	completeRelayFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var aliases []string
		for _, co := range cfg.CustomOutbounds {
			aliases = append(aliases, co.Alias)
		}
		return aliases, cobra.ShellCompDirectiveNoFileComp
	}
	completeBoolFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
	}
	completeWANFn := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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
	}

	gatewayExportCmd.Flags().BoolVarP(&gatewayExportWrite, "write", "w", false, "Write directly to active user's gateway.conf")
	gatewayExportCmd.Flags().StringVarP(&gatewayExportOut, "output", "o", "", "Output file path")

	_ = gatewaySetCmd.Flags().MarkHidden("lan-interface")
	_ = gatewaySetCmd.Flags().MarkHidden("lan-enable")
	_ = gatewaySetCmd.Flags().MarkHidden("lan-disable")
	_ = gatewaySetCmd.Flags().MarkHidden("local-enable")
	_ = gatewaySetCmd.Flags().MarkHidden("local-disable")

	gatewayStateCmd.Flags().BoolVar(&gatewayStateProxy, "proxy", false, "Set gateway state to proxy in staging")
	gatewayStateCmd.Flags().BoolVar(&gatewayStateForwardOnly, "forward-only", false, "Set gateway state to forward-only in staging")
	gatewayStateCmd.Flags().BoolVar(&gatewayStateDisabled, "disabled", false, "Set gateway state to disabled in staging")
	gatewayStateCmd.Flags().BoolVar(&gatewayStateJSON, "json", false, "Output in JSON format")

	gatewayTunCmd.Flags().BoolVar(&gatewayTunEnable, "enable", false, "Enable standalone TUN adapter (proxya-tun) in staging")
	gatewayTunCmd.Flags().BoolVar(&gatewayTunDisable, "disable", false, "Disable standalone TUN adapter in staging")
	gatewayTunCmd.Flags().BoolVar(&gatewayTunNow, "now", false, "Immediately apply changes and bring runtime rules up")
	gatewayTunCmd.Flags().BoolVar(&gatewayTunJSON, "json", false, "Output in JSON format")

	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyEnable, "enable", false, "Enable transparent proxy gateway (local & lan) in staging")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyDisable, "disable", false, "Disable transparent proxy gateway (local & lan) in staging")
	gatewayTProxyCmd.Flags().Bool("tun", false, "Enable standalone TUN adapter (proxya-tun) in staging")
	gatewayTProxyCmd.Flags().Bool("no-tun", false, "Disable standalone TUN adapter in staging")
	gatewayTProxyCmd.Flags().StringP("mode", "m", "", "Gateway mode: 'tproxy' (default) or 'tun' (standalone virtual adapter only)")
	gatewayTProxyCmd.Flags().StringP("state", "s", "", "Gateway state (disabled, proxy, or experimental forward-only)")
	gatewayTProxyCmd.Flags().StringVarP(&gatewayTProxyRelay, "relay", "r", "", "Relay alias to bind")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyLocal, "local", false, "Enable local machine transparent proxy in staging")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyNoLocal, "no-local", false, "Disable local machine transparent proxy in staging")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyLAN, "lan", false, "Enable LAN gateway forwarding in staging")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyNoLAN, "no-lan", false, "Disable LAN gateway forwarding in staging")
	gatewayTProxyCmd.Flags().StringVarP(&gatewayTProxyInterface, "interface", "i", "", "LAN interface name (supports comma-separated multiple interfaces)")
	gatewayTProxyCmd.Flags().StringVar(&gatewayTProxyInterface, "lan-interface", "", "LAN interface name(s)")
	gatewayTProxyCmd.Flags().StringVar(&gatewayTProxyWAN, "wan", "", "WAN interface name ('auto' or empty to auto-detect)")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyNAT, "nat", false, "Enable WAN NAT masquerade in staging")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyNoNAT, "no-nat", false, "Disable WAN NAT masquerade in staging")
	gatewayTProxyCmd.Flags().StringSliceVarP(&gatewayTProxyBypassDNS, "bypass-dns", "d", nil, "DNS server IPs to bypass transparent proxy hijacking")
	gatewayTProxyCmd.Flags().StringSliceVarP(&gatewayTProxyBypassCountries, "bypass-countries", "c", nil, "Country codes to bypass (e.g. CN)")
	gatewayTProxyCmd.Flags().IntVar(&gatewayTProxyPort, "port", 0, "TProxy listener port (e.g. 53905)")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyNow, "now", false, "Immediately apply changes and update runtime rules")
	gatewayTProxyCmd.Flags().BoolVar(&gatewayTProxyJSON, "json", false, "Output in JSON format")
	_ = gatewayTProxyCmd.Flags().MarkHidden("lan-interface")

	for _, c := range []*cobra.Command{gatewaySetCmd, gatewayTProxyCmd} {
		_ = c.RegisterFlagCompletionFunc("mode", completeModeFn)
		_ = c.RegisterFlagCompletionFunc("state", completeStateFn)
		_ = c.RegisterFlagCompletionFunc("bypass-countries", completeBypassCountriesFn)
		_ = c.RegisterFlagCompletionFunc("bypass-dns", completeBypassDNSFn)
		_ = c.RegisterFlagCompletionFunc("relay", completeRelayFn)
		_ = c.RegisterFlagCompletionFunc("lan", completeBoolFn)
		_ = c.RegisterFlagCompletionFunc("interface", completeInterfaceNames)
		_ = c.RegisterFlagCompletionFunc("wan", completeWANFn)
	}

	gatewayCmd.AddCommand(
		gatewayStatusCmd,
		gatewayStateCmd,
		gatewayTProxyCmd,
		gatewayTunCmd,
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
