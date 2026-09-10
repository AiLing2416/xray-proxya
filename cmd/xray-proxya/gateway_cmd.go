package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	proxyaSELinux "xray-proxya/internal/selinux"
	"xray-proxya/internal/tui"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

var gatewayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway configuration and system state",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Printf("❌ Failed to load gateway configuration: %v\n", err)
			return
		}
		fmt.Println("\n🛰️ GATEWAY CONFIGURATION (STAGING)")
		fmt.Println("--------------------------------------------------")
		localState := "DISABLED"
		if cfg.Gateway.LocalEnabled {
			localState = "ENABLED"
		}
		lanState := "DISABLED"
		if cfg.Gateway.LANEnabled {
			lanState = "ENABLED"
		}
		fmt.Printf("Local Proxy: %s\n", localState)
		fmt.Printf("LAN Gateway: %s\n", lanState)
		fmt.Printf("Relay:       %s\n", cfg.Gateway.RelayAlias)
		fmt.Printf("LAN Iface:   %s\n", cfg.Gateway.LANInterface)
		fmt.Printf("State:       %s\n", cfg.Gateway.State)
		fmt.Printf("Bypass DNS:  %s\n", strings.Join(cfg.Gateway.BypassDNS, ", "))
		fmt.Printf("Bypass Geo:  %s\n\n", strings.Join(cfg.Gateway.BypassCountries, ", "))
	},
}

var gatewayEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Turn on transparent gateway (local & lan) in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.LocalEnabled = true
		cfg.Gateway.LANEnabled = true
		cfg.Gateway.Mode = "tun"
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway ENABLED in STAGING. Run 'apply' to commit, then 'gateway up' to update runtime rules.")
	},
}

var gatewayDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Turn off transparent gateway (local & lan) in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.LocalEnabled = false
		cfg.Gateway.LANEnabled = false
		cfg.Gateway.Mode = "tun"
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway DISABLED in STAGING. Run 'apply' to commit, then 'gateway down' to remove runtime rules.")
	},
}

var gatewaySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure gateway parameters in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGatewaySet(cmd, args)
	},
	RunE: runGatewaySet,
}

func runGatewaySet(cmd *cobra.Command, args []string) error {
	hasChanged := false
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

	cfg.Gateway.Mode = "tun"
	if cmd.Flags().Changed("relay") {
		relay, _ := cmd.Flags().GetString("relay")
		cfg.Gateway.RelayAlias = relay
	}

	var iface string
	if cmd.Flags().Changed("interface") {
		iface, _ = cmd.Flags().GetString("interface")
	} else if cmd.Flags().Changed("lan-interface") {
		iface, _ = cmd.Flags().GetString("lan-interface")
	}
	if iface != "" {
		for _, r := range iface {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
				return fmt.Errorf("❌ Invalid interface name: %s", iface)
			}
		}
		cfg.Gateway.LANInterface = iface
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
		fmt.Println("ip route replace default dev proxya-tun table 100")
	},
}

var gatewayCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check gateway runtime state",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
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

		if cfg.Gateway.State != "proxy" {
			fmt.Printf("ℹ️  Gateway transparent tests skipped: active state is %q, not proxy.\n", cfg.Gateway.State)
			fmt.Println("   Hint: xray-proxya gateway set --state proxy && xray-proxya apply")
			return
		}

		if cfg.Gateway.LocalEnabled {
			fmt.Println("🔍 Running Local Proxy Route Test (observing public IP through a non-bypassed endpoint)...")
			localIP, err := tui.RunLocalProxyTest(cfg)
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
			lanIP, err := tui.RunSimulatedLANTest(cfg)
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

func init() {
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("interface", "i", "", "LAN interface name")
	gatewaySetCmd.Flags().String("lan-interface", "", "LAN interface name")
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
	)
	rootCmd.AddCommand(gatewayCmd)
}
