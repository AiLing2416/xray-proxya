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
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Manage transparent proxy gateway (STAGING)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		utils.EnsureRoot()
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
		fmt.Printf("Synthetic Ping: %t\n", cfg.Gateway.SyntheticPing)
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

var gatewayLocalEnableCmd = &cobra.Command{
	Use:    "local-enable",
	Short:  "Enable local machine transparent proxy in staging",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.LocalEnabled = true
		cfg.SaveEx(true)
		fmt.Println("✅ Local transparent proxy ENABLED in STAGING.")
	},
}

var gatewayLocalDisableCmd = &cobra.Command{
	Use:    "local-disable",
	Short:  "Disable local machine transparent proxy in staging",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.LocalEnabled = false
		cfg.SaveEx(true)
		fmt.Println("✅ Local transparent proxy DISABLED in STAGING.")
	},
}

var gatewayLANEnableCmd = &cobra.Command{
	Use:    "lan-enable",
	Short:  "Enable LAN gateway (IP forwarding) in staging",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.LANEnabled = true
		cfg.SaveEx(true)
		fmt.Println("✅ LAN gateway ENABLED in STAGING.")
	},
}

var gatewayLANDisableCmd = &cobra.Command{
	Use:    "lan-disable",
	Short:  "Disable LAN gateway in staging",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.LANEnabled = false
		cfg.SaveEx(true)
		fmt.Println("✅ LAN gateway DISABLED in STAGING.")
	},
}

var gatewaySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure gateway parameters in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		relay, _ := cmd.Flags().GetString("relay")
		lan, _ := cmd.Flags().GetString("lan")
		state, _ := cmd.Flags().GetString("state")
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		cfg.Gateway.Mode = "tun"
		if relay != "" {
			cfg.Gateway.RelayAlias = relay
		}
		if lan != "" {
			// Basic validation for interface name: alphanumeric and common separators
			for _, r := range lan {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
					fmt.Printf("❌ Invalid interface name: %s\n", lan)
					return
				}
			}
			cfg.Gateway.LANInterface = lan
		}
		if state != "" {
			stateLower := strings.ToLower(strings.TrimSpace(state))
			if stateLower != "disabled" && stateLower != "forward-only" && stateLower != "proxy" {
				fmt.Printf("❌ Invalid state: %s (must be one of: disabled, forward-only, proxy)\n", state)
				return
			}
			cfg.Gateway.State = stateLower
			if stateLower == "forward-only" {
				fmt.Println("⚠️  forward-only is experimental: it enables kernel forwarding only, without NAT or transparent proxying.")
			}
		}
		if cmd.Flags().Changed("bypass-dns") {
			bypassDNS, _ := cmd.Flags().GetStringSlice("bypass-dns")
			cfg.Gateway.BypassDNS = bypassDNS
		}
		if cmd.Flags().Changed("bypass-countries") {
			bypassCountries, _ := cmd.Flags().GetStringSlice("bypass-countries")
			cfg.Gateway.BypassCountries = bypassCountries
		}
		if cmd.Flags().Changed("synthetic-ping") {
			enabled, _ := cmd.Flags().GetBool("synthetic-ping")
			cfg.Gateway.SyntheticPing = enabled
		}

		cfg.SaveEx(true)
		fmt.Println("✅ Gateway parameters updated in STAGING.")
	},
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

var gatewayApplyCompatCmd = &cobra.Command{
	Use:    "apply",
	Short:  "Apply gateway runtime rules",
	Hidden: true,
	RunE:   gatewayUpCmd.RunE,
}

var gatewaySyncFirewallCompatCmd = &cobra.Command{
	Use:    "sync-firewall",
	Short:  "Regenerate and apply gateway runtime rules",
	Hidden: true,
	RunE:   gatewayUpCmd.RunE,
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

var gatewayVerifyCompatCmd = &cobra.Command{
	Use:    "verify",
	Short:  "Verify gateway runtime state",
	Hidden: true,
	Run:    gatewayCheckCmd.Run,
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
		if err := gateway.SyncDesired(cfg); err != nil {
			return fmt.Errorf("synchronize gateway runtime: %w", err)
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

var gatewayRollbackCompatCmd = &cobra.Command{
	Use:    "rollback",
	Short:  "Remove xray-proxya gateway runtime rules",
	Hidden: true,
	RunE:   gatewayDownCmd.RunE,
}

func init() {
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("lan", "l", "", "LAN interface name")
	gatewaySetCmd.Flags().StringSliceP("bypass-dns", "d", nil, "DNS server IPs to bypass transparent proxy hijacking")
	gatewaySetCmd.Flags().StringSliceP("bypass-countries", "c", nil, "Country codes to bypass (e.g. CN)")
	gatewaySetCmd.Flags().Bool("synthetic-ping", false, "Reply to LAN ICMP ping using TCP reachability through the selected relay")
	gatewaySetCmd.Flags().StringP("state", "s", "", "Gateway state (disabled, proxy, or experimental forward-only)")

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
		gatewayLocalEnableCmd,
		gatewayLocalDisableCmd,
		gatewayLANEnableCmd,
		gatewayLANDisableCmd,
		gatewaySetCmd,
		gatewayUpCmd,
		gatewaySystemUpCmd,
		gatewayApplyCompatCmd,
		gatewaySyncFirewallCompatCmd,
		gatewayDownCmd,
		gatewaySystemDownCmd,
		gatewaySystemSyncCmd,
		gatewayRollbackCompatCmd,
		gatewayCheckCmd,
		gatewayVerifyCompatCmd,
		gatewayDiffCmd,
		gatewayTestCmd,
	)
	rootCmd.AddCommand(gatewayCmd)
}
