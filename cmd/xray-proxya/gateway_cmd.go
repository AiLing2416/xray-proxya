package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Manage transparent proxy gateway (STAGING)",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		utils.EnsureRoot()
	},
}

var gatewayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway configuration and system state",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
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
		fmt.Printf("Blacklist:   %d domains, %d IPs\n\n", len(cfg.Gateway.Blacklist), len(cfg.Gateway.BlacklistIPs))
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

		cfg.SaveEx(true)
		fmt.Println("✅ Gateway parameters updated in STAGING.")
	},
}

var gatewayBlacklistAddCmd = &cobra.Command{
	Use:   "blacklist-add [domain/ip]",
	Short: "Add a domain or IP to the gateway blacklist",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		if net.ParseIP(target) != nil || strings.Contains(target, "/") {
			cfg.Gateway.BlacklistIPs = append(cfg.Gateway.BlacklistIPs, target)
		} else {
			cfg.Gateway.Blacklist = append(cfg.Gateway.Blacklist, target)
		}
		cfg.SaveEx(true)
		fmt.Printf("✅ Added '%s' to blacklist in STAGING.\n", target)
	},
}

var gatewayBlacklistClearCmd = &cobra.Command{
	Use:   "blacklist-clear",
	Short: "Clear all domains and IPs from the gateway blacklist",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.Gateway.Blacklist = []string{}
		cfg.Gateway.BlacklistIPs = []string{}
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway blacklist CLEARED in STAGING.")
	},
}

var gatewayUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring gateway runtime rules up",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			return
		}
		if err := gateway.ApplyFirewall(cfg); err != nil {
			fmt.Printf("❌ Failed: %v\n", err)
			return
		}
		fmt.Println("✅ Gateway runtime rules are up.")
	},
}

var gatewayApplyCompatCmd = &cobra.Command{
	Use:    "apply",
	Short:  "Apply gateway runtime rules",
	Hidden: true,
	Run:    gatewayUpCmd.Run,
}

var gatewaySyncFirewallCompatCmd = &cobra.Command{
	Use:    "sync-firewall",
	Short:  "Regenerate and apply gateway runtime rules",
	Hidden: true,
	Run:    gatewayUpCmd.Run,
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
		fmt.Println("ip rule add fwmark 1 table 100 pref 100")
		fmt.Println("ip rule add fwmark 255 table main pref 10")
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
	Short: "Bring gateway runtime rules down",
	Run: func(cmd *cobra.Command, args []string) {
		gateway.CleanupFirewall()
		fmt.Println("✅ Gateway runtime rules are down.")
	},
}

var gatewayRollbackCompatCmd = &cobra.Command{
	Use:    "rollback",
	Short:  "Remove xray-proxya gateway runtime rules",
	Hidden: true,
	Run:    gatewayDownCmd.Run,
}

func init() {
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("lan", "l", "", "LAN interface name")

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
		gatewayBlacklistAddCmd,
		gatewayBlacklistClearCmd,
		gatewayUpCmd,
		gatewayApplyCompatCmd,
		gatewaySyncFirewallCompatCmd,
		gatewayDownCmd,
		gatewayRollbackCompatCmd,
		gatewayCheckCmd,
		gatewayVerifyCompatCmd,
		gatewayDiffCmd,
	)
	rootCmd.AddCommand(gatewayCmd)
}
