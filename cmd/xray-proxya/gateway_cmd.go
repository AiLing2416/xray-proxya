package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"

	"github.com/spf13/cobra"
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Manage transparent proxy gateway (STAGING)",
}

var gatewayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway configuration and system state",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		fmt.Println("\n🛰️ GATEWAY CONFIGURATION (STAGING)")
		fmt.Println("--------------------------------------------------")
		localState := "DISABLED"; if cfg.Gateway.LocalEnabled { localState = "ENABLED" }
		lanState := "DISABLED"; if cfg.Gateway.LANEnabled { lanState = "ENABLED" }
		fmt.Printf("Local Proxy: %s\n", localState)
		fmt.Printf("LAN Gateway: %s\n", lanState)
		fmt.Printf("Mode:        %s\n", cfg.Gateway.Mode)
		fmt.Printf("Relay:       %s\n", cfg.Gateway.RelayAlias)
		fmt.Printf("LAN Iface:   %s\n", cfg.Gateway.LANInterface)
		fmt.Printf("Blacklist:   %d domains, %d IPs\n\n", len(cfg.Gateway.Blacklist), len(cfg.Gateway.BlacklistIPs))
	},
}

var gatewayEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Turn on transparent gateway (local & lan) in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.LocalEnabled = true
		cfg.Gateway.LANEnabled = true
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway (Local & LAN) ENABLED in STAGING. Run 'apply' to commit.")
	},
}

var gatewayDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Turn off transparent gateway (local & lan) in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.LocalEnabled = false
		cfg.Gateway.LANEnabled = false
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway (Local & LAN) DISABLED in STAGING. Run 'apply' to commit.")
	},
}

var gatewayLocalEnableCmd = &cobra.Command{
	Use:   "local-enable",
	Short: "Enable local machine transparent proxy in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.LocalEnabled = true
		cfg.SaveEx(true)
		fmt.Println("✅ Local transparent proxy ENABLED in STAGING.")
	},
}

var gatewayLocalDisableCmd = &cobra.Command{
	Use:   "local-disable",
	Short: "Disable local machine transparent proxy in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.LocalEnabled = false
		cfg.SaveEx(true)
		fmt.Println("✅ Local transparent proxy DISABLED in STAGING.")
	},
}

var gatewayLANEnableCmd = &cobra.Command{
	Use:   "lan-enable",
	Short: "Enable LAN gateway (IP forwarding) in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.LANEnabled = true
		cfg.SaveEx(true)
		fmt.Println("✅ LAN gateway ENABLED in STAGING.")
	},
}

var gatewayLANDisableCmd = &cobra.Command{
	Use:   "lan-disable",
	Short: "Disable LAN gateway in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.LANEnabled = false
		cfg.SaveEx(true)
		fmt.Println("✅ LAN gateway DISABLED in STAGING.")
	},
}

var gatewaySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure gateway parameters",
	Run: func(cmd *cobra.Command, args []string) {
		mode, _ := cmd.Flags().GetString("mode")
		relay, _ := cmd.Flags().GetString("relay")
		lan, _ := cmd.Flags().GetString("lan")
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }

		if mode != "" { cfg.Gateway.Mode = mode }
		if relay != "" { cfg.Gateway.RelayAlias = relay }
		if lan != "" { cfg.Gateway.LANInterface = lan }

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
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
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
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		cfg.Gateway.Blacklist = []string{}
		cfg.Gateway.BlacklistIPs = []string{}
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway blacklist CLEARED in STAGING.")
	},
}

var gatewaySyncFirewallCmd = &cobra.Command{
	Use:   "sync-firewall",
	Short: "Regenerate and apply NFTables rules",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig(); if cfg == nil { return }
		if err := gateway.SyncFirewall(cfg); err != nil {
			fmt.Printf("❌ Failed to sync firewall: %v\n", err)
		} else {
			fmt.Println("✅ Firewall rules synchronized.")
		}
	},
}

var gatewaySetupKernelCmd = &cobra.Command{
	Use:   "setup-kernel",
	Short: "Enable IP forwarding and required kernel modules",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔧 Optimizing kernel for gateway...")
		exec.Command("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1").Run()
		fmt.Println("✅ Kernel parameters optimized.")
	},
}

func init() {
	gatewaySetCmd.Flags().StringP("mode", "m", "", "Gateway mode: tun or tproxy")
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("lan", "l", "", "LAN interface name")
	
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
		gatewaySyncFirewallCmd, 
		gatewaySetupKernelCmd,
	)
	rootCmd.AddCommand(gatewayCmd)
}
