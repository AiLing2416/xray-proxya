package main

import (
	"fmt"
	"net"
	"os/exec"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Manage transparent proxy gateway (STAGING)",
}

var gatewayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway status",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		
		status := "Disabled"
		if cfg.Gateway.Enabled { status = "Enabled" }
		
		fmt.Printf("\n=== Gateway Status (STAGING) ===\n")
		fmt.Printf("Role:   %s\n", cfg.Role)
		fmt.Printf("Status: %s\n", status)
		fmt.Printf("Mode:   %s\n", cfg.Gateway.Mode)
		fmt.Printf("Relay:  %s\n", cfg.Gateway.RelayAlias)
		fmt.Printf("LAN:    %s\n", cfg.Gateway.LANInterface)
		fmt.Printf("Blacklist count: %d\n", len(cfg.Gateway.Blacklist))
		fmt.Printf("Blacklist IPs:   %d\n", len(cfg.Gateway.BlacklistIPs))
	},
}

var gatewayEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable gateway mode (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleGateway {
			fmt.Printf("❌ Command 'gateway %s' is only available in 'gateway' mode (Current: %s).\n", cmd.Name(), cfg.Role)
			return
		}
		cfg.Gateway.Enabled = true
		if cfg.Gateway.Mode == "" { cfg.Gateway.Mode = "tun" }
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway enabled in STAGING. Run 'apply' to commit.")
	},
}

var gatewayDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable gateway mode (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleGateway {
			fmt.Printf("❌ Command 'gateway %s' is only available in 'gateway' mode (Current: %s).\n", cmd.Name(), cfg.Role)
			return
		}
		cfg.Gateway.Enabled = false
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway disabled in STAGING. Run 'apply' to commit.")
	},
}

var gatewaySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set gateway parameters (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleGateway {
			fmt.Printf("❌ Command 'gateway %s' is only available in 'gateway' mode (Current: %s).\n", cmd.Name(), cfg.Role)
			return
		}
		
		mode, _ := cmd.Flags().GetString("mode")
		relay, _ := cmd.Flags().GetString("relay")
		lan, _ := cmd.Flags().GetString("lan")
		
		if mode != "" { cfg.Gateway.Mode = mode }
		if relay != "" { cfg.Gateway.RelayAlias = relay }
		if lan != "" { cfg.Gateway.LANInterface = lan }
		
		cfg.SaveEx(true)
		fmt.Println("✅ Gateway parameters updated in STAGING. Run 'apply' to commit.")
	},
}

var gatewaySyncFirewallCmd = &cobra.Command{
	Use:   "sync-firewall",
	Short: "Sync blacklist IPs to system nftables (Requires Root)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil { return }
		if cfg.Role != config.RoleGateway {
			fmt.Printf("❌ Command 'gateway %s' is only available in 'gateway' mode (Current: %s).\n", cmd.Name(), cfg.Role)
			return
		}

		fmt.Println("🛡️ Syncing kernel-level blacklist...")
		
		exec.Command("nft", "delete", "table", "inet", "xray_gateway").Run()
		exec.Command("nft", "add", "table", "inet", "xray_gateway").Run()
		exec.Command("nft", "add", "set", "inet", "xray_gateway", "blacklist_ips", "{ type ipv4_addr; flags interval; }").Run()
		exec.Command("nft", "add", "set", "inet", "xray_gateway", "blacklist_ips6", "{ type ipv6_addr; flags interval; }").Run()
		exec.Command("nft", "add", "chain", "inet", "xray_gateway", "prerouting", "{ type filter hook prerouting priority -300; policy accept; }").Run()
		exec.Command("nft", "add", "chain", "inet", "xray_gateway", "forward", "{ type filter hook forward priority 0; policy accept; }").Run()

		for _, ipStr := range cfg.Gateway.BlacklistIPs {
			set := "blacklist_ips"
			if net.ParseIP(ipStr).To4() == nil { set = "blacklist_ips6" }
			exec.Command("nft", "add", "element", "inet", "xray_gateway", set, "{ "+ipStr+" }").Run()
		}
		
		exec.Command("nft", "add", "rule", "inet", "xray_gateway", "prerouting", "ip daddr @blacklist_ips drop").Run()
		exec.Command("nft", "add", "rule", "inet", "xray_gateway", "forward", "ip daddr @blacklist_ips drop").Run()
		
		fmt.Println("✅ Kernel blacklist synced.")
	},
}

var gatewayBlacklistAddCmd = &cobra.Command{
	Use:   "add-blacklist [item]",
	Short: "Add domain, IP, or CIDR to blacklist (STAGING)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleGateway {
			fmt.Printf("❌ Command 'gateway %s' is only available in 'gateway' mode (Current: %s).\n", cmd.Name(), cfg.Role)
			return
		}
		
		input := args[0]
		if _, _, err := net.ParseCIDR(input); err == nil {
			addBlacklistIP(cfg, input)
		} else if ip := net.ParseIP(input); ip != nil {
			addBlacklistIP(cfg, input)
		} else {
			cfg.Gateway.Blacklist = append(cfg.Gateway.Blacklist, input)
			fmt.Printf("🔍 Resolving IPs for %s...\n", input)
			ips, _ := net.LookupIP(input)
			for _, ip := range ips { addBlacklistIP(cfg, ip.String()) }
		}
		
		cfg.SaveEx(true)
		fmt.Println("✅ Blacklist updated in STAGING. Run 'apply' to commit.")
	},
}

func addBlacklistIP(cfg *config.UserConfig, ipStr string) {
	for _, existing := range cfg.Gateway.BlacklistIPs {
		if existing == ipStr { return }
	}
	cfg.Gateway.BlacklistIPs = append(cfg.Gateway.BlacklistIPs, ipStr)
}

var gatewaySetupKernelCmd = &cobra.Command{
	Use:   "setup-kernel",
	Short: "Configure kernel parameters (Requires Root)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil { return }
		if cfg.Role != config.RoleGateway {
			fmt.Printf("❌ Command 'gateway %s' is only available in 'gateway' mode (Current: %s).\n", cmd.Name(), cfg.Role)
			return
		}
		params := [][]string{
			{"net.ipv4.ip_forward", "1"},
			{"net.ipv6.conf.all.forwarding", "1"},
			{"net.ipv4.conf.all.rp_filter", "0"},
			{"net.ipv4.conf.default.rp_filter", "0"},
		}
		for _, p := range params { exec.Command("sysctl", "-w", p[0]+"="+p[1]).Run() }
		fmt.Println("✅ Kernel parameters optimized.")
	},
}

func init() {
	gatewaySetCmd.Flags().StringP("mode", "m", "", "Gateway mode: tun or tproxy")
	gatewaySetCmd.Flags().StringP("relay", "r", "", "Relay alias to bind")
	gatewaySetCmd.Flags().StringP("lan", "l", "", "LAN interface name")
	
	gatewayCmd.AddCommand(gatewayStatusCmd, gatewayEnableCmd, gatewayDisableCmd, gatewaySetCmd, gatewayBlacklistAddCmd, gatewaySyncFirewallCmd, gatewaySetupKernelCmd)
	rootCmd.AddCommand(gatewayCmd)
}
