package main

import (
	"fmt"
	"net"
	"os"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	ipv6Subnet string
	ipv6Iface  string
	ipv6Max    int
	ipv6NDP    bool
)

var ipv6Cmd = &cobra.Command{
	Use:   "ipv6",
	Short: "Manage IPv6 block rotation and NDP settings (Requires Root)",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ IPv6 Rolling Pool requires root privileges.")
			os.Exit(1)
		}
	},
}

var ipv6StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current IPv6 configuration and detection results",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			return
		}

		fmt.Printf("\n%-15s | %-s\n", "SETTING", "VALUE")
		fmt.Println("------------------------------------------")
		state := "DISABLED"
		if cfg.IPv6Pool.Enabled {
			state = "ENABLED"
		}
		fmt.Printf("%-15s | %s\n", "Status", state)
		fmt.Printf("%-15s | %s\n", "Subnet", cfg.IPv6Pool.Subnet)
		fmt.Printf("%-15s | %s\n", "Interface", cfg.IPv6Pool.Interface)
		fmt.Printf("%-15s | %d\n", "Max Links", cfg.IPv6Pool.MaxAddresses)
		fmt.Printf("%-15s | %v\n", "Enable NDP", cfg.IPv6Pool.EnableNDP)

		fmt.Println("\n🔍 Detection Results:")
		s, i, err := utils.AutoDetectIPv6Subnet()
		if err != nil {
			fmt.Printf("❌ Auto-detection failed: %v\n", err)
		} else {
			fmt.Printf("✅ Detected Subnet: %s\n", s)
			fmt.Printf("✅ Detected Interface: %s\n", i)
		}
		fmt.Println()
	},
}

var ipv6EnableCmd = &cobra.Command{
	Use:   "enable [subnet]",
	Short: "Enable IPv6 block rotation (STAGING)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		subnet := ipv6Subnet
		if len(args) > 0 {
			subnet = args[0]
		}
		if subnet == "" {
			s, i, err := utils.AutoDetectIPv6Subnet()
			if err == nil {
				subnet = s
				if ipv6Iface == "" {
					ipv6Iface = i
				}
				fmt.Printf("📡 Auto-detected subnet: %s on interface: %s\n", subnet, ipv6Iface)
			} else {
				fmt.Println("❌ Could not auto-detect subnet. Please provide it manually.")
				return
			}
		}

		cfg.IPv6Pool.Enabled = true
		cfg.IPv6Pool.Subnet = subnet
		cfg.IPv6Pool.Interface = ipv6Iface
		cfg.IPv6Pool.MaxAddresses = ipv6Max
		cfg.IPv6Pool.EnableNDP = ipv6NDP

		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ IPv6 Block Rotation enabled in STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var ipv6DisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable IPv6 block rotation (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		cfg.IPv6Pool.Enabled = false
		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ IPv6 Block Rotation disabled in STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var ipv6TestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test if a random IP from the block is reachable (Requires root for binding/ping)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			return
		}
		if cfg.IPv6Pool.Subnet == "" {
			fmt.Println("❌ No IPv6 subnet configured.")
			return
		}

		ip, err := utils.GenerateRandomIPv6(cfg.IPv6Pool.Subnet)
		if err != nil {
			fmt.Printf("❌ Failed to generate test IP: %v\n", err)
			return
		}
		fmt.Printf("🧪 Testing reachability of %s...\n", ip)

		reachable := utils.TestIPv6Reachability(ip)
		if reachable {
			fmt.Printf("✅ IP %s is reachable directly.\n", ip)
		} else {
			fmt.Printf("⚠️  IP %s is NOT reachable. Attempting NDP configuration...\n", ip)
			if cfg.IPv6Pool.Interface == "" {
				fmt.Println("❌ Interface not configured. Cannot perform NDP setup.")
				return
			}
			err := utils.SetupIPv6Addr(ip, cfg.IPv6Pool.Interface)
			if err != nil {
				fmt.Printf("❌ NDP setup failed: %v. (Check if you have sudo permissions)\n", err)
				return
			}
			fmt.Println("⏳ Waiting for NDP propagation...")
			// Test again
			if utils.TestIPv6Reachability(ip) {
				fmt.Printf("✅ IP %s is reachable after NDP setup.\n", ip)
			} else {
				fmt.Printf("❌ IP %s is still NOT reachable after NDP setup. Block might be blocked by ISP.\n", ip)
			}
		}
	},
}

func init() {
	ipv6EnableCmd.Flags().StringVarP(&ipv6Iface, "interface", "i", "", "Interface to use")
	ipv6EnableCmd.Flags().IntVarP(&ipv6Max, "max", "m", 6, "Max addresses to keep active (FIFO rotation)")
	ipv6EnableCmd.Flags().BoolVarP(&ipv6NDP, "ndp", "n", true, "Enable auto-NDP configuration")
	ipv6EnableCmd.RegisterFlagCompletionFunc("interface", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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

	ipv6Cmd.AddCommand(ipv6StatusCmd, ipv6EnableCmd, ipv6DisableCmd, ipv6TestCmd)
	rootCmd.AddCommand(ipv6Cmd)
}
