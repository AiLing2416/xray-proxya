package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show sharing links for active modes",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("❌ Configuration not found. Please run 'init' first.")
			return
		}

		isIPv6, _ := cmd.Flags().GetBool("ipv6")
		allIPs, _ := cmd.Flags().GetBool("all")

		var ips []string
		if allIPs {
			ips = append(ips, utils.GetSmartIP(false), utils.GetSmartIP(true))
		} else {
			ips = append(ips, utils.GetSmartIP(isIPv6))
		}

		fmt.Printf("\n🚀 SHARING LINKS (Address: %s)\n", ips[0])
		fmt.Println("============================================================")
		
		fmt.Println("# PRESET LINKS")
		for _, ip := range ips {
			links := xray.GenerateLinks(cfg, ip)
			for _, link := range links {
				fmt.Println(link)
			}
		}

		if len(cfg.CustomOutbounds) > 0 {
			fmt.Println("\n# RELAY (INBOUND) LINKS")
			for _, co := range cfg.CustomOutbounds {
				if !co.Enabled { continue }
				for _, ip := range ips {
					links := xray.GenerateRelayLinks(cfg, ip, co)
					for _, link := range links {
						fmt.Println(link)
					}
				}
			}
		}
		fmt.Println()
	},
}

func init() {
	showCmd.Flags().BoolP("ipv4", "4", true, "Use IPv4 address")
	showCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 address")
	showCmd.Flags().BoolP("all", "a", false, "Show all available IP addresses")
	rootCmd.AddCommand(showCmd)
}
