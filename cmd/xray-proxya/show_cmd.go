package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	showIPv4 bool
	showIPv6 bool
	showAddr string
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

		var ips []string
		if showAddr != "" {
			ips = []string{showAddr}
		} else {
			if showIPv4 {
				if ip := utils.GetPublicIPv4(); ip != "" { ips = append(ips, ip) }
			}
			if showIPv6 {
				if ip := utils.GetPublicIPv6(); ip != "" { ips = append(ips, ip) }
			}
			// Fallback to local if no public IP found
			if len(ips) == 0 {
				ips = []string{utils.GetLocalIP()}
			}
		}

		if len(ips) == 0 {
			fmt.Println("❌ Could not determine any IP address. Use -a to specify manually.")
			return
		}

		fmt.Printf("\n🚀 SHARING LINKS (Primary Address: %s)\n", ips[0])
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
	showCmd.Flags().BoolVarP(&showIPv4, "ipv4", "4", true, "Use public IPv4 address")
	showCmd.Flags().BoolVarP(&showIPv6, "ipv6", "6", false, "Use public IPv6 address")
	showCmd.Flags().StringVarP(&showAddr, "address", "a", "", "Override server address/hostname in links")
	rootCmd.AddCommand(showCmd)
}
