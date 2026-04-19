package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	showIPv4     bool
	showIPv6     bool
	showAddr     string
	showOutbound string
	showGuest    string
	showAll      bool
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

		ip := ips[0]
		fmt.Printf("\n🚀 SHARING LINKS (Address: %s)\n", ip)
		fmt.Println("============================================================")
		
		showDirect := !showAll && showOutbound == "" && showGuest == ""
		
		if showAll || showDirect {
			fmt.Println("# DIRECT (PRESET) LINKS")
			links := xray.GenerateLinks(cfg, ip)
			for _, link := range links {
				fmt.Println(link)
			}
		}

		if showAll || showGuest != "" {
			if showGuest != "" {
				var target *config.GuestConfig
				for _, g := range cfg.Guests {
					if g.Alias == showGuest {
						target = &g
						break
					}
				}
				if target != nil {
					fmt.Printf("\n# GUEST LINKS: %s\n", target.Alias)
					links := xray.GenerateGuestLinks(cfg, ip, target.UUID, target.Alias)
					for _, link := range links {
						fmt.Println(link)
					}
				} else {
					fmt.Printf("❌ Guest '%s' not found.\n", showGuest)
				}
			} else if len(cfg.Guests) > 0 {
				fmt.Println("\n# ALL GUEST LINKS")
				for _, g := range cfg.Guests {
					links := xray.GenerateGuestLinks(cfg, ip, g.UUID, g.Alias)
					for _, link := range links {
						fmt.Println(link)
					}
				}
			}
		}

		if showAll || showOutbound != "" {
			if showOutbound != "" {
				var target *config.CustomOutbound
				for _, o := range cfg.CustomOutbounds {
					if o.Alias == showOutbound {
						target = &o
						break
					}
				}
				if target != nil {
					fmt.Printf("\n# RELAY LINKS: %s\n", target.Alias)
					links := xray.GenerateRelayLinks(cfg, ip, *target)
					for _, link := range links {
						fmt.Println(link)
					}
				} else {
					fmt.Printf("❌ Outbound '%s' not found.\n", showOutbound)
				}
			} else if len(cfg.CustomOutbounds) > 0 {
				fmt.Println("\n# ALL RELAY LINKS")
				for _, co := range cfg.CustomOutbounds {
					if !co.Enabled { continue }
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
	showCmd.Flags().StringVarP(&showOutbound, "outbound", "o", "", "Show links for specific custom outbound")
	showCmd.Flags().StringVarP(&showGuest, "guest", "g", "", "Show links for specific guest user")
	showCmd.Flags().BoolVar(&showAll, "all", false, "Show all sharing links")

	showCmd.RegisterFlagCompletionFunc("outbound", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})
	showCmd.RegisterFlagCompletionFunc("guest", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	})

	rootCmd.AddCommand(showCmd)
}
