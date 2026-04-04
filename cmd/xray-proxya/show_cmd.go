package main

import (
	"fmt"
	"net"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	useIPv4      bool
	useIPv6      bool
	manualAddr   string
	showOutbound string
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show sharing links for active modes",
	Long: `Display sharing links for currently enabled presets and relays.
By default, it auto-detects your public IPv4 address.

Examples:
  xray-proxya show           (Auto IPv4, all links)
  xray-proxya show -o hk-01  (Only show links for relay 'hk-01')
  xray-proxya show -6        (Auto IPv6)
  xray-proxya show -a my.ddns.com`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			return
		}

		var targetAddrs []string

		// 1. Handle manual address first
		if manualAddr != "" {
			isIP := net.ParseIP(manualAddr) != nil
			validHost := true
			if !isIP {
				for _, r := range manualAddr {
					if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
						validHost = false
						break
					}
				}
			}
			if !isIP && !validHost {
				fmt.Printf("❌ Invalid address format: %s\n", manualAddr)
				return
			}
			if !isIP {
				_, err := net.LookupHost(manualAddr)
				if err != nil {
					fmt.Printf("⚠️  Warning: Hostname '%s' could not be resolved, but will be used anyway.\n", manualAddr)
				}
			}
			targetAddrs = append(targetAddrs, manualAddr)
		} else {
			if useIPv6 {
				ip6 := utils.GetSmartIP(true)
				if ip6 != "" { targetAddrs = append(targetAddrs, ip6) } else { fmt.Println("⚠️ IPv6 not detected.") }
			}
			if useIPv4 || (!useIPv4 && !useIPv6) {
				ip4 := utils.GetSmartIP(false)
				if ip4 != "" { targetAddrs = append(targetAddrs, ip4) } else { fmt.Println("⚠️ IPv4 not detected.") }
			}
		}

		if len(targetAddrs) == 0 {
			fmt.Println("❌ No valid address available to generate links.")
			return
		}

		for _, ip := range targetAddrs {
			fmt.Printf("\n🚀 SHARING LINKS (Address: %s)\n", ip)
			fmt.Println("============================================================")
			
			// Show Presets (Skip if specific outbound is requested)
			if showOutbound == "" {
				fmt.Printf("# PRESET LINKS\n")
				links := xray.GenerateLinks(cfg, ip)
				for _, l := range links { fmt.Println(l) }
			}

			// Show Relays
			if len(cfg.CustomOutbounds) > 0 {
				found := false
				var headerPrinted bool
				for _, r := range cfg.CustomOutbounds {
					if !r.Enabled { continue }
					if showOutbound != "" && r.Alias != showOutbound { continue }
					
					if !headerPrinted {
						fmt.Printf("\n# RELAY LINKS\n")
						headerPrinted = true
					}
					found = true
					rLinks := xray.GenerateRelayLinks(cfg, ip, r)
					for _, l := range rLinks { fmt.Println(l) }
				}
				if showOutbound != "" && !found {
					fmt.Printf("❌ Relay '%s' not found or not enabled.\n", showOutbound)
				}
			}
		}
	},
}

func init() {
	showCmd.Flags().BoolVarP(&useIPv4, "ipv4", "4", false, "Auto-detect and show IPv4 links")
	showCmd.Flags().BoolVarP(&useIPv6, "ipv6", "6", false, "Auto-detect and show IPv6 links")
	showCmd.Flags().StringVarP(&manualAddr, "address", "a", "", "Use a custom IP or domain name")
	showCmd.Flags().StringVarP(&showOutbound, "outbound", "o", "", "Only show links for a specific relay alias")
	
	// Link autocompletion for relay aliases
	showCmd.RegisterFlagCompletionFunc("outbound", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})

	rootCmd.AddCommand(showCmd)
}
