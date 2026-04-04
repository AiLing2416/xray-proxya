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
	useIPv4 bool
	useIPv6 bool
	manualAddr string
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show sharing links for active modes",
	Long: `Display sharing links for currently enabled presets and relays.
By default, it auto-detects your public IPv4 address.

Examples:
  xray-proxya show           (Auto IPv4)
  xray-proxya show -4        (Auto IPv4)
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
			// Strict Format Validation
			isIP := net.ParseIP(manualAddr) != nil
			
			// Simple check for valid hostname characters (RFC 1123ish)
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

			// If it's a domain, attempt a lookup but don't strictly fail for LAN hostnames 
			// unless they are clearly broken.
			if !isIP {
				_, err := net.LookupHost(manualAddr)
				if err != nil {
					fmt.Printf("⚠️  Warning: Hostname '%s' could not be resolved, but will be used anyway.\n", manualAddr)
				}
			}
			targetAddrs = append(targetAddrs, manualAddr)
		} else {
			// 2. Handle protocol flags
			if useIPv6 {
				ip6 := utils.GetSmartIP(true)
				if ip6 != "" { targetAddrs = append(targetAddrs, ip6) } else { fmt.Println("⚠️ IPv6 not detected.") }
			}
			// If -4 was requested OR nothing was requested (default behavior)
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
			
			// Show Presets
			fmt.Printf("# PRESET LINKS\n")
			links := xray.GenerateLinks(cfg, ip)
			for _, l := range links { fmt.Println(l) }

			// Show Relays
			if len(cfg.CustomOutbounds) > 0 {
				fmt.Printf("\n# RELAY LINKS\n")
				for _, r := range cfg.CustomOutbounds {
					if !r.Enabled { continue }
					rLinks := xray.GenerateRelayLinks(cfg, ip, r)
					for _, l := range rLinks { fmt.Println(l) }
				}
			}
		}
	},
}

func init() {
	showCmd.Flags().BoolVarP(&useIPv4, "ipv4", "4", false, "Auto-detect and show IPv4 links")
	showCmd.Flags().BoolVarP(&useIPv6, "ipv6", "6", false, "Auto-detect and show IPv6 links")
	showCmd.Flags().StringVarP(&manualAddr, "address", "a", "", "Use a custom IP or domain name")
	
	rootCmd.AddCommand(showCmd)
}
