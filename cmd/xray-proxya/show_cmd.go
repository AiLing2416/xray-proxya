package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	ipv4         string
	ipv6         string
	showOutbound string
	showDirect   bool
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show sharing links for active modes",
	Long:  `Display sharing links. Use --outbound to show links routed through a specific node.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			return
		}

		ip := ipv4
		if ip == "" { ip = utils.GetSmartIP(false) }
		if ip == "" { ip = utils.GetSmartIP(true) }

		if showOutbound != "" {
			var relay *config.CustomOutbound
			for _, co := range cfg.CustomOutbounds {
				if co.Alias == showOutbound {
					relay = &co
					break
				}
			}
			if relay == nil {
				fmt.Printf("❌ Outbound alias '%s' not found.\n", showOutbound)
				return
			}
			links := xray.GenerateRelayLinks(cfg, ip, *relay)
			for _, l := range links { fmt.Println(l) }
			return
		}

		// Show Presets
		fmt.Printf("# PRESET LINKS (IP: %s)\n", ip)
		links := xray.GenerateLinks(cfg, ip)
		for _, l := range links { fmt.Println(l) }

		// Show Relays
		if len(cfg.CustomOutbounds) > 0 {
			fmt.Printf("\n# RELAY LINKS\n")
			for _, r := range cfg.CustomOutbounds {
				if !r.Enabled { continue }
				rLinks := xray.GenerateRelayLinks(cfg, ip, r)
				for _, l := range rLinks {
					fmt.Println(l)
				}
			}
		}
	},
}

func init() {
	showCmd.Flags().StringVarP(&ipv4, "ipv4", "4", "", "Specify IPv4 address")
	showCmd.Flags().StringVarP(&ipv6, "ipv6", "6", "", "Specify IPv6 address")
	showCmd.Flags().StringVarP(&showOutbound, "outbound", "o", "", "Show links routed through this outbound alias")
	showCmd.Flags().BoolVarP(&showDirect, "direct", "d", true, "Show direct outbound links (default)")
	rootCmd.AddCommand(showCmd)
}
