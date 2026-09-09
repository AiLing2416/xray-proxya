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
	showRelay    string
	showOutbound string
	showGuest    string
	showAll      bool
)

var (
	getPublicIPv4Func = utils.GetPublicIPv4
	getPublicIPv6Func = utils.GetPublicIPv6
	getLocalIPFunc    = utils.GetLocalIP
)

func resolveShowIPs(cmd *cobra.Command) []string {
	if showAddr != "" {
		return []string{showAddr}
	}

	ipv4Changed := cmd != nil && cmd.Flags().Changed("ipv4")
	ipv6Changed := cmd != nil && cmd.Flags().Changed("ipv6")

	useIPv4 := false
	useIPv6 := false

	if ipv4Changed && ipv6Changed {
		useIPv4 = showIPv4
		useIPv6 = showIPv6
	} else if ipv6Changed && !ipv4Changed {
		useIPv6 = showIPv6
	} else if ipv4Changed && !ipv6Changed {
		useIPv4 = showIPv4
	} else {
		useIPv4 = true
	}

	var ips []string
	if useIPv4 {
		if ip := getPublicIPv4Func(); ip != "" {
			ips = append(ips, ip)
		}
	}
	if useIPv6 {
		if ip := getPublicIPv6Func(); ip != "" {
			ips = append(ips, ip)
		}
	}

	// Fallback to local if no public IP found, only when IPv4 was requested and IPv6 was not requested
	if len(ips) == 0 && useIPv4 && !useIPv6 {
		if local := getLocalIPFunc(); local != "" {
			ips = append(ips, local)
		}
	}

	return ips
}

func runShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("❌ Configuration not found. Please run 'init' first.")
	}

	ips := resolveShowIPs(cmd)
	if len(ips) == 0 {
		return fmt.Errorf("❌ Could not determine any IP address. Use -a to specify manually.")
	}

	targetRelay := showRelay
	if targetRelay == "" {
		targetRelay = showOutbound
	}

	showDirect := !showAll && targetRelay == "" && showGuest == ""

	for i, ip := range ips {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("\n🚀 SHARING LINKS (Address: %s)\n", ip)
		fmt.Println("============================================================")
		fmt.Printf("=== Address: %s ===\n", ip)

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

		if showAll || targetRelay != "" {
			if targetRelay != "" {
				var target *config.CustomOutbound
				for _, o := range cfg.CustomOutbounds {
					if o.Alias == targetRelay {
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
					fmt.Printf("❌ Relay '%s' not found.\n", targetRelay)
				}
			} else if len(cfg.CustomOutbounds) > 0 {
				fmt.Println("\n# ALL RELAY LINKS")
				for _, co := range cfg.CustomOutbounds {
					if !co.Enabled {
						continue
					}
					links := xray.GenerateRelayLinks(cfg, ip, co)
					for _, link := range links {
						fmt.Println(link)
					}
				}
			}
		}
	}
	fmt.Println()
	return nil
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show sharing links for active modes",
	RunE:  runShow,
}

func init() {
	showCmd.Flags().BoolVarP(&showIPv4, "ipv4", "4", true, "Use public IPv4 address")
	showCmd.Flags().BoolVarP(&showIPv6, "ipv6", "6", false, "Use public IPv6 address")
	showCmd.Flags().StringVarP(&showAddr, "address", "a", "", "Override server address/hostname in links")
	showCmd.Flags().StringVarP(&showRelay, "relay", "r", "", "Show links for specific relay node")
	showCmd.Flags().StringVarP(&showOutbound, "outbound", "o", "", "Show links for specific custom outbound (deprecated)")
	showCmd.Flags().StringVarP(&showGuest, "guest", "g", "", "Show links for specific guest user")
	showCmd.Flags().BoolVar(&showAll, "all", false, "Show all sharing links")

	showCmd.Flags().MarkHidden("outbound")

	showCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})
	showCmd.RegisterFlagCompletionFunc("outbound", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})
	showCmd.RegisterFlagCompletionFunc("guest", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	})

	rootCmd.AddCommand(showCmd)
}
