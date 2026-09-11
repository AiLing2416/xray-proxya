package main

import (
	"fmt"
	"net"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/endpoint"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

const showDivider = "==========================================================="

func formatAddressDisplay(rawAddr string) (addrType string, displayAddr string) {
	addr := strings.TrimSpace(rawAddr)
	unbracketed := strings.Trim(addr, "[]")
	if parsed := net.ParseIP(unbracketed); parsed != nil {
		if parsed.To4() != nil {
			return "IP", parsed.String()
		}
		return "IP", fmt.Sprintf("[%s]", parsed.String())
	}
	return "Hostname", addr
}

var (
	showEndpoint string = "default"
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

func resolveEndpointAddrs(cfg *config.UserConfig, name string) ([]string, error) {
	if cfg == nil || cfg.Endpoints == nil {
		return nil, fmt.Errorf("endpoint '%s' not found", name)
	}
	ep, ok := cfg.Endpoints[name]
	if !ok {
		return endpoint.Resolve(cfg, name)
	}
	if ep.Type == config.EndpointTypeAuto {
		var ip string
		if strings.EqualFold(ep.Family, "v6") {
			ip = getPublicIPv6Func()
		} else {
			ip = getPublicIPv4Func()
			if ip == "" {
				ip = getLocalIPFunc()
			}
		}
		if ip == "" {
			return nil, fmt.Errorf("failed to detect public IP for auto endpoint '%s'", name)
		}
		return []string{ip}, nil
	}
	return endpoint.Resolve(cfg, name)
}

func resolveShowIPs(cmd *cobra.Command, optionalCfg ...*config.UserConfig) []string {
	if addr := strings.TrimSpace(showAddr); addr != "" {
		unbracketed := strings.Trim(addr, "[]")
		if parsed := net.ParseIP(unbracketed); parsed != nil {
			return []string{parsed.String()}
		}
		return []string{addr}
	}

	endpointChanged := cmd != nil && cmd.Flags().Changed("endpoint")
	ipv4Changed := cmd != nil && cmd.Flags().Changed("ipv4")
	ipv6Changed := cmd != nil && cmd.Flags().Changed("ipv6")

	var cfg *config.UserConfig
	if len(optionalCfg) > 0 && optionalCfg[0] != nil {
		cfg = optionalCfg[0]
	} else {
		cfg, _ = config.LoadConfig()
	}

	if cfg != nil && len(cfg.Endpoints) > 0 {
		if ipv6Changed && !ipv4Changed && !endpointChanged {
			// Explicit -6 without -4 and without --endpoint
			var v6EpName string
			for name, ep := range cfg.Endpoints {
				if ep.Type == config.EndpointTypeAuto && strings.EqualFold(ep.Family, "v6") {
					v6EpName = name
					break
				}
			}
			if v6EpName != "" {
				if addrs, err := resolveEndpointAddrs(cfg, v6EpName); err == nil && len(addrs) > 0 {
					return addrs
				}
			} else if defEp, ok := cfg.Endpoints["default"]; ok && defEp.Type == config.EndpointTypeAuto {
				tempCfg := *cfg
				tempEndpoints := make(map[string]config.EndpointConfig, len(cfg.Endpoints))
				for k, v := range cfg.Endpoints {
					tempEndpoints[k] = v
				}
				tempDef := defEp
				tempDef.Family = "v6"
				tempEndpoints["default"] = tempDef
				tempCfg.Endpoints = tempEndpoints
				if addrs, err := resolveEndpointAddrs(&tempCfg, "default"); err == nil && len(addrs) > 0 {
					return addrs
				}
			}
			if ip := getPublicIPv6Func(); ip != "" {
				return []string{ip}
			}
			return nil
		}

		if ipv4Changed && ipv6Changed && !endpointChanged {
			// Explicit dual stack -4 and -6 without --endpoint
			var ips []string
			if ip := getPublicIPv4Func(); ip != "" {
				ips = append(ips, ip)
			}
			if ip := getPublicIPv6Func(); ip != "" {
				ips = append(ips, ip)
			}
			if len(ips) > 0 {
				return ips
			}
		}

		epName := showEndpoint
		if epName == "" {
			epName = "default"
		}
		addrs, err := resolveEndpointAddrs(cfg, epName)
		if err == nil && len(addrs) > 0 {
			return addrs
		}
		if endpointChanged {
			return nil
		}
	}

	if endpointChanged {
		return nil
	}

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
	defer func() {
		if f := cmd.Flags().Lookup("endpoint"); f != nil {
			f.Changed = false
		}
		showEndpoint = "default"
	}()

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("❌ Configuration not found. Please run 'init' first.")
	}

	ips := resolveShowIPs(cmd, cfg)
	if len(ips) == 0 {
		return fmt.Errorf("❌ Could not determine any IP address. Use -a to specify manually.")
	}

	targetRelay := showRelay
	if targetRelay == "" {
		targetRelay = showOutbound
	}

	showDirect := !showAll && targetRelay == "" && showGuest == ""

	first := true
	printGroup := func(target string, addr string, links []string) {
		if showAll && len(links) == 0 {
			return
		}
		if !first {
			fmt.Println()
		}
		first = false

		addrType, displayAddr := formatAddressDisplay(addr)
		fmt.Printf("Sharing Links for %s, Using %s %s\n", target, addrType, displayAddr)
		fmt.Println(showDivider)
		for _, link := range links {
			fmt.Println(link)
		}
	}

	for _, ip := range ips {
		if showAll || showDirect {
			links := xray.GenerateLinks(cfg, ip)
			printGroup("Admin", ip, links)
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
					links := xray.GenerateGuestLinks(cfg, ip, target.UUID, target.Alias)
					printGroup("Guest "+target.Alias, ip, links)
				} else {
					return fmt.Errorf("❌ Guest '%s' not found.", showGuest)
				}
			} else if len(cfg.Guests) > 0 {
				for _, g := range cfg.Guests {
					links := xray.GenerateGuestLinks(cfg, ip, g.UUID, g.Alias)
					printGroup("Guest "+g.Alias, ip, links)
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
					links := xray.GenerateRelayLinks(cfg, ip, *target)
					printGroup("Relay "+target.Alias, ip, links)
				} else {
					return fmt.Errorf("❌ Relay '%s' not found.", targetRelay)
				}
			} else if len(cfg.CustomOutbounds) > 0 {
				for _, co := range cfg.CustomOutbounds {
					if !co.Enabled {
						continue
					}
					links := xray.GenerateRelayLinks(cfg, ip, co)
					printGroup("Relay "+co.Alias, ip, links)
				}
			}
		}
	}
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
	showCmd.Flags().StringVarP(&showEndpoint, "endpoint", "e", "default", "Endpoint to use for node addresses")
	showCmd.RegisterFlagCompletionFunc("endpoint", completeEndpointNames)

	rootCmd.AddCommand(showCmd)
}
