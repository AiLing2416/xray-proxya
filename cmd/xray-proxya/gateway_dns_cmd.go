package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	gatewayDNSStatusJSON bool

	dnsSetListen   string
	dnsSetPort     int
	dnsSetOff      bool
	dnsSetServers  []string
	dnsSetStrategy string
	dnsSetReset    bool
)

var gatewayDNSCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage gateway internal DNS resolution and static records (STAGING)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayDNSStatus(cmd, args)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return utils.RequireRootShell("gateway dns")
	},
}

type GatewayDNSConfigJSON struct {
	Listen   string              `json:"listen"`
	Strategy string              `json:"strategy"`
	Servers  []string            `json:"servers"`
	Records  map[string][]string `json:"records"`
}

type GatewayDNSStatusJSON struct {
	Active  *GatewayDNSConfigJSON `json:"active"`
	Staging *GatewayDNSConfigJSON `json:"staging"`
}

var gatewayDNSStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway DNS configuration",
	Args:  cobra.NoArgs,
	RunE:  runGatewayDNSStatus,
}

func toGatewayDNSConfigJSON(g *config.GatewayConfig) *GatewayDNSConfigJSON {
	if g == nil {
		return nil
	}
	strategy := g.DNSStrategy
	if strategy == "" {
		strategy = "UseIP"
	}
	records := g.DNSRecords
	if records == nil {
		records = make(map[string][]string)
	}
	return &GatewayDNSConfigJSON{
		Listen:   g.DNSListen,
		Strategy: strategy,
		Servers:  g.DNSServers,
		Records:  records,
	}
}

func runGatewayDNSStatus(cmd *cobra.Command, args []string) error {
	activeCfg, _ := config.LoadConfigEx(false)
	stagingCfg, _ := config.LoadConfigEx(true)
	if activeCfg == nil && stagingCfg == nil {
		return fmt.Errorf("❌ Failed to load gateway configuration")
	}

	if gatewayDNSStatusJSON {
		var activeJSON, stagingJSON *GatewayDNSConfigJSON
		if activeCfg != nil {
			activeJSON = toGatewayDNSConfigJSON(&activeCfg.Gateway)
		}
		if stagingCfg != nil {
			stagingJSON = toGatewayDNSConfigJSON(&stagingCfg.Gateway)
		}
		out := GatewayDNSStatusJSON{
			Active:  activeJSON,
			Staging: stagingJSON,
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("\n🛰️ GATEWAY DNS CONFIGURATION")
	fmt.Println("--------------------------------------------------")
	printSection := func(label string, cfg *config.UserConfig) {
		fmt.Printf("%s:\n", label)
		if cfg == nil {
			fmt.Println("  (not configured)")
			return
		}
		listen := cfg.Gateway.DNSListen
		if listen == "" {
			listen = "(disabled)"
		}
		strategy := cfg.Gateway.DNSStrategy
		if strategy == "" {
			strategy = "UseIP (default)"
		}
		servers := "(default built-in)"
		if len(cfg.Gateway.DNSServers) > 0 {
			servers = strings.Join(cfg.Gateway.DNSServers, ", ")
		}
		fmt.Printf("  Listen:      %s\n", listen)
		fmt.Printf("  Strategy:    %s\n", strategy)
		fmt.Printf("  Servers:     %s\n", servers)
		if len(cfg.Gateway.DNSRecords) == 0 {
			fmt.Println("  Records:     (none)")
		} else {
			fmt.Printf("  Records:     %d domain(s)\n", len(cfg.Gateway.DNSRecords))
			keys := make([]string, 0, len(cfg.Gateway.DNSRecords))
			for k := range cfg.Gateway.DNSRecords {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("    • %-26s -> %s\n", k, strings.Join(cfg.Gateway.DNSRecords[k], ", "))
			}
		}
	}

	printSection("ACTIVE", activeCfg)
	printSection("STAGING", stagingCfg)
	return nil
}

var gatewayDNSSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure gateway DNS settings in STAGING",
	Args:  cobra.NoArgs,
	RunE:  runGatewayDNSSet,
}

func runGatewayDNSSet(cmd *cobra.Command, args []string) error {
	hasChanged := false
	cmd.Flags().Visit(func(f *pflag.Flag) {
		hasChanged = true
	})
	if !hasChanged {
		return fmt.Errorf("❌ Error: No flags specified. Run 'xray-proxya gateway dns set --help' for usage.")
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}

	reset, _ := cmd.Flags().GetBool("reset")
	if reset {
		cfg.Gateway.DNSListen = ""
		cfg.Gateway.DNSStrategy = ""
		cfg.Gateway.DNSServers = nil
	}

	off, _ := cmd.Flags().GetBool("off")
	if off {
		cfg.Gateway.DNSListen = ""
	}

	if cmd.Flags().Changed("listen") {
		listen, _ := cmd.Flags().GetString("listen")
		_, _, normListen, err := config.ParseDNSListen(listen)
		if err != nil {
			return fmt.Errorf("❌ Invalid dns listen address: %w", err)
		}
		cfg.Gateway.DNSListen = normListen
	}

	if cmd.Flags().Changed("port") {
		port, _ := cmd.Flags().GetInt("port")
		if port < 1 || port > 65535 {
			return fmt.Errorf("❌ Invalid port %d: must be between 1 and 65535", port)
		}
		if cfg.Gateway.DNSListen == "" {
			cfg.Gateway.DNSListen = fmt.Sprintf("127.0.0.1:%d", port)
		} else {
			host, _, _, err := config.ParseDNSListen(cfg.Gateway.DNSListen)
			if err != nil || host == "::" {
				cfg.Gateway.DNSListen = fmt.Sprintf(":%d", port)
			} else if strings.Contains(host, ":") {
				cfg.Gateway.DNSListen = fmt.Sprintf("[%s]:%d", host, port)
			} else {
				cfg.Gateway.DNSListen = fmt.Sprintf("%s:%d", host, port)
			}
		}
	}

	if cmd.Flags().Changed("strategy") {
		strategy, _ := cmd.Flags().GetString("strategy")
		norm, ok := config.NormalizeDNSQueryStrategy(strategy)
		if !ok {
			return fmt.Errorf("❌ Invalid dns strategy %q (must be UseIP, UseIPv4, or UseIPv6)", strategy)
		}
		cfg.Gateway.DNSStrategy = norm
	}

	if cmd.Flags().Changed("servers") {
		servers, _ := cmd.Flags().GetStringSlice("servers")
		var normServers []string
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			norm, err := config.ValidateDNSServerEntry(s)
			if err != nil {
				return fmt.Errorf("❌ Invalid dns server %q: %w", s, err)
			}
			normServers = append(normServers, norm)
		}
		cfg.Gateway.DNSServers = normServers
	}

	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Println("✅ Gateway DNS parameters updated in STAGING.")
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var gatewayDNSRecordCmd = &cobra.Command{
	Use:   "record",
	Short: "Manage static A/AAAA records in STAGING",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return gatewayDNSRecordListCmd.RunE(cmd, args)
	},
}

var gatewayDNSRecordSetCmd = &cobra.Command{
	Use:   "set <domain> <ip1> [ip2...]",
	Short: "Set static A/AAAA record(s) for a domain in STAGING",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := config.NormalizeDNSRecordDomain(args[0])
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		ips, err := config.ValidateDNSRecordIPs(args[1:])
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return fmt.Errorf("❌ Failed to load staging config: %v", err)
		}
		if cfg.Gateway.DNSRecords == nil {
			cfg.Gateway.DNSRecords = make(map[string][]string)
		}
		cfg.Gateway.DNSRecords[domain] = ips
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("❌ Failed to save staging config: %w", err)
		}
		fmt.Printf("✅ Static record %s -> %s set in STAGING.\n", domain, strings.Join(ips, ", "))
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

var gatewayDNSRecordDelCmd = &cobra.Command{
	Use:               "del <domain>",
	Aliases:           []string{"rm", "remove"},
	Short:             "Remove static record for a domain in STAGING",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeDNSRecordDomains,
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := config.NormalizeDNSRecordDomain(args[0])
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return fmt.Errorf("❌ Failed to load staging config: %v", err)
		}
		if cfg.Gateway.DNSRecords == nil {
			return fmt.Errorf("❌ Record for domain %q not found in staging", domain)
		}
		if _, exists := cfg.Gateway.DNSRecords[domain]; !exists {
			return fmt.Errorf("❌ Record for domain %q not found in staging", domain)
		}
		delete(cfg.Gateway.DNSRecords, domain)
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("❌ Failed to save staging config: %w", err)
		}
		fmt.Printf("✅ Static record for %s removed in STAGING.\n", domain)
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

var gatewayDNSRecordListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List static A/AAAA records in STAGING",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return fmt.Errorf("❌ Failed to load staging config: %v", err)
		}
		if len(cfg.Gateway.DNSRecords) == 0 {
			fmt.Println("ℹ️  No static DNS records configured in STAGING.")
			return nil
		}
		fmt.Println("\n📋 STATIC DNS RECORDS (STAGING)")
		fmt.Println("--------------------------------------------------")
		keys := make([]string, 0, len(cfg.Gateway.DNSRecords))
		for k := range cfg.Gateway.DNSRecords {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  • %-30s -> %s\n", k, strings.Join(cfg.Gateway.DNSRecords[k], ", "))
		}
		return nil
	},
}

var gatewayDNSRecordClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all static DNS records in STAGING",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return fmt.Errorf("❌ Failed to load staging config: %v", err)
		}
		cfg.Gateway.DNSRecords = make(map[string][]string)
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("❌ Failed to save staging config: %w", err)
		}
		fmt.Println("✅ Cleared all static DNS records in STAGING.")
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

func completeDNSRecordDomains(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var domains []string
	for dom := range cfg.Gateway.DNSRecords {
		if strings.HasPrefix(dom, toComplete) {
			domains = append(domains, dom)
		}
	}
	sort.Strings(domains)
	return domains, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	gatewayDNSCmd.Flags().BoolVar(&gatewayDNSStatusJSON, "json", false, "Output in JSON format")
	gatewayDNSStatusCmd.Flags().BoolVar(&gatewayDNSStatusJSON, "json", false, "Output in JSON format")

	gatewayDNSSetCmd.Flags().StringVarP(&dnsSetListen, "listen", "l", "", "DNS listen address (e.g. 127.0.0.1:5353, :53)")
	gatewayDNSSetCmd.Flags().IntVarP(&dnsSetPort, "port", "p", 0, "DNS listen port (e.g. 5353)")
	gatewayDNSSetCmd.Flags().BoolVar(&dnsSetOff, "off", false, "Disable gateway DNS listener")
	gatewayDNSSetCmd.Flags().StringSliceVarP(&dnsSetServers, "servers", "v", nil, "Upstream DNS servers (e.g. 1.1.1.1, tcp://8.8.8.8:53, https://1.1.1.1/dns-query)")
	gatewayDNSSetCmd.Flags().StringVarP(&dnsSetStrategy, "strategy", "s", "", "DNS query strategy (UseIP, UseIPv4, UseIPv6)")
	gatewayDNSSetCmd.Flags().BoolVar(&dnsSetReset, "reset", false, "Reset gateway DNS listen, strategy, and servers to empty/default")

	_ = gatewayDNSSetCmd.RegisterFlagCompletionFunc("strategy", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"UseIP", "UseIPv4", "UseIPv6"}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = gatewayDNSSetCmd.RegisterFlagCompletionFunc("servers", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"1.1.1.1", "8.8.8.8", "https://1.1.1.1/dns-query", "https://dns.google/dns-query", "tls://1.1.1.1:853"}, cobra.ShellCompDirectiveNoFileComp
	})

	gatewayDNSRecordCmd.AddCommand(
		gatewayDNSRecordSetCmd,
		gatewayDNSRecordDelCmd,
		gatewayDNSRecordListCmd,
		gatewayDNSRecordClearCmd,
	)

	gatewayDNSCmd.AddCommand(
		gatewayDNSStatusCmd,
		gatewayDNSSetCmd,
		gatewayDNSRecordCmd,
	)

	gatewayCmd.AddCommand(gatewayDNSCmd)
}
