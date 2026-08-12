package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/sub"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	subModeStr  string
	subHostname string
	subPort     int
	subIface    string
	subSubnet   string
	subMax      int
	subNDP      bool
	subInstance string

	subShowGuest  string
	subShowRelay  string
	subResetGuest string
	subResetRelay string
)

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Manage subscriptions (admin, guests, relays) and standalone HTTP server",
}

const managedSubAlias = "admin"

func ensureManagedSubscription(cfg *config.UserConfig) *config.AdminSubConfig {
	if cfg == nil {
		return nil
	}
	cfg.AdminSub.Enabled = true
	if cfg.AdminSub.TargetType == "" {
		cfg.AdminSub.TargetType = "direct"
	}
	if cfg.AdminSub.Mode == "" {
		cfg.AdminSub.Mode = config.AdminSubModeFixed
	}
	if cfg.AdminSub.Token == "" {
		cfg.AdminSub.Token = utils.GenerateRandomString(24)
	}
	return &cfg.AdminSub
}

func ensureSubPortConfigured(cfg *config.UserConfig) {
	if cfg == nil {
		return
	}
	if cfg.AdminSub.Port > 0 {
		cfg.SubPort = cfg.AdminSub.Port
		return
	}
	if cfg.SubPort > 0 {
		cfg.AdminSub.Port = cfg.SubPort
		return
	}
	const preferredPort = 8443
	if utils.IsPortFree(preferredPort) {
		cfg.AdminSub.Port = preferredPort
		cfg.SubPort = preferredPort
		return
	}
	port, err := utils.GetFreePort()
	if err == nil {
		cfg.AdminSub.Port = port
		cfg.SubPort = port
	}
}

func detectOrUseIPv6Settings(cfg *config.UserConfig, ifaceOverride string, subnetOverride string, max int, ndp bool) error {
	if cfg == nil {
		return fmt.Errorf("missing config")
	}
	subnet := strings.TrimSpace(subnetOverride)
	iface := strings.TrimSpace(ifaceOverride)
	if subnet == "" {
		subnet = strings.TrimSpace(cfg.AdminSub.IPv6Rotate.Subnet)
	}
	if iface == "" {
		iface = strings.TrimSpace(cfg.AdminSub.IPv6Rotate.Interface)
	}
	if subnet == "" || iface == "" {
		detectedSubnet, detectedIface, err := utils.AutoDetectIPv6Subnet()
		if err != nil {
			return fmt.Errorf("could not auto-detect IPv6 subnet/interface; use '--subnet ... --interface ...'")
		}
		if subnet == "" {
			subnet = detectedSubnet
		}
		if iface == "" {
			iface = detectedIface
		}
	}
	cfg.AdminSub.IPv6Rotate.Subnet = subnet
	cfg.AdminSub.IPv6Rotate.Interface = iface
	if max > 0 {
		cfg.AdminSub.IPv6Rotate.MaxAddresses = max
	} else if cfg.AdminSub.IPv6Rotate.MaxAddresses <= 0 {
		cfg.AdminSub.IPv6Rotate.MaxAddresses = 6
	}
	cfg.AdminSub.IPv6Rotate.EnableNDP = ndp
	cfg.AdminSub.IPv6Rotate.Enabled = true
	return nil
}

func currentSubMode(cfg *config.UserConfig) string {
	if cfg == nil {
		return string(config.AdminSubModeFixed)
	}
	if cfg.AdminSub.Mode == "" {
		return string(config.AdminSubModeFixed)
	}
	return string(cfg.AdminSub.Mode)
}

func managedSubURL(cfg *config.UserConfig, subEntry *config.AdminSubConfig) string {
	if cfg == nil || subEntry == nil || subEntry.Token == "" {
		return ""
	}
	host := strings.TrimSpace(subEntry.Address)
	if host == "" {
		host = utils.GetSmartIP(false)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Sprintf("http://%s/sub/%s", host, subEntry.Token)
	}
	return fmt.Sprintf("http://%s/sub/%s", net.JoinHostPort(host, fmt.Sprintf("%d", cfg.AdminSub.Port)), subEntry.Token)
}

func subGuestSubURL(cfg *config.UserConfig, token string) string {
	host := strings.TrimSpace(cfg.AdminSub.Address)
	if host == "" {
		host = utils.GetSmartIP(false)
	}
	port := cfg.GuestSubPort
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Sprintf("http://%s/guest-sub/%s", host, token)
	}
	return fmt.Sprintf("http://%s/guest-sub/%s", net.JoinHostPort(host, fmt.Sprintf("%d", port)), token)
}

func customSubURL(cfg *config.UserConfig, token string) string {
	host := strings.TrimSpace(cfg.AdminSub.Address)
	if host == "" {
		host = utils.GetSmartIP(false)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Sprintf("http://%s/sub/%s", host, token)
	}
	return fmt.Sprintf("http://%s/sub/%s", net.JoinHostPort(host, fmt.Sprintf("%d", cfg.AdminSub.Port)), token)
}

func completeNetworkInterfaces(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Name != "" {
			names = append(names, iface.Name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func completeGuestAliases(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	res := []string{"all"}
	for _, g := range cfg.Guests {
		res = append(res, g.Alias)
	}
	return res, cobra.ShellCompDirectiveNoFileComp
}

func completeRelayAliases(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	res := []string{"all"}
	for _, co := range cfg.CustomOutbounds {
		res = append(res, co.Alias)
	}
	return res, cobra.ShellCompDirectiveNoFileComp
}

func reconcileSubscriptions(cfg *config.UserConfig) bool {
	changed := false

	// 1. Reconcile Guest tokens
	for i := range cfg.Guests {
		if cfg.Guests[i].SubToken == "" {
			cfg.Guests[i].SubToken = utils.GenerateRandomString(24)
			changed = true
		}
	}

	// 2. Reconcile Relay (Outbound) subscriptions
	activeRelays := make(map[string]bool)
	for _, r := range cfg.CustomOutbounds {
		activeRelays[r.Alias] = true
	}

	// Remove custom subs for deleted relays
	var newSubs []config.Subscription
	for _, s := range cfg.Subscriptions {
		if s.TargetType == "outbound" {
			if activeRelays[s.TargetAlias] {
				newSubs = append(newSubs, s)
			} else {
				changed = true
			}
		} else {
			newSubs = append(newSubs, s)
		}
	}

	// Add missing custom subs for active relays
	for alias := range activeRelays {
		found := false
		for _, s := range newSubs {
			if s.TargetType == "outbound" && s.TargetAlias == alias {
				found = true
				break
			}
		}
		if !found {
			newSubs = append(newSubs, config.Subscription{
				Alias:       alias,
				TargetType:  "outbound",
				TargetAlias: alias,
				Token:       utils.GenerateRandomString(24),
			})
			changed = true
		}
	}
	cfg.Subscriptions = newSubs

	return changed
}

// --- Per-instance service configuration ---

const defaultSubInstance = "default"

func subInstancePath(name string) (string, error) {
	if !systemdInstanceName.MatchString(name) {
		return "", fmt.Errorf("invalid subscription instance %q", name)
	}
	return filepath.Join(config.GetConfigDir(), "subscriptions", name+".json"), nil
}

func ensureSubInstance(name string) error {
	path, err := subInstancePath(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect subscription instance %s: %w", name, err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("load active configuration: %w", err)
	}
	if !cfg.AdminSub.Enabled || cfg.AdminSub.Token == "" || cfg.AdminSub.Port <= 0 {
		return fmt.Errorf("admin subscription is not configured; use 'sub enable', apply, then retry")
	}
	port := cfg.AdminSub.Port
	guestPort := cfg.GuestSubPort
	if name != defaultSubInstance {
		port, err = xray.GetFreePort()
		if err != nil {
			return fmt.Errorf("allocate listener port for %s: %w", name, err)
		}
		guestPort = 0
	}
	instance := config.SubscriptionServiceConfig{
		Listen:    "127.0.0.1",
		Port:      port,
		GuestBind: cfg.GuestSubBind,
		GuestPort: guestPort,
		AdminSub:  cfg.AdminSub,
	}
	data, err := json.MarshalIndent(instance, "", "  ")
	if err != nil {
		return fmt.Errorf("encode subscription instance: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create subscription instance directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write subscription instance %s: %w", name, err)
	}
	return nil
}

func loadSubInstance(name string) (config.SubscriptionServiceConfig, error) {
	path, err := subInstancePath(name)
	if err != nil {
		return config.SubscriptionServiceConfig{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config.SubscriptionServiceConfig{}, fmt.Errorf("read subscription instance %s: %w", name, err)
	}
	var instance config.SubscriptionServiceConfig
	if err := json.Unmarshal(data, &instance); err != nil {
		return config.SubscriptionServiceConfig{}, fmt.Errorf("decode subscription instance %s: %w", name, err)
	}
	if instance.Listen == "" {
		instance.Listen = "127.0.0.1"
	}
	if instance.GuestPort > 0 && instance.GuestBind == "" {
		instance.GuestBind = "127.0.0.1"
	}
	return instance, nil
}

var subEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable the default subscription configuration in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			fmt.Println("❌ Error: Xray-Proxya has not been initialized. Please run 'xray-proxya init' first.")
			return
		}

		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Printf("❌ Failed to load staging configuration: %v\n", err)
			return
		}
		reconcileSubscriptions(cfg)
		ensureManagedSubscription(cfg)
		ensureSubPortConfigured(cfg)
		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to save staging configuration: %v\n", err)
			return
		}
		fmt.Println("✅ Default subscription enabled in STAGING. Run 'apply', then 'service start xray-proxya-sub@default'.")
	},
}

var subDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable the default subscription configuration in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Printf("❌ Failed to load staging configuration: %v\n", err)
			return
		}
		cfg.AdminSub.Enabled = false
		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to save staging configuration: %v\n", err)
			return
		}
		fmt.Println("✅ Default subscription disabled in STAGING. Stop its instance explicitly with service stop xray-proxya-sub@default.")
	},
}

var subModeCmd = &cobra.Command{
	Use:   "mode",
	Short: "Configure subscription server mode and settings (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		subEntry := ensureManagedSubscription(cfg)
		ensureSubPortConfigured(cfg)

		changed := false

		if cmd.Flags().Changed("mode") {
			switch subModeStr {
			case "fixed":
				cfg.AdminSub.Mode = config.AdminSubModeFixed
				cfg.AdminSub.IPv6Rotate.Enabled = false
				changed = true
			case "ipv6-rotate":
				cfg.AdminSub.Mode = config.AdminSubModeIPv6Rotate
				cfg.AdminSub.IPv6Rotate.Enabled = true
				changed = true
			default:
				fmt.Println("❌ Mode must be 'fixed' or 'ipv6-rotate'.")
				return
			}
		}

		if cmd.Flags().Changed("hostname") {
			subEntry.Address = subHostname
			changed = true
		}
		if cmd.Flags().Changed("port") {
			cfg.AdminSub.Port = subPort
			cfg.SubPort = subPort
			changed = true
		}
		if cmd.Flags().Changed("interface") {
			cfg.AdminSub.IPv6Rotate.Interface = subIface
			changed = true
		}
		if cmd.Flags().Changed("subnet") {
			cfg.AdminSub.IPv6Rotate.Subnet = subSubnet
			changed = true
		}
		if cmd.Flags().Changed("max") {
			cfg.AdminSub.IPv6Rotate.MaxAddresses = subMax
			changed = true
		}
		if cmd.Flags().Changed("ndp") {
			cfg.AdminSub.IPv6Rotate.EnableNDP = subNDP
			changed = true
		}

		if !changed {
			subShowCmd.Run(cmd, args)
			return
		}

		if cfg.AdminSub.Mode == config.AdminSubModeIPv6Rotate {
			if err := detectOrUseIPv6Settings(cfg, subIface, subSubnet, subMax, subNDP); err != nil {
				fmt.Printf("❌ %v\n", err)
				return
			}
		}

		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ Admin subscription settings updated in STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var subShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show subscription URLs and details",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		if reconcileSubscriptions(cfg) {
			cfg.SaveEx(true)
		}

		guestFlagPassed := cmd.Flags().Changed("guest")
		relayFlagPassed := cmd.Flags().Changed("relay")

		if !guestFlagPassed && !relayFlagPassed {
			if cfg.AdminSub.Enabled && cfg.AdminSub.Token != "" {
				subEntry := &cfg.AdminSub
				mode := currentSubMode(cfg)
				address := subEntry.Address
				if address == "" {
					address = "(auto)"
				}
				fmt.Printf("\n--- Admin Subscription ---\n")
				fmt.Printf("Alias: %s\n", managedSubAlias)
				fmt.Printf("Mode: %s\n", mode)
				fmt.Printf("Port: %d\n", cfg.AdminSub.Port)
				fmt.Printf("Hostname/Address Override: %s\n", address)
				fmt.Printf("URL: %s\n", managedSubURL(cfg, subEntry))
				fmt.Printf("Token Path: /sub/%s\n", subEntry.Token)
				if mode == string(config.AdminSubModeIPv6Rotate) {
					fmt.Printf("IPv6 Subnet: %s\n", cfg.AdminSub.IPv6Rotate.Subnet)
					fmt.Printf("Interface: %s\n", cfg.AdminSub.IPv6Rotate.Interface)
					fmt.Printf("Rotation Limit: %d\n", cfg.AdminSub.IPv6Rotate.MaxAddresses)
					fmt.Printf("NDP: %v\n", cfg.AdminSub.IPv6Rotate.EnableNDP)
				}
			} else {
				fmt.Println("ℹ️  No managed admin subscription found. Run 'sub mode --mode fixed' to configure.")
			}

			fmt.Printf("\n--- Guest Subscriptions ---\n")
			if len(cfg.Guests) == 0 {
				fmt.Println("ℹ️  No guests configured.")
			} else {
				for _, g := range cfg.Guests {
					fmt.Printf("Guest: %-15s URL: %s\n", g.Alias, subGuestSubURL(cfg, g.SubToken))
				}
			}

			fmt.Printf("\n--- Relay Subscriptions ---\n")
			outboundSubs := []config.Subscription{}
			for _, s := range cfg.Subscriptions {
				if s.TargetType == "outbound" {
					outboundSubs = append(outboundSubs, s)
				}
			}
			if len(outboundSubs) == 0 {
				fmt.Println("ℹ️  No relay subscriptions found.")
			} else {
				for _, s := range outboundSubs {
					fmt.Printf("Relay: %-15s URL: %s\n", s.TargetAlias, customSubURL(cfg, s.Token))
				}
			}
			fmt.Println()
			return
		}

		if guestFlagPassed {
			fmt.Printf("\n--- Guest Subscriptions ---\n")
			if strings.ToLower(subShowGuest) == "all" || subShowGuest == "" {
				if len(cfg.Guests) == 0 {
					fmt.Println("ℹ️  No guests configured.")
				} else {
					for _, g := range cfg.Guests {
						fmt.Printf("Guest: %-15s URL: %s\n", g.Alias, subGuestSubURL(cfg, g.SubToken))
					}
				}
			} else {
				var target *config.GuestConfig
				for i := range cfg.Guests {
					if cfg.Guests[i].Alias == subShowGuest {
						target = &cfg.Guests[i]
						break
					}
				}
				if target == nil {
					fmt.Printf("❌ Guest '%s' not found.\n", subShowGuest)
				} else {
					fmt.Printf("Guest: %-15s URL: %s\n", target.Alias, subGuestSubURL(cfg, target.SubToken))
				}
			}
			fmt.Println()
		}

		if relayFlagPassed {
			fmt.Printf("\n--- Relay Subscriptions ---\n")
			if strings.ToLower(subShowRelay) == "all" || subShowRelay == "" {
				outboundSubs := []config.Subscription{}
				for _, s := range cfg.Subscriptions {
					if s.TargetType == "outbound" {
						outboundSubs = append(outboundSubs, s)
					}
				}
				if len(outboundSubs) == 0 {
					fmt.Println("ℹ️  No relay subscriptions found.")
				} else {
					for _, s := range outboundSubs {
						fmt.Printf("Relay: %-15s URL: %s\n", s.TargetAlias, customSubURL(cfg, s.Token))
					}
				}
			} else {
				var target *config.Subscription
				for i := range cfg.Subscriptions {
					if cfg.Subscriptions[i].TargetType == "outbound" && cfg.Subscriptions[i].TargetAlias == subShowRelay {
						target = &cfg.Subscriptions[i]
						break
					}
				}
				if target == nil {
					fmt.Printf("❌ Relay '%s' subscription not found.\n", subShowRelay)
				} else {
					fmt.Printf("Relay: %-15s URL: %s\n", target.TargetAlias, customSubURL(cfg, target.Token))
				}
			}
			fmt.Println()
		}
	},
}

var subResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset subscription configuration and generate a new access token (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		reconcileSubscriptions(cfg)

		guestFlagPassed := cmd.Flags().Changed("guest")
		relayFlagPassed := cmd.Flags().Changed("relay")

		if !guestFlagPassed && !relayFlagPassed {
			subEntry := ensureManagedSubscription(cfg)
			subEntry.Token = utils.GenerateRandomString(24)
			if err := cfg.SaveEx(true); err == nil {
				fmt.Println("✅ Admin subscription reset/token rotated in STAGING.")
				fmt.Printf("🔗 New Path: /sub/%s\n", subEntry.Token)
				fmt.Println("🚀 Run 'apply' to commit changes.")
			}
			return
		}

		changed := false

		if guestFlagPassed {
			if strings.ToLower(subResetGuest) == "all" || subResetGuest == "" {
				if len(cfg.Guests) == 0 {
					fmt.Println("ℹ️  No guests configured.")
				} else {
					for i := range cfg.Guests {
						cfg.Guests[i].SubToken = utils.GenerateRandomString(24)
					}
					changed = true
					fmt.Println("✅ Reset subscription tokens for all guests in STAGING.")
				}
			} else {
				found := false
				for i := range cfg.Guests {
					if cfg.Guests[i].Alias == subResetGuest {
						cfg.Guests[i].SubToken = utils.GenerateRandomString(24)
						found = true
						changed = true
						fmt.Printf("✅ Reset subscription token for guest '%s' in STAGING.\n", subResetGuest)
						break
					}
				}
				if !found {
					fmt.Printf("❌ Guest '%s' not found.\n", subResetGuest)
				}
			}
		}

		if relayFlagPassed {
			if strings.ToLower(subResetRelay) == "all" || subResetRelay == "" {
				relayResetCount := 0
				for i := range cfg.Subscriptions {
					if cfg.Subscriptions[i].TargetType == "outbound" {
						cfg.Subscriptions[i].Token = utils.GenerateRandomString(24)
						relayResetCount++
					}
				}
				if relayResetCount == 0 {
					fmt.Println("ℹ️  No relay subscriptions found.")
				} else {
					changed = true
					fmt.Println("✅ Reset subscription tokens for all relays in STAGING.")
				}
			} else {
				found := false
				for i := range cfg.Subscriptions {
					if cfg.Subscriptions[i].TargetType == "outbound" && cfg.Subscriptions[i].TargetAlias == subResetRelay {
						cfg.Subscriptions[i].Token = utils.GenerateRandomString(24)
						found = true
						changed = true
						fmt.Printf("✅ Reset subscription token for relay '%s' in STAGING.\n", subResetRelay)
						break
					}
				}
				if !found {
					fmt.Printf("❌ Relay '%s' subscription not found.\n", subResetRelay)
				}
			}
		}

		if changed {
			if err := cfg.SaveEx(true); err == nil {
				fmt.Println("🚀 Run 'apply' to commit changes.")
			}
		}
	},
}

var subRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Run one subscription instance in the foreground",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		instance, err := loadSubInstance(subInstance)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			return
		}
		if instance.AdminSub.Mode == config.AdminSubModeIPv6Rotate && !utils.IsRoot() {
			fmt.Println("❌ IPv6 Rolling Pool requires root privileges.")
			return
		}
		if instance.Port <= 1024 && !utils.IsRoot() {
			fmt.Println("❌ Listening on ports <= 1024 requires root privileges.")
			return
		}
		if err := sub.StartSubServer(instance); err != nil {
			fmt.Printf("❌ Failed: %v\n", err)
		}
	},
}

var subEnsureInstanceCmd = &cobra.Command{
	Use:    "ensure-instance <name>",
	Short:  "Create a subscription instance configuration if it is missing",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ensureSubInstance(args[0])
	},
}

func init() {
	subModeCmd.Flags().StringVarP(&subModeStr, "mode", "m", "", "Subscription server mode ('fixed' or 'ipv6-rotate')")
	subModeCmd.Flags().StringVarP(&subHostname, "hostname", "H", "", "Override external domain/hostname in subscription links")
	subModeCmd.Flags().IntVarP(&subPort, "port", "p", 0, "Subscription HTTP port")
	subModeCmd.Flags().StringVarP(&subIface, "interface", "i", "", "IPv6 interface for rotate mode")
	subModeCmd.Flags().StringVar(&subSubnet, "subnet", "", "IPv6 subnet for rotate mode")
	subModeCmd.Flags().IntVar(&subMax, "max", 0, "Max active rotated IPv6 addresses")
	subModeCmd.Flags().BoolVarP(&subNDP, "ndp", "n", true, "Enable NDP while rotating IPv6 addresses")

	subModeCmd.RegisterFlagCompletionFunc("interface", completeNetworkInterfaces)
	subModeCmd.RegisterFlagCompletionFunc("mode", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"fixed", "ipv6-rotate"}, cobra.ShellCompDirectiveNoFileComp
	})

	subShowCmd.Flags().StringVarP(&subShowGuest, "guest", "g", "", "Show guest subscription URL(s) (use 'all' or empty for all guests)")
	subShowCmd.Flags().StringVarP(&subShowRelay, "relay", "r", "", "Show relay subscription URL(s) (use 'all' or empty for all relays)")
	subShowCmd.RegisterFlagCompletionFunc("guest", completeGuestAliases)
	subShowCmd.RegisterFlagCompletionFunc("relay", completeRelayAliases)

	subResetCmd.Flags().StringVarP(&subResetGuest, "guest", "g", "", "Reset guest subscription URL token(s) (use 'all' or empty for all guests)")
	subResetCmd.Flags().StringVarP(&subResetRelay, "relay", "r", "", "Reset relay subscription URL token(s) (use 'all' or empty for all relays)")
	subResetCmd.RegisterFlagCompletionFunc("guest", completeGuestAliases)
	subResetCmd.RegisterFlagCompletionFunc("relay", completeRelayAliases)

	subRunCmd.Flags().StringVar(&subInstance, "instance", defaultSubInstance, "subscription instance name")

	subCmd.AddCommand(subEnableCmd, subDisableCmd, subModeCmd, subShowCmd, subResetCmd, subRunCmd, subEnsureInstanceCmd)
	rootCmd.AddCommand(subCmd)
}
