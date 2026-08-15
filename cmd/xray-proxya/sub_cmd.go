package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/sub"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

const defaultSubInstance = "default"
const managedSubAlias = "admin"

var (
	subListen, subAddress, subToken, subTargetType, subTargetAlias, subRotation, subInstance string
	subPort                                                                                  int
	subShowGuest, subShowRelay, subResetGuest, subResetRelay                                 string
)

var subCmd = &cobra.Command{Use: "sub", Short: "Configure subscriptions; systemd controls their lifecycle"}

func requireServerSubscription(cfg *config.UserConfig) error {
	if cfg == nil || cfg.Role != config.RoleServer {
		return fmt.Errorf("subscription services can run only on a Server")
	}
	return nil
}

func ensureManagedSubscription(cfg *config.UserConfig) *config.AdminSubConfig {
	return ensureSubscriptionInstance(cfg, defaultSubInstance)
}

func ensureSubscriptionInstance(cfg *config.UserConfig, instance string) *config.AdminSubConfig {
	if cfg == nil {
		return nil
	}
	if cfg.SubscriptionInstances == nil {
		cfg.SubscriptionInstances = make(map[string]config.AdminSubConfig)
	}
	entry, ok := cfg.SubscriptionInstances[instance]
	if !ok {
		if instance == defaultSubInstance && cfg.AdminSub.Token != "" {
			entry = cfg.AdminSub
		} else {
			entry = config.AdminSubConfig{}
		}
	}
	if entry.TargetType == "" {
		entry.TargetType = "direct"
	}
	if entry.Token == "" {
		entry.Token = utils.GenerateRandomString(24)
	}
	if entry.Listen == "" {
		entry.Listen = "127.0.0.1"
	}
	if entry.Port <= 0 {
		if instance == defaultSubInstance && cfg.SubPort > 0 {
			entry.Port = cfg.SubPort
		} else {
			const preferredPort = 8443
			if utils.IsPortFree(preferredPort) {
				entry.Port = preferredPort
			} else if port, err := utils.GetFreePort(); err == nil {
				entry.Port = port
			}
		}
	}
	cfg.SubscriptionInstances[instance] = entry
	if instance == defaultSubInstance {
		cfg.AdminSub = entry
		cfg.SubPort = entry.Port
	}
	return &entry
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
	} else if port, err := utils.GetFreePort(); err == nil {
		cfg.AdminSub.Port = port
	}
	cfg.SubPort = cfg.AdminSub.Port
}

func managedSubURL(cfg *config.UserConfig, entry *config.AdminSubConfig) string {
	if cfg == nil || entry == nil || entry.Token == "" {
		return ""
	}
	host := strings.TrimSpace(entry.Address)
	if host == "" {
		host = utils.GetSmartIP(false)
	}
	port := entry.Port
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Sprintf("http://%s/sub/%s", host, entry.Token)
	}
	return fmt.Sprintf("http://%s/sub/%s", net.JoinHostPort(host, fmt.Sprintf("%d", port)), entry.Token)
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
	return managedSubURL(cfg, &config.AdminSubConfig{Token: token, Address: cfg.AdminSub.Address, Port: cfg.AdminSub.Port})
}

func completeNetworkInterfaces(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	res := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Name != "" {
			res = append(res, iface.Name)
		}
	}
	return res, cobra.ShellCompDirectiveNoFileComp
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
	for _, o := range cfg.CustomOutbounds {
		res = append(res, o.Alias)
	}
	return res, cobra.ShellCompDirectiveNoFileComp
}

func completeSubscriptionInstances(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return []string{defaultSubInstance}, cobra.ShellCompDirectiveNoFileComp
	}
	var res []string
	if cfg.SubscriptionInstances != nil {
		for inst := range cfg.SubscriptionInstances {
			res = append(res, inst)
		}
	}
	if len(res) == 0 {
		res = append(res, defaultSubInstance)
	}
	sort.Strings(res)
	return res, cobra.ShellCompDirectiveNoFileComp
}

func reconcileSubscriptions(cfg *config.UserConfig) bool {
	changed := false
	for i := range cfg.Guests {
		if cfg.Guests[i].SubToken == "" {
			cfg.Guests[i].SubToken = utils.GenerateRandomString(24)
			changed = true
		}
	}
	active := map[string]bool{}
	for _, o := range cfg.CustomOutbounds {
		active[o.Alias] = true
	}
	kept := make([]config.Subscription, 0, len(cfg.Subscriptions))
	for _, s := range cfg.Subscriptions {
		if s.TargetType != "outbound" || active[s.TargetAlias] {
			kept = append(kept, s)
		} else {
			changed = true
		}
	}
	for alias := range active {
		found := false
		for _, s := range kept {
			if s.TargetType == "outbound" && s.TargetAlias == alias {
				found = true
				break
			}
		}
		if !found {
			kept = append(kept, config.Subscription{Alias: alias, TargetType: "outbound", TargetAlias: alias, Token: utils.GenerateRandomString(24)})
			changed = true
		}
	}
	cfg.Subscriptions = kept
	return changed
}

// subscriptionInstance reads the active config for the requested instance.
func subscriptionInstance(name ...string) (config.SubscriptionServiceConfig, error) {
	inst := defaultSubInstance
	if len(name) > 0 && strings.TrimSpace(name[0]) != "" {
		inst = strings.TrimSpace(name[0])
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return config.SubscriptionServiceConfig{}, fmt.Errorf("load active configuration: %w", err)
	}
	if err := requireServerSubscription(cfg); err != nil {
		return config.SubscriptionServiceConfig{}, err
	}
	var entry config.AdminSubConfig
	found := false
	if cfg.SubscriptionInstances != nil {
		if subEntry, ok := cfg.SubscriptionInstances[inst]; ok && subEntry.Token != "" {
			entry = subEntry
			found = true
		}
	}
	if !found && inst == defaultSubInstance && cfg.AdminSub.Token != "" {
		entry = cfg.AdminSub
		found = true
	}
	if !found || entry.Token == "" || entry.Port <= 0 {
		return config.SubscriptionServiceConfig{}, fmt.Errorf("subscription instance %q is not configured; use 'sub set %s', then apply", inst, inst)
	}
	listen := entry.Listen
	if listen == "" {
		listen = "127.0.0.1"
	}
	guestBind := cfg.GuestSubBind
	if guestBind == "" {
		guestBind = "127.0.0.1"
	}
	return config.SubscriptionServiceConfig{Listen: listen, Port: entry.Port, GuestBind: guestBind, GuestPort: cfg.GuestSubPort, AdminSub: entry}, nil
}

func validateSubInstance(name ...string) error { _, err := subscriptionInstance(name...); return err }

var subSetCmd = &cobra.Command{
	Use:   "set [instance]",
	Short: "Set subscription instance parameters in STAGING",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return err
		}
		if err := requireServerSubscription(cfg); err != nil {
			return err
		}
		inst := defaultSubInstance
		if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
			inst = strings.TrimSpace(args[0])
		} else if subInstance != "" {
			inst = subInstance
		}
		if !systemdInstanceName.MatchString(inst) {
			return fmt.Errorf("invalid subscription instance name %q", inst)
		}
		entry := *ensureSubscriptionInstance(cfg, inst)
		changed := false
		if cmd.Flags().Changed("listen") {
			entry.Listen = strings.TrimSpace(subListen)
			changed = true
		}
		if cmd.Flags().Changed("address") {
			entry.Address = strings.TrimSpace(subAddress)
			changed = true
		}
		if cmd.Flags().Changed("token") {
			entry.Token = strings.TrimSpace(subToken)
			changed = true
		}
		if cmd.Flags().Changed("port") {
			if subPort < 1 || subPort > 65535 {
				return fmt.Errorf("port must be between 1 and 65535")
			}
			entry.Port = subPort
			changed = true
		}
		if cmd.Flags().Changed("target-type") {
			if subTargetType != "direct" && subTargetType != "outbound" && subTargetType != "guest" {
				return fmt.Errorf("target-type must be direct, outbound, or guest")
			}
			entry.TargetType = subTargetType
			changed = true
		}
		if cmd.Flags().Changed("target") {
			entry.TargetAlias = subTargetAlias
			changed = true
		}
		if cmd.Flags().Changed("ipv6-rotation") {
			if subRotation == "none" || subRotation == "false" {
				subRotation = ""
			}
			if subRotation != "" {
				if cfg.IPv6Rotation.Subnet == "" && (cfg.IPv6Rotations == nil || cfg.IPv6Rotations["default"].Subnet == "") {
					return fmt.Errorf("IPv6 rotation is not configured; use 'ipv6-rotate set' first")
				}
			}
			entry.IPv6Rotation = subRotation
			changed = true
		}
		if !changed && !cmd.Flags().Changed("instance") && len(args) == 0 {
			return fmt.Errorf("no parameter supplied")
		}
		if cfg.SubscriptionInstances == nil {
			cfg.SubscriptionInstances = make(map[string]config.AdminSubConfig)
		}
		cfg.SubscriptionInstances[inst] = entry
		if inst == defaultSubInstance {
			cfg.AdminSub = entry
			cfg.SubPort = entry.Port
		}
		reconcileSubscriptions(cfg)
		if err := cfg.SaveEx(true); err != nil {
			return err
		}
		fmt.Printf("✅ Subscription instance %q updated in STAGING. Run 'apply', then control it with 'service start xray-proxya-sub@%s'.\n", inst, inst)
		return nil
	},
}

var subShowCmd = &cobra.Command{
	Use:   "show [instance]",
	Short: "Show subscription URLs and configuration",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			return
		}
		if reconcileSubscriptions(cfg) {
			_ = cfg.SaveEx(true)
		}
		filterInstance := ""
		if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
			filterInstance = strings.TrimSpace(args[0])
		}
		if !cmd.Flags().Changed("guest") && !cmd.Flags().Changed("relay") {
			allSubs := make(map[string]config.AdminSubConfig)
			if cfg.SubscriptionInstances != nil {
				for k, v := range cfg.SubscriptionInstances {
					if v.Token != "" {
						allSubs[k] = v
					}
				}
			}
			if cfg.AdminSub.Token != "" {
				if _, ok := allSubs[defaultSubInstance]; !ok {
					allSubs[defaultSubInstance] = cfg.AdminSub
				}
			}
			if len(allSubs) == 0 {
				fmt.Println("ℹ️  No subscription instances configured. Use 'sub set'.")
			} else {
				fmt.Println("\n--- Subscription Instances ---")
				keys := make([]string, 0, len(allSubs))
				for k := range allSubs {
					if filterInstance == "" || filterInstance == k {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				if len(keys) == 0 && filterInstance != "" {
					fmt.Printf("ℹ️  Subscription instance %q is not configured.\n", filterInstance)
				}
				for _, name := range keys {
					s := allSubs[name]
					fmt.Printf("Instance: %-15s Listen: %s:%-5d Target: %-8s URL: %s\n", name, s.Listen, s.Port, s.TargetType, managedSubURL(cfg, &s))
					if s.IPv6Rotation != "" {
						fmt.Printf("          └─ IPv6 rotation: enabled (%s)\n", s.IPv6Rotation)
					}
				}
			}
		}
		if filterInstance == "" {
			if !cmd.Flags().Changed("relay") {
				fmt.Println("\n--- Guest Subscriptions ---")
				for _, g := range cfg.Guests {
					fmt.Printf("Guest: %-15s URL: %s\n", g.Alias, subGuestSubURL(cfg, g.SubToken))
				}
			}
			if !cmd.Flags().Changed("guest") {
				fmt.Println("\n--- Relay Subscriptions ---")
				for _, s := range cfg.Subscriptions {
					if s.TargetType == "outbound" {
						fmt.Printf("Relay: %-15s URL: %s\n", s.TargetAlias, customSubURL(cfg, s.Token))
					}
				}
			}
		}
	},
}

var subDelCmd = &cobra.Command{
	Use:     "del <instance>",
	Aliases: []string{"delete", "rm"},
	Short:   "Delete a subscription instance in STAGING",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return err
		}
		if err := requireServerSubscription(cfg); err != nil {
			return err
		}
		inst := strings.TrimSpace(args[0])
		if cfg.SubscriptionInstances == nil {
			return fmt.Errorf("subscription instance %q not found", inst)
		}
		if _, ok := cfg.SubscriptionInstances[inst]; !ok && (inst != defaultSubInstance || cfg.AdminSub.Token == "") {
			return fmt.Errorf("subscription instance %q not found", inst)
		}
		delete(cfg.SubscriptionInstances, inst)
		if inst == defaultSubInstance {
			cfg.AdminSub = config.AdminSubConfig{}
		}
		if err := cfg.SaveEx(true); err != nil {
			return err
		}
		fmt.Printf("✅ Subscription instance %q deleted in STAGING. Run 'apply' to commit.\n", inst)
		return nil
	},
}

var subResetCmd = &cobra.Command{
	Use:   "reset [instance]",
	Short: "Rotate subscription token(s) in STAGING",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return err
		}
		if err := requireServerSubscription(cfg); err != nil {
			return err
		}
		reconcileSubscriptions(cfg)
		inst := defaultSubInstance
		if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
			inst = strings.TrimSpace(args[0])
		}
		if !cmd.Flags().Changed("guest") && !cmd.Flags().Changed("relay") {
			entry := ensureSubscriptionInstance(cfg, inst)
			entry.Token = utils.GenerateRandomString(24)
			cfg.SubscriptionInstances[inst] = *entry
			if inst == defaultSubInstance {
				cfg.AdminSub = *entry
			}
			if err := cfg.SaveEx(true); err != nil {
				return err
			}
			fmt.Printf("✅ Subscription token for instance %q rotated in STAGING: /sub/%s\n", inst, entry.Token)
			return nil
		}
		changed := false
		for i := range cfg.Guests {
			if cmd.Flags().Changed("guest") && (subResetGuest == "" || subResetGuest == "all" || cfg.Guests[i].Alias == subResetGuest) {
				cfg.Guests[i].SubToken = utils.GenerateRandomString(24)
				changed = true
			}
		}
		for i := range cfg.Subscriptions {
			if cmd.Flags().Changed("relay") && cfg.Subscriptions[i].TargetType == "outbound" && (subResetRelay == "" || subResetRelay == "all" || cfg.Subscriptions[i].TargetAlias == subResetRelay) {
				cfg.Subscriptions[i].Token = utils.GenerateRandomString(24)
				changed = true
			}
		}
		if changed {
			return cfg.SaveEx(true)
		}
		return fmt.Errorf("no matching subscription")
	},
}

var subRunCmd = &cobra.Command{
	Use:    "run [instance]",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inst := defaultSubInstance
		if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
			inst = strings.TrimSpace(args[0])
		} else if subInstance != "" {
			inst = subInstance
		}
		instance, err := subscriptionInstance(inst)
		if err != nil {
			return err
		}
		if instance.Port <= 1024 && !utils.IsRoot() {
			return fmt.Errorf("subscription ports <= 1024 require root")
		}
		return sub.StartSubServer(instance)
	},
}

var subValidateCmd = &cobra.Command{
	Use:    "validate [instance]",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inst := defaultSubInstance
		if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
			inst = strings.TrimSpace(args[0])
		}
		return validateSubInstance(inst)
	},
}

func init() {
	subSetCmd.Flags().StringVar(&subInstance, "instance", "", "Subscription instance name (default: 'default')")
	subSetCmd.Flags().StringVarP(&subListen, "listen", "l", "", "Loopback listener address")
	subSetCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Advertised hostname or address")
	subSetCmd.Flags().StringVarP(&subToken, "token", "t", "", "Subscription access token")
	subSetCmd.Flags().IntVarP(&subPort, "port", "p", 0, "Subscription HTTP port")
	subSetCmd.Flags().StringVar(&subTargetType, "target-type", "", "direct, outbound, or guest")
	subSetCmd.Flags().StringVar(&subTargetAlias, "target", "", "Target alias for outbound or guest")
	subSetCmd.Flags().StringVar(&subRotation, "ipv6-rotation", "", "IPv6 rotation (e.g. 'default', or 'none')")
	subSetCmd.RegisterFlagCompletionFunc("listen", completeNetworkInterfaces)
	subSetCmd.RegisterFlagCompletionFunc("instance", completeSubscriptionInstances)
	subShowCmd.Flags().StringVarP(&subShowGuest, "guest", "g", "", "Show guest subscription URL(s)")
	subShowCmd.Flags().StringVarP(&subShowRelay, "relay", "r", "", "Show relay subscription URL(s)")
	subResetCmd.Flags().StringVarP(&subResetGuest, "guest", "g", "", "Reset guest token(s)")
	subResetCmd.Flags().StringVarP(&subResetRelay, "relay", "r", "", "Reset relay token(s)")
	subRunCmd.Flags().StringVar(&subInstance, "instance", defaultSubInstance, "subscription instance")
	subRunCmd.RegisterFlagCompletionFunc("instance", completeSubscriptionInstances)
	subCmd.AddCommand(subSetCmd, subShowCmd, subDelCmd, subResetCmd, subRunCmd, subValidateCmd)
	rootCmd.AddCommand(subCmd)
}
