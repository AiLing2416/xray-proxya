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

var (
	subListen, subAddress, subAddressSub, subAddressNode, subToken, subTargetType, subTargetAlias, subRotation string
	subPort                                                                                                    int
	subShowGuest                                                                                               string
)

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Configure subscriptions; systemd controls their lifecycle",
	Long: `Configure subscription server and manage distribution URLs in STAGING.
The subscription server runs on its own port and token, and distributes direct server nodes,
guest nodes, or outbound relay chains.

Use 'xray-proxya apply' to commit staged changes, then manage its background
systemd lifecycle using 'xray-proxya service start/stop xray-proxya-sub'.`,
}

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
	host := entry.AddressSub
	if host == "" {
		host = cfg.AddressSub
	}
	if host == "" {
		host = entry.Address
	}
	if host == "" {
		host = utils.GetSmartIP(false)
	}
	port := entry.Port
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	if port <= 0 {
		port = cfg.SubPort
	}
	return sub.FormatSubURL(host, port, entry.Token)
}

func subGuestSubURL(cfg *config.UserConfig, tokenOrUUID string) string {
	if cfg == nil || tokenOrUUID == "" {
		return ""
	}
	host := sub.ResolveSubAddress(cfg)
	port := cfg.SubPort
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	return sub.FormatSubURL(host, port, tokenOrUUID)
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

func completeSubscriptionInstanceArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeSubscriptionInstances(cmd, args, toComplete)
}

func completeTargetTypes(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"direct", "outbound", "guest"}, cobra.ShellCompDirectiveNoFileComp
}

func completeTargetAliases(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	targetType, _ := cmd.Flags().GetString("target-type")
	var res []string
	if targetType == "" || targetType == "guest" {
		for _, g := range cfg.Guests {
			res = append(res, g.Alias)
		}
	}
	if targetType == "" || targetType == "outbound" {
		for _, o := range cfg.CustomOutbounds {
			res = append(res, o.Alias)
		}
	}
	return res, cobra.ShellCompDirectiveNoFileComp
}

func completeIPv6Rotations(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"default", "none"}, cobra.ShellCompDirectiveNoFileComp
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

// subscriptionInstance reads the active config for the subscription server.
func subscriptionInstance(name ...string) (config.SubscriptionServiceConfig, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return config.SubscriptionServiceConfig{}, fmt.Errorf("load active configuration: %w", err)
	}
	if err := requireServerSubscription(cfg); err != nil {
		return config.SubscriptionServiceConfig{}, err
	}
	instanceName := defaultSubInstance
	if len(name) > 0 && strings.TrimSpace(name[0]) != "" {
		instanceName = strings.TrimSpace(name[0])
	}
	if instanceName != defaultSubInstance {
		if cfg.SubscriptionInstances == nil {
			return config.SubscriptionServiceConfig{}, fmt.Errorf("subscription instance %q is not configured", instanceName)
		}
		inst, ok := cfg.SubscriptionInstances[instanceName]
		if !ok || inst.Token == "" {
			return config.SubscriptionServiceConfig{}, fmt.Errorf("subscription instance %q is not configured", instanceName)
		}
		port := inst.Port
		if port <= 0 {
			port = cfg.SubPort
		}
		if port <= 0 {
			port = cfg.AdminSub.Port
		}
		listen := inst.Listen
		if listen == "" {
			listen = "127.0.0.1"
		}
		inst.Port = port
		return config.SubscriptionServiceConfig{Listen: listen, Port: port, AdminSub: inst}, nil
	}
	entry := cfg.AdminSub
	if entry.Token == "" && cfg.SubscriptionInstances != nil {
		if def, ok := cfg.SubscriptionInstances[defaultSubInstance]; ok {
			entry = def
		}
	}
	port := entry.Port
	if port <= 0 {
		port = cfg.SubPort
	}
	if entry.Token == "" || port <= 0 {
		return config.SubscriptionServiceConfig{}, fmt.Errorf("subscription service is not configured; use 'sub set', then apply")
	}
	listen := entry.Listen
	if listen == "" {
		listen = "127.0.0.1"
	}
	entry.Port = port
	return config.SubscriptionServiceConfig{Listen: listen, Port: port, AdminSub: entry}, nil
}

func validateSubInstance(name ...string) error { _, err := subscriptionInstance(name...); return err }

var subSetCmd = &cobra.Command{
	Use:   "set [instance]",
	Short: "Set subscription parameters in STAGING",
	Long: `Configure or update subscription server parameters in the STAGING configuration.

Supported target types:
  - direct:   Distribute local server inbounds (default)
  - outbound: Distribute custom outbound relay nodes (specify with --target <relay-alias>)
  - guest:    Distribute guest tenant credentials (specify with --target <guest-alias>)`,
	Example: `  # Configure subscription server on port 8443
  xray-proxya sub set --port 8443 --token mytoken

  # Configure advertised subscription URL and proxy node addresses
  xray-proxya sub set --address-sub https://sub.example.com --address-node 1.1.2.2,2006:9999::8844,proxy.example.com

  # Configure a subscription instance with IPv6 address rotation
  xray-proxya sub set --ipv6-rotation default`,
	Args: cobra.MaximumNArgs(1),
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
		}
		entry := *ensureSubscriptionInstance(cfg, inst)
		changed := false
		if cmd.Flags().Changed("listen") {
			entry.Listen = strings.TrimSpace(subListen)
			changed = true
		}
		if cmd.Flags().Changed("address-sub") {
			entry.AddressSub = strings.TrimSpace(subAddressSub)
			cfg.AddressSub = entry.AddressSub
			changed = true
		}
		if cmd.Flags().Changed("address") {
			entry.Address = strings.TrimSpace(subAddress)
			if entry.AddressSub == "" {
				entry.AddressSub = entry.Address
				cfg.AddressSub = entry.Address
			}
			changed = true
		}
		if cmd.Flags().Changed("address-node") {
			entry.AddressNode = strings.TrimSpace(subAddressNode)
			cfg.AddressNode = entry.AddressNode
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
			cfg.SubPort = subPort
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
		if !changed {
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
		fmt.Println("✅ Subscription configuration updated in STAGING. Run 'apply', then control it with 'service start xray-proxya-sub'.")
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

		adminSub := ensureManagedSubscription(cfg)
		if adminSub.Token == "" {
			fmt.Println("ℹ️  No subscription configured. Use 'sub set'.")
		} else {
			fmt.Println("\n--- Admin Subscription ---")
			fmt.Printf("Listen: %s:%-5d Target: %-8s URL: %s\n", adminSub.Listen, adminSub.Port, adminSub.TargetType, managedSubURL(cfg, adminSub))
			if adminSub.AddressNode != "" {
				fmt.Printf("          └─ Node Address: %s\n", adminSub.AddressNode)
			}
			if adminSub.IPv6Rotation != "" {
				fmt.Printf("          └─ IPv6 rotation: enabled (%s)\n", adminSub.IPv6Rotation)
			}
		}

		if len(cfg.Guests) > 0 {
			fmt.Println("\n--- Guest Subscriptions ---")
			fmt.Printf("%-15s | %-8s | %-18s | %-5s | %-s\n", "ALIAS", "STATE", "QUOTA (USED/LIM)", "RESET", "URL")
			fmt.Println("-----------------------------------------------------------------------------------------")
			for _, g := range cfg.Guests {
				if subShowGuest != "" && g.Alias != subShowGuest {
					continue
				}
				state := "active"
				if !g.Enabled {
					state = "disabled"
				}
				limit := config.FormatByteSize(g.EffectiveLimitBytes())
				used := config.FormatByteSize(g.UsedBytes)
				url := subGuestSubURL(cfg, g.UUID)
				fmt.Printf("%-15s | %-8s | %-18s | %-5d | %s\n", g.Alias, state, used+"/"+limit, g.ResetDay, url)
			}
			fmt.Println()
		}
	},
}

var subRunCmd = &cobra.Command{
	Use:    "run [instance]",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		instance, err := subscriptionInstance()
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
		return validateSubInstance()
	},
}

func init() {
	subSetCmd.Flags().StringVarP(&subListen, "listen", "l", "", "Loopback listener address")
	subSetCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Advertised address (alias to --address-sub)")
	subSetCmd.Flags().StringVar(&subAddressSub, "address-sub", "", "Advertised hostname or URL for subscription links")
	subSetCmd.Flags().StringVar(&subAddressNode, "address-node", "", "Advertised hostname(s) or IP(s) for proxy nodes (comma-separated)")
	subSetCmd.Flags().StringVarP(&subToken, "token", "t", "", "Subscription access token")
	subSetCmd.Flags().IntVarP(&subPort, "port", "p", 0, "Subscription HTTP port")
	subSetCmd.Flags().StringVar(&subTargetType, "target-type", "", "direct, outbound, or guest")
	subSetCmd.Flags().StringVar(&subTargetAlias, "target", "", "Target alias for outbound or guest")
	subSetCmd.Flags().StringVar(&subRotation, "ipv6-rotation", "", "IPv6 rotation (e.g. 'default', or 'none')")
	subSetCmd.ValidArgsFunction = completeSubscriptionInstanceArg
	subSetCmd.RegisterFlagCompletionFunc("listen", completeNetworkInterfaces)
	subSetCmd.RegisterFlagCompletionFunc("target-type", completeTargetTypes)
	subSetCmd.RegisterFlagCompletionFunc("target", completeTargetAliases)
	subSetCmd.RegisterFlagCompletionFunc("ipv6-rotation", completeIPv6Rotations)

	subShowCmd.ValidArgsFunction = completeSubscriptionInstanceArg
	subShowCmd.Flags().StringVarP(&subShowGuest, "guest", "g", "", "Filter by guest alias")
	subShowCmd.RegisterFlagCompletionFunc("guest", completeGuestAliases)

	subRunCmd.ValidArgsFunction = completeSubscriptionInstanceArg
	subValidateCmd.ValidArgsFunction = completeSubscriptionInstanceArg

	subCmd.AddCommand(subSetCmd, subShowCmd, subRunCmd, subValidateCmd)
	rootCmd.AddCommand(subCmd)
}
