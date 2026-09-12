package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/endpoint"
	"xray-proxya/internal/sub"
	"xray-proxya/pkg/qrcode"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

const defaultSubInstance = "default"

var (
	subGateURL, subEndpoint, subListen, subToken, subTargetType, subTargetAlias string
	subPort                                                                     int
	subShowGuest                                                                string
	subShowAll                                                                  bool
	subShowQRCode                                                               bool
	subShowQRInvert                                                             bool
	subListGuest                                                                string
	subListQRCode                                                               bool
	subListQRInvert                                                             bool
)

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Configure subscriptions; systemd controls their lifecycle",
	Long: `Configure subscription server and manage distribution URLs in STAGING.
The subscription server runs on its own port and token, and distributes direct server nodes,
guest nodes, or outbound relay chains.

Use 'xray-proxya apply' to commit staged changes, then manage its background
systemd lifecycle using 'xray-proxya service start/stop xray-proxya-sub'.

Notice: This command manages central subscription distribution on Server nodes.
  - To manage individual tenant (guest) subscription links: see 'xray-proxya guests sub'
  - To import relay nodes from upstream airport subscriptions: see 'xray-proxya relay sub'`,
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
	host := ""
	if entry.AddressSub != "" {
		host = entry.AddressSub
	} else if cfg.GateURL != "" {
		host = cfg.GateURL
	} else if cfg.AddressSub != "" {
		host = cfg.AddressSub
	} else if entry.Address != "" {
		host = entry.Address
	} else if cfg.AddressNode != "" {
		host = cfg.AddressNode
	} else {
		host = sub.ResolveSubAddress(cfg)
	}
	port := entry.Port
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	if port <= 0 {
		port = cfg.SubPort
	}
	return sub.FormatSubURL(host, port, entry.Token, cfg)
}

func subGuestSubURL(cfg *config.UserConfig, tokenOrUUID string) string {
	if cfg == nil || tokenOrUUID == "" {
		return ""
	}
	host := ""
	if cfg.GateURL != "" {
		host = cfg.GateURL
	}
	if host == "" {
		host = sub.ResolveSubAddress(cfg)
	}
	port := cfg.SubPort
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	return sub.FormatSubURL(host, port, tokenOrUUID, cfg)
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

func completeIPListenAddresses(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	candidates := []string{
		"127.0.0.1\tLocal loopback",
		"0.0.0.0\tAll IPv4 interfaces",
		"::\tAll IPv6 interfaces",
	}

	seen := map[string]bool{
		"127.0.0.1": true,
		"0.0.0.0":   true,
		"::":        true,
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil {
					continue
				}
				ipStr := ip.String()
				if !seen[ipStr] {
					seen[ipStr] = true
					candidates = append(candidates, fmt.Sprintf("%s\tInterface %s", ipStr, iface.Name))
				}
			}
		}
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
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

  # Configure advertised subscription URL and proxy node endpoints
  xray-proxya sub set --gate-url https://sub.example.com -e default,v6-pool`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return err
		}
		if err := requireServerSubscription(cfg); err != nil {
			return err
		}
		defer func() {
			subEndpoint = ""
			subGateURL = ""
			if cmd != nil {
				if f := cmd.Flag("endpoint"); f != nil {
					f.Changed = false
					_ = f.Value.Set("")
				}
				if f := cmd.Flag("gate-url"); f != nil {
					f.Changed = false
					_ = f.Value.Set("")
				}
			}
		}()
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
		if cmd.Flags().Changed("gate-url") {
			entry.AddressSub = strings.TrimSpace(subGateURL)
			cfg.GateURL = strings.TrimSpace(subGateURL)
			cfg.AddressSub = entry.AddressSub
			changed = true
		}
		if cmd.Flags().Changed("endpoint") {
			epVal := strings.TrimSpace(subEndpoint)
			if epVal == "" {
				return fmt.Errorf("❌ Error: Endpoint cannot be empty. Specify a valid endpoint alias (e.g. -e default) or comma-separated list.")
			}
			if _, err := endpoint.ResolveTargets(cfg, epVal, "sub:"+inst, false); err != nil {
				return fmt.Errorf("❌ Error: Invalid endpoint %q: %w", epVal, err)
			}
			entry.Endpoint = epVal
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
		subURL := managedSubURL(cfg, &entry)
		proto := "HTTP"
		if strings.HasPrefix(subURL, "https://") {
			proto = "HTTPS"
		}
		fmt.Printf("✅ Subscription configuration updated in STAGING (%s). Run 'apply', then control it with 'service start xray-proxya-sub'.\n", proto)
		return nil
	},
}

func printSubscriptionsList(cfg *config.UserConfig, guestFilter string, withQR bool, invertQR bool) error {
	if guestFilter != "" {
		var target *config.GuestConfig
		for _, g := range cfg.Guests {
			if g.Alias == guestFilter {
				target = &g
				break
			}
		}
		if target == nil {
			return fmt.Errorf("❌ Guest '%s' not found.", guestFilter)
		}

		fmt.Println("\n--- Guest Subscription ---")
		fmt.Printf("%-15s | %-8s | %-18s | %-5s | %-s\n", "ALIAS", "STATE", "QUOTA (USED/LIM)", "RESET", "URL")
		fmt.Println("-----------------------------------------------------------------------------------------")
		state := "active"
		if !target.Enabled {
			state = "disabled"
		}
		limit := config.FormatByteSize(target.EffectiveLimitBytes())
		used := config.FormatByteSize(target.UsedBytes)
		url := subGuestSubURL(cfg, target.UUID)
		fmt.Printf("%-15s | %-8s | %-18s | %-5d | %s\n", target.Alias, state, used+"/"+limit, target.ResetDay, url)
		if withQR && url != "" {
			fmt.Println()
			if qr, err := qrcode.RenderTerminal(url, invertQR); err == nil {
				fmt.Print(qr)
				fmt.Println()
			}
		}
		fmt.Println()
		return nil
	}

	adminSub := ensureManagedSubscription(cfg)
	if adminSub.Token == "" {
		fmt.Println("ℹ️  No subscription configured. Use 'sub set'.")
	} else {
		subURL := managedSubURL(cfg, adminSub)
		proto := "HTTP"
		if strings.HasPrefix(subURL, "https://") {
			proto = "HTTPS"
		}
		fmt.Println("\n--- Admin Subscription ---")
		fmt.Printf("Listen: %s:%-5d Target: %-8s Proto: %-5s URL: %s\n", adminSub.Listen, adminSub.Port, adminSub.TargetType, proto, subURL)
		ep := adminSub.Endpoint
		if ep == "" {
			ep = "default"
		}
		fmt.Printf("          └─ Endpoint: %s\n", ep)
		if withQR && subURL != "" {
			fmt.Println()
			if qr, err := qrcode.RenderTerminal(subURL, invertQR); err == nil {
				fmt.Print(qr)
				fmt.Println()
			}
		}
	}

	if len(cfg.SubscriptionInstances) > 0 {
		var names []string
		for name := range cfg.SubscriptionInstances {
			if name != defaultSubInstance {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			fmt.Println("\n--- Subscription Instances ---")
			for _, name := range names {
				inst := cfg.SubscriptionInstances[name]
				if inst.Token == "" {
					continue
				}
				port := inst.Port
				if port <= 0 {
					port = cfg.SubPort
				}
				listen := inst.Listen
				if listen == "" {
					listen = "127.0.0.1"
				}
				inst.Port = port
				inst.Listen = listen
				subURL := managedSubURL(cfg, &inst)
				proto := "HTTP"
				if strings.HasPrefix(subURL, "https://") {
					proto = "HTTPS"
				}
				fmt.Printf("[%s] Listen: %s:%-5d Target: %-8s Proto: %-5s URL: %s\n", name, inst.Listen, inst.Port, inst.TargetType, proto, subURL)
				ep := inst.Endpoint
				if ep == "" {
					ep = "default"
				}
				fmt.Printf("          └─ Endpoint: %s\n", ep)
				if withQR && subURL != "" {
					fmt.Println()
					if qr, err := qrcode.RenderTerminal(subURL, invertQR); err == nil {
						fmt.Print(qr)
						fmt.Println()
					}
				}
			}
		}
	}

	if len(cfg.Guests) > 0 {
		fmt.Println("\n--- Guest Subscriptions ---")
		fmt.Printf("%-15s | %-8s | %-18s | %-5s | %-s\n", "ALIAS", "STATE", "QUOTA (USED/LIM)", "RESET", "URL")
		fmt.Println("-----------------------------------------------------------------------------------------")
		for _, g := range cfg.Guests {
			state := "active"
			if !g.Enabled {
				state = "disabled"
			}
			limit := config.FormatByteSize(g.EffectiveLimitBytes())
			used := config.FormatByteSize(g.UsedBytes)
			url := subGuestSubURL(cfg, g.UUID)
			fmt.Printf("%-15s | %-8s | %-18s | %-5d | %s\n", g.Alias, state, used+"/"+limit, g.ResetDay, url)
			if withQR && url != "" {
				fmt.Println()
				if qr, err := qrcode.RenderTerminal(url, invertQR); err == nil {
					fmt.Print(qr)
					fmt.Println()
				}
			}
		}
		fmt.Println()
	}
	return nil
}

var subListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List subscription instances and guest subscriptions",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		if reconcileSubscriptions(cfg) {
			_ = cfg.SaveEx(true)
		}

		return printSubscriptionsList(cfg, subListGuest, subListQRCode, subListQRInvert)
	},
}

var subShowCmd = &cobra.Command{
	Use:   "show [instance]",
	Short: "Show subscription URLs and configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		if reconcileSubscriptions(cfg) {
			_ = cfg.SaveEx(true)
		}

		// 1. Show all subscriptions when --all is set
		if subShowAll {
			return printSubscriptionsList(cfg, subShowGuest, subShowQRCode, subShowQRInvert)
		}

		// 2. Show specific subscription instance when positional arg is provided
		if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
			instName := strings.TrimSpace(args[0])
			var inst config.AdminSubConfig
			found := false
			if instName == defaultSubInstance {
				adminSub := ensureManagedSubscription(cfg)
				if adminSub != nil && adminSub.Token != "" {
					inst = *adminSub
					found = true
				}
			} else if cfg.SubscriptionInstances != nil {
				if entry, ok := cfg.SubscriptionInstances[instName]; ok && entry.Token != "" {
					inst = entry
					found = true
				}
			}
			if !found {
				return fmt.Errorf("❌ Subscription instance '%s' not found.", instName)
			}
			port := inst.Port
			if port <= 0 {
				port = cfg.SubPort
			}
			listen := inst.Listen
			if listen == "" {
				listen = "127.0.0.1"
			}
			subURL := managedSubURL(cfg, &inst)
			proto := "HTTP"
			if strings.HasPrefix(subURL, "https://") {
				proto = "HTTPS"
			}
			fmt.Printf("\n--- Subscription Instance: %s ---\n", instName)
			fmt.Printf("Listen: %s:%-5d Target: %-8s Proto: %-5s URL: %s\n", inst.Listen, inst.Port, inst.TargetType, proto, subURL)
			if inst.Endpoint != "" {
				fmt.Printf("          └─ Endpoint: %s\n", inst.Endpoint)
			}
			if inst.AddressNode != "" {
				fmt.Printf("          └─ Node Address: %s\n", inst.AddressNode)
			}
			if subShowQRCode && subURL != "" {
				fmt.Println()
				if qr, err := qrcode.RenderTerminal(subURL, subShowQRInvert); err == nil {
					fmt.Print(qr)
					fmt.Println()
				}
			}
			fmt.Println()
			return nil
		}

		// 3. Show specific guest subscription when -g is provided
		if subShowGuest != "" {
			var target *config.GuestConfig
			for _, g := range cfg.Guests {
				if g.Alias == subShowGuest {
					target = &g
					break
				}
			}
			if target == nil {
				return fmt.Errorf("❌ Guest '%s' not found.", subShowGuest)
			}

			fmt.Println("\n--- Guest Subscription ---")
			fmt.Printf("%-15s | %-8s | %-18s | %-5s | %-s\n", "ALIAS", "STATE", "QUOTA (USED/LIM)", "RESET", "URL")
			fmt.Println("-----------------------------------------------------------------------------------------")
			state := "active"
			if !target.Enabled {
				state = "disabled"
			}
			limit := config.FormatByteSize(target.EffectiveLimitBytes())
			used := config.FormatByteSize(target.UsedBytes)
			url := subGuestSubURL(cfg, target.UUID)
			fmt.Printf("%-15s | %-8s | %-18s | %-5d | %s\n", target.Alias, state, used+"/"+limit, target.ResetDay, url)
			if subShowQRCode && url != "" {
				fmt.Println()
				if qr, err := qrcode.RenderTerminal(url, subShowQRInvert); err == nil {
					fmt.Print(qr)
					fmt.Println()
				}
			}
			fmt.Println()
			return nil
		}

		// 4. Default: No args, no -g, no --all -> show Admin Subscription only (aligned with show)
		adminSub := ensureManagedSubscription(cfg)
		if adminSub.Token == "" {
			fmt.Println("ℹ️  No subscription configured. Use 'sub set'.")
			return nil
		}
		subURL := managedSubURL(cfg, adminSub)
		proto := "HTTP"
		if strings.HasPrefix(subURL, "https://") {
			proto = "HTTPS"
		}
		fmt.Println("\n--- Admin Subscription ---")
		fmt.Printf("Listen: %s:%-5d Target: %-8s Proto: %-5s URL: %s\n", adminSub.Listen, adminSub.Port, adminSub.TargetType, proto, subURL)
		ep := adminSub.Endpoint
		if ep == "" {
			ep = "default"
		}
		fmt.Printf("          └─ Endpoint: %s\n", ep)
		if subShowQRCode && subURL != "" {
			fmt.Println()
			if qr, err := qrcode.RenderTerminal(subURL, subShowQRInvert); err == nil {
				fmt.Print(qr)
				fmt.Println()
			}
		}
		fmt.Println()
		return nil
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
	subSetCmd.Flags().StringVar(&subGateURL, "gate-url", "", "Advertised subscription download URL (e.g. https://sub.example.com)")
	subSetCmd.Flags().StringVarP(&subListen, "listen", "l", "", "Loopback listener address")
	subSetCmd.Flags().StringVarP(&subToken, "token", "t", "", "Subscription access token")
	subSetCmd.Flags().IntVarP(&subPort, "port", "p", 0, "Subscription HTTP port")
	subSetCmd.Flags().StringVar(&subTargetType, "target-type", "", "direct, outbound, or guest")
	subSetCmd.Flags().StringVar(&subTargetAlias, "target", "", "Target alias for outbound or guest")
	subSetCmd.Flags().StringVarP(&subEndpoint, "endpoint", "e", "", "Endpoint(s) to bind for proxy nodes")
	subSetCmd.ValidArgsFunction = completeSubscriptionInstanceArg
	subSetCmd.RegisterFlagCompletionFunc("listen", completeIPListenAddresses)
	subSetCmd.RegisterFlagCompletionFunc("target-type", completeTargetTypes)
	subSetCmd.RegisterFlagCompletionFunc("target", completeTargetAliases)
	subSetCmd.RegisterFlagCompletionFunc("endpoint", completeEndpointNames)

	subShowCmd.ValidArgsFunction = completeSubscriptionInstanceArg
	subShowCmd.Flags().StringVarP(&subShowGuest, "guest", "g", "", "Filter by guest alias")
	subShowCmd.Flags().BoolVarP(&subShowAll, "all", "a", false, "Show all subscription instances and guest subscriptions")
	subShowCmd.Flags().BoolVarP(&subShowQRCode, "qrcode", "q", false, "Display QR code for subscription URLs")
	subShowCmd.Flags().BoolVar(&subShowQRInvert, "qr-invert", false, "Invert QR code colors for light-background terminals")
	subShowCmd.RegisterFlagCompletionFunc("guest", completeGuestAliases)

	subListCmd.Flags().StringVarP(&subListGuest, "guest", "g", "", "Filter by guest alias")
	subListCmd.Flags().BoolVarP(&subListQRCode, "qrcode", "q", false, "Display QR code for subscription URLs")
	subListCmd.Flags().BoolVar(&subListQRInvert, "qr-invert", false, "Invert QR code colors for light-background terminals")
	subListCmd.RegisterFlagCompletionFunc("guest", completeGuestAliases)

	subRunCmd.ValidArgsFunction = completeSubscriptionInstanceArg
	subValidateCmd.ValidArgsFunction = completeSubscriptionInstanceArg

	subCmd.AddCommand(subSetCmd, subShowCmd, subListCmd, subRunCmd, subValidateCmd)
	rootCmd.AddCommand(subCmd)
}
