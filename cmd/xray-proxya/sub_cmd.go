package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/sub"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	subRelay    string
	subOutbound string
	subGuest    string
	subAddress  string
	subAll      bool
	subPort     int
	subIface    string
	subSubnet   string
	subMax      int
	subNDP      bool
)

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Manage admin subscription and standalone HTTPS server",
}

const managedSubAlias = "admin"

func getSubscriptionAliases() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		return nil
	}
	var aliases []string
	for _, s := range cfg.Subscriptions {
		aliases = append(aliases, s.Alias)
	}
	return aliases
}

func findSubscription(cfg *config.UserConfig, alias string) (int, *config.Subscription) {
	if cfg == nil {
		return -1, nil
	}
	for i := range cfg.Subscriptions {
		if cfg.Subscriptions[i].Alias == alias {
			return i, &cfg.Subscriptions[i]
		}
	}
	return -1, nil
}

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
			return fmt.Errorf("could not auto-detect IPv6 subnet/interface; use 'sub set --subnet ... --interface ...'")
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
		return fmt.Sprintf("https://%s/sub/%s", host, subEntry.Token)
	}
	return fmt.Sprintf("https://%s/sub/%s", net.JoinHostPort(host, fmt.Sprintf("%d", cfg.AdminSub.Port)), subEntry.Token)
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

var subInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the managed admin subscription (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		subEntry := ensureManagedSubscription(cfg)
		ensureSubPortConfigured(cfg)
		if subAddress != "" {
			subEntry.Address = subAddress
		}
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Admin subscription initialized in STAGING.\n🔗 Path: /sub/%s\n", subEntry.Token)
			fmt.Printf("📡 Port: %d\n", cfg.AdminSub.Port)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var subModeCmd = &cobra.Command{
	Use:   "mode [fixed|ipv6-rotate]",
	Short: "Set the managed admin subscription address strategy (STAGING)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		subEntry := ensureManagedSubscription(cfg)
		ensureSubPortConfigured(cfg)

		switch args[0] {
		case "fixed":
			cfg.AdminSub.Mode = config.AdminSubModeFixed
			cfg.AdminSub.IPv6Rotate.Enabled = false
			if subAddress != "" {
				subEntry.Address = subAddress
			}
			if err := cfg.SaveEx(true); err == nil {
				fmt.Println("✅ Admin subscription mode set to fixed in STAGING.")
				fmt.Println("🚀 Run 'apply' to commit changes.")
			}
		case "ipv6-rotate":
			if err := detectOrUseIPv6Settings(cfg, subIface, subSubnet, subMax, subNDP); err != nil {
				fmt.Printf("❌ %v\n", err)
				return
			}
			cfg.AdminSub.Mode = config.AdminSubModeIPv6Rotate
			if subAddress != "" {
				subEntry.Address = subAddress
			}
			if err := cfg.SaveEx(true); err == nil {
				fmt.Printf("✅ Admin subscription mode set to ipv6-rotate in STAGING.\n📡 Subnet: %s\n🧭 Interface: %s\n", cfg.AdminSub.IPv6Rotate.Subnet, cfg.AdminSub.IPv6Rotate.Interface)
				fmt.Println("🚀 Run 'apply' to commit changes.")
			}
		default:
			fmt.Println("❌ Mode must be 'fixed' or 'ipv6-rotate'.")
		}
	},
}

var subSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update managed admin subscription settings (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		subEntry := ensureManagedSubscription(cfg)
		changed := false

		if cmd.Flags().Changed("address") {
			subEntry.Address = subAddress
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
			fmt.Println("❌ No settings specified.")
			return
		}
		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ Admin subscription settings updated in STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var subShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the managed admin subscription summary",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		if !cfg.AdminSub.Enabled || cfg.AdminSub.Token == "" {
			fmt.Println("ℹ️  No managed admin subscription found. Run 'sub init' first.")
			return
		}
		subEntry := &cfg.AdminSub
		mode := currentSubMode(cfg)
		address := subEntry.Address
		if address == "" {
			address = "(auto)"
		}
		fmt.Printf("\nAlias: %s\n", managedSubAlias)
		fmt.Printf("Mode: %s\n", mode)
		fmt.Printf("Port: %d\n", cfg.AdminSub.Port)
		fmt.Printf("Address Override: %s\n", address)
		fmt.Printf("URL: %s\n", managedSubURL(cfg, subEntry))
		fmt.Printf("Token Path: /sub/%s\n", subEntry.Token)
		if mode == string(config.AdminSubModeIPv6Rotate) {
			fmt.Printf("IPv6 Subnet: %s\n", cfg.AdminSub.IPv6Rotate.Subnet)
			fmt.Printf("Interface: %s\n", cfg.AdminSub.IPv6Rotate.Interface)
			fmt.Printf("Rotation Limit: %d\n", cfg.AdminSub.IPv6Rotate.MaxAddresses)
			fmt.Printf("NDP: %v\n", cfg.AdminSub.IPv6Rotate.EnableNDP)
			fmt.Println("Behavior: each subscription request rotates to a fresh IPv6 address")
		}
		fmt.Println()
	},
}

var subRotateTokenCmd = &cobra.Command{
	Use:   "rotate-token",
	Short: "Rotate the managed admin subscription token (STAGING)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		subEntry := ensureManagedSubscription(cfg)
		subEntry.Token = utils.GenerateRandomString(24)
		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ Admin subscription token rotated in STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

// --- Service Management ---

func getSubServicePath() string {
	return "/etc/systemd/system/xray-proxya-sub.service"
}

var subStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the subscription service",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ Requires root.")
			return
		}
		exec.Command("systemctl", "start", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service started.")
	},
}

var subStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the subscription service",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ Requires root.")
			return
		}
		exec.Command("systemctl", "stop", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service stopped.")
	},
}

var subRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the subscription service",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ Requires root.")
			return
		}
		exec.Command("systemctl", "restart", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service restarted.")
	},
}

var subEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable sub-server (Install service & autostart)",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ Requires root.")
			return
		}
		binPath, _ := os.Executable()
		home, _ := os.UserHomeDir()
		if os.Geteuid() == 0 {
			home = "/root"
		}
		workDir := filepath.Join(home, ".local", "share", "xray-proxya")

		content := fmt.Sprintf(`[Unit]
Description=Xray-Proxya Subscription Server
After=network.target xray-proxya.service

[Service]
Type=simple
ExecStart=%s sub run
Restart=on-failure
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, binPath, workDir)

		os.WriteFile(getSubServicePath(), []byte(content), 0644)
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service enabled and installed.")
	},
}

var subDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable sub-server (Uninstall service)",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ Requires root.")
			return
		}
		exec.Command("systemctl", "stop", "xray-proxya-sub").Run()
		exec.Command("systemctl", "disable", "xray-proxya-sub").Run()
		os.Remove(getSubServicePath())
		exec.Command("systemctl", "daemon-reload").Run()
		fmt.Println("✅ Subscription service disabled and removed.")
	},
}

var subRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the subscription HTTPS server in foreground (Requires Root)",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ IPv6 Rolling Pool requires root privileges.")
			os.Exit(1)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		adminPort := subPort
		if !cmd.Flags().Changed("port") && cfg.AdminSub.Port > 0 {
			adminPort = cfg.AdminSub.Port
		} else if !cmd.Flags().Changed("port") && cfg.SubPort > 0 {
			adminPort = cfg.SubPort
		}

		// v0.2.4: Explicitly audit and persist ONLY during RUN
		if adminPort > 0 && !utils.IsPortFree(adminPort) {
			p, _ := xray.GetFreePort()
			fmt.Printf("⚠️  Warning: Subscription Port %d occupied, using %d\n", adminPort, p)
			adminPort = p
			cfg.AdminSub.Port = p
			cfg.SubPort = p
			cfg.Save()
		}

		guestPort := cfg.GuestSubPort
		if guestPort > 0 && !utils.IsPortFree(guestPort) {
			p, _ := xray.GetFreePort()
			fmt.Printf("⚠️  Warning: Guest subscription port %d occupied, using %d\n", guestPort, p)
			guestPort = p
			cfg.GuestSubPort = guestPort
			cfg.Save()
		}

		if err := sub.StartSubServer(adminPort, cfg.GuestSubBind, guestPort); err != nil {

			fmt.Printf("❌ Failed: %v\n", err)
		}
	},
}

// --- Link Management (Remains same) ---

var subGenCmd = &cobra.Command{
	Use:   "gen [alias]",
	Short: "Generate a subscription link (STAGING)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		alias := ""
		if len(args) > 0 {
			alias = args[0]
		}
		cfg, _ := config.LoadConfigEx(true)
		targetType := "direct"
		targetAlias := ""
		targetRelay := subRelay
		if targetRelay == "" {
			targetRelay = subOutbound
		}
		if targetRelay != "" {
			targetType = "outbound"
			targetAlias = targetRelay
		} else if subGuest != "" {
			targetType = "guest"
			targetAlias = subGuest
		}

		foundIdx := -1
		for i, s := range cfg.Subscriptions {
			if s.Alias == alias {
				foundIdx = i
				break
			}
		}

		newToken := utils.GenerateRandomString(8)
		newSub := config.Subscription{Alias: alias, TargetType: targetType, TargetAlias: targetAlias, Address: subAddress, Token: newToken}

		if foundIdx != -1 {
			cfg.Subscriptions[foundIdx] = newSub
		} else {
			cfg.Subscriptions = append(cfg.Subscriptions, newSub)
		}

		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Subscription '%s' generated in STAGING.\n🔗 Path: /sub/%s\n", alias, newToken)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var subDelCmd = &cobra.Command{
	Use:   "del [alias]",
	Short: "Delete a subscription link (STAGING)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if subAll {
			cfg.Subscriptions = nil
			cfg.SaveEx(true)
			return
		}
		alias := ""
		if len(args) > 0 {
			alias = args[0]
		}
		var newSubs []config.Subscription
		found := false
		for _, s := range cfg.Subscriptions {
			if s.Alias == alias {
				found = true
				continue
			}
			newSubs = append(newSubs, s)
		}
		if found {
			cfg.Subscriptions = newSubs
			cfg.SaveEx(true)
			fmt.Printf("✅ Deleted '%s' from STAGING.\n", alias)
		}
	},
}

func init() {
	subGenCmd.Flags().StringVarP(&subRelay, "relay", "r", "", "Target relay node alias")
	subGenCmd.Flags().StringVarP(&subOutbound, "outbound", "o", "", "Target custom outbound alias (deprecated)")
	subGenCmd.Flags().MarkHidden("outbound")
	subGenCmd.Flags().StringVarP(&subGuest, "guest", "g", "", "Target guest alias")
	subGenCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Override address in links")
	subInitCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Override address/hostname in the managed admin subscription")
	subModeCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Override address/hostname in the managed admin subscription")
	subModeCmd.Flags().StringVarP(&subIface, "interface", "i", "", "IPv6 interface for rotate mode")
	subModeCmd.Flags().StringVar(&subSubnet, "subnet", "", "IPv6 subnet for rotate mode")
	subModeCmd.Flags().IntVarP(&subMax, "max", "m", 6, "Max active rotated IPv6 addresses")
	subModeCmd.Flags().BoolVarP(&subNDP, "ndp", "n", true, "Enable NDP while rotating IPv6 addresses")
	subSetCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Override address/hostname in the managed admin subscription")
	subSetCmd.Flags().IntVarP(&subPort, "port", "p", 0, "Managed admin subscription HTTPS port")
	subSetCmd.Flags().StringVarP(&subIface, "interface", "i", "", "IPv6 interface for rotate mode")
	subSetCmd.Flags().StringVar(&subSubnet, "subnet", "", "IPv6 subnet for rotate mode")
	subSetCmd.Flags().IntVarP(&subMax, "max", "m", 0, "Max active rotated IPv6 addresses")
	subSetCmd.Flags().BoolVarP(&subNDP, "ndp", "n", true, "Enable NDP while rotating IPv6 addresses")

	subDelCmd.Flags().BoolVarP(&subAll, "all", "A", false, "Delete all subscriptions")
	subRunCmd.Flags().IntVarP(&subPort, "port", "p", 8443, "HTTPS port")
	subModeCmd.RegisterFlagCompletionFunc("interface", completeNetworkInterfaces)
	subSetCmd.RegisterFlagCompletionFunc("interface", completeNetworkInterfaces)

	subCmd.AddCommand(subInitCmd, subModeCmd, subSetCmd, subShowCmd, subRotateTokenCmd, subGenCmd, subDelCmd, subRunCmd, subStartCmd, subStopCmd, subRestartCmd, subEnableCmd, subDisableCmd)
	rootCmd.AddCommand(subCmd)
}
