package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/quota"
	"xray-proxya/internal/sub"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	quotaStr         string
	relayStr         string
	outboundStr      string
	resetDay         int
	guestSubShowAddr string
)

var guestsCmd = &cobra.Command{
	Use:     "guests",
	Aliases: []string{"guest"},
	Short:   "Manage multi-tenant guests (STAGING)",
}

func getGuestAliases() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		return nil
	}
	var aliases []string
	for _, g := range cfg.Guests {
		aliases = append(aliases, g.Alias)
	}
	return aliases
}

func findGuest(cfg *config.UserConfig, alias string) (int, *config.GuestConfig) {
	if cfg == nil {
		return -1, nil
	}
	for i := range cfg.Guests {
		if cfg.Guests[i].Alias == alias {
			return i, &cfg.Guests[i]
		}
	}
	return -1, nil
}

func formatGuestQuota(value float64) string {
	switch {
	case value < 0:
		return "Unlimited"
	case value == 0:
		return "Paused"
	case value >= 10:
		return fmt.Sprintf("%.1fGB", value)
	case value >= 1:
		return fmt.Sprintf("%.2fGB", value)
	default:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", value), "0"), ".") + "GB"
	}
}

func guestStateLabel(guest config.GuestConfig) string {
	if guest.Enabled {
		return "ON"
	}
	switch guest.DisabledReason {
	case config.GuestDisabledQuotaReached:
		return "QUOTA"
	case config.GuestDisabledQuotaZero:
		return "PAUSED"
	case config.GuestDisabledManual:
		return "PAUSED"
	default:
		return "OFF"
	}
}

func guestReasonLabel(guest config.GuestConfig) string {
	switch guest.DisabledReason {
	case config.GuestDisabledManual:
		return "manual"
	case config.GuestDisabledQuotaReached:
		return "quota reached"
	case config.GuestDisabledQuotaZero:
		return "quota=0"
	default:
		return "-"
	}
}

func ensureGuestSubListenerConfig(cfg *config.UserConfig) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(cfg.GuestSubBind) == "" {
		cfg.GuestSubBind = "127.0.0.1"
	}
	if cfg.GuestSubPort > 0 {
		return
	}
	const preferredPort = 9444
	if utils.IsPortFree(preferredPort) {
		cfg.GuestSubPort = preferredPort
		return
	}
	port, _ := xray.GetFreePort()
	cfg.GuestSubPort = port
}

func guestSubURL(host string, port int, token string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Sprintf("http://%s/guest-sub/%s", host, token)
	}
	return fmt.Sprintf("http://%s/guest-sub/%s", net.JoinHostPort(host, strconv.Itoa(port)), token)
}

var guestsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all guests status and quota",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			return
		}
		fmt.Printf("\n%-12s | %-8s | %-13s | %-18s | %-8s | %-s\n", "ALIAS", "STATE", "REASON", "QUOTA (USED/LIM)", "RESET", "RELAY")
		fmt.Println("----------------------------------------------------------------------------------------------------------------")
		for _, g := range cfg.Guests {
			state := guestStateLabel(g)
			limit := formatGuestQuota(g.QuotaGB)
			used := fmt.Sprintf("%.2fGB", float64(g.UsedBytes)/(1024*1024*1024))
			out := "direct"
			if g.OutboundLink != "" {
				out = "custom-link"
			}
			fmt.Printf("%-12s | %-8s | %-13s | %-18s | %-8d | %-s\n", g.Alias, state, guestReasonLabel(g), used+"/"+limit, g.ResetDay, out)
		}
		fmt.Println()
	},
}

var guestsAddCmd = &cobra.Command{
	Use:   "add [alias]",
	Short: "Add a new guest user (STAGING)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		// Validate alias: alphanumeric and underscore only, 3-20 chars
		if len(alias) < 3 || len(alias) > 20 {
			fmt.Println("❌ Guest alias must be between 3 and 20 characters.")
			return
		}
		for _, r := range alias {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
				fmt.Printf("❌ Invalid guest alias: %s (Only alphanumeric, underscore, and hyphen allowed)\n", alias)
				return
			}
		}

		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		for _, g := range cfg.Guests {
			if g.Alias == alias {
				fmt.Printf("❌ Guest '%s' already exists.\n", alias)
				return
			}
		}
		newG := config.GuestConfig{
			Alias: alias, UUID: uuid.New().String(), Enabled: true, DisabledReason: config.GuestDisabledNone, QuotaGB: -1, ResetDay: 1,
		}
		cfg.Guests = append(cfg.Guests, newG)
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Guest '%s' added to STAGING. UUID: %s\n", alias, newG.UUID)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsDelCmd = &cobra.Command{
	Use:   "del [alias]",
	Short: "Remove a guest user (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		var newGuests []config.GuestConfig
		found := false
		for _, g := range cfg.Guests {
			if g.Alias == alias {
				found = true
				continue
			}
			newGuests = append(newGuests, g)
		}
		if found {
			cfg.Guests = newGuests
			cfg.SaveEx(true)
			fmt.Printf("✅ Guest '%s' removed from STAGING.\n", alias)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		} else {
			fmt.Printf("❌ Guest '%s' not found.\n", alias)
		}
	},
}

var guestsSetCmd = &cobra.Command{
	Use:   "set [alias]",
	Short: "Configure guest parameters (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		idx, guest := findGuest(cfg, alias)
		if idx == -1 || guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", alias)
			return
		}

		success := false
		if quotaStr != "" {
			if quotaStr == "reset" {
				cfg.Guests[idx].UsedBytes = -1
				if cfg.Guests[idx].DisabledReason == config.GuestDisabledQuotaReached && cfg.Guests[idx].QuotaGB > 0 {
					cfg.Guests[idx].Enabled = true
					cfg.Guests[idx].DisabledReason = config.GuestDisabledNone
					fmt.Printf("✅ Guest '%s' re-enabled after usage reset.\n", alias)
				}
				fmt.Printf("✅ Usage for '%s' reset to 0.\n", alias)
				success = true
			} else {
				val, err := strconv.ParseFloat(quotaStr, 64)
				if err == nil {
					cfg.Guests[idx].QuotaGB = val
					if val == 0 {
						cfg.Guests[idx].Enabled = false
						cfg.Guests[idx].DisabledReason = config.GuestDisabledQuotaZero
					} else {
						if cfg.Guests[idx].DisabledReason != config.GuestDisabledManual {
							cfg.Guests[idx].Enabled = true
							cfg.Guests[idx].DisabledReason = config.GuestDisabledNone
						}
					}
					fmt.Printf("✅ Quota for '%s' set to %s.\n", alias, formatGuestQuota(val))
					success = true
				}
			}
		}
		targetRelay := relayStr
		if targetRelay == "" {
			targetRelay = outboundStr
		}
		if targetRelay != "" {
			if targetRelay == "direct" {
				cfg.Guests[idx].OutboundLink = ""
				cfg.Guests[idx].OutboundConf = nil
				fmt.Printf("✅ Relay for '%s' set to direct.\n", alias)
				success = true
			} else {
				conf, err := xray.ParseProxyLink(targetRelay)
				if err == nil {
					cfg.Guests[idx].OutboundLink = targetRelay
					cfg.Guests[idx].OutboundConf = conf
					fmt.Printf("✅ Relay for '%s' updated via link.\n", alias)
					success = true
				} else {
					fmt.Printf("❌ Failed to parse link: %v\n", err)
				}
			}
		}
		if cmd.Flags().Changed("reset") {
			if resetDay >= 1 && resetDay <= 31 {
				cfg.Guests[idx].ResetDay = resetDay
				fmt.Printf("✅ Reset day for '%s' set to %d.\n", alias, resetDay)
				success = true
			}
		}
		if success {
			cfg.SaveEx(true)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsPauseCmd = &cobra.Command{
	Use:   "pause [alias]",
	Short: "Pause a guest manually (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		idx, guest := findGuest(cfg, args[0])
		if idx == -1 || guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		cfg.Guests[idx].Enabled = false
		cfg.Guests[idx].DisabledReason = config.GuestDisabledManual
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Guest '%s' paused in STAGING.\n", args[0])
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsResumeCmd = &cobra.Command{
	Use:   "resume [alias]",
	Short: "Resume a paused guest (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		idx, guest := findGuest(cfg, args[0])
		if idx == -1 || guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		if cfg.Guests[idx].QuotaGB == 0 {
			fmt.Printf("❌ Guest '%s' still has quota=0. Set a positive quota first.\n", args[0])
			return
		}
		cfg.Guests[idx].Enabled = true
		cfg.Guests[idx].DisabledReason = config.GuestDisabledNone
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Guest '%s' resumed in STAGING.\n", args[0])
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsInfoCmd = &cobra.Command{
	Use:   "info [alias]",
	Short: "Show detailed guest runtime state",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		_, guest := findGuest(cfg, args[0])
		if guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		out := "direct"
		if guest.OutboundLink != "" {
			out = "custom-link"
		}
		lastReset := guest.LastResetYM
		if lastReset == "" {
			lastReset = "-"
		}
		fmt.Printf("\nGuest: %s\n", guest.Alias)
		fmt.Printf("UUID: %s\n", guest.UUID)
		fmt.Printf("State: %s\n", guestStateLabel(*guest))
		fmt.Printf("Reason: %s\n", guestReasonLabel(*guest))
		fmt.Printf("Quota: %s\n", formatGuestQuota(guest.QuotaGB))
		fmt.Printf("Used: %.2fGB\n", float64(guest.UsedBytes)/(1024*1024*1024))
		fmt.Printf("Reset Day: %d\n", guest.ResetDay)
		fmt.Printf("Last Reset Month: %s\n", lastReset)
		fmt.Printf("Relay: %s\n\n", out)
	},
}

var guestsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check quota usage now and update active guest states",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil || cfg == nil {
			fmt.Println("❌ Error: Failed to load active config.")
			return
		}
		monitor, err := quota.LoadMonitor()
		if err != nil {
			fmt.Printf("⚠️  Failed to load quota monitor state: %v\n", err)
			monitor = quota.NewMonitor()
		}
		update, err := checkGuestQuotaState(cfg, monitor, time.Now())
		if err != nil {
			fmt.Printf("❌ Guest check failed: %v\n", err)
			return
		}
		if !update.Changed {
			fmt.Println("ℹ️ No guest state changes were needed.")
			return
		}
		for _, msg := range update.Messages {
			fmt.Printf("ℹ️  %s\n", msg)
		}
		if update.RestartNeeded {
			fmt.Println("🔄 Restarting service to apply guest state changes...")
			if err := xray.RestartXrayService(); err != nil {
				fmt.Printf("❌ State updated, but restart failed: %v\n", err)
				return
			}
		}
		fmt.Println("✅ Guest state check completed.")
	},
}

var guestsShowCmd = &cobra.Command{
	Use:   "show [alias]",
	Short: "Show sharing links for a guest",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, err := config.LoadConfig()
		if err != nil || cfg == nil {
			fmt.Println("❌ Error: Failed to load config.")
			return
		}
		var target *config.GuestConfig
		for i := range cfg.Guests {
			if cfg.Guests[i].Alias == alias {
				target = &cfg.Guests[i]
				break
			}
		}
		if target == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", alias)
			return
		}

		allIPs, _ := cmd.Flags().GetBool("all")
		var ips []string
		if allIPs {
			ips = append(ips, utils.GetLocalIP())
		} else {
			ips = append(ips, utils.GetLocalIP())
		}

		fmt.Printf("\n🚀 GUEST LINKS for [%s] (UUID: %s)\n", alias, target.UUID)
		fmt.Println("============================================================")
		for _, ip := range ips {
			links := xray.GenerateGuestLinks(cfg, ip, target.UUID, target.Alias)
			for _, l := range links {
				fmt.Println(l)
			}
		}
		fmt.Println()
	},
}

var guestsSubCmd = &cobra.Command{
	Use:   "sub",
	Short: "Manage guest self-service subscription links (STAGING)",
}

var guestsSubEnableCmd = &cobra.Command{
	Use:   "enable [alias]",
	Short: "Enable self-service subscription for a guest (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		idx, guest := findGuest(cfg, args[0])
		if idx == -1 || guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		ensureGuestSubListenerConfig(cfg)
		if cfg.Guests[idx].SubToken == "" {
			cfg.Guests[idx].SubToken = utils.GenerateRandomString(32)
		}
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Guest sub enabled for '%s' in STAGING.\n", args[0])
			fmt.Printf("🔒 Listener: https://%s:%d/guest-sub/<token>\n", cfg.GuestSubBind, cfg.GuestSubPort)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsSubDisableCmd = &cobra.Command{
	Use:   "disable [alias]",
	Short: "Disable self-service subscription for a guest (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		idx, guest := findGuest(cfg, args[0])
		if idx == -1 || guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		cfg.Guests[idx].SubToken = ""
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Guest sub disabled for '%s' in STAGING.\n", args[0])
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsSubRotateCmd = &cobra.Command{
	Use:   "rotate [alias]",
	Short: "Rotate the guest self-service subscription token (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		idx, guest := findGuest(cfg, args[0])
		if idx == -1 || guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		ensureGuestSubListenerConfig(cfg)
		cfg.Guests[idx].SubToken = utils.GenerateRandomString(32)
		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("✅ Guest sub token rotated for '%s' in STAGING.\n", args[0])
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsSubShowCmd = &cobra.Command{
	Use:   "show [alias]",
	Short: "Show a guest self-service subscription link",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		_, guest := findGuest(cfg, args[0])
		if guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		if guest.SubToken == "" {
			fmt.Printf("❌ Guest sub is not enabled for '%s'.\n", args[0])
			return
		}
		ensureGuestSubListenerConfig(cfg)
		host := cfg.GuestSubBind
		if guestSubShowAddr != "" {
			host = guestSubShowAddr
		}
		fmt.Printf("\nGuest: %s\n", guest.Alias)
		fmt.Printf("State: %s\n", guestStateLabel(*guest))
		fmt.Printf("Quota: %s\n", formatGuestQuota(guest.QuotaGB))
		fmt.Printf("Used: %.2fGB\n", float64(guest.UsedBytes)/(1024*1024*1024))
		fmt.Printf("Reset Day: %d\n", guest.ResetDay)
		fmt.Printf("Remark Preview: %s\n", sub.FormatGuestSubRemarkForDisplay(*guest, time.Now()))
		fmt.Printf("Listener: %s:%d\n", cfg.GuestSubBind, cfg.GuestSubPort)
		fmt.Printf("Path: /guest-sub/%s\n", guest.SubToken)
		fmt.Printf("URL: %s\n\n", guestSubURL(host, cfg.GuestSubPort, guest.SubToken))
	},
}

func init() {
	guestsSetCmd.Flags().StringVarP(&quotaStr, "quota", "q", "", "Set quota (GB, -1, 0, or 'reset')")
	guestsSetCmd.Flags().StringVar(&relayStr, "relay", "", "Set relay node to a proxy link or 'direct'")
	guestsSetCmd.Flags().StringVarP(&outboundStr, "outbound", "o", "", "Set outbound to a proxy link or 'direct' (deprecated)")
	guestsSetCmd.Flags().MarkHidden("outbound")
	guestsSetCmd.Flags().IntVarP(&resetDay, "reset", "r", 1, "Monthly reset day (1-31)")
	guestsSetCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"direct"}, cobra.ShellCompDirectiveNoFileComp
	})
	guestsSetCmd.RegisterFlagCompletionFunc("outbound", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"direct"}, cobra.ShellCompDirectiveNoFileComp
	})

	guestsShowCmd.Flags().BoolP("ipv4", "4", true, "Use IPv4")
	guestsShowCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6")
	guestsShowCmd.Flags().BoolP("all", "a", false, "Show all available IPs")
	guestsSubShowCmd.Flags().StringVarP(&guestSubShowAddr, "address", "a", "", "Override the host used when printing the guest sub URL")

	guestsSubCmd.AddCommand(guestsSubEnableCmd, guestsSubDisableCmd, guestsSubRotateCmd, guestsSubShowCmd)
	guestsCmd.AddCommand(guestsListCmd, guestsAddCmd, guestsDelCmd, guestsSetCmd, guestsPauseCmd, guestsResumeCmd, guestsInfoCmd, guestsCheckCmd, guestsShowCmd, guestsSubCmd)
	rootCmd.AddCommand(guestsCmd)
}
