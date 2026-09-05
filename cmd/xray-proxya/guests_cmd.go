package main

import (
	"fmt"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/notify"
	"xray-proxya/internal/quota"
	"xray-proxya/internal/sub"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	limitStr         string
	quotaStr         string
	relayStr         string
	outboundStr      string
	resetDay         int
	guestSubShowAddr string
	notifyStr        string
	notifyWebhookStr string
	notifyTriggerStr string
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

func completeGuestAliasesArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
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
	return quota.FormatQuota(value)
}

func guestStateLabel(guest config.GuestConfig) string {
	return quota.GuestStateLabel(guest)
}

func guestReasonLabel(guest config.GuestConfig) string {
	return quota.GuestReasonLabel(guest)
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
	return sub.FormatSubURL(host, port, token)
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
		for _, v := range quota.BuildAllGuestViews(cfg.Guests, time.Now()) {
			limit := config.FormatByteSize(v.LimitBytes)
			used := config.FormatByteSize(v.UsedBytes)
			fmt.Printf("%-12s | %-8s | %-13s | %-18s | %-8d | %-s\n", v.Alias, v.StateLabel, v.ReasonLabel, used+"/"+limit, v.ResetDay, v.RelayLabel)
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
			Alias: alias, UUID: uuid.New().String(), Enabled: true, DisabledReason: config.GuestDisabledNone, QuotaGB: -1, LimitBytes: -1, ResetDay: 1,
			Notify: config.GuestNotifyOff,
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
	ValidArgsFunction: completeGuestAliasesArg,
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
	ValidArgsFunction: completeGuestAliasesArg,
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
		effectiveLimitInput := limitStr
		if effectiveLimitInput == "" && quotaStr != "" {
			effectiveLimitInput = quotaStr
		}

		if effectiveLimitInput != "" {
			if strings.EqualFold(effectiveLimitInput, "reset") {
				cfg.Guests[idx].UsedBytes = -1
				cfg.Guests[idx].AlertedYM = ""
				cfg.Guests[idx].AlertedTriggers = nil
				if cfg.Guests[idx].DisabledReason == config.GuestDisabledQuotaReached && cfg.Guests[idx].EffectiveLimitBytes() > 0 {
					cfg.Guests[idx].Enabled = true
					cfg.Guests[idx].DisabledReason = config.GuestDisabledNone
					fmt.Printf("✅ Guest '%s' re-enabled after usage reset.\n", alias)
				}
				fmt.Printf("✅ Usage for '%s' reset to 0.\n", alias)
				success = true
			} else {
				byteVal, err := config.ParseByteSize(effectiveLimitInput)
				if err != nil {
					fmt.Printf("❌ Invalid limit value %q: %v\n", effectiveLimitInput, err)
					return
				}
				cfg.Guests[idx].LimitBytes = byteVal
				if byteVal > 0 {
					cfg.Guests[idx].QuotaGB = float64(byteVal) / float64(config.GigaByte)
				} else {
					cfg.Guests[idx].QuotaGB = float64(byteVal)
				}

				if byteVal == 0 {
					cfg.Guests[idx].Enabled = false
					cfg.Guests[idx].DisabledReason = config.GuestDisabledQuotaZero
				} else {
					if cfg.Guests[idx].DisabledReason != config.GuestDisabledManual {
						cfg.Guests[idx].Enabled = true
						cfg.Guests[idx].DisabledReason = config.GuestDisabledNone
					}
				}
				fmt.Printf("✅ Limit for '%s' set to %s.\n", alias, config.FormatByteSize(byteVal))
				success = true
			}
		}

		if cmd.Flags().Changed("notify-trigger") {
			currLimitBytes := cfg.Guests[idx].EffectiveLimitBytes()
			normalizedTriggers, _, err := config.ParseTriggers(notifyTriggerStr, currLimitBytes)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				return
			}
			cfg.Guests[idx].NotifyTrigger = normalizedTriggers
			if len(normalizedTriggers) == 0 {
				fmt.Printf("✅ Notify triggers for '%s' cleared.\n", alias)
			} else {
				fmt.Printf("✅ Notify triggers for '%s' set to [%s].\n", alias, strings.Join(normalizedTriggers, ", "))
			}
			success = true
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
		if cmd.Flags().Changed("notify") {
			mode := config.GuestNotifyMode(strings.ToLower(strings.TrimSpace(notifyStr)))
			switch mode {
			case config.GuestNotifyOff, config.GuestNotifyHeader, config.GuestNotifyRemark, config.GuestNotifyAll:
				cfg.Guests[idx].Notify = mode
				fmt.Printf("✅ Notify mode for '%s' set to '%s'.\n", alias, mode)
				success = true
			default:
				fmt.Printf("❌ Invalid notify mode '%s'. Valid options: off, header, remark, all\n", notifyStr)
			}
		}
		if cmd.Flags().Changed("notify-webhook") {
			webhook := strings.TrimSpace(notifyWebhookStr)
			cfg.Guests[idx].NotifyWebhook = webhook
			if webhook == "" {
				fmt.Printf("✅ Notify webhook for '%s' cleared.\n", alias)
			} else {
				fmt.Printf("✅ Notify webhook for '%s' set to %s.\n", alias, webhook)
			}
			success = true
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
	ValidArgsFunction: completeGuestAliasesArg,
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
	ValidArgsFunction: completeGuestAliasesArg,
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
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		_, guest := findGuest(cfg, args[0])
		if guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		view := quota.BuildGuestView(*guest, time.Now())
		lastReset := view.LastResetYM
		if lastReset == "" {
			lastReset = "-"
		}
		webhook := view.NotifyWebhook
		if webhook == "" {
			webhook = "-"
		}
		triggers := "-"
		if len(view.NotifyTriggers) > 0 {
			triggers = strings.Join(view.NotifyTriggers, ", ")
		}
		alerted := "-"
		if len(view.AlertedTriggers) > 0 {
			alerted = strings.Join(view.AlertedTriggers, ", ")
		}
		fmt.Printf("\nGuest: %s\n", view.Alias)
		fmt.Printf("UUID: %s\n", view.UUID)
		fmt.Printf("State: %s\n", view.StateLabel)
		fmt.Printf("Reason: %s\n", view.ReasonLabel)
		fmt.Printf("Limit: %s\n", config.FormatByteSize(view.LimitBytes))
		fmt.Printf("Used: %s\n", config.FormatByteSize(view.UsedBytes))
		fmt.Printf("Reset Day: %d\n", view.ResetDay)
		fmt.Printf("Last Reset Month: %s\n", lastReset)
		fmt.Printf("Notify: %s\n", guest.NormalizedNotifyMode())
		fmt.Printf("Notify Webhook: %s\n", webhook)
		fmt.Printf("Notify Trigger: %s\n", triggers)
		fmt.Printf("Alerted Triggers: %s\n", alerted)
		fmt.Printf("Relay: %s\n\n", view.RelayLabel)
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
		notify.Wait()
		fmt.Println("✅ Guest state check completed.")
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
	ValidArgsFunction: completeGuestAliasesArg,
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
			fmt.Printf("🔒 Listener: http://%s:%d/guest-sub/<token>\n", cfg.GuestSubBind, cfg.GuestSubPort)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var guestsSubDisableCmd = &cobra.Command{
	Use:   "disable [alias]",
	Short: "Disable self-service subscription for a guest (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
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
	ValidArgsFunction: completeGuestAliasesArg,
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
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		_, guest := findGuest(cfg, args[0])
		if guest == nil {
			fmt.Printf("❌ Guest '%s' not found.\n", args[0])
			return
		}
		tokenOrUUID := guest.UUID
		if tokenOrUUID == "" {
			tokenOrUUID = guest.SubToken
		}
		if tokenOrUUID == "" {
			fmt.Printf("❌ Guest sub is not enabled for '%s'.\n", args[0])
			return
		}
		host := guestSubShowAddr
		if host == "" {
			host = sub.ResolveSubAddress(cfg)
		}
		port := cfg.SubPort
		if port <= 0 {
			port = cfg.AdminSub.Port
		}
		fmt.Printf("\nGuest: %s\n", guest.Alias)
		fmt.Printf("State: %s\n", guestStateLabel(*guest))
		fmt.Printf("Limit: %s\n", config.FormatByteSize(guest.EffectiveLimitBytes()))
		fmt.Printf("Used: %s\n", config.FormatByteSize(guest.UsedBytes))
		fmt.Printf("Reset Day: %d\n", guest.ResetDay)
		fmt.Printf("Notify: %s\n", guest.NormalizedNotifyMode())
		if guest.NormalizedNotifyMode() == config.GuestNotifyRemark || guest.NormalizedNotifyMode() == config.GuestNotifyAll {
			fmt.Printf("Remark Preview: %s\n", sub.FormatGuestSubRemarkForDisplay(*guest, time.Now()))
		}
		fmt.Printf("URL: %s\n\n", guestSubURL(host, port, tokenOrUUID))
	},
}

var (
	guestSubSetAddr string
	guestSubSetPort int
	guestSubSetBind string
)

var guestsSubSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure guest self-service subscription listener and address (STAGING)",
	Example: `  # Set custom hostname for proxy nodes in guest subscriptions
  xray-proxya guests sub set --address proxy.example.com

  # Change guest subscription listener port and bind address
  xray-proxya guests sub set --port 9445 --bind 127.0.0.1`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return err
		}
		ensureGuestSubListenerConfig(cfg)
		changed := false
		if cmd.Flags().Changed("address") {
			cfg.GuestSubAddress = strings.TrimSpace(guestSubSetAddr)
			changed = true
		}
		if cmd.Flags().Changed("port") {
			if guestSubSetPort < 1 || guestSubSetPort > 65535 {
				return fmt.Errorf("port must be between 1 and 65535")
			}
			cfg.GuestSubPort = guestSubSetPort
			changed = true
		}
		if cmd.Flags().Changed("bind") {
			bind := strings.TrimSpace(guestSubSetBind)
			if err := sub.ValidatePrivateBindAddress(bind); err != nil {
				return err
			}
			cfg.GuestSubBind = bind
			changed = true
		}
		if !changed {
			return fmt.Errorf("no parameter supplied")
		}
		if err := cfg.SaveEx(true); err != nil {
			return err
		}
		fmt.Println("✅ Guest subscription configuration updated in STAGING.")
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

func init() {
	guestsSetCmd.Flags().StringVarP(&limitStr, "limit", "l", "", "Set usage limit (e.g. 500MB, 10GB, 1TiB, -1, 0, or 'reset')")
	guestsSetCmd.Flags().StringVarP(&quotaStr, "quota", "q", "", "Set usage limit (deprecated, alias to --limit)")
	guestsSetCmd.Flags().MarkHidden("quota")
	guestsSetCmd.Flags().StringVar(&relayStr, "relay", "", "Set relay node to a proxy link or 'direct'")
	guestsSetCmd.Flags().StringVarP(&outboundStr, "outbound", "o", "", "Set outbound to a proxy link or 'direct' (deprecated)")
	guestsSetCmd.Flags().MarkHidden("outbound")
	guestsSetCmd.Flags().IntVarP(&resetDay, "reset", "r", 1, "Monthly reset day (1-31)")
	guestsSetCmd.Flags().StringVar(&notifyStr, "notify", "", "Subscription usage notify mode (off, header, remark, all)")
	guestsSetCmd.Flags().StringVar(&notifyWebhookStr, "notify-webhook", "", "Set webhook URL for guest usage notifications (or empty to clear)")
	guestsSetCmd.Flags().StringVar(&notifyTriggerStr, "notify-trigger", "", "Set remaining quota triggers, comma-separated (e.g. 80p,45p,40G,5G, or 'none' to clear)")
	guestsSetCmd.RegisterFlagCompletionFunc("limit", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"reset", "-1", "0", "100MB", "10GB", "50GB", "100GB", "1TB", "1TiB"}, cobra.ShellCompDirectiveNoFileComp
	})
	guestsSetCmd.RegisterFlagCompletionFunc("quota", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"reset", "-1", "0", "10", "50", "100"}, cobra.ShellCompDirectiveNoFileComp
	})
	guestsSetCmd.RegisterFlagCompletionFunc("notify-trigger", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"80p,45p,40G,5G", "80p,20p,5G", "none"}, cobra.ShellCompDirectiveNoFileComp
	})
	guestsSetCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return []string{"direct"}, cobra.ShellCompDirectiveNoFileComp
		}
		aliases := []string{"direct"}
		for _, co := range cfg.CustomOutbounds {
			aliases = append(aliases, co.Alias)
		}
		return aliases, cobra.ShellCompDirectiveNoFileComp
	})
	guestsSetCmd.RegisterFlagCompletionFunc("outbound", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return []string{"direct"}, cobra.ShellCompDirectiveNoFileComp
		}
		aliases := []string{"direct"}
		for _, co := range cfg.CustomOutbounds {
			aliases = append(aliases, co.Alias)
		}
		return aliases, cobra.ShellCompDirectiveNoFileComp
	})
	guestsSetCmd.RegisterFlagCompletionFunc("notify", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"off", "header", "remark", "all"}, cobra.ShellCompDirectiveNoFileComp
	})

	guestsSubShowCmd.Flags().StringVarP(&guestSubShowAddr, "address", "a", "", "Override the host used when printing the guest sub URL")

	guestsSubSetCmd.Flags().StringVarP(&guestSubSetAddr, "address", "a", "", "Public IP or domain for proxy nodes in guest subscriptions (or empty to auto-detect)")
	guestsSubSetCmd.Flags().IntVarP(&guestSubSetPort, "port", "p", 0, "Guest subscription listener port (1-65535)")
	guestsSubSetCmd.Flags().StringVarP(&guestSubSetBind, "bind", "b", "", "Guest subscription bind address (loopback or private IP)")

	guestsSubCmd.AddCommand(guestsSubEnableCmd, guestsSubDisableCmd, guestsSubRotateCmd, guestsSubShowCmd, guestsSubSetCmd)
	guestsCmd.AddCommand(guestsListCmd, guestsAddCmd, guestsDelCmd, guestsSetCmd, guestsPauseCmd, guestsResumeCmd, guestsInfoCmd, guestsCheckCmd, guestsSubCmd)
	rootCmd.AddCommand(guestsCmd)
}
