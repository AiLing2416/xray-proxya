package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/endpoint"
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
	relayLinkStr     string
	outboundStr      string
	resetDay         int
	guestSubShowAddr string
	notifyStr        string
	notifyWebhookStr  string
	notifyTriggerStr  string
	guestsListJSON    bool
	guestAddLimit     string
	guestAddRelay     string
	guestAddRelayLink string
	guestAddResetDay  int
	guestAddNotify    string
	guestAddEndpoint  string
	guestSetEndpoint  string
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

func runGuestsList(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load active config.")
	}
	views := quota.BuildAllGuestViews(cfg.Guests, time.Now())
	if guestsListJSON {
		if views == nil {
			views = []quota.GuestQuotaView{}
		}
		data, err := json.MarshalIndent(views, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to serialize guests JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n%-12s | %-8s | %-13s | %-18s | %-8s | %-12s | %-s\n", "ALIAS", "STATE", "REASON", "QUOTA (USED/LIM)", "RESET", "ENDPOINT", "RELAY")
	fmt.Println("-----------------------------------------------------------------------------------------------------------------------------")
	for _, v := range views {
		limit := config.FormatByteSize(v.LimitBytes)
		used := config.FormatByteSize(v.UsedBytes)
		ep := v.Endpoint
		if ep == "" {
			ep = "default"
		}
		fmt.Printf("%-12s | %-8s | %-13s | %-18s | %-8d | %-12s | %-s\n", v.Alias, v.StateLabel, v.ReasonLabel, used+"/"+limit, v.ResetDay, ep, v.RelayLabel)
	}
	fmt.Println()
	return nil
}

var guestsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "Show all guests status and quota",
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsList(cmd, args)
	},
	RunE: runGuestsList,
}

func runGuestsAdd(cmd *cobra.Command, args []string) error {
	alias := args[0]
	// Validate alias: alphanumeric and underscore only, 3-20 chars
	if len(alias) < 3 || len(alias) > 20 {
		return fmt.Errorf("❌ Guest alias must be between 3 and 20 characters.")
	}
	for _, r := range alias {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("❌ Invalid guest alias: %s (Only alphanumeric, underscore, and hyphen allowed)", alias)
		}
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	for _, g := range cfg.Guests {
		if g.Alias == alias {
			return fmt.Errorf("❌ Guest '%s' already exists.", alias)
		}
	}

	hasRelay := (cmd != nil && cmd.Flags().Changed("relay")) || guestAddRelay != ""
	hasRelayLink := (cmd != nil && cmd.Flags().Changed("relay-link")) || guestAddRelayLink != ""

	if hasRelay && hasRelayLink {
		return fmt.Errorf("❌ Error: Cannot specify both --relay and --relay-link")
	}

	newG := config.GuestConfig{
		Alias:          alias,
		UUID:           uuid.New().String(),
		Enabled:        true,
		DisabledReason: config.GuestDisabledNone,
		QuotaGB:        -1,
		LimitBytes:     -1,
		ResetDay:       1,
		Notify:         config.GuestNotifyOff,
	}

	// 1. Limit
	limitInput := strings.TrimSpace(guestAddLimit)
	if cmd != nil && cmd.Flags().Changed("limit") {
		limitInput = strings.TrimSpace(cmd.Flag("limit").Value.String())
	}
	if limitInput != "" {
		if strings.EqualFold(limitInput, "reset") {
			return fmt.Errorf("❌ 'reset' is only valid for 'guests set', not 'guests add'.")
		}
		byteVal, err := config.ParseByteSize(limitInput)
		if err != nil {
			return fmt.Errorf("❌ Invalid limit value %q: %w", limitInput, err)
		}
		newG.LimitBytes = byteVal
		if byteVal > 0 {
			newG.QuotaGB = float64(byteVal) / float64(config.GigaByte)
		} else {
			newG.QuotaGB = float64(byteVal)
		}
		if byteVal == 0 {
			newG.Enabled = false
			newG.DisabledReason = config.GuestDisabledQuotaZero
		}
	}

	// 2. Relay / RelayLink
	if hasRelayLink {
		rawLink := strings.TrimSpace(guestAddRelayLink)
		if cmd != nil && cmd.Flags().Changed("relay-link") {
			rawLink = strings.TrimSpace(cmd.Flag("relay-link").Value.String())
		}
		if rawLink == "" {
			return fmt.Errorf("❌ Error: --relay-link cannot be empty")
		}
		conf, err := xray.ParseProxyLink(rawLink)
		if err != nil {
			return fmt.Errorf("❌ Failed to parse link: %w", err)
		}
		newG.OutboundLink = rawLink
		newG.OutboundConf = conf
	} else if hasRelay {
		targetRelay := strings.TrimSpace(guestAddRelay)
		if cmd != nil && cmd.Flags().Changed("relay") {
			targetRelay = strings.TrimSpace(cmd.Flag("relay").Value.String())
		}
		if targetRelay == "direct" {
			newG.OutboundLink = ""
			newG.OutboundConf = nil
		} else {
			var found *config.CustomOutbound
			for _, co := range cfg.CustomOutbounds {
				if co.Alias == targetRelay {
					found = &co
					break
				}
			}
			if found != nil {
				newG.OutboundLink = found.Alias
				newG.OutboundConf = found.Config
			} else {
				return fmt.Errorf("❌ Relay '%s' not found.", targetRelay)
			}
		}
	}

	// 3. Reset day
	effectiveResetDay := guestAddResetDay
	if cmd != nil && cmd.Flags().Changed("reset") {
		rVal, err := cmd.Flags().GetInt("reset")
		if err == nil {
			effectiveResetDay = rVal
		}
	}
	if effectiveResetDay >= 1 && effectiveResetDay <= 31 {
		newG.ResetDay = effectiveResetDay
	} else {
		return fmt.Errorf("❌ Reset day must be between 1 and 31.")
	}

	// 4. Notify
	notifyInput := strings.TrimSpace(guestAddNotify)
	if cmd != nil && cmd.Flags().Changed("notify") {
		notifyInput = strings.TrimSpace(cmd.Flag("notify").Value.String())
	}
	if notifyInput != "" {
		mode := config.GuestNotifyMode(strings.ToLower(notifyInput))
		switch mode {
		case config.GuestNotifyOff, config.GuestNotifyHeader, config.GuestNotifyRemark, config.GuestNotifyAll:
			newG.Notify = mode
		default:
			return fmt.Errorf("❌ Invalid notify mode '%s'. Valid options: off, header, remark, all", notifyInput)
		}
	}

	// 5. Endpoint
	if cmd != nil && cmd.Flags().Changed("endpoint") {
		epVal := strings.TrimSpace(guestAddEndpoint)
		if epVal == "" {
			return fmt.Errorf("❌ Error: Endpoint cannot be empty. Specify a valid endpoint alias (e.g. -e default) or comma-separated list.")
		}
		if _, err := endpoint.ResolveTargets(cfg, epVal, "guest:"+alias, false); err != nil {
			return fmt.Errorf("❌ Error: Invalid endpoint %q: %w", epVal, err)
		}
		newG.Endpoint = epVal
	} else {
		newG.Endpoint = "default"
	}
	defer func() {
		guestAddEndpoint = ""
		if cmd != nil {
			if f := cmd.Flag("endpoint"); f != nil {
				f.Changed = false
				_ = f.Value.Set("")
			}
		}
	}()

	cfg.Guests = append(cfg.Guests, newG)
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}

	limitDesc := config.FormatByteSize(newG.LimitBytes)
	relayDesc := "direct"
	if newG.OutboundLink != "" {
		relayDesc = newG.OutboundLink
	}
	epDesc := "default"
	if newG.Endpoint != "" {
		epDesc = newG.Endpoint
	}
	fmt.Printf("✅ Guest '%s' added to STAGING. Limit: %s, Relay: %s, Endpoint: %s, Reset Day: %d. Run 'apply' to commit.\n",
		alias, limitDesc, relayDesc, epDesc, newG.ResetDay)
	return nil
}

var guestsAddCmd = &cobra.Command{
	Use:   "add [alias]",
	Short: "Add a new guest user (STAGING)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsAdd(cmd, args)
	},
	RunE: runGuestsAdd,
}

func runGuestsRemove(cmd *cobra.Command, args []string) error {
	alias := args[0]
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
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
	if !found {
		return fmt.Errorf("❌ Guest '%s' not found.", alias)
	}
	cfg.Guests = newGuests
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Guest '%s' removed from STAGING.\n", alias)
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var guestsRemoveCmd = &cobra.Command{
	Use:               "remove [alias]",
	Aliases:           []string{"rm", "del", "delete"},
	Short:             "Remove a guest user (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsRemove(cmd, args)
	},
	RunE: runGuestsRemove,
}

func runGuestsSet(cmd *cobra.Command, args []string) error {
	alias := args[0]
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	idx, guest := findGuest(cfg, alias)
	if idx == -1 || guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", alias)
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
				return fmt.Errorf("❌ Invalid limit value %q: %w", effectiveLimitInput, err)
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

	if cmd != nil && cmd.Flags().Changed("notify-trigger") {
		currLimitBytes := cfg.Guests[idx].EffectiveLimitBytes()
		normalizedTriggers, _, err := config.ParseTriggers(notifyTriggerStr, currLimitBytes)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		cfg.Guests[idx].NotifyTrigger = normalizedTriggers
		if len(normalizedTriggers) == 0 {
			fmt.Printf("✅ Notify triggers for '%s' cleared.\n", alias)
		} else {
			fmt.Printf("✅ Notify triggers for '%s' set to [%s].\n", alias, strings.Join(normalizedTriggers, ", "))
		}
		success = true
	}
	hasRelay := (cmd != nil && (cmd.Flags().Changed("relay") || cmd.Flags().Changed("outbound"))) || relayStr != "" || outboundStr != ""
	hasRelayLink := (cmd != nil && cmd.Flags().Changed("relay-link")) || relayLinkStr != ""

	if hasRelay && hasRelayLink {
		return fmt.Errorf("❌ Error: Cannot specify both --relay and --relay-link")
	}

	if hasRelayLink {
		rawLink := strings.TrimSpace(relayLinkStr)
		if rawLink == "" {
			return fmt.Errorf("❌ Error: --relay-link cannot be empty")
		}
		conf, err := xray.ParseProxyLink(rawLink)
		if err != nil {
			return fmt.Errorf("❌ Failed to parse link: %w", err)
		}
		cfg.Guests[idx].OutboundLink = rawLink
		cfg.Guests[idx].OutboundConf = conf
		fmt.Printf("✅ Relay for '%s' updated via link.\n", alias)
		success = true
	} else if hasRelay {
		targetRelay := strings.TrimSpace(relayStr)
		if targetRelay == "" {
			targetRelay = strings.TrimSpace(outboundStr)
		}
		if targetRelay == "direct" {
			cfg.Guests[idx].OutboundLink = ""
			cfg.Guests[idx].OutboundConf = nil
			fmt.Printf("✅ Relay for '%s' set to direct.\n", alias)
			success = true
		} else {
			var found *config.CustomOutbound
			for _, co := range cfg.CustomOutbounds {
				if co.Alias == targetRelay {
					found = &co
					break
				}
			}
			if found != nil {
				cfg.Guests[idx].OutboundLink = found.Alias
				cfg.Guests[idx].OutboundConf = found.Config
				fmt.Printf("✅ Relay for '%s' set to '%s'.\n", alias, found.Alias)
				success = true
			} else {
				return fmt.Errorf("❌ Relay '%s' not found.", targetRelay)
			}
		}
	}
	if cmd != nil && cmd.Flags().Changed("reset") {
		if resetDay >= 1 && resetDay <= 31 {
			cfg.Guests[idx].ResetDay = resetDay
			fmt.Printf("✅ Reset day for '%s' set to %d.\n", alias, resetDay)
			success = true
		} else {
			return fmt.Errorf("❌ Reset day must be between 1 and 31.")
		}
	}
	if cmd != nil && cmd.Flags().Changed("notify") {
		mode := config.GuestNotifyMode(strings.ToLower(strings.TrimSpace(notifyStr)))
		switch mode {
		case config.GuestNotifyOff, config.GuestNotifyHeader, config.GuestNotifyRemark, config.GuestNotifyAll:
			cfg.Guests[idx].Notify = mode
			fmt.Printf("✅ Notify mode for '%s' set to '%s'.\n", alias, mode)
			success = true
		default:
			return fmt.Errorf("❌ Invalid notify mode '%s'. Valid options: off, header, remark, all", notifyStr)
		}
	}
	if cmd != nil && cmd.Flags().Changed("notify-webhook") {
		webhook := strings.TrimSpace(notifyWebhookStr)
		cfg.Guests[idx].NotifyWebhook = webhook
		if webhook == "" {
			fmt.Printf("✅ Notify webhook for '%s' cleared.\n", alias)
		} else {
			fmt.Printf("✅ Notify webhook for '%s' set to %s.\n", alias, webhook)
		}
		success = true
	}
	if cmd != nil && cmd.Flags().Changed("endpoint") {
		epVal := strings.TrimSpace(guestSetEndpoint)
		if epVal == "" {
			return fmt.Errorf("❌ Error: Endpoint cannot be empty. Specify a valid endpoint alias (e.g. -e default) or comma-separated list.")
		}
		if _, err := endpoint.ResolveTargets(cfg, epVal, "guest:"+alias, false); err != nil {
			return fmt.Errorf("❌ Error: Invalid endpoint %q: %w", epVal, err)
		}
		cfg.Guests[idx].Endpoint = epVal
		fmt.Printf("✅ Endpoint for '%s' set to '%s'.\n", alias, epVal)
		success = true
	}
	defer func() {
		guestSetEndpoint = ""
		if cmd != nil {
			if f := cmd.Flag("endpoint"); f != nil {
				f.Changed = false
				_ = f.Value.Set("")
			}
		}
	}()
	if success {
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("❌ Failed to save staging config: %w", err)
		}
		fmt.Println("🚀 Run 'apply' to commit changes.")
	}
	return nil
}

var guestsSetCmd = &cobra.Command{
	Use:               "set [alias]",
	Short:             "Configure guest parameters (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsSet(cmd, args)
	},
	RunE: runGuestsSet,
}

func runGuestsPause(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	idx, guest := findGuest(cfg, args[0])
	if idx == -1 || guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
	}
	cfg.Guests[idx].Enabled = false
	cfg.Guests[idx].DisabledReason = config.GuestDisabledManual
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Guest '%s' paused in STAGING.\n", args[0])
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var guestsPauseCmd = &cobra.Command{
	Use:               "pause [alias]",
	Short:             "Pause a guest manually (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsPause(cmd, args)
	},
	RunE: runGuestsPause,
}

func runGuestsResume(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	idx, guest := findGuest(cfg, args[0])
	if idx == -1 || guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
	}
	if cfg.Guests[idx].QuotaGB == 0 {
		return fmt.Errorf("❌ Guest '%s' still has quota=0. Set a positive quota first.", args[0])
	}
	cfg.Guests[idx].Enabled = true
	cfg.Guests[idx].DisabledReason = config.GuestDisabledNone
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Guest '%s' resumed in STAGING.\n", args[0])
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var guestsResumeCmd = &cobra.Command{
	Use:               "resume [alias]",
	Short:             "Resume a paused guest (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsResume(cmd, args)
	},
	RunE: runGuestsResume,
}

func runGuestsInfo(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load active config: %v", err)
	}
	_, guest := findGuest(cfg, args[0])
	if guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
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
	ep := view.Endpoint
	if ep == "" {
		ep = "default"
	}
	fmt.Printf("Endpoint: %s\n", ep)
	fmt.Printf("Notify: %s\n", guest.NormalizedNotifyMode())
	fmt.Printf("Notify Webhook: %s\n", webhook)
	fmt.Printf("Notify Trigger: %s\n", triggers)
	fmt.Printf("Alerted Triggers: %s\n", alerted)
	fmt.Printf("Relay: %s\n\n", view.RelayLabel)
	return nil
}

var guestsInfoCmd = &cobra.Command{
	Use:               "info [alias]",
	Aliases:           []string{"show"},
	Short:             "Show detailed guest runtime state",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsInfo(cmd, args)
	},
	RunE: runGuestsInfo,
}

func runGuestsCheck(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Error: Failed to load active config.")
	}
	monitor, err := quota.LoadMonitor()
	if err != nil {
		fmt.Printf("⚠️  Failed to load quota monitor state: %v\n", err)
		monitor = quota.NewMonitor()
	}
	update, err := checkGuestQuotaState(cfg, monitor, time.Now())
	if err != nil {
		return fmt.Errorf("❌ Guest check failed: %w", err)
	}
	if !update.Changed {
		fmt.Println("ℹ️ No guest state changes were needed.")
		return nil
	}
	for _, msg := range update.Messages {
		fmt.Printf("ℹ️  %s\n", msg)
	}
	if update.RestartNeeded {
		fmt.Println("🔄 Restarting service to apply guest state changes...")
		if err := xray.RestartXrayService(); err != nil {
			return fmt.Errorf("❌ State updated, but restart failed: %w", err)
		}
	}
	notify.Wait()
	fmt.Println("✅ Guest state check completed.")
	return nil
}

var guestsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check quota usage now and update active guest states",
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsCheck(cmd, args)
	},
	RunE: runGuestsCheck,
}

var guestsSubCmd = &cobra.Command{
	Use:   "sub",
	Short: "Manage guest self-service subscription links (STAGING)",
	Long: `Manage guest self-service subscription links (STAGING).
For central server subscription distribution, see 'xray-proxya sub'.`,
}

func runGuestsSubEnable(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	idx, guest := findGuest(cfg, args[0])
	if idx == -1 || guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
	}
	ensureGuestSubListenerConfig(cfg)
	if cfg.Guests[idx].SubToken == "" {
		cfg.Guests[idx].SubToken = utils.GenerateRandomString(32)
	}
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Guest sub enabled for '%s' in STAGING.\n", args[0])
	fmt.Printf("🔒 Listener: http://%s:%d/guest-sub/<token>\n", cfg.GuestSubBind, cfg.GuestSubPort)
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var guestsSubEnableCmd = &cobra.Command{
	Use:               "enable [alias]",
	Short:             "Enable self-service subscription for a guest (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsSubEnable(cmd, args)
	},
	RunE: runGuestsSubEnable,
}

func runGuestsSubDisable(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	idx, guest := findGuest(cfg, args[0])
	if idx == -1 || guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
	}
	cfg.Guests[idx].SubToken = ""
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Guest sub disabled for '%s' in STAGING.\n", args[0])
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var guestsSubDisableCmd = &cobra.Command{
	Use:               "disable [alias]",
	Short:             "Disable self-service subscription for a guest (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsSubDisable(cmd, args)
	},
	RunE: runGuestsSubDisable,
}

func runGuestsSubRotate(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	idx, guest := findGuest(cfg, args[0])
	if idx == -1 || guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
	}
	ensureGuestSubListenerConfig(cfg)
	cfg.Guests[idx].SubToken = utils.GenerateRandomString(32)
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Guest sub token rotated for '%s' in STAGING.\n", args[0])
	fmt.Println("🚀 Run 'apply' to commit changes.")
	return nil
}

var guestsSubRotateCmd = &cobra.Command{
	Use:               "rotate [alias]",
	Short:             "Rotate the guest self-service subscription token (STAGING)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsSubRotate(cmd, args)
	},
	RunE: runGuestsSubRotate,
}

func runGuestsSubShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}
	_, guest := findGuest(cfg, args[0])
	if guest == nil {
		return fmt.Errorf("❌ Guest '%s' not found.", args[0])
	}
	tokenOrUUID := guest.UUID
	if tokenOrUUID == "" {
		tokenOrUUID = guest.SubToken
	}
	if tokenOrUUID == "" {
		return fmt.Errorf("❌ Guest sub is not enabled for '%s'.", args[0])
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
	ep := guest.Endpoint
	if ep == "" {
		ep = "default"
	}
	fmt.Printf("Endpoint: %s\n", ep)
	fmt.Printf("Notify: %s\n", guest.NormalizedNotifyMode())
	if guest.NormalizedNotifyMode() == config.GuestNotifyRemark || guest.NormalizedNotifyMode() == config.GuestNotifyAll {
		fmt.Printf("Remark Preview: %s\n", sub.FormatGuestSubRemarkForDisplay(*guest, time.Now()))
	}
	fmt.Printf("URL: %s\n\n", guestSubURL(host, port, tokenOrUUID))
	return nil
}

var guestsSubShowCmd = &cobra.Command{
	Use:               "show [alias]",
	Short:             "Show a guest self-service subscription link",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeGuestAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runGuestsSubShow(cmd, args)
	},
	RunE: runGuestsSubShow,
}

var (
	guestSubSetAddr   string
	guestSubSetPort   int
	guestSubSetBind   string
	guestSubSetListen string
)

var guestsSubSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure guest self-service subscription listener and address (STAGING)",
	Example: `  # Set custom hostname for proxy nodes in guest subscriptions
  xray-proxya guests sub set --address proxy.example.com

  # Change guest subscription listener port and listen/bind address
  xray-proxya guests sub set --port 9445 --listen 127.0.0.1`,
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
		bindVal := ""
		if cmd.Flags().Changed("listen") {
			bindVal = strings.TrimSpace(guestSubSetListen)
		} else if cmd.Flags().Changed("bind") {
			bindVal = strings.TrimSpace(guestSubSetBind)
		}
		if bindVal != "" {
			if err := sub.ValidatePrivateBindAddress(bindVal); err != nil {
				return err
			}
			cfg.GuestSubBind = bindVal
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
	guestsAddCmd.Flags().StringVarP(&guestAddLimit, "limit", "l", "", "Set initial usage limit (e.g. 500MB, 10GB, 1TiB, -1, 0)")
	guestsAddCmd.Flags().StringVar(&guestAddRelay, "relay", "", "Bind guest to a configured relay alias or 'direct'")
	guestsAddCmd.Flags().StringVar(&guestAddRelayLink, "relay-link", "", "Set relay outbound to a raw proxy link (e.g. vless://...)")
	guestsAddCmd.Flags().StringVarP(&guestAddEndpoint, "endpoint", "e", "", "Bind guest to a connection endpoint")
	guestsAddCmd.Flags().IntVarP(&guestAddResetDay, "reset", "r", 1, "Monthly reset day (1-31)")
	guestsAddCmd.Flags().StringVar(&guestAddNotify, "notify", "", "Subscription usage notify mode (off, header, remark, all)")
	guestsAddCmd.RegisterFlagCompletionFunc("endpoint", completeEndpointNames)
	guestsAddCmd.RegisterFlagCompletionFunc("limit", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"-1", "0", "100MB", "10GB", "50GB", "100GB", "1TB", "1TiB"}, cobra.ShellCompDirectiveNoFileComp
	})
	guestsAddCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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
	guestsAddCmd.RegisterFlagCompletionFunc("notify", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"off", "header", "remark", "all"}, cobra.ShellCompDirectiveNoFileComp
	})

	guestsSetCmd.Flags().StringVarP(&limitStr, "limit", "l", "", "Set usage limit (e.g. 500MB, 10GB, 1TiB, -1, 0, or 'reset')")
	guestsSetCmd.Flags().StringVarP(&quotaStr, "quota", "q", "", "Set usage limit (deprecated, alias to --limit)")
	guestsSetCmd.Flags().MarkHidden("quota")
	guestsSetCmd.Flags().StringVar(&relayStr, "relay", "", "Bind guest to a configured relay alias or 'direct'")
	guestsSetCmd.Flags().StringVar(&relayLinkStr, "relay-link", "", "Set relay outbound to a raw proxy link (e.g. vless://...)")
	guestsSetCmd.Flags().StringVarP(&guestSetEndpoint, "endpoint", "e", "", "Bind guest to a connection endpoint (or 'default')")
	guestsSetCmd.Flags().StringVarP(&outboundStr, "outbound", "o", "", "Set outbound to a proxy link or 'direct' (deprecated)")
	guestsSetCmd.Flags().MarkHidden("outbound")
	guestsSetCmd.Flags().IntVarP(&resetDay, "reset", "r", 1, "Monthly reset day (1-31)")
	guestsSetCmd.Flags().StringVar(&notifyStr, "notify", "", "Subscription usage notify mode (off, header, remark, all)")
	guestsSetCmd.Flags().StringVar(&notifyWebhookStr, "notify-webhook", "", "Set webhook URL for guest usage notifications (or empty to clear)")
	guestsSetCmd.Flags().StringVar(&notifyTriggerStr, "notify-trigger", "", "Set remaining quota triggers, comma-separated (e.g. 80p,45p,40G,5G, or 'none' to clear)")
	guestsSetCmd.RegisterFlagCompletionFunc("endpoint", completeEndpointNames)
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
	guestsSubSetCmd.Flags().StringVarP(&guestSubSetListen, "listen", "l", "", "Guest subscription bind address (loopback or private IP)")
	guestsSubSetCmd.Flags().StringVarP(&guestSubSetBind, "bind", "b", "", "Guest subscription bind address (loopback or private IP)")
	guestsSubSetCmd.RegisterFlagCompletionFunc("listen", completeIPListenAddresses)

	guestsListCmd.Flags().BoolVar(&guestsListJSON, "json", false, "Output guests list in JSON format")
	guestsSubCmd.AddCommand(guestsSubEnableCmd, guestsSubDisableCmd, guestsSubRotateCmd, guestsSubShowCmd, guestsSubSetCmd)
	guestsCmd.AddCommand(guestsListCmd, guestsAddCmd, guestsRemoveCmd, guestsSetCmd, guestsPauseCmd, guestsResumeCmd, guestsInfoCmd, guestsCheckCmd, guestsSubCmd)
	rootCmd.AddCommand(guestsCmd)
}
