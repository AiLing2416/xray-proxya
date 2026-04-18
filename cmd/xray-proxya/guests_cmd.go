package main

import (
	"fmt"
	"strconv"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	quotaStr    string
	outboundStr string
	resetDay    int
)

var guestsCmd = &cobra.Command{
	Use:   "guests",
	Aliases: []string{"guest"},
	Short: "Manage multi-tenant guests (STAGING)",
}

func getGuestAliases() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil { return nil }
	var aliases []string
	for _, g := range cfg.Guests { aliases = append(aliases, g.Alias) }
	return aliases
}

var guestsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all guests status and quota",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		fmt.Printf("\n%-12s | %-8s | %-15s | %-8s | %-s\n", "ALIAS", "STATE", "QUOTA (USED/LIM)", "RESET", "OUTBOUND")
		fmt.Println("------------------------------------------------------------------------------------")
		for _, g := range cfg.Guests {
			state := "OFF"; if g.Enabled { state = "ON" }
			limit := "Unlimited"; if g.QuotaGB > 0 { limit = fmt.Sprintf("%.1fGB", g.QuotaGB) } else if g.QuotaGB == 0 { limit = "PAUSED" }
			used := fmt.Sprintf("%.2fGB", float64(g.UsedBytes)/(1024*1024*1024))
			out := "direct"; if g.OutboundLink != "" { out = "custom-link" }
			fmt.Printf("%-12s | %-8s | %-15s | %-8d | %-s\n", g.Alias, state, used+"/"+limit, g.ResetDay, out)
		}
		fmt.Println()
	},
}

var guestsAddCmd = &cobra.Command{
	Use:   "add [alias]",
	Short: "Add a new guest user",
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

		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		for _, g := range cfg.Guests {
			if g.Alias == alias { fmt.Printf("❌ Guest '%s' already exists.\n", alias); return }
		}
		newG := config.GuestConfig{
			Alias: alias, UUID: uuid.New().String(), Enabled: true, QuotaGB: -1, ResetDay: 1,
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
	Short: "Remove a guest user",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		var newGuests []config.GuestConfig
		found := false
		for _, g := range cfg.Guests {
			if g.Alias == alias { found = true; continue }
			newGuests = append(newGuests, g)
		}
		if found {
			cfg.Guests = newGuests
			cfg.SaveEx(true)
			fmt.Printf("✅ Guest '%s' removed from STAGING.\n", alias)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		} else { fmt.Printf("❌ Guest '%s' not found.\n", alias) }
	},
}

var guestsSetCmd = &cobra.Command{
	Use:   "set [alias]",
	Short: "Configure guest parameters (quota, outbound, reset day)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getGuestAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		idx := -1
		for i, g := range cfg.Guests { if g.Alias == alias { idx = i; break } }
		if idx == -1 { fmt.Printf("❌ Guest '%s' not found.\n", alias); return }

		success := false
		if quotaStr != "" {
			if quotaStr == "reset" {
				cfg.Guests[idx].UsedBytes = 0
				fmt.Printf("✅ Usage for '%s' reset to 0.\n", alias)
				success = true
			} else {
				val, err := strconv.ParseFloat(quotaStr, 64)
				if err == nil {
					cfg.Guests[idx].QuotaGB = val
					if val == 0 { cfg.Guests[idx].Enabled = false } else { cfg.Guests[idx].Enabled = true }
					fmt.Printf("✅ Quota for '%s' set to %.1f GB.\n", alias, val)
					success = true
				}
			}
		}
		if outboundStr != "" {
			if outboundStr == "direct" {
				cfg.Guests[idx].OutboundLink = ""; cfg.Guests[idx].OutboundConf = nil
				fmt.Printf("✅ Outbound for '%s' set to direct.\n", alias)
				success = true
			} else {
				conf, err := xray.ParseProxyLink(outboundStr)
				if err == nil {
					cfg.Guests[idx].OutboundLink = outboundStr; cfg.Guests[idx].OutboundConf = conf
					fmt.Printf("✅ Outbound for '%s' updated via link.\n", alias)
					success = true
				} else { fmt.Printf("❌ Failed to parse link: %v\n", err) }
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
		for i := range cfg.Guests { if cfg.Guests[i].Alias == alias { target = &cfg.Guests[i]; break } }
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
			for _, l := range links { fmt.Println(l) }
		}
		fmt.Println()
	},
}

func init() {
	guestsSetCmd.Flags().StringVarP(&quotaStr, "quota", "q", "", "Set quota (GB, -1, 0, or 'reset')")
	guestsSetCmd.Flags().StringVarP(&outboundStr, "outbound", "o", "", "Set custom outbound link or 'direct'")
	guestsSetCmd.Flags().IntVarP(&resetDay, "reset", "r", 1, "Monthly reset day (1-31)")

	guestsShowCmd.Flags().BoolP("ipv4", "4", true, "Use IPv4")
	guestsShowCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6")
	guestsShowCmd.Flags().BoolP("all", "a", false, "Show all available IPs")

	guestsCmd.AddCommand(guestsListCmd, guestsAddCmd, guestsDelCmd, guestsSetCmd, guestsShowCmd)
	rootCmd.AddCommand(guestsCmd)
}
