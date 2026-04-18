package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/sub"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	subOutbound string
	subGuest    string
	subAddress  string
	subAll      bool
	subPort     int
)

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Manage subscription links and server",
}

var subGenCmd = &cobra.Command{
	Use:   "gen [alias]",
	Short: "Generate a subscription link (STAGING)",
	Long: `Generate a subscription link for direct outbound, a specific guest, or a custom outbound.
If no alias is provided, it defaults to the direct outbound subscription.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		alias := ""
		if len(args) > 0 {
			alias = args[0]
		}

		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Println("❌ Failed to load config.")
			return
		}

		targetType := "direct"
		targetAlias := ""
		if subOutbound != "" {
			targetType = "outbound"
			targetAlias = subOutbound
		} else if subGuest != "" {
			targetType = "guest"
			targetAlias = subGuest
		}

		// Check if alias already exists
		foundIdx := -1
		for i, s := range cfg.Subscriptions {
			if s.Alias == alias {
				foundIdx = i
				break
			}
		}

		newToken := utils.GenerateRandomString(8)
		newSub := config.Subscription{
			Alias:       alias,
			TargetType:  targetType,
			TargetAlias: targetAlias,
			Address:     subAddress,
			Token:       newToken,
		}

		if foundIdx != -1 {
			cfg.Subscriptions[foundIdx] = newSub
			fmt.Printf("✅ Updated subscription '%s' in STAGING.\n", alias)
		} else {
			cfg.Subscriptions = append(cfg.Subscriptions, newSub)
			fmt.Printf("✅ Generated new subscription '%s' in STAGING.\n", alias)
		}

		if err := cfg.SaveEx(true); err == nil {
			fmt.Printf("🔗 Path: /sub/%s\n", newToken)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var subDelCmd = &cobra.Command{
	Use:   "del [alias]",
	Short: "Delete a subscription link (STAGING)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Println("❌ Failed to load config.")
			return
		}

		if subAll {
			cfg.Subscriptions = nil
			cfg.SaveEx(true)
			fmt.Println("✅ Deleted all subscriptions in STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
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
			fmt.Printf("✅ Deleted subscription '%s' in STAGING.\n", alias)
			fmt.Println("🚀 Run 'apply' to commit changes.")
		} else {
			fmt.Printf("❌ Subscription '%s' not found.\n", alias)
		}
	},
}

var subServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the subscription HTTPS server",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("❌ Failed to load config.")
			return
		}

		finalPort := subPort
		// If flag -p 8443 (default) is used, we check if we should use saved port
		if !cmd.Flags().Changed("port") {
			if cfg.SubPort > 0 {
				finalPort = cfg.SubPort
			}
		}

		// Validation: Check if the selected port is free.
		// If not, find a new random port.
		if !utils.IsPortFree(finalPort) {
			fmt.Printf("⚠️  Port %d is already in use.\n", finalPort)
			newP, err := xray.GetFreePort()
			if err != nil {
				fmt.Printf("❌ Failed to find a free port: %v\n", err)
				return
			}
			finalPort = newP
			fmt.Printf("🔄 Auto-selected free port: %d\n", finalPort)
		}

		// Save the selected port to config for future runs
		if cfg.SubPort != finalPort {
			cfg.SubPort = finalPort
			cfg.Save()
			fmt.Printf("💾 Port %d saved to config.\n", finalPort)
		}

		if err := sub.StartSubServer(finalPort); err != nil {
			fmt.Printf("❌ Server error: %v\n", err)
		}
	},
}

func init() {
	subGenCmd.Flags().StringVarP(&subOutbound, "outbound", "o", "", "Target custom outbound alias")
	subGenCmd.Flags().StringVarP(&subGuest, "guest", "g", "", "Target guest alias")
	subGenCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Override server address/hostname in links")

	subDelCmd.Flags().BoolVarP(&subAll, "all", "a", false, "Delete all subscriptions")

	subServeCmd.Flags().IntVarP(&subPort, "port", "p", 8443, "HTTPS port to listen on (default 8443, auto-fallback if busy)")

	subCmd.AddCommand(subGenCmd, subDelCmd, subServeCmd)
	rootCmd.AddCommand(subCmd)
}
