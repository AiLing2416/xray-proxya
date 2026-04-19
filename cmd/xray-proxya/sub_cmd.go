package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	Short: "Manage subscription links and standalone HTTPS server",
}

func getSubscriptionAliases() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil { return nil }
	var aliases []string
	for _, s := range cfg.Subscriptions {
		aliases = append(aliases, s.Alias)
	}
	return aliases
}

// --- Service Management ---

func getSubServicePath() string {
	return "/etc/systemd/system/xray-proxya-sub.service"
}

var subStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the subscription service",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() { fmt.Println("❌ Requires root."); return }
		exec.Command("systemctl", "start", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service started.")
	},
}

var subStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the subscription service",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() { fmt.Println("❌ Requires root."); return }
		exec.Command("systemctl", "stop", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service stopped.")
	},
}

var subRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the subscription service",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() { fmt.Println("❌ Requires root."); return }
		exec.Command("systemctl", "restart", "xray-proxya-sub").Run()
		fmt.Println("✅ Subscription service restarted.")
	},
}

var subEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable sub-server (Install service & autostart)",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() { fmt.Println("❌ Requires root."); return }
		binPath, _ := os.Executable()
		home, _ := os.UserHomeDir()
		if os.Geteuid() == 0 { home = "/root" }
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
		if !utils.IsRoot() { fmt.Println("❌ Requires root."); return }
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
		port := subPort
		if !cmd.Flags().Changed("port") && cfg.SubPort > 0 { port = cfg.SubPort }

		// v0.2.4: Explicitly audit and persist ONLY during RUN
		if !utils.IsPortFree(port) {
			p, _ := xray.GetFreePort()
			fmt.Printf("⚠️  Warning: Subscription Port %d occupied, using %d\n", port, p)
			port = p
			cfg.SubPort = port
			cfg.Save()
		}

		if err := sub.StartSubServer(port); err != nil {

			fmt.Printf("❌ Failed: %v\n", err)
		}
	},
}

// --- Link Management (Remains same) ---

var subGenCmd = &cobra.Command{
	Use:   "gen [alias]",
	Short: "Generate a subscription link (STAGING)",
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		alias := ""; if len(args) > 0 { alias = args[0] }
		cfg, _ := config.LoadConfigEx(true)
		targetType := "direct"; targetAlias := ""
		if subOutbound != "" { targetType = "outbound"; targetAlias = subOutbound
		} else if subGuest != "" { targetType = "guest"; targetAlias = subGuest }

		foundIdx := -1
		for i, s := range cfg.Subscriptions {
			if s.Alias == alias { foundIdx = i; break }
		}

		newToken := utils.GenerateRandomString(8)
		newSub := config.Subscription{Alias: alias, TargetType: targetType, TargetAlias: targetAlias, Address: subAddress, Token: newToken}

		if foundIdx != -1 { cfg.Subscriptions[foundIdx] = newSub
		} else { cfg.Subscriptions = append(cfg.Subscriptions, newSub) }

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
		if subAll { cfg.Subscriptions = nil; cfg.SaveEx(true); return }
		alias := ""; if len(args) > 0 { alias = args[0] }
		var newSubs []config.Subscription
		found := false
		for _, s := range cfg.Subscriptions {
			if s.Alias == alias { found = true; continue }
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
	subGenCmd.Flags().StringVarP(&subOutbound, "outbound", "o", "", "Target custom outbound alias")
	subGenCmd.Flags().StringVarP(&subGuest, "guest", "g", "", "Target guest alias")
	subGenCmd.Flags().StringVarP(&subAddress, "address", "a", "", "Override address in links")
	
	subDelCmd.Flags().BoolVarP(&subAll, "all", "A", false, "Delete all subscriptions")
	subRunCmd.Flags().IntVarP(&subPort, "port", "p", 8443, "HTTPS port")

	subCmd.AddCommand(subGenCmd, subDelCmd, subRunCmd, subStartCmd, subStopCmd, subRestartCmd, subEnableCmd, subDisableCmd)
	rootCmd.AddCommand(subCmd)
}
