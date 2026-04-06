package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Xray service in background using current config",
	Run: func(cmd *cobra.Command, args []string) {
		active, pid := xray.GetXrayStatus()
		if active {
			fmt.Printf("ℹ️ Xray is already running (PID: %d).\n", pid)
			return
		}
		if err := xray.StartXrayBackground(); err != nil {
			fmt.Printf("❌ Failed to start: %v\n", err)
		}
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running Xray service",
	Run: func(cmd *cobra.Command, args []string) {
		active, pid := xray.GetXrayStatus()
		if !active {
			fmt.Println("ℹ️ Xray is not running.")
			return
		}
		fmt.Printf("🛑 Stopping Xray (PID: %d)...\n", pid)
		xray.StopXray()
		cfg, _ := config.LoadConfig()
		if cfg != nil && (cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled) {
			gateway.CleanupFirewall()
		}
		fmt.Println("✅ Xray stopped.")
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the Xray service (Systemd/OpenRC or manual)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := xray.RestartXrayService(); err != nil {
			fmt.Printf("❌ Restart failed: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd, stopCmd, restartCmd)
}
