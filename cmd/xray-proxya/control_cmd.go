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
	Short: "Start Xray service in background (Auto-detects Root/Rootless)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := xray.StartService(); err != nil {
			fmt.Printf("❌ Failed to start: %v\n", err)
		}
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running Xray service (Auto-detects Root/Rootless)",
	Run: func(cmd *cobra.Command, args []string) {
		xray.StopService()
		cfg, _ := config.LoadConfig()
		if cfg != nil && (cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled) {
			gateway.CleanupFirewall()
		}
		fmt.Println("✅ Stop command executed.")
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the Xray service (Auto-detects Root/Rootless)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := xray.RestartXrayService(); err != nil {
			fmt.Printf("❌ Restart failed: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd, stopCmd, restartCmd)
}
