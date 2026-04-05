package main

import (
	"fmt"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

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
	rootCmd.AddCommand(stopCmd, restartCmd)
}
