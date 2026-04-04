package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/tui"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Xray core status and traffic overview",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfig()
		active, pid := xray.GetXrayStatus()
		
		if !active {
			fmt.Println("Xray Core: Inactive")
			return
		}

		uptime := xray.GetXrayUptime(pid)
		direct, relay, err := xray.GetXrayStats(cfg.APIInbound)
		
		directStr := tui.HumanizeBytes(direct)
		relayStr := tui.HumanizeBytes(relay)
		if err != nil {
			directStr = "N/A"
			relayStr = "N/A"
		}

		fmt.Printf("PID %d | UpTime: %s | Direct: %s | Relay: %s\n", 
			pid, uptime, directStr, relayStr)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
