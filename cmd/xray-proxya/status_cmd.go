package main

import (
	"fmt"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Xray core status and traffic overview",
	Run: func(cmd *cobra.Command, args []string) {
		active, pid := xray.GetXrayStatus()
		if !active {
			fmt.Println("Xray Core: Inactive")
			return
		}

		uptime := xray.GetXrayUptime(pid)
		up, down, _ := xray.GetXrayStats(pid)

		fmt.Printf("PID %d | UpTime: %s | Direct: %d B | Relay: %d B\n", 
			pid, uptime, down, up)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
