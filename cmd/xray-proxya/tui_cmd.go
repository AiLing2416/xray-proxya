package main

import (
	"fmt"
	"os"
	"xray-proxya/internal/config"
	"xray-proxya/internal/tui"

	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Start the interactive TUI manager",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			return fmt.Errorf("❌ Error: Xray-Proxya has not been initialized. Please run 'xray-proxya init' first.")
		}
		return tui.Start()
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
