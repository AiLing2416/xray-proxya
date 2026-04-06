package main

import (
	"fmt"
	"xray-proxya/internal/tui"

	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Start the interactive TUI manager",
	Run: func(cmd *cobra.Command, args []string) {
		if err := tui.Start(); err != nil {
			fmt.Printf("❌ TUI Error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
