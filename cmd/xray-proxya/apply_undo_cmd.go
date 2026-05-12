package main

import (
	"fmt"
	"xray-proxya/internal/applyops"

	"github.com/spf13/cobra"
)

var (
	forceApply bool
	fullApply  bool
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Validate and commit staged changes with selective restart",
	Run: func(cmd *cobra.Command, args []string) {
		lines, err := applyops.ApplyPending(applyops.Options{Force: forceApply, Full: fullApply})
		for _, line := range lines {
			fmt.Println(line)
		}
		if err != nil {
			fmt.Printf("❌ %v\n", err)
		}
	},
}

var undoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Discard all pending changes in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		if err := applyops.ClearPending(); err != nil {
			fmt.Printf("❌ Failed: %v\n", err)
		} else {
			fmt.Println("✅ STAGING changes discarded.")
		}
	},
}

func init() {
	applyCmd.Flags().BoolVarP(&forceApply, "force", "f", false, "Commit changes without validation")
	applyCmd.Flags().BoolVar(&fullApply, "full", false, "Run full Xray validation and restart all managed services regardless of changed sections")
	rootCmd.AddCommand(applyCmd, undoCmd)
}
