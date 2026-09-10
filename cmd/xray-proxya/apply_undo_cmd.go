package main

import (
	"fmt"
	"xray-proxya/internal/applyops"

	"github.com/spf13/cobra"
)

var (
	forceApply  bool
	fullApply   bool
	dryRunApply bool
	startApply  bool
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Validate and commit staged changes with selective restart",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.RunE(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		lines, err := applyops.ApplyPending(applyops.Options{
			Force:  forceApply,
			Full:   fullApply,
			DryRun: dryRunApply,
			Start:  startApply,
		})
		for _, line := range lines {
			fmt.Println(line)
		}
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		return nil
	},
}

var undoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Discard all pending changes in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.RunE(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := applyops.ClearPending(); err != nil {
			return fmt.Errorf("❌ Failed: %w", err)
		}
		fmt.Println("✅ STAGING changes discarded.")
		return nil
	},
}

func init() {
	applyCmd.Flags().BoolVarP(&forceApply, "force", "f", false, "Commit changes without validation")
	applyCmd.Flags().BoolVar(&fullApply, "full", false, "Run full Xray validation and restart all managed services regardless of changed sections")
	applyCmd.Flags().BoolVar(&dryRunApply, "dry-run", false, "Preview changes and service actions without modifying active config or services")
	applyCmd.Flags().BoolVar(&startApply, "start", false, "Start affected managed services if they are currently stopped")
	rootCmd.AddCommand(applyCmd, undoCmd)
}
