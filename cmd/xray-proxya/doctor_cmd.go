package main

import "github.com/spf13/cobra"

// doctorCmd is intentionally a command container. Diagnostic actions belong to
// explicit subcommands so invoking `doctor` alone cannot change host state.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Environment diagnostics and automated tuning tools",
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
