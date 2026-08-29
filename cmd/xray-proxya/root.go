package main

import (
	"fmt"
	"os"
	"xray-proxya/internal/buildinfo"

	"github.com/spf13/cobra"
)

var Version = buildinfo.Version

var rootCmd = &cobra.Command{
	Use:               "xray-proxya",
	Short:             "Xray-Proxya: A modern, role-based proxy manager and transparent gateway",
	SilenceUsage:      true,
	SilenceErrors:     true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Long:              "Xray-Proxya is a Go-based successor to the archive bash scripts.\nIt features a staging-based configuration system with mandatory normalization.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Xray-Proxya v%s\n", Version)
	},
}
