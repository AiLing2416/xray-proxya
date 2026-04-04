package main

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
)

var (
	Version = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "xray-proxya",
	Short: "Xray-Proxya: A modern, role-based proxy manager and transparent gateway",
	Long: `Xray-Proxya is a Go-based successor to the archive bash scripts. 
It features a staging-based configuration system, ensuring all changes are 
validated before being applied to the production environment.

Supports Server (Reality/KEM) and Gateway (TUN/TPROXY) roles.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	// Cobra provides completion command by default, we just need to make sure it's not hidden if needed.
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Xray-Proxya v%s\n", Version)
	},
}
