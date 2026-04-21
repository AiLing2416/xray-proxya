package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	configUpgradeStaging bool
	configUpgradeDryRun  bool
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect and upgrade configuration files",
}

var configUpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Backfill missing configuration fields and rewrite the config file",
	Long: strings.TrimSpace(`
Load an existing config file, fill in fields introduced by newer versions, and
rewrite the file in normalized form.

Use --dry-run to preview the upgrade without modifying the file.
`),
	Example: strings.TrimSpace(`
  xray-proxya config upgrade
  xray-proxya config upgrade --staging
  xray-proxya config upgrade --dry-run
`),
	Args: cobra.NoArgs,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		staging := configUpgradeStaging
		path := config.GetConfigPathEx(staging)
		if staging && !config.StagingExists() {
			fmt.Println("❌ No staging config found.")
			return
		}
		if _, err := os.Stat(path); err != nil {
			fmt.Printf("❌ Config file not found: %s\n", path)
			return
		}

		cfg, err := config.LoadConfigFile(path, false)
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			return
		}

		changes := cfg.BackfillDefaults()
		if len(changes) == 0 {
			fmt.Printf("ℹ️ No upgrade changes needed for %s.\n", path)
			return
		}
		if configUpgradeDryRun {
			label := "ACTIVE"
			if staging {
				label = "STAGING"
			}
			fmt.Printf("🔎 Dry run for %s config: %s\n", label, path)
			fmt.Println("Pending changes:")
			for _, change := range changes {
				fmt.Printf(" - %s\n", change)
			}
			fmt.Println("No files were modified.")
			return
		}

		backupPath, err := backupConfigFile(path)
		if err != nil {
			fmt.Printf("❌ Failed to create backup: %v\n", err)
			return
		}
		if err := cfg.SaveEx(staging); err != nil {
			fmt.Printf("❌ Failed to write upgraded config: %v\n", err)
			return
		}

		label := "ACTIVE"
		if staging {
			label = "STAGING"
		}
		fmt.Printf("✅ Upgraded %s config: %s\n", label, path)
		fmt.Printf("🗂️ Backup: %s\n", backupPath)
		fmt.Println("Applied changes:")
		for _, change := range changes {
			fmt.Printf(" - %s\n", change)
		}
	},
}

func backupConfigFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backupPath := fmt.Sprintf("%s.bak-%s", path, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", err
	}
	return backupPath, nil
}

func init() {
	configUpgradeCmd.Flags().BoolVar(&configUpgradeStaging, "staging", false, "Upgrade the staging config instead of the active config")
	configUpgradeCmd.Flags().BoolVar(&configUpgradeDryRun, "dry-run", false, "Preview upgrade changes without writing the config file")
	configCmd.AddCommand(configUpgradeCmd)
	rootCmd.AddCommand(configCmd)
}
