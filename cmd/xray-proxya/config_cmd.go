package main

import (
	"encoding/json"
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

func runConfigUpgrade(cmd *cobra.Command, args []string) error {
	staging := configUpgradeStaging
	path := config.GetConfigPathEx(staging)
	if staging && !config.StagingExists() {
		return fmt.Errorf("❌ No staging config found.")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("❌ Config file not found: %s", path)
	}

	cfg, err := config.LoadConfigFile(path, false)
	if err != nil {
		return fmt.Errorf("❌ Failed to load config: %w", err)
	}

	changes := cfg.BackfillDefaults()
	if len(changes) == 0 {
		fmt.Printf("ℹ️ No upgrade changes needed for %s.\n", path)
		return nil
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
		return nil
	}

	backupPath, err := backupConfigFile(path)
	if err != nil {
		return fmt.Errorf("❌ Failed to create backup: %w", err)
	}
	if err := cfg.SaveEx(staging); err != nil {
		return fmt.Errorf("❌ Failed to write upgraded config: %w", err)
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
	return nil
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
		_ = runConfigUpgrade(cmd, args)
	},
	RunE: runConfigUpgrade,
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

var (
	configPathStaging bool
	configPathActive  bool
	configPathJSON    bool
)

type ConfigPathJSON struct {
	ConfigDir     string `json:"config_dir"`
	ActivePath    string `json:"active_path"`
	ActiveExists  bool   `json:"active_exists"`
	StagingPath   string `json:"staging_path"`
	StagingExists bool   `json:"staging_exists"`
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print filesystem paths for active and staging configuration files",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if configPathStaging && configPathActive {
			return fmt.Errorf("❌ Cannot specify both --staging and --active")
		}

		configDir := config.GetConfigDir()
		activePath := config.GetConfigPathEx(false)
		stagingPath := config.GetConfigPathEx(true)

		_, activeErr := os.Stat(activePath)
		activeExists := (activeErr == nil)

		_, stagingErr := os.Stat(stagingPath)
		stagingExists := (stagingErr == nil)

		if configPathStaging {
			fmt.Println(stagingPath)
			return nil
		}
		if configPathActive {
			fmt.Println(activePath)
			return nil
		}
		if configPathJSON {
			out := ConfigPathJSON{
				ConfigDir:     configDir,
				ActivePath:    activePath,
				ActiveExists:  activeExists,
				StagingPath:   stagingPath,
				StagingExists: stagingExists,
			}
			data, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Config Directory: %s\n", configDir)
		fmt.Printf("Active Config:    %s (exists: %t)\n", activePath, activeExists)
		fmt.Printf("Staging Config:   %s (exists: %t)\n", stagingPath, stagingExists)
		return nil
	},
}

var (
	configShowStaging bool
	configShowRaw     bool
	configShowFilter  string
)

var configShowCmd = &cobra.Command{
	Use:     "show",
	Aliases: []string{"view"},
	Short:   "Display formatted configuration JSON",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var targetPath string
		if configShowStaging {
			if !config.StagingExists() {
				return fmt.Errorf("❌ No staging config found.")
			}
			targetPath = config.GetConfigPathEx(true)
		} else {
			targetPath = config.GetConfigPathEx(false)
			if _, err := os.Stat(targetPath); os.IsNotExist(err) {
				return fmt.Errorf("❌ xray-proxya has not been initialized. Run 'init' first.")
			}
		}

		data, err := os.ReadFile(targetPath)
		if err != nil {
			return fmt.Errorf("❌ Failed to read config file: %w", err)
		}

		if configShowFilter != "" {
			var rawMap map[string]json.RawMessage
			if err := json.Unmarshal(data, &rawMap); err != nil {
				return fmt.Errorf("❌ Failed to parse config JSON: %w", err)
			}
			filterKey := strings.TrimSpace(configShowFilter)
			rawVal, ok := rawMap[filterKey]
			if !ok {
				rawVal, ok = rawMap[strings.ToLower(filterKey)]
			}
			if !ok {
				return fmt.Errorf("❌ Section '%s' not found in configuration.", filterKey)
			}
			if configShowRaw {
				fmt.Println(strings.TrimSpace(string(rawVal)))
				return nil
			}
			var parsedVal interface{}
			if err := json.Unmarshal(rawVal, &parsedVal); err != nil {
				return fmt.Errorf("❌ Failed to parse section JSON: %w", err)
			}
			formatted, err := json.MarshalIndent(parsedVal, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(formatted))
			return nil
		}

		if configShowRaw {
			fmt.Println(strings.TrimRight(string(data), "\n"))
			return nil
		}

		var parsedVal interface{}
		if err := json.Unmarshal(data, &parsedVal); err != nil {
			return fmt.Errorf("❌ Failed to parse config JSON: %w", err)
		}
		formatted, err := json.MarshalIndent(parsedVal, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to format JSON: %w", err)
		}
		fmt.Println(string(formatted))
		return nil
	},
}

func init() {
	configUpgradeCmd.Flags().BoolVar(&configUpgradeStaging, "staging", false, "Upgrade the staging config instead of the active config")
	configUpgradeCmd.Flags().BoolVar(&configUpgradeDryRun, "dry-run", false, "Preview upgrade changes without writing the config file")

	configPathCmd.Flags().BoolVarP(&configPathStaging, "staging", "s", false, "Print only the staging config path")
	configPathCmd.Flags().BoolVarP(&configPathActive, "active", "a", false, "Print only the active config path")
	configPathCmd.Flags().BoolVar(&configPathJSON, "json", false, "Output in JSON format")

	configShowCmd.Flags().BoolVarP(&configShowStaging, "staging", "s", false, "Display the staging configuration")
	configShowCmd.Flags().BoolVarP(&configShowRaw, "raw", "r", false, "Output raw unformatted file content")
	configShowCmd.Flags().StringVarP(&configShowFilter, "filter", "f", "", "Filter output by top-level section (e.g. gateway, presets, guests)")
	configShowCmd.RegisterFlagCompletionFunc("filter", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"role", "uuid", "api_inbound", "test_inbound", "presets", "custom_outbounds",
			"relay_subs", "guests", "gateway", "path", "admin_sub", "subscription_instances",
			"ipv6_rotation", "subscriptions",
		}, cobra.ShellCompDirectiveNoFileComp
	})

	configCmd.AddCommand(configUpgradeCmd, configPathCmd, configShowCmd)
	rootCmd.AddCommand(configCmd)
}
