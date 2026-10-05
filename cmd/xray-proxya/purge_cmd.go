package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/purge"

	"github.com/spf13/cobra"
)

var (
	purgeInclude []string
	purgeDryRun  bool
	purgeForce   bool
)

var purgeCmd = &cobra.Command{
	Use:   "purge -i <types> [flags]",
	Short: "Safely purge specified components, configurations, and data",
	Long: `Permanently delete explicitly specified resources, files, and managed services.

Available target types (-i/--include):
  - config:     Configuration files (presets, active/staging configs, routing rules)
  - cert:       TLS certificates and keys (~/.config/xray-proxya/certs)
  - core:       Downloaded Xray-core binary and geoip/geosite databases
  - service:    Managed systemd services (gracefully stops and removes units)
  - bin:        xray-proxya and pathd executable binaries
  - data:       Runtime share directory (~/.local/share/xray-proxya)
  - cache:      Temporary cache directory (~/.cache/xray-proxya)
  - backup:     Historical configuration backup archives (.tar.gz)
  - completion: Shell autocompletion scripts and profile source lines
  - profile:    Shell profile PATH export entries (~/.bashrc, ~/.zshrc)
  - all:        All of the above (complete system wipe)

Examples:
  # Preview what would be removed if configs and core are purged
  xray-proxya purge -i config,core --dry-run

  # Purge config, core, service, and cert with interactive confirmation
  xray-proxya purge -i config,core,service,cert

  # Force purge all components without confirmation
  xray-proxya purge -i all --force`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		include, err := cmd.Flags().GetStringSlice("include")
		if err != nil || len(include) == 0 {
			cmd.SilenceUsage = true
			return fmt.Errorf("no target types specified via -i/--include\n" +
				"Usage example: xray-proxya purge -i config,core,service,cert\n" +
				"Run 'xray-proxya purge --help' for details")
		}

		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")

		configDir := config.GetConfigDir()
		if envDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR"); envDir != "" {
			if os.Geteuid() != 0 || strings.Contains(os.Args[0], ".test") || os.Getenv("XRAY_PROXYA_TEST_ENV") == "1" {
				configDir = envDir
			}
		}
		homeDir := config.GetHomeDir()
		var installDir string
		if os.Geteuid() == 0 {
			installDir = "/root/.local/bin"
		} else {
			installDir = filepath.Join(homeDir, ".local", "bin")
		}

		plan, err := purge.BuildPlan(purge.Options{
			Targets:    include,
			DryRun:     dryRun,
			Force:      force,
			ConfigDir:  configDir,
			HomeDir:    homeDir,
			InstallDir: installDir,
		})
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		fmt.Fprintln(out, "📋 Purge Execution Plan:")
		if len(plan.Items) == 0 {
			fmt.Fprintln(out, "  (No matching files or services found on disk)")
		} else {
			currentCat := purge.ActionCategory("")
			for _, item := range plan.Items {
				if item.Category != currentCat {
					currentCat = item.Category
					fmt.Fprintf(out, "\n[%s]\n", currentCat)
				}
				detail := ""
				if item.Detail != "" {
					detail = fmt.Sprintf(" (%s)", item.Detail)
				}
				fmt.Fprintf(out, "  - %-7s %s%s\n", strings.ToUpper(item.Action)+":", item.Target, detail)
			}
		}

		if len(plan.Preserved) > 0 {
			fmt.Fprintln(out, "\n[Preserved (Not Included)]")
			for _, p := range plan.Preserved {
				fmt.Fprintf(out, "  - %s\n", p)
			}
		}

		if len(plan.Items) == 0 {
			fmt.Fprintln(out, "\nNothing to purge.")
			return nil
		}

		if dryRun {
			fmt.Fprintf(out, "\n[DRY-RUN] %d item(s) planned. No changes were made.\n", len(plan.Items))
			return nil
		}

		// Interactive confirmation if not --force
		if !force {
			fmt.Fprintf(out, "\n⚠️  The above actions will permanently modify your system.\n")
			fmt.Fprintf(out, "Are you sure you want to proceed? [y/N]: ")

			reader := bufio.NewReader(cmd.InOrStdin())
			input, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("read input: %w", err)
			}
			answer := strings.ToLower(strings.TrimSpace(input))
			if answer != "y" && answer != "yes" {
				fmt.Fprintln(out, "Purge cancelled.")
				return nil
			}
		}

		fmt.Fprintln(out, "\n🚀 Executing purge...")
		err = config.WithLifecycleLock(func() error {
			return purge.Execute(plan, configDir, homeDir, installDir, out)
		})
		if err != nil {
			return fmt.Errorf("purge completed with errors: %w", err)
		}

		if configDir != "" {
			lockFile := filepath.Join(configDir, "lifecycle.lock")
			entries, readErr := os.ReadDir(configDir)
			if readErr == nil && (len(entries) == 0 || (len(entries) == 1 && entries[0].Name() == "lifecycle.lock")) {
				_ = os.Remove(lockFile)
				if err := os.Remove(configDir); err == nil {
					fmt.Fprintf(out, "✅ Cleaned empty config directory: %s\n", configDir)
				}
			}
		}

		fmt.Fprintln(out, "\n✨ Purge operation completed.")
		return nil
	},
}

func init() {
	purgeCmd.Flags().StringSliceVarP(&purgeInclude, "include", "i", nil, "Target types to purge (comma-separated or repeated)")
	purgeCmd.Flags().BoolVarP(&purgeDryRun, "dry-run", "d", false, "Preview changes without applying them")
	purgeCmd.Flags().BoolVarP(&purgeForce, "force", "f", false, "Execute purge without interactive confirmation")

	_ = purgeCmd.RegisterFlagCompletionFunc("include", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prefix := ""
		alreadySelected := make(map[string]bool)
		if idx := strings.LastIndex(toComplete, ","); idx >= 0 {
			prefix = toComplete[:idx+1]
			for _, part := range strings.Split(toComplete[:idx], ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					alreadySelected[part] = true
				}
			}
		}

		var completions []string
		for _, t := range purge.AllTargetTypes {
			name := string(t)
			if alreadySelected[name] {
				continue
			}
			desc := purge.TargetDescriptions[t]
			completions = append(completions, fmt.Sprintf("%s%s\t%s", prefix, name, desc))
		}
		return completions, cobra.ShellCompDirectiveNoFileComp
	})

	rootCmd.AddCommand(purgeCmd)
}
