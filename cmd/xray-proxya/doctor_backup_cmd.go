package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"xray-proxya/internal/config"
	"xray-proxya/internal/doctor"

	"github.com/spf13/cobra"
)

var (
	doctorBackupRollPath string
)

var doctorBackupCmd = &cobra.Command{
	Use:   "backup [output-path]",
	Short: "Create a single archive backup of configurations, or rollback from an existing backup",
	Long: `Create a single self-contained .tar.gz archive containing active configurations,
certificates, and metadata, or rollback to a previous state using -r/--roll.

Examples:
  xray-proxya doctor backup                         # Create a timestamped backup in config dir
  xray-proxya doctor backup /tmp/my-backup.tar.gz   # Create backup at custom destination
  xray-proxya doctor backup -r backup-20260909.tar.gz  # Rollback using a backup in config dir
  xray-proxya doctor backup --roll /path/to/bak.tar.gz # Rollback from absolute path`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		configDir := config.GetConfigDir()

		// Rollback mode
		if strings.TrimSpace(doctorBackupRollPath) != "" {
			res, err := doctor.RestoreBackup(doctorBackupRollPath, configDir)
			if err != nil {
				return fmt.Errorf("rollback failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✅ Successfully restored configuration from %s\n", res.BackupPath)
			fmt.Fprintln(cmd.OutOrStdout(), "Restored files:")
			for _, f := range res.RestoredFiles {
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", f)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\n💡 Tip: Run 'xray-proxya apply' or 'xray-proxya doctor check' to inspect and sync runtime services.")
			return nil
		}

		// Backup mode
		targetPath := ""
		if len(args) > 0 {
			targetPath = args[0]
		}

		res, err := doctor.CreateBackup(configDir, targetPath)
		if err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "✅ Configuration backup created successfully: %s\n", res.BackupPath)
		fmt.Fprintln(cmd.OutOrStdout(), "Archived files:")
		for _, f := range res.ArchivedFiles {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", f)
		}
		baseName := filepath.Base(res.BackupPath)
		fmt.Fprintf(cmd.OutOrStdout(), "\n💡 Tip: You can rollback anytime with:\n   xray-proxya doctor backup -r %s\n", baseName)
		return nil
	},
}

func init() {
	doctorBackupCmd.Flags().StringVarP(&doctorBackupRollPath, "roll", "r", "", "Rollback configuration from a specified backup file")

	_ = doctorBackupCmd.RegisterFlagCompletionFunc("roll", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		configDir := config.GetConfigDir()
		files, err := doctor.ListBackupFiles(configDir)
		if err != nil || len(files) == 0 {
			return nil, cobra.ShellCompDirectiveDefault
		}

		var matches []string
		for _, f := range files {
			if strings.HasPrefix(f, toComplete) {
				matches = append(matches, f)
			}
		}
		if len(matches) == 0 {
			return files, cobra.ShellCompDirectiveDefault
		}
		return matches, cobra.ShellCompDirectiveDefault
	})

	doctorCmd.AddCommand(doctorBackupCmd)
}
