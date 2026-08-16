package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var doctorLingerCmd = &cobra.Command{
	Use:   "linger",
	Short: "Inspect or configure user session lingering for user-level systemd services",
	Long: `Inspect, enable, or disable systemd user session lingering for the current user.
When lingering is enabled, the systemd user manager starts at boot and persists across logouts,
allowing user-level systemd services (e.g. xray-proxya.service --user) to run continuously in the background.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		username := currentLingerUser()
		enabled, err := checkLingerStatus(username)
		if err != nil {
			return err
		}
		if enabled {
			fmt.Fprintf(cmd.OutOrStdout(), "✅ User lingering is ENABLED for %q.\n   User-level systemd services will persist across sessions and system boots.\n", username)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️  User lingering is DISABLED for %q.\n   User-level systemd services will terminate when you log out.\n💡 To enable lingering, run: xray-proxya doctor linger enable\n", username)
		}
		return nil
	},
}

var doctorLingerEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable user lingering for the current user",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		username := currentLingerUser()
		if err := setLinger(username, true); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✅ User lingering ENABLED for %q.\n   User systemd services will persist across logouts.\n", username)
		return nil
	},
}

var doctorLingerDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable user lingering for the current user",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		username := currentLingerUser()
		if err := setLinger(username, false); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✅ User lingering DISABLED for %q.\n", username)
		return nil
	},
}

func currentLingerUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if name := os.Getenv("USER"); name != "" {
		return name
	}
	if name := os.Getenv("LOGNAME"); name != "" {
		return name
	}
	return "unknown"
}

func parseLingerOutput(output string) (bool, bool) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Linger=yes" {
			return true, true
		}
		if trimmed == "Linger=no" {
			return false, true
		}
	}
	return false, false
}

func checkLingerStatus(username string) (bool, error) {
	if loginctl, err := exec.LookPath("loginctl"); err == nil {
		out, err := exec.Command(loginctl, "show-user", username, "-p", "Linger").CombinedOutput()
		if err == nil {
			if enabled, ok := parseLingerOutput(string(out)); ok {
				return enabled, nil
			}
		}
	}
	// Fallback to checking /var/lib/systemd/linger/<username>
	if _, err := os.Stat(filepath.Join("/var/lib/systemd/linger", username)); err == nil {
		return true, nil
	}
	return false, nil
}

func setLinger(username string, enable bool) error {
	loginctl, err := exec.LookPath("loginctl")
	if err != nil {
		return fmt.Errorf("loginctl is required for managing user lingering: %w", err)
	}
	action := "enable-linger"
	if !enable {
		action = "disable-linger"
	}
	out, err := exec.Command(loginctl, action, username).CombinedOutput()
	if err != nil {
		// Fallback without explicit username arg (loginctl enable-linger defaults to current user)
		if out2, err2 := exec.Command(loginctl, action).CombinedOutput(); err2 == nil {
			return nil
		} else {
			_ = out2
		}
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("failed to %s for %s: %s (try 'sudo loginctl %s %s')", action, username, trimmed, action, username)
		}
		return fmt.Errorf("failed to %s for %s: %w (try 'sudo loginctl %s %s')", action, username, err, action, username)
	}
	return nil
}

func init() {
	doctorLingerCmd.AddCommand(doctorLingerEnableCmd, doctorLingerDisableCmd)
}
