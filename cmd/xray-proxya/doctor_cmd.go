package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	proxyaSELinux "xray-proxya/internal/selinux"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

// doctorCmd is intentionally a command container. Diagnostic actions belong to
// explicit subcommands so invoking `doctor` alone cannot change host state.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Environment diagnostics, completion, and automated tuning tools",
	Long: `Diagnostic, environment setup, and security helper tools for Xray-Proxya.
Includes shell autocompletion installer, user session lingering manager,
and SELinux security policy installer.`,
}

var doctorSELinuxCmd = &cobra.Command{
	Use:   "selinux",
	Short: "Install the reviewed SELinux policy for the root service",
	Long: `Compile, package, and load the dedicated SELinux policy module (xray_proxya.te)
and set appropriate security contexts for Xray-Proxya binaries, configs, and sockets.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !utils.IsRoot() {
			return fmt.Errorf("doctor selinux requires root privileges")
		}
		if err := installSELinuxPolicy(); err != nil {
			return fmt.Errorf("SELinux policy installation failed: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✅ Reviewed SELinux policy installed. SELinux enforcing mode was not changed.")
		return nil
	},
}

func installSELinuxPolicy() error {
	for _, name := range []string{"sestatus", "make", "semodule", "semanage", "restorecon"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("%s is required (Fedora: dnf install selinux-policy-devel policycoreutils-python-utils)", name)
		}
	}
	if out, err := exec.Command("sestatus").Output(); err != nil || !containsSELinuxEnabled(string(out)) {
		return fmt.Errorf("SELinux is not enabled")
	}

	dir, err := os.MkdirTemp("", "xray-proxya-selinux-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "xray_proxya.te"), []byte(proxyaSELinux.PolicySource), 0600); err != nil {
		return err
	}
	if out, err := exec.Command("make", "-C", dir, "-f", "/usr/share/selinux/devel/Makefile", "xray_proxya.pp").CombinedOutput(); err != nil {
		return fmt.Errorf("compile policy: %w (%s)", err, out)
	}
	// Remove local fcontext entries from development builds before semodule
	// validates the local database.  In particular, xray_proxya_log_t no
	// longer exists because service output is handled by journald.
	for _, pattern := range []string{
		`/root/.config/xray-proxya/xray\.log`,
		`/root/.local/share/xray-proxya/bin/xray`,
		`/root/.local/share/xray-proxya/bin(/.*)?`,
		`/root/.local/share/xray-proxya/bin/pathd`,
	} {
		_ = exec.Command("semanage", "fcontext", "-d", pattern).Run()
	}
	if out, err := exec.Command("semodule", "-i", filepath.Join(dir, "xray_proxya.pp")).CombinedOutput(); err != nil {
		return fmt.Errorf("install policy: %w (%s)", err, out)
	}
	for _, entry := range []struct{ pattern, label string }{
		{`/root/.local/share/xray-proxya(/.*)?`, "xray_proxya_data_t"},
		// semanage evaluates later local entries first, so the dedicated pathd
		// executable rule must follow the broad private-data rule.
		{`/root/.local/share/xray-proxya/bin/pathd`, "xray_proxya_pathd_exec_t"},
		{`/root/.local/bin/xray-proxya`, "xray_proxya_exec_t"},
		{`/root/.config/xray-proxya(/.*)?`, "xray_proxya_config_t"},
	} {
		if _, err := exec.Command("semanage", "fcontext", "-a", "-t", entry.label, entry.pattern).CombinedOutput(); err != nil {
			if out, retryErr := exec.Command("semanage", "fcontext", "-m", "-t", entry.label, entry.pattern).CombinedOutput(); retryErr != nil {
				return fmt.Errorf("set file context for %s: %w (%s)", entry.pattern, retryErr, out)
			}
		}
	}
	for _, path := range []string{"/root/.local/bin/xray-proxya", "/root/.local/share/xray-proxya", "/root/.config/xray-proxya"} {
		if out, err := exec.Command("restorecon", "-RF", path).CombinedOutput(); err != nil {
			return fmt.Errorf("restore context on %s: %w (%s)", path, err, out)
		}
	}
	return nil
}

func containsSELinuxEnabled(status string) bool {
	return strings.Contains(status, "SELinux status:") && strings.Contains(status, "enabled")
}

func init() {
	doctorCmd.AddCommand(doctorSELinuxCmd, doctorCompletionCmd, doctorLingerCmd)
	rootCmd.AddCommand(doctorCmd)
}
