package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	proxyaSELinux "xray-proxya/internal/selinux"

	"github.com/spf13/cobra"
)

var selinuxCmd = &cobra.Command{
	Use:   "selinux",
	Short: "Manage SELinux policies and permissions for Xray-Proxya",
}

var selinuxInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the reviewed SELinux policy for the root service",
	Run: func(cmd *cobra.Command, args []string) {
		if !requireRoot() {
			return
		}
		if err := installSELinuxPolicy(); err != nil {
			fmt.Printf("❌ SELinux policy installation failed: %v\n", err)
			return
		}
		fmt.Println("✅ Reviewed SELinux policy installed. SELinux enforcing mode was not changed.")
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
	if err != nil { return err }
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "xray_proxya.te"), []byte(proxyaSELinux.PolicySource), 0600); err != nil { return err }
	if out, err := exec.Command("make", "-C", dir, "-f", "/usr/share/selinux/devel/Makefile", "xray_proxya.pp").CombinedOutput(); err != nil {
		return fmt.Errorf("compile policy: %w (%s)", err, out)
	}
	if out, err := exec.Command("semodule", "-i", filepath.Join(dir, "xray_proxya.pp")).CombinedOutput(); err != nil {
		return fmt.Errorf("install policy: %w (%s)", err, out)
	}
	// Older development builds labelled the bundled core as an entrypoint.  The
	// core must instead stay a same-domain child executable.
	_ = exec.Command("semanage", "fcontext", "-d", `/root/.local/share/xray-proxya/bin/xray`).Run()
	for _, entry := range []struct{ pattern, label string }{
		{`/root/.local/share/xray-proxya(/.*)?`, "xray_proxya_data_t"},
		{`/root/.local/bin/xray-proxya`, "xray_proxya_exec_t"},
		{`/root/.config/xray-proxya(/.*)?`, "xray_proxya_config_t"},
		{`/root/.config/xray-proxya/xray\.log`, "xray_proxya_log_t"},
	} {
		if _, err := exec.Command("semanage", "fcontext", "-a", "-t", entry.label, entry.pattern).CombinedOutput(); err != nil {
			if out, retryErr := exec.Command("semanage", "fcontext", "-m", "-t", entry.label, entry.pattern).CombinedOutput(); retryErr != nil {
				return fmt.Errorf("set file context for %s: %w (%s)", entry.pattern, retryErr, out)
			}
		}
	}
	for _, path := range []string{"/root/.local/bin/xray-proxya", "/root/.local/share/xray-proxya", "/root/.config/xray-proxya"} {
		if out, err := exec.Command("restorecon", "-RF", path).CombinedOutput(); err != nil { return fmt.Errorf("restore context on %s: %w (%s)", path, err, out) }
	}
	return nil
}

func containsSELinuxEnabled(status string) bool { return strings.Contains(status, "SELinux status:") && strings.Contains(status, "enabled") }

func init() {
	selinuxCmd.AddCommand(selinuxInstallCmd)
	rootCmd.AddCommand(selinuxCmd)
}
