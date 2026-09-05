package service

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

// UserSystemdUnitDir returns the systemd user unit directory for the current user.
func UserSystemdUnitDir() string {
	return filepath.Join(config.GetHomeDir(), ".config", "systemd", "user")
}

// UnitDirectory returns the destination directory for systemd units according to the effective UID.
func UnitDirectory() string {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system"
	}
	return UserSystemdUnitDir()
}

// ManagedUnitPath returns the expected file path for a managed unit.
func ManagedUnitPath(unit string) string {
	return filepath.Join(UnitDirectory(), unit)
}

// FindUnitFile looks for the unit file across known systemd directories.
func FindUnitFile(unit string) string {
	if os.Geteuid() != 0 {
		p := filepath.Join(UserSystemdUnitDir(), unit)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		p := filepath.Join(dir, unit)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DirectRootServiceError validates that privileged root service commands are invoked
// from a direct root shell rather than unapproved sudo invocations.
func DirectRootServiceError() error {
	return DirectRootServiceErrorFor(os.Geteuid(), os.Getenv("SUDO_USER"), os.Getenv("SUDO_UID"), os.Getenv("SUDO_COMMAND"))
}

// DirectRootServiceErrorFor performs the root shell check for the provided parameters.
func DirectRootServiceErrorFor(euid int, sudoUser, sudoUID, sudoCommand string) error {
	return utils.RequireRootShellFor(euid, sudoUser, sudoUID, sudoCommand, "system service")
}

// ValidateRootManagerBinary ensures the root manager binary matches the canonical path and permissions.
func ValidateRootManagerBinary() (string, error) {
	path, err := filepath.EvalSymlinks(xray.GetXrayProxyaPath())
	if err != nil {
		return "", fmt.Errorf("resolve manager binary: %w", err)
	}
	path = filepath.Clean(path)
	if path != RootManagerBinary {
		return "", fmt.Errorf("root service binary must be %s, got %s", RootManagerBinary, path)
	}
	return ValidateRootOwnedExecutable(path)
}

// ValidateRootOwnedExecutable verifies that an executable and its parent directories
// are owned by root and not group- or world-writable.
func ValidateRootOwnedExecutable(path string) (string, error) {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	path = filepath.Clean(path)
	for current := path; current != "/"; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return "", fmt.Errorf("inspect %s: %w", current, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", fmt.Errorf("%s must be owned by root", current)
		}
		if info.Mode().Perm()&0022 != 0 {
			return "", fmt.Errorf("%s must not be group- or world-writable", current)
		}
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular executable file", path)
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%s is not executable", path)
	}
	return path, nil
}
