package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ColorYellow = "\033[33m"
	ColorReset  = "\033[0m"
)

// Yellow wraps a message in ANSI yellow escape sequences.
func Yellow(msg string) string {
	return ColorYellow + msg + ColorReset
}

// IsRoot returns true if the current effective user ID is 0.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// IsRootShellCommand returns true if the specified command is an interactive root shell or login shell.
func IsRootShellCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	switch filepath.Base(fields[0]) {
	case "bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "nu", "xonsh", "elvish", "su":
		return true
	default:
		return false
	}
}

// RequireRootShell checks that the process is running as root and is inside a root shell / login shell,
// rejecting single-command sudo invocations (e.g. `sudo xray-proxya ...`).
func RequireRootShell(operation string) error {
	return RequireRootShellFor(os.Geteuid(), os.Getenv("SUDO_USER"), os.Getenv("SUDO_UID"), os.Getenv("SUDO_COMMAND"), operation)
}

// RequireRootShellFor validates root shell requirements for given credentials.
func RequireRootShellFor(euid int, sudoUser, sudoUID, sudoCommand, operation string) error {
	prefix := ""
	if operation != "" {
		prefix = operation + " "
	}
	if euid != 0 {
		return fmt.Errorf("%s", Yellow(fmt.Sprintf("⚠️  %soperation requires a root shell; use sudo -i, su -, or a direct root login", prefix)))
	}
	if (sudoUser != "" || sudoUID != "") && !IsRootShellCommand(sudoCommand) {
		return fmt.Errorf("%s", Yellow(fmt.Sprintf("⚠️  %soperation requires a root shell; use sudo -i, su -, or a direct root login", prefix)))
	}
	return nil
}

// RequireRootOnly checks that the process is running as root (euid == 0),
// but permits single-command sudo invocations (e.g. for `tune` module).
func RequireRootOnly(operation string) error {
	return RequireRootOnlyFor(os.Geteuid(), operation)
}

// RequireRootOnlyFor validates root requirement (permitting single sudo) for given euid.
func RequireRootOnlyFor(euid int, operation string) error {
	prefix := ""
	if operation != "" {
		prefix = operation + " "
	}
	if euid != 0 {
		return fmt.Errorf("%s", Yellow(fmt.Sprintf("⚠️  %soperation requires root privileges (use sudo or a root shell)", prefix)))
	}
	return nil
}

// EnsureRoot checks if the current process is running with root privileges.
// If not, it prints a yellow warning message and exits.
func EnsureRoot() {
	if os.Geteuid() != 0 {
		fmt.Println(Yellow("⚠️  Error: This command requires root privileges (use sudo -i, su -, or a direct root login)."))
		os.Exit(1)
	}
}
