package xray

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const MainServiceUnit = "xray-proxya.service"

// SystemdScopeArgs returns the scope for the effective user. Root operates on
// system units; an ordinary user can operate only on that user's manager.
func SystemdScopeArgs() []string {
	if os.Geteuid() == 0 {
		return nil
	}
	return []string{"--user"}
}

func ManageSystemdUnit(action, unit string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl is required: %w", err)
	}
	args := append(SystemdScopeArgs(), "--no-ask-password", action, unit)
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return systemdError(action, unit, err, out)
	}
	return nil
}

// RunSystemd forwards a validated systemctl invocation to the terminal while
// preserving systemctl's failure as a Go error for CLI callers.
func RunSystemd(args ...string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl is required: %w", err)
	}
	commandArgs := append(SystemdScopeArgs(), "--no-ask-password")
	commandArgs = append(commandArgs, args...)
	cmd := exec.Command("systemctl", commandArgs...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func ReloadSystemdDaemon() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl is required: %w", err)
	}
	args := append(SystemdScopeArgs(), "daemon-reload")
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return systemdError("daemon-reload", "", err, out)
	}
	return nil
}

func JournalTail(unit string, lines int) (string, error) {
	if lines <= 0 {
		lines = 40
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return "", fmt.Errorf("journalctl is required: %w", err)
	}
	args := append(SystemdScopeArgs(), "--no-pager", "-u", unit, "-n", fmt.Sprintf("%d", lines))
	out, err := exec.Command("journalctl", args...).CombinedOutput()
	if err != nil {
		return "", systemdError("read journal", unit, err, out)
	}
	return string(out), nil
}

func FollowJournal(unit string, lines int) error {
	if lines <= 0 {
		lines = 40
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return fmt.Errorf("journalctl is required: %w", err)
	}
	args := append(SystemdScopeArgs(), "--no-pager", "-u", unit, "-n", fmt.Sprintf("%d", lines), "-f")
	cmd := exec.Command("journalctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func systemdError(action, unit string, err error, output []byte) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	if unit == "" {
		return fmt.Errorf("systemctl %s: %s", action, message)
	}
	return fmt.Errorf("systemctl %s %s: %s", action, unit, message)
}
