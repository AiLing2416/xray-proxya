package xray

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func activeInitType() string {
	if b := getServiceBridge(); b != nil && b.GetInitType != nil {
		if t := b.GetInitType(); t != "" && t != "unknown" {
			return t
		}
	}
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "systemd"
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "procd"
	}
	if fi, err := os.Stat("/run/openrc"); err == nil && fi.IsDir() {
		return "openrc"
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return "openrc"
	}
	if _, err := exec.LookPath("logread"); err == nil {
		return "procd"
	}
	return "systemd"
}

func unitBaseName(unit string) string {
	base := strings.TrimSuffix(strings.TrimSpace(unit), ".service")
	switch base {
	case "", "core":
		return "xray-proxya"
	case "sub":
		return "xray-proxya-sub"
	case "pathd":
		return "xray-proxya-pathd"
	default:
		return base
	}
}

func JournalTail(unit string, lines int) (string, error) {
	if lines <= 0 {
		lines = 40
	}
	initType := activeInitType()
	switch initType {
	case "openrc":
		base := unitBaseName(unit)
		logFile := filepath.Join("/var/log", base+".log")
		errFile := filepath.Join("/var/log", base+".err")

		var logContent strings.Builder
		if data, err := os.ReadFile(logFile); err == nil && len(data) > 0 {
			logContent.Write(data)
		}
		if data, err := os.ReadFile(errFile); err == nil && len(data) > 0 {
			if logContent.Len() > 0 && !strings.HasSuffix(logContent.String(), "\n") {
				logContent.WriteString("\n")
			}
			logContent.Write(data)
		}
		if logContent.Len() == 0 {
			if _, err1 := os.Stat(logFile); os.IsNotExist(err1) {
				if _, err2 := os.Stat(errFile); os.IsNotExist(err2) {
					return fmt.Sprintf("No log files found at %s or %s\n", logFile, errFile), nil
				}
			}
			return "", nil
		}
		return tailLogContent(logContent.String(), lines), nil

	case "procd":
		if _, err := exec.LookPath("logread"); err != nil {
			return "", fmt.Errorf("logread is required: %w", err)
		}
		base := unitBaseName(unit)
		out, err := exec.Command("logread", "-e", base).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("logread -e %s: %w", base, err)
		}
		return tailLogContent(string(out), lines), nil

	default: // systemd
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
}

func FollowJournal(unit string, lines int) error {
	if lines <= 0 {
		lines = 40
	}
	initType := activeInitType()
	switch initType {
	case "openrc":
		base := unitBaseName(unit)
		logFile := filepath.Join("/var/log", base+".log")
		errFile := filepath.Join("/var/log", base+".err")

		var files []string
		if _, err := os.Stat(logFile); err == nil {
			files = append(files, logFile)
		}
		if _, err := os.Stat(errFile); err == nil {
			files = append(files, errFile)
		}
		if len(files) == 0 {
			files = append(files, logFile)
		}

		args := append([]string{"-n", fmt.Sprintf("%d", lines), "-f"}, files...)
		cmd := exec.Command("tail", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()

	case "procd":
		if _, err := exec.LookPath("logread"); err != nil {
			return fmt.Errorf("logread is required: %w", err)
		}
		base := unitBaseName(unit)
		cmd := exec.Command("logread", "-f", "-e", base)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()

	default: // systemd
		if _, err := exec.LookPath("journalctl"); err != nil {
			return fmt.Errorf("journalctl is required: %w", err)
		}
		args := append(SystemdScopeArgs(), "--no-pager", "-u", unit, "-n", fmt.Sprintf("%d", lines), "-f")
		cmd := exec.Command("journalctl", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
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
