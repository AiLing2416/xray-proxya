package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// CheckUserLinger checks whether systemd session lingering is enabled for non-root users.
func CheckUserLinger(ctx context.Context) CheckResult {
	start := time.Now()

	// If running as root, lingering is irrelevant (system services run under PID 1)
	if os.Geteuid() == 0 {
		return CheckResult{
			Category:   "System Environment",
			Name:       "User Session Lingering",
			Status:     StatusSkip,
			Detail:     "Running as root user (system services persist automatically)",
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	username := currentUsername()
	enabled, err := checkLinger(username)
	if err != nil {
		return CheckResult{
			Category:    "System Environment",
			Name:        "User Session Lingering",
			Status:      StatusWarn,
			Detail:      fmt.Sprintf("Could not verify linger status for user %q: %v", username, err),
			Remediation: "Run 'xray-proxya doctor linger enable' to ensure continuous service execution",
			DurationMs:  time.Since(start).Milliseconds(),
		}
	}

	if enabled {
		return CheckResult{
			Category:   "System Environment",
			Name:       "User Session Lingering",
			Status:     StatusPass,
			Detail:     fmt.Sprintf("Enabled for user %q (services persist across logouts)", username),
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	return CheckResult{
		Category:    "System Environment",
		Name:        "User Session Lingering",
		Status:      StatusWarn,
		Detail:      fmt.Sprintf("Disabled for user %q (user services terminate on logout)", username),
		Remediation: "Run 'xray-proxya doctor linger enable' to enable background persistence",
		DurationMs:  time.Since(start).Milliseconds(),
	}
}

func currentUsername() string {
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

func checkLinger(username string) (bool, error) {
	if loginctl, err := exec.LookPath("loginctl"); err == nil {
		out, err := exec.Command(loginctl, "show-user", username, "-p", "Linger").CombinedOutput()
		if err == nil {
			str := string(out)
			if strings.Contains(str, "Linger=yes") {
				return true, nil
			}
			if strings.Contains(str, "Linger=no") {
				return false, nil
			}
		}
	}

	// Fallback to /var/lib/systemd/linger
	if _, err := os.Stat(filepath.Join("/var/lib/systemd/linger", username)); err == nil {
		return true, nil
	}
	return false, nil
}
