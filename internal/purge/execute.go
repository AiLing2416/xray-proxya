package purge

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/tune"
	"xray-proxya/internal/xray"
)

// Execute runs the actions defined in the plan in a safe, dependency-ordered manner.
func Execute(plan *Plan, configDir, homeDir, installDir string, out io.Writer) error {
	if plan == nil || len(plan.Items) == 0 {
		fmt.Fprintln(out, "Nothing to purge.")
		return nil
	}

	var errs []error

	// Phase 1: Stop services.
	// Critical safety constraint: If stopping an active service fails, we must abort
	// immediately to prevent deleting units/binaries/configs while an unmanaged process runs.
	for _, item := range plan.Items {
		if item.Category == CatService && item.Action == ActionStop {
			if err := xray.ManageSystemdUnit("stop", item.Target); err != nil {
				return fmt.Errorf("stop %s: %w (aborting purge to prevent orphaned running service)", item.Target, err)
			}
			fmt.Fprintf(out, "✅ Stopped service: %s\n", item.Target)
		}
	}

	// Phase 2: Flush network firewall & rollback tune
	for _, item := range plan.Items {
		if item.Category == CatService && item.Action == ActionFlush {
			if os.Geteuid() == 0 {
				if _, err := exec.LookPath("nft"); err == nil {
					if err := gateway.CleanupFirewall(); err != nil {
						fmt.Fprintf(out, "⚠️  Gateway firewall cleanup notice: %v\n", err)
					} else {
						fmt.Fprintln(out, "✅ Flushed gateway firewall & routing rules")
					}
					_ = exec.Command("nft", "delete", "table", "inet", "xray-proxya").Run()
				}
				if state, err := tune.LoadRuntimeState(); err == nil && state != nil {
					if _, rErr := tune.RollbackRuntimeState(state); rErr != nil {
						fmt.Fprintf(out, "⚠️  Kernel tune rollback notice: %v\n", rErr)
					} else {
						fmt.Fprintln(out, "✅ Rolled back kernel tune sysctl parameters")
					}
				}
			}
		}
	}

	// Phase 3: Disable services, remove unit files & reload daemon
	for _, item := range plan.Items {
		if item.Category == CatService && item.Action == ActionDisable {
			if err := xray.ManageSystemdUnit("disable", item.Target); err != nil {
				// Non-fatal notice if service was not previously enabled
				fmt.Fprintf(out, "ℹ️  Service disable notice (%s): %v\n", item.Target, err)
			} else {
				fmt.Fprintf(out, "✅ Disabled service: %s\n", item.Target)
			}
		}
	}

	for _, item := range plan.Items {
		if item.Category == CatService && item.Action == ActionRemove {
			if err := os.Remove(item.Target); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove unit file %s: %w", item.Target, err))
			} else {
				fmt.Fprintf(out, "✅ Removed unit file: %s\n", item.Target)
			}
		}
	}

	for _, item := range plan.Items {
		if item.Category == CatService && item.Action == ActionReload {
			if err := xray.ReloadSystemdDaemon(); err != nil {
				errs = append(errs, fmt.Errorf("systemd daemon-reload: %w", err))
			} else {
				fmt.Fprintln(out, "✅ Reloaded systemd daemon")
			}
		}
	}

	// Phase 4: Shell environment & completions
	for _, item := range plan.Items {
		if item.Category == CatProfile {
			switch item.Action {
			case ActionRemove:
				if err := os.Remove(item.Target); err != nil && !os.IsNotExist(err) {
					errs = append(errs, fmt.Errorf("remove completion file %s: %w", item.Target, err))
				} else {
					fmt.Fprintf(out, "✅ Removed shell completion file: %s\n", item.Target)
				}
			case ActionCleanCompletion:
				if err := cleanProfileCompletion(item.Target); err != nil {
					errs = append(errs, fmt.Errorf("clean profile completion %s: %w", item.Target, err))
				} else {
					fmt.Fprintf(out, "✅ Cleaned shell completion from: %s\n", item.Target)
				}
			case ActionCleanPath:
				if err := cleanProfilePath(item.Target, installDir); err != nil {
					errs = append(errs, fmt.Errorf("clean profile PATH %s: %w", item.Target, err))
				} else {
					fmt.Fprintf(out, "✅ Cleaned PATH export from: %s\n", item.Target)
				}
			}
		}
	}

	// Phase 5: Files and directories
	for _, item := range plan.Items {
		if item.Category == CatFile && item.Action == ActionRemove {
			if err := os.RemoveAll(item.Target); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove %s: %w", item.Target, err))
			} else {
				fmt.Fprintf(out, "✅ Removed: %s\n", item.Target)
			}
		}
	}

	// Clean up empty directories if config or data was cleared
	if configDir != "" {
		if entries, err := os.ReadDir(configDir); err == nil && len(entries) == 0 {
			_ = os.Remove(configDir)
			fmt.Fprintf(out, "✅ Cleaned empty config directory: %s\n", configDir)
		}
	}
	if homeDir != "" {
		shareDir := filepath.Join(homeDir, ".local", "share", "xray-proxya")
		if entries, err := os.ReadDir(shareDir); err == nil && len(entries) == 0 {
			_ = os.Remove(shareDir)
			fmt.Fprintf(out, "✅ Cleaned empty data directory: %s\n", shareDir)
		}
	}

	// Phase 6: Binaries (Self-deletion as final step)
	for _, item := range plan.Items {
		if item.Category == CatBinary && item.Action == ActionRemove {
			if err := os.Remove(item.Target); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove binary %s: %w", item.Target, err))
			} else {
				fmt.Fprintf(out, "✅ Removed binary: %s\n", item.Target)
			}
		}
	}

	return errors.Join(errs...)
}

const (
	completionStartMarker = "# >>> xray-proxya completion >>>"
	completionEndMarker   = "# <<< xray-proxya completion <<<"
)

func cleanProfileCompletion(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Remove completion marker block
	if strings.Contains(content, completionStartMarker) {
		start := strings.Index(content, completionStartMarker)
		end := strings.Index(content, completionEndMarker)
		if start >= 0 && end > start {
			end += len(completionEndMarker)
			if end < len(content) && content[end] == '\n' {
				end++
			}
			content = content[:start] + content[end:]
		}
	}

	return os.WriteFile(path, []byte(content), info.Mode().Perm())
}

func cleanProfilePath(path, installDir string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	var kept []string
	for _, line := range lines {
		if isXrayProxyaPathLine(line, installDir) {
			continue
		}
		kept = append(kept, line)
	}
	content := strings.Join(kept, "\n")
	return os.WriteFile(path, []byte(content), info.Mode().Perm())
}
