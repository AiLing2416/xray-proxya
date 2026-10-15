package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"
)

// DefaultManager is the default implementation of Controller.
var DefaultManager = NewManager()

// Manager coordinates unit installation, lifecycle operations, and state queries
// across different supported init systems.
type Manager struct {
	provider Provider
}

// NewManager creates a new service Manager using the active init Provider.
func NewManager() *Manager {
	return &Manager{}
}

// NewManagerWithProvider creates a service Manager with an explicit Provider.
func NewManagerWithProvider(p Provider) *Manager {
	return &Manager{provider: p}
}

func (m *Manager) activeProvider() Provider {
	if m.provider != nil {
		return m.provider
	}
	return CurrentProvider()
}

func (m *Manager) Install(cfg *config.UserConfig) error {
	return m.activeProvider().Install(cfg)
}

func (m *Manager) Uninstall() error {
	return m.activeProvider().Uninstall()
}

func (m *Manager) Start(unit string) error {
	return m.ExecuteAction("start", unit, false)
}

func (m *Manager) Stop(unit string) error {
	return m.ExecuteAction("stop", unit, false)
}

func (m *Manager) Restart(unit string) error {
	return m.ExecuteAction("restart", unit, false)
}

func (m *Manager) Enable(unit string, now bool) error {
	return m.ExecuteAction("enable", unit, now)
}

func (m *Manager) Disable(unit string, now bool) error {
	return m.ExecuteAction("disable", unit, now)
}

func (m *Manager) GetStatus(unit string) (Status, error) {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		return Status{}, err
	}
	return m.activeProvider().GetStatus(norm)
}

func (m *Manager) ListManaged(cfg *config.UserConfig) ([]Status, error) {
	return m.activeProvider().ListManaged(cfg)
}

func (m *Manager) IsActive(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return m.activeProvider().IsActive(norm)
}

func (m *Manager) IsEnabled(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return m.activeProvider().IsEnabled(norm)
}

func (m *Manager) IsInstalled(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return m.activeProvider().IsInstalled(norm)
}

// ExecuteAction performs a validated lifecycle action on a managed unit with full gateway hooks and locks.
func (m *Manager) ExecuteAction(action, unitInput string, now bool) error {
	if os.Geteuid() == 0 {
		if err := DirectRootServiceError(); err != nil {
			return err
		}
	}
	unit, err := NormalizeUnitName(unitInput)
	if err != nil {
		return err
	}

	if action == "start" || action == "restart" || (action == "enable" && now) {
		if err := ValidateServiceStart(unit); err != nil {
			return err
		}
	}

	p := m.activeProvider()

	// Main service lifecycle operations
	if unit == MainUnit {
		if action == "restart" {
			if p.Type() == InitSystemd {
				return xray.RestartXrayService()
			}
			return config.WithLifecycleLock(func() error {
				if err := p.Restart(unit); err != nil {
					return err
				}
				if os.Geteuid() == 0 {
					cfg, err := config.LoadConfig()
					if err == nil && cfg.Role == config.RoleGateway {
						_ = gateway.RestoreTunState(cfg)
					}
				}
				return nil
			})
		}
		if action == "stop" || (action == "disable" && now) {
			if os.Geteuid() == 0 {
				return config.WithLifecycleLock(func() error {
					cleanupErr := gateway.CleanupFirewall()
					var actionErr error
					if action == "stop" {
						actionErr = p.Stop(unit)
					} else {
						actionErr = p.Disable(unit, now)
					}
					return errors.Join(cleanupErr, actionErr)
				})
			}
			if action == "stop" {
				return p.Stop(unit)
			}
			return p.Disable(unit, now)
		}

		var actionErr error
		switch action {
		case "start":
			actionErr = p.Start(unit)
		case "enable":
			actionErr = p.Enable(unit, now)
		case "disable":
			actionErr = p.Disable(unit, now)
		default:
			actionErr = fmt.Errorf("unknown service action: %s", action)
		}
		if actionErr != nil {
			return actionErr
		}

		if (action == "start" || (action == "enable" && now)) && os.Geteuid() == 0 {
			cfg, err := config.LoadConfig()
			if err != nil {
				return fmt.Errorf("load active config after service start: %w", err)
			}
			if cfg.Role == config.RoleGateway {
				if err := gateway.RestoreTunState(cfg); err != nil {
					return fmt.Errorf("restore gateway runtime after service start: %w", err)
				}
			}
		}
		return nil
	}

	switch action {
	case "start":
		return p.Start(unit)
	case "stop":
		return p.Stop(unit)
	case "restart":
		return p.Restart(unit)
	case "enable":
		return p.Enable(unit, now)
	case "disable":
		return p.Disable(unit, now)
	default:
		return fmt.Errorf("unknown service action: %s", action)
	}
}

func runSystemctlAction(action, unit string, now bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl is required: %w", err)
	}
	args := append(xray.SystemdScopeArgs(), "--no-ask-password", action)
	if now {
		args = append(args, "--now")
	}
	args = append(args, unit)
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl %s %s: %s", action, unit, msg)
	}
	return nil
}

// Package-level forwarders

func Install(cfg *config.UserConfig) error {
	return DefaultManager.Install(cfg)
}

func Uninstall() error {
	return DefaultManager.Uninstall()
}

func Start(unit string) error {
	return DefaultManager.Start(unit)
}

func Stop(unit string) error {
	return DefaultManager.Stop(unit)
}

func Restart(unit string) error {
	return DefaultManager.Restart(unit)
}

func Enable(unit string, now bool) error {
	return DefaultManager.Enable(unit, now)
}

func Disable(unit string, now bool) error {
	return DefaultManager.Disable(unit, now)
}

func GetStatus(unit string) (Status, error) {
	return DefaultManager.GetStatus(unit)
}

func ListManaged(cfg *config.UserConfig) ([]Status, error) {
	return DefaultManager.ListManaged(cfg)
}

func configureNetworkManagerUnmanaged() error {
	dir := "/etc/NetworkManager/conf.d"
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil
	}
	content := "[keyfile]\nunmanaged-devices=interface-name:proxya-tun;interface-name:path-tun\n"
	target := filepath.Join(dir, "99-xray-proxya.conf")
	if err := os.WriteFile(target, []byte(content), 0644); err != nil {
		return err
	}
	if _, err := exec.LookPath("nmcli"); err == nil {
		_ = exec.Command("nmcli", "general", "reload", "conf").Run()
	}
	return nil
}

func removeNetworkManagerUnmanaged() {
	target := "/etc/NetworkManager/conf.d/99-xray-proxya.conf"
	if _, err := os.Stat(target); err == nil {
		_ = os.Remove(target)
		if _, err := exec.LookPath("nmcli"); err == nil {
			_ = exec.Command("nmcli", "general", "reload", "conf").Run()
		}
	}
}
