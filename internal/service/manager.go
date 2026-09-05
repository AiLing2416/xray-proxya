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

// Manager coordinates systemd unit installation, lifecycle operations, and state queries.
type Manager struct{}

// NewManager creates a new systemd service Manager.
func NewManager() *Manager {
	return &Manager{}
}

// Install writes unit files for managed services and reloads systemd.
func (m *Manager) Install(cfg *config.UserConfig) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd is required for service installation: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := DirectRootServiceError(); err != nil {
			return err
		}
	}
	if cfg == nil {
		var err error
		cfg, err = config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load configuration: %w", err)
		}
	}
	system := os.Geteuid() == 0
	if system {
		if err := DirectRootServiceError(); err != nil {
			return err
		}
	} else if cfg.Role == config.RoleGateway {
		return fmt.Errorf("gateway role requires a direct-root system service; user services are non-privileged")
	}

	binPath := xray.GetXrayProxyaPath()
	var err error
	if system {
		if binPath, err = ValidateRootManagerBinary(); err != nil {
			return err
		}
	} else if binPath, err = filepath.Abs(binPath); err != nil {
		return fmt.Errorf("resolve manager binary: %w", err)
	}

	workDir := filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya")
	assetDir := filepath.Join(workDir, "bin")
	configDir := config.GetConfigDir()
	if err := os.MkdirAll(assetDir, 0700); err != nil {
		return fmt.Errorf("create asset directory: %w", err)
	}

	var pathdContent string
	if system {
		pathdPath, err := ValidateRootOwnedExecutable(PathdBinaryPath())
		if err != nil {
			return fmt.Errorf("pathd binary is unavailable: %w", err)
		}
		if cfg.Role == config.RoleServer && cfg.Path.Token != "" {
			if err := WritePathdConfig(cfg); err != nil {
				return fmt.Errorf("write pathd configuration: %w", err)
			}
		}
		pathdContent = BuildPathdServiceContent(pathdPath, PathdConfigPath())
	}

	if err := os.MkdirAll(UnitDirectory(), 0700); err != nil {
		return fmt.Errorf("create systemd unit directory: %w", err)
	}

	privateDevices := cfg.Role != config.RoleGateway
	mainContent := BuildSystemdServiceContent(binPath, workDir, assetDir, configDir, MainUnitCapabilities(cfg), system, privateDevices)
	if err := os.WriteFile(ManagedUnitPath(MainUnit), []byte(mainContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", MainUnit, err)
	}

	subContent := BuildSubServiceContent(binPath, workDir, configDir, assetDir, system)
	if err := os.WriteFile(ManagedUnitPath(SubUnit), []byte(subContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", SubUnit, err)
	}

	if system {
		rotateContent := BuildIPv6RotateServiceContent(binPath, workDir, configDir, assetDir)
		if err := os.WriteFile(ManagedUnitPath(RotateUnit), []byte(rotateContent), 0644); err != nil {
			return fmt.Errorf("write %s: %w", RotateUnit, err)
		}
	}

	if pathdContent != "" {
		if err := os.WriteFile(ManagedUnitPath(PathdUnit), []byte(pathdContent), 0644); err != nil {
			return fmt.Errorf("write %s: %w", PathdUnit, err)
		}
	}

	return xray.ReloadSystemdDaemon()
}

// Uninstall removes all managed systemd unit files and reloads systemd.
func (m *Manager) Uninstall() error {
	if os.Geteuid() == 0 {
		if err := DirectRootServiceError(); err != nil {
			return err
		}
	}
	active, err := ActiveManagedUnits()
	if err != nil {
		return err
	}
	if len(active) > 0 {
		return fmt.Errorf("stop all managed services before uninstalling: %s", strings.Join(active, ", "))
	}
	for _, unit := range []string{MainUnit, PathdUnit, SubUnit, SubTemplateUnit, RotateUnit} {
		if err := os.Remove(ManagedUnitPath(unit)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", unit, err)
		}
	}
	return xray.ReloadSystemdDaemon()
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

	// Main service lifecycle operations
	if unit == MainUnit {
		if action == "restart" {
			return xray.RestartXrayService()
		}
		if action == "stop" || (action == "disable" && now) {
			return config.WithLifecycleLock(func() error {
				cleanupErr := gateway.CleanupFirewall()
				return errors.Join(cleanupErr, runSystemctlAction(action, unit, now))
			})
		}
		if err := runSystemctlAction(action, unit, now); err != nil {
			return err
		}
		if action == "start" || (action == "enable" && now) {
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

	// Auxiliary service lifecycle operations
	if action == "start" || action == "restart" || (action == "enable" && now) {
		if err := ValidateServiceStart(unit); err != nil {
			return err
		}
	}

	return runSystemctlAction(action, unit, now)
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
	return GetUnitStatus(norm), nil
}

func (m *Manager) ListManaged(cfg *config.UserConfig) ([]Status, error) {
	return ListManagedServices(cfg)
}

func (m *Manager) IsActive(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return IsUnitActive(norm)
}

func (m *Manager) IsEnabled(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return IsUnitEnabled(norm)
}

func (m *Manager) IsInstalled(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return IsUnitInstalled(norm)
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
