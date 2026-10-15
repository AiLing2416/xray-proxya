package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
)

// SystemdProvider implements Provider for systemd init and service manager.
type SystemdProvider struct{}

// NewSystemdProvider creates a new SystemdProvider.
func NewSystemdProvider() *SystemdProvider {
	return &SystemdProvider{}
}

func (p *SystemdProvider) Type() InitType {
	return InitSystemd
}

func (p *SystemdProvider) Detect() bool {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return true
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func (p *SystemdProvider) UnitDirectory() string {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system"
	}
	return filepath.Join(config.GetHomeDir(), ".config", "systemd", "user")
}

func (p *SystemdProvider) UnitPath(unit string) string {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return filepath.Join(p.UnitDirectory(), norm)
}

func (p *SystemdProvider) Install(cfg *config.UserConfig) error {
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

	if err := os.MkdirAll(p.UnitDirectory(), 0700); err != nil {
		return fmt.Errorf("create systemd unit directory: %w", err)
	}

	privateDevices := cfg.Role != config.RoleGateway
	mainContent := BuildSystemdServiceContent(binPath, workDir, assetDir, configDir, MainUnitCapabilities(cfg), system, privateDevices)
	if err := os.WriteFile(p.UnitPath(MainUnit), []byte(mainContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", MainUnit, err)
	}

	subContent := BuildSubServiceContent(binPath, workDir, configDir, assetDir, system)
	if err := os.WriteFile(p.UnitPath(SubUnit), []byte(subContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", SubUnit, err)
	}

	if system {
		restoreContent := BuildGatewayRestoreServiceContent(binPath)
		if err := os.WriteFile(p.UnitPath(GatewayRestoreUnit), []byte(restoreContent), 0644); err != nil {
			return fmt.Errorf("write %s: %w", GatewayRestoreUnit, err)
		}
		_ = xray.ManageSystemdUnit("enable", GatewayRestoreUnit)
		_ = configureNetworkManagerUnmanaged()
	}

	// Clean up obsolete legacy ipv6-rotate service unit if present
	_ = os.Remove(p.UnitPath("xray-proxya-ipv6-rotate.service"))

	if pathdContent != "" {
		if err := os.WriteFile(p.UnitPath(PathdUnit), []byte(pathdContent), 0644); err != nil {
			return fmt.Errorf("write %s: %w", PathdUnit, err)
		}
	}

	return xray.ReloadSystemdDaemon()
}

func (p *SystemdProvider) Uninstall() error {
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
	managedUnits := []string{MainUnit, PathdUnit, SubUnit, SubTemplateUnit, GatewayRestoreUnit, "xray-proxya-ipv6-rotate.service"}
	for _, unit := range managedUnits {
		if _, err := os.Stat(p.UnitPath(unit)); err == nil {
			_ = xray.ManageSystemdUnit("disable", unit)
		}
	}
	for _, unit := range managedUnits {
		if err := os.Remove(p.UnitPath(unit)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", unit, err)
		}
	}
	removeNetworkManagerUnmanaged()
	return xray.ReloadSystemdDaemon()
}

func (p *SystemdProvider) Start(unit string) error {
	return p.action("start", unit, false)
}

func (p *SystemdProvider) Stop(unit string) error {
	return p.action("stop", unit, false)
}

func (p *SystemdProvider) Restart(unit string) error {
	return p.action("restart", unit, false)
}

func (p *SystemdProvider) Enable(unit string, now bool) error {
	return p.action("enable", unit, now)
}

func (p *SystemdProvider) Disable(unit string, now bool) error {
	return p.action("disable", unit, now)
}

func (p *SystemdProvider) action(action, unit string, now bool) error {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		return err
	}
	return runSystemctlAction(action, norm, now)
}

func (p *SystemdProvider) GetStatus(unit string) (Status, error) {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		return Status{}, err
	}
	st := Status{
		UnitName:    norm,
		DisplayName: UnitDisplayName(norm),
		State:       "Stopped",
	}
	switch norm {
	case MainUnit:
		st.Description = "Main Xray-Core proxy service"
	case GatewayRestoreUnit:
		st.Description = "Gateway runtime state restore"
	case PathdUnit:
		st.Description = "PathLink ICMP latency & health daemon"
	case SubUnit:
		st.Description = "Subscription server"
	default:
		st.Description = "Managed systemd service"
	}

	st.UnitPath = p.findUnitFile(norm)
	st.Installed = st.UnitPath != ""

	if _, err := exec.LookPath("systemctl"); err != nil {
		st.State = "Unavailable (systemctl missing)"
		return st, nil
	}

	// Check if active
	args := append(xray.SystemdScopeArgs(), "is-active", norm)
	if err := exec.Command("systemctl", args...).Run(); err == nil {
		st.Active = true
		st.State = "Running"
		showPIDArgs := append(xray.SystemdScopeArgs(), "show", "-p", "MainPID", "--value", norm)
		if out, err := exec.Command("systemctl", showPIDArgs...).Output(); err == nil {
			st.PID, _ = strconv.Atoi(strings.TrimSpace(string(out)))
		}
	} else {
		showArgs := append(xray.SystemdScopeArgs(), "show", "-p", "ActiveState", "-p", "LoadState", norm)
		if out, err := exec.Command("systemctl", showArgs...).Output(); err == nil {
			state, installed := parseUnitShowState(string(out))
			st.State = state
			if !installed {
				st.Installed = false
			}
		}
	}

	enabledArgs := append(xray.SystemdScopeArgs(), "is-enabled", norm)
	if out, err := exec.Command("systemctl", enabledArgs...).Output(); err == nil {
		st.Enabled = strings.TrimSpace(string(out)) == "enabled"
	}

	return st, nil
}

func (p *SystemdProvider) findUnitFile(unit string) string {
	if os.Geteuid() != 0 {
		path := filepath.Join(p.UnitDirectory(), unit)
		if _, err := os.Stat(path); err == nil {
			return path
		}
		return ""
	}
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		path := filepath.Join(dir, unit)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func (p *SystemdProvider) ListManaged(cfg *config.UserConfig) ([]Status, error) {
	var list []Status
	for _, u := range []string{MainUnit, PathdUnit, SubUnit} {
		st, _ := p.GetStatus(u)
		list = append(list, st)
	}
	return list, nil
}

func (p *SystemdProvider) IsActive(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	args := append(xray.SystemdScopeArgs(), "is-active", "--quiet", norm)
	return exec.Command("systemctl", args...).Run() == nil
}

func (p *SystemdProvider) IsEnabled(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	args := append(xray.SystemdScopeArgs(), "is-enabled", "--quiet", norm)
	return exec.Command("systemctl", args...).Run() == nil
}

func (p *SystemdProvider) IsInstalled(unit string) bool {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	return p.findUnitFile(norm) != ""
}
