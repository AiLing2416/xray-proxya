package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
)

// OpenRCProvider implements Provider for Alpine/Gentoo OpenRC init system.
type OpenRCProvider struct{}

// NewOpenRCProvider creates a new OpenRCProvider.
func NewOpenRCProvider() *OpenRCProvider {
	return &OpenRCProvider{}
}

func (p *OpenRCProvider) Type() InitType {
	return InitOpenRC
}

func (p *OpenRCProvider) Detect() bool {
	if fi, err := os.Stat("/run/openrc"); err == nil && fi.IsDir() {
		return true
	}
	_, err := exec.LookPath("rc-service")
	return err == nil
}

func (p *OpenRCProvider) UnitDirectory() string {
	return "/etc/init.d"
}

func (p *OpenRCProvider) UnitPath(unit string) string {
	name := BaseServiceName(unit)
	return filepath.Join(p.UnitDirectory(), name)
}

func (p *OpenRCProvider) requireRoot(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("openrc %s requires direct root execution; user services are not supported", action)
	}
	return DirectRootServiceError()
}

func (p *OpenRCProvider) Install(cfg *config.UserConfig) error {
	if err := p.requireRoot("install"); err != nil {
		return err
	}
	if _, err := exec.LookPath("rc-service"); err != nil {
		return fmt.Errorf("openrc rc-service binary not found: %w", err)
	}
	if cfg == nil {
		var err error
		cfg, err = config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load configuration: %w", err)
		}
	}

	binPath, err := ValidateRootManagerBinary()
	if err != nil {
		return err
	}

	workDir := filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya")
	assetDir := filepath.Join(workDir, "bin")
	if err := os.MkdirAll(assetDir, 0700); err != nil {
		return fmt.Errorf("create asset directory: %w", err)
	}

	// 1. Write /etc/init.d/xray-proxya
	mainContent := BuildOpenRCServiceContent(binPath, workDir, assetDir)
	mainPath := p.UnitPath(MainUnit)
	if err := os.WriteFile(mainPath, []byte(mainContent), 0755); err != nil {
		return fmt.Errorf("write %s: %w", mainPath, err)
	}

	// 2. Write /etc/init.d/xray-proxya-sub
	subContent := BuildOpenRCSubServiceContent(binPath, workDir, assetDir)
	subPath := p.UnitPath(SubUnit)
	if err := os.WriteFile(subPath, []byte(subContent), 0755); err != nil {
		return fmt.Errorf("write %s: %w", subPath, err)
	}

	// 3. Write /etc/init.d/xray-proxya-pathd if pathd binary is available
	pathdPath, err := ValidateRootOwnedExecutable(PathdBinaryPath())
	if err == nil {
		if cfg.Role == config.RoleServer && cfg.Path.Token != "" {
			_ = WritePathdConfig(cfg)
		}
		pathdContent := BuildOpenRCPathdServiceContent(pathdPath, PathdConfigPath())
		if err := os.WriteFile(p.UnitPath(PathdUnit), []byte(pathdContent), 0755); err != nil {
			return fmt.Errorf("write %s: %w", p.UnitPath(PathdUnit), err)
		}
	}

	_ = configureNetworkManagerUnmanaged()
	return nil
}

func (p *OpenRCProvider) Uninstall() error {
	if err := p.requireRoot("uninstall"); err != nil {
		return err
	}
	managed := []string{MainUnit, PathdUnit, SubUnit}
	for _, u := range managed {
		if p.IsActive(u) {
			return fmt.Errorf("stop service %s before uninstalling", BaseServiceName(u))
		}
	}
	for _, u := range managed {
		_ = p.Disable(u, false)
		path := p.UnitPath(u)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	removeNetworkManagerUnmanaged()
	return nil
}

func (p *OpenRCProvider) Start(unit string) error {
	if err := p.requireRoot("start"); err != nil {
		return err
	}
	name := BaseServiceName(unit)
	out, err := exec.Command("rc-service", name, "start").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rc-service %s start: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *OpenRCProvider) Stop(unit string) error {
	if err := p.requireRoot("stop"); err != nil {
		return err
	}
	name := BaseServiceName(unit)
	out, err := exec.Command("rc-service", name, "stop").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rc-service %s stop: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *OpenRCProvider) Restart(unit string) error {
	if err := p.requireRoot("restart"); err != nil {
		return err
	}
	name := BaseServiceName(unit)
	out, err := exec.Command("rc-service", name, "restart").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rc-service %s restart: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *OpenRCProvider) Enable(unit string, now bool) error {
	if err := p.requireRoot("enable"); err != nil {
		return err
	}
	name := BaseServiceName(unit)
	out, err := exec.Command("rc-update", "add", name, "default").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already added") {
		return fmt.Errorf("rc-update add %s default: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	if now {
		return p.Start(unit)
	}
	return nil
}

func (p *OpenRCProvider) Disable(unit string, now bool) error {
	if err := p.requireRoot("disable"); err != nil {
		return err
	}
	name := BaseServiceName(unit)
	if now {
		_ = p.Stop(unit)
	}
	out, err := exec.Command("rc-update", "del", name, "default").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "is not in the runlevel") {
		return fmt.Errorf("rc-update del %s default: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *OpenRCProvider) GetStatus(unit string) (Status, error) {
	name := BaseServiceName(unit)
	st := Status{
		UnitName:    name,
		DisplayName: UnitDisplayName(unit),
		State:       "Stopped",
		UnitPath:    p.UnitPath(unit),
	}
	st.Installed = p.IsInstalled(unit)
	if !st.Installed {
		st.State = "Not Installed"
		return st, nil
	}

	st.Enabled = p.IsEnabled(unit)

	out, err := exec.Command("rc-service", name, "status").CombinedOutput()
	text := string(out)
	if err == nil {
		st.Active = true
		st.State = "Running"
		st.PID = p.findPid(name)
	} else if strings.Contains(text, "crashed") {
		st.State = "Failed"
	} else {
		st.State = "Stopped"
	}
	return st, nil
}

func (p *OpenRCProvider) findPid(name string) int {
	pidPath := filepath.Join("/run", name+".pid")
	if data, err := os.ReadFile(pidPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

func (p *OpenRCProvider) ListManaged(cfg *config.UserConfig) ([]Status, error) {
	var list []Status
	for _, u := range []string{MainUnit, PathdUnit, SubUnit} {
		st, _ := p.GetStatus(u)
		list = append(list, st)
	}
	return list, nil
}

func (p *OpenRCProvider) IsActive(unit string) bool {
	name := BaseServiceName(unit)
	return exec.Command("rc-service", name, "status").Run() == nil
}

func (p *OpenRCProvider) IsEnabled(unit string) bool {
	name := BaseServiceName(unit)
	symlink := filepath.Join("/etc/runlevels/default", name)
	_, err := os.Lstat(symlink)
	return err == nil
}

func (p *OpenRCProvider) IsInstalled(unit string) bool {
	_, err := os.Stat(p.UnitPath(unit))
	return err == nil
}
