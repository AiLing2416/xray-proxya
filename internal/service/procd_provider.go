package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
)

// ProcdProvider implements Provider for OpenWrt procd init system.
type ProcdProvider struct{}

// NewProcdProvider creates a new ProcdProvider.
func NewProcdProvider() *ProcdProvider {
	return &ProcdProvider{}
}

func (p *ProcdProvider) Type() InitType {
	return InitProcd
}

func (p *ProcdProvider) Detect() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if _, err := os.Stat("/sbin/procd"); err == nil {
		return true
	}
	return false
}

func (p *ProcdProvider) UnitDirectory() string {
	return "/etc/init.d"
}

func (p *ProcdProvider) UnitPath(unit string) string {
	name := BaseServiceName(unit)
	return filepath.Join(p.UnitDirectory(), name)
}

func (p *ProcdProvider) requireRoot(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("procd %s requires direct root execution; user services are not supported", action)
	}
	return DirectRootServiceError()
}

func (p *ProcdProvider) Install(cfg *config.UserConfig) error {
	if err := p.requireRoot("install"); err != nil {
		return err
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
	mainContent := BuildProcdServiceContent(binPath, workDir, assetDir)
	mainPath := p.UnitPath(MainUnit)
	if err := os.WriteFile(mainPath, []byte(mainContent), 0755); err != nil {
		return fmt.Errorf("write %s: %w", mainPath, err)
	}

	// 2. Write /etc/init.d/xray-proxya-sub
	subContent := BuildProcdSubServiceContent(binPath, workDir, assetDir)
	subPath := p.UnitPath(SubUnit)
	if err := os.WriteFile(subPath, []byte(subContent), 0755); err != nil {
		return fmt.Errorf("write %s: %w", subPath, err)
	}

	// 3. Write /etc/init.d/xray-proxya-pathd if pathd binary is available
	pathdPath, err := ValidateRootOwnedExecutable(PathdBinaryPath())
	if err == nil {
		if cfg.Role == config.RoleServer && cfg.Path.Token != "" {
			if err := WritePathdConfig(cfg); err != nil {
				return fmt.Errorf("write pathd configuration: %w", err)
			}
		}
		pathdContent := BuildProcdPathdServiceContent(pathdPath, PathdConfigPath())
		if err := os.WriteFile(p.UnitPath(PathdUnit), []byte(pathdContent), 0755); err != nil {
			return fmt.Errorf("write %s: %w", p.UnitPath(PathdUnit), err)
		}
	} else {
		_ = os.Remove(p.UnitPath(PathdUnit))
	}

	_ = configureNetworkManagerUnmanaged()
	return nil
}

func (p *ProcdProvider) Uninstall() error {
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

func (p *ProcdProvider) Start(unit string) error {
	if err := p.requireRoot("start"); err != nil {
		return err
	}
	path := p.UnitPath(unit)
	out, err := exec.Command(path, "start").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s start: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *ProcdProvider) Stop(unit string) error {
	if err := p.requireRoot("stop"); err != nil {
		return err
	}
	path := p.UnitPath(unit)
	out, err := exec.Command(path, "stop").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s stop: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *ProcdProvider) Restart(unit string) error {
	if err := p.requireRoot("restart"); err != nil {
		return err
	}
	path := p.UnitPath(unit)
	out, err := exec.Command(path, "restart").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s restart: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *ProcdProvider) Enable(unit string, now bool) error {
	if err := p.requireRoot("enable"); err != nil {
		return err
	}
	path := p.UnitPath(unit)
	out, err := exec.Command(path, "enable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s enable: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	if now {
		return p.Start(unit)
	}
	return nil
}

func (p *ProcdProvider) Disable(unit string, now bool) error {
	if err := p.requireRoot("disable"); err != nil {
		return err
	}
	path := p.UnitPath(unit)
	if now {
		_ = p.Stop(unit)
	}
	out, err := exec.Command(path, "disable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s disable: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *ProcdProvider) GetStatus(unit string) (Status, error) {
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

	// Check procd state via ubus if available
	active, pid := p.queryUbus(name)
	if active {
		st.Active = true
		st.State = "Running"
		st.PID = pid
	} else {
		// Fallback to running /etc/init.d/<name> status if executable
		if err := exec.Command(st.UnitPath, "status").Run(); err == nil {
			st.Active = true
			st.State = "Running"
		} else {
			st.State = "Stopped"
		}
	}
	return st, nil
}

func (p *ProcdProvider) queryUbus(name string) (bool, int) {
	out, err := exec.Command("ubus", "call", "service", "list", fmt.Sprintf(`{"name":"%s"}`, name)).Output()
	if err != nil {
		return false, 0
	}
	var resp map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
			PID     int  `json:"pid"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(out, &resp); err == nil {
		if svc, ok := resp[name]; ok {
			for _, inst := range svc.Instances {
				if inst.Running {
					return true, inst.PID
				}
			}
		}
	}
	return false, 0
}

func (p *ProcdProvider) ListManaged(cfg *config.UserConfig) ([]Status, error) {
	var list []Status
	for _, u := range []string{MainUnit, PathdUnit, SubUnit} {
		st, _ := p.GetStatus(u)
		list = append(list, st)
	}
	return list, nil
}

func (p *ProcdProvider) IsActive(unit string) bool {
	st, err := p.GetStatus(unit)
	return err == nil && st.Active
}

func (p *ProcdProvider) IsEnabled(unit string) bool {
	path := p.UnitPath(unit)
	return exec.Command(path, "enabled").Run() == nil
}

func (p *ProcdProvider) IsInstalled(unit string) bool {
	_, err := os.Stat(p.UnitPath(unit))
	return err == nil
}
