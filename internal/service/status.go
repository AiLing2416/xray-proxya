package service

import (
	"fmt"
	"os/exec"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
)

// GetUnitStatus queries the active provider for the current status of a specific unit.
func GetUnitStatus(unit string) Status {
	norm, err := NormalizeUnitName(unit)
	if err != nil {
		norm = unit
	}
	st, err := CurrentProvider().GetStatus(norm)
	if err != nil {
		return Status{
			UnitName:    norm,
			DisplayName: UnitDisplayName(norm),
			State:       fmt.Sprintf("Error: %v", err),
		}
	}
	return st
}

// parseUnitShowState parses systemd show key-value outputs for load and active states.
func parseUnitShowState(output string) (state string, installed bool) {
	activeState := ""
	loadState := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ActiveState=") {
			activeState = strings.TrimPrefix(line, "ActiveState=")
		} else if strings.HasPrefix(line, "LoadState=") {
			loadState = strings.TrimPrefix(line, "LoadState=")
		}
	}
	if loadState == "not-found" {
		return "Not Installed", false
	}
	if activeState == "failed" {
		return "Failed", true
	}
	return "Stopped", true
}

// IsUnitActive reports whether the given unit is currently active.
func IsUnitActive(unit string) bool {
	return CurrentProvider().IsActive(unit)
}

// IsUnitEnabled reports whether the given unit is enabled for autostart.
func IsUnitEnabled(unit string) bool {
	return CurrentProvider().IsEnabled(unit)
}

// IsUnitInstalled reports whether the unit file exists on disk.
func IsUnitInstalled(unit string) bool {
	return CurrentProvider().IsInstalled(unit)
}

// ActiveManagedUnits lists all currently active managed service unit names.
func ActiveManagedUnits() ([]string, error) {
	p := CurrentProvider()
	if p.Type() == InitSystemd {
		if _, err := exec.LookPath("systemctl"); err != nil {
			return nil, fmt.Errorf("systemctl is required: %w", err)
		}
		args := append(xray.SystemdScopeArgs(), "--no-legend", "--plain", "--type=service", "--state=active", "list-units",
			MainUnit, GatewayRestoreUnit, PathdUnit, SubUnit, "xray-proxya-sub@*.service", "he-tunnel*.service")
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("list active managed units: %w: %s", err, strings.TrimSpace(string(out)))
		}
		var units []string
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				units = append(units, fields[0])
			}
		}
		return units, nil
	}

	var active []string
	for _, u := range []string{MainUnit, PathdUnit, SubUnit} {
		if p.IsActive(u) {
			active = append(active, u)
		}
	}
	return active, nil
}

// ListManagedServices queries and returns the status of all managed services for the given configuration.
func ListManagedServices(cfg *config.UserConfig) ([]Status, error) {
	return CurrentProvider().ListManaged(cfg)
}
