package service

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
)

// GetUnitStatus queries systemd for the current status of a specific unit.
func GetUnitStatus(unit string) Status {
	st := Status{
		UnitName: unit,
		State:    "Stopped",
	}
	switch unit {
	case MainUnit:
		st.DisplayName = "Core"
		st.Description = "Main Xray-Core proxy service"
	case PathdUnit:
		st.DisplayName = "Pathd"
		st.Description = "PathLink ICMP latency & health daemon"
	case RotateUnit:
		st.DisplayName = "IPv6-Rotate"
		st.Description = "Privileged IPv6 subnet address rotator"
	case SubUnit:
		st.DisplayName = "Sub"
		st.Description = "Subscription server"
	default:
		st.DisplayName = unit
		st.Description = "Managed systemd service"
	}

	st.UnitPath = FindUnitFile(unit)
	st.Installed = st.UnitPath != ""

	if _, err := exec.LookPath("systemctl"); err != nil {
		st.State = "Unavailable (systemctl missing)"
		return st
	}

	// Check if active
	args := append(xray.SystemdScopeArgs(), "is-active", unit)
	if err := exec.Command("systemctl", args...).Run(); err == nil {
		st.Active = true
		st.State = "Running"
		showPIDArgs := append(xray.SystemdScopeArgs(), "show", "-p", "MainPID", "--value", unit)
		if out, err := exec.Command("systemctl", showPIDArgs...).Output(); err == nil {
			st.PID, _ = strconv.Atoi(strings.TrimSpace(string(out)))
		}
	} else {
		// Not active: check detailed load/active state
		showArgs := append(xray.SystemdScopeArgs(), "show", "-p", "ActiveState,LoadState", "--value", unit)
		if out, err := exec.Command("systemctl", showArgs...).Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) >= 2 && lines[1] == "not-found" {
				st.State = "Not Installed"
				st.Installed = false
			} else if len(lines) >= 1 && lines[0] == "failed" {
				st.State = "Failed"
			} else {
				st.State = "Stopped"
			}
		}
	}

	// Check if enabled
	enabledArgs := append(xray.SystemdScopeArgs(), "is-enabled", unit)
	if out, err := exec.Command("systemctl", enabledArgs...).Output(); err == nil {
		st.Enabled = strings.TrimSpace(string(out)) == "enabled"
	}

	return st
}

// IsUnitActive reports whether the given unit is currently active.
func IsUnitActive(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	args := append(xray.SystemdScopeArgs(), "is-active", "--quiet", unit)
	return exec.Command("systemctl", args...).Run() == nil
}

// IsUnitEnabled reports whether the given unit is enabled for autostart.
func IsUnitEnabled(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	args := append(xray.SystemdScopeArgs(), "is-enabled", "--quiet", unit)
	return exec.Command("systemctl", args...).Run() == nil
}

// IsUnitInstalled reports whether the unit file exists on disk.
func IsUnitInstalled(unit string) bool {
	return FindUnitFile(unit) != ""
}

// ActiveManagedUnits lists all currently active managed service unit names.
func ActiveManagedUnits() ([]string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, fmt.Errorf("systemctl is required: %w", err)
	}
	args := append(xray.SystemdScopeArgs(), "--no-legend", "--plain", "--type=service", "--state=active", "list-units",
		MainUnit, PathdUnit, SubUnit, "xray-proxya-sub@*.service", RotateUnit)
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

// ListManagedServices queries and returns the status of all managed services for the given configuration.
func ListManagedServices(cfg *config.UserConfig) ([]Status, error) {
	var list []Status

	// 1. Core Service
	list = append(list, GetUnitStatus(MainUnit))

	// 2. Pathd Probe Service
	list = append(list, GetUnitStatus(PathdUnit))

	// 3. IPv6-Rotate Service (Server mode)
	if cfg == nil || cfg.Role == config.RoleServer {
		list = append(list, GetUnitStatus(RotateUnit))
	}

	// 4. Subscription service
	list = append(list, GetUnitStatus(SubUnit))

	return list, nil
}
