package tui

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

// ManagedServiceItem represents a simplified service unit entry for the list-based SERVICE view.
type ManagedServiceItem struct {
	DisplayName string // e.g. "Core", "Pathd", "IPv6-Rotate", "Sub@default"
	UnitName    string // e.g. "xray-proxya.service", "xray-proxya-pathd.service"
	Active      bool
	PID         int
	Status      string // "Running", "Stopped", "Failed"
	Enabled     bool   // systemd enabled on boot
	Description string
}

// QueryManagedServices scans and checks status for all core and auxiliary services.
func QueryManagedServices(cfg *config.UserConfig) []ManagedServiceItem {
	var list []ManagedServiceItem

	// 1. Core Service
	coreActive, corePID := checkUnitState(xray.MainServiceUnit)
	coreStatus := "Stopped"
	if coreActive {
		coreStatus = "Running"
	}
	list = append(list, ManagedServiceItem{
		DisplayName: "Core",
		UnitName:    xray.MainServiceUnit,
		Active:      coreActive,
		PID:         corePID,
		Status:      coreStatus,
		Enabled:     checkUnitEnabled(xray.MainServiceUnit),
		Description: "Main Xray-Core proxy service",
	})

	// 2. Pathd Probe Service
	pathdUnit := "xray-proxya-pathd.service"
	pathdActive, pathdPID := checkUnitState(pathdUnit)
	pathdStatus := "Stopped"
	if pathdActive {
		pathdStatus = "Running"
	}
	list = append(list, ManagedServiceItem{
		DisplayName: "Pathd",
		UnitName:    pathdUnit,
		Active:      pathdActive,
		PID:         pathdPID,
		Status:      pathdStatus,
		Enabled:     checkUnitEnabled(pathdUnit),
		Description: "PathLink ICMP latency & health daemon",
	})

	// 3. IPv6-Rotate Service (Server mode)
	if cfg == nil || cfg.Role == config.RoleServer {
		rotUnit := "xray-proxya-ipv6-rotate.service"
		rotActive, rotPID := checkUnitState(rotUnit)
		rotStatus := "Stopped"
		if rotActive {
			rotStatus = "Running"
		}
		list = append(list, ManagedServiceItem{
			DisplayName: "IPv6-Rotate",
			UnitName:    rotUnit,
			Active:      rotActive,
			PID:         rotPID,
			Status:      rotStatus,
			Enabled:     checkUnitEnabled(rotUnit),
			Description: "Privileged IPv6 subnet address rotator",
		})
	}

	// 4. Subscription service
	subUnit := "xray-proxya-sub.service"
	subActive, subPID := checkUnitState(subUnit)
	subStatus := "Stopped"
	if subActive {
		subStatus = "Running"
	}
	list = append(list, ManagedServiceItem{
		DisplayName: "Sub",
		UnitName:    subUnit,
		Active:      subActive,
		PID:         subPID,
		Status:      subStatus,
		Enabled:     checkUnitEnabled(subUnit),
		Description: "Subscription server",
	})

	return list
}

// RenderServiceList renders the list table of managed services with simplified names.
func RenderServiceList(active *config.UserConfig, staging *config.UserConfig, services []ManagedServiceItem, selectedIdx int, width int) string {
	if len(services) == 0 {
		return "No managed services found."
	}

	headers := []string{"   ", "SERVICE", "STATUS", "PID", "AUTOSTART", "DESCRIPTION"}
	rows := make([][]string, 0, len(services))

	for _, s := range services {
		indicator := "   "
		if serviceHasStagedChanges(active, staging, s) {
			indicator = "[*]"
		}
		pidStr := "--"
		if s.PID > 0 {
			pidStr = fmt.Sprintf("%d", s.PID)
		}
		autostartStr := "Off"
		if s.Enabled {
			autostartStr = "On"
		}

		rows = append(rows, []string{
			indicator,
			s.DisplayName,
			s.Status,
			pidStr,
			autostartStr,
			s.Description,
		})
	}

	widths := fitTableWidths(headers, rows, []int{3, 12, 9, 6, 9, 28}, width)

	var b strings.Builder
	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")

	for i, row := range rows {
		s := renderRow(row, widths, false)
		if !services[i].Active {
			s = faintStyle.Render(s)
		}
		if i == selectedIdx {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// BuildServiceReport builds an informative report for the selected service item.
func BuildServiceReport(item ManagedServiceItem) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Service:     %s\n", item.DisplayName))
	b.WriteString(fmt.Sprintf("Unit File:   %s\n", item.UnitName))
	b.WriteString(fmt.Sprintf("Status:      %s\n", item.Status))
	if item.PID > 0 {
		b.WriteString(fmt.Sprintf("Main PID:    %d\n", item.PID))
	} else {
		b.WriteString("Main PID:    -\n")
	}
	if item.Enabled {
		b.WriteString("Autostart:   Enabled (starts on boot)\n")
	} else {
		b.WriteString("Autostart:   Disabled\n")
	}
	b.WriteString(fmt.Sprintf("Description: %s\n", item.Description))
	return strings.TrimSpace(b.String())
}

func checkUnitState(unit string) (bool, int) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, 0
	}
	args := append(xray.SystemdScopeArgs(), "is-active", unit)
	if err := exec.Command("systemctl", args...).Run(); err != nil {
		return false, 0
	}
	showArgs := append(xray.SystemdScopeArgs(), "show", "-p", "MainPID", "--value", unit)
	out, err := exec.Command("systemctl", showArgs...).Output()
	if err != nil {
		return true, 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return true, pid
}

func checkUnitEnabled(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	args := append(xray.SystemdScopeArgs(), "is-enabled", unit)
	out, err := exec.Command("systemctl", args...).Output()
	if err != nil {
		return false
	}
	res := strings.TrimSpace(string(out))
	return res == "enabled"
}

func findUnitPath(unit string) string {
	if os.Geteuid() != 0 {
		p := filepath.Join(config.GetHomeDir(), ".config", "systemd", "user", unit)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		p := filepath.Join(dir, unit)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
