package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/service"
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
	statuses, _ := service.ListManagedServices(cfg)
	list := make([]ManagedServiceItem, len(statuses))
	for i, st := range statuses {
		status := st.State
		if st.Active {
			status = "Running"
		} else if st.State == "Not Installed" {
			status = "Stopped"
		}
		list[i] = ManagedServiceItem{
			DisplayName: st.DisplayName,
			UnitName:    st.UnitName,
			Active:      st.Active,
			PID:         st.PID,
			Status:      status,
			Enabled:     st.Enabled,
			Description: st.Description,
		}
	}
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

