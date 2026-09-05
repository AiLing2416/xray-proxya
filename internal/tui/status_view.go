package tui

import (
	"fmt"
	"sort"
	"strings"
	"xray-proxya/internal/buildinfo"
	"xray-proxya/internal/config"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/units"

	"github.com/charmbracelet/lipgloss"
)

type namedStatRow struct {
	name  string
	value int64
}

// RenderStatus renders the optimized STATUS home view, combining the ASCII banner,
// core service runtime status, and real-time cumulative traffic analytics.
func RenderStatus(cfg *config.UserConfig, state xray.ServiceState, allStats map[string]int64) string {
	statusStr := "Inactive (Stopped)"
	statusStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	if state.Active {
		if state.PID > 0 {
			statusStr = fmt.Sprintf("Active (PID: %d)", state.PID)
		} else {
			statusStr = "Active"
		}
		statusStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))
	}

	summary := trafficstats.Summarize(allStats)
	var b strings.Builder

	// 1. ASCII Banner & Version
	b.WriteString(renderHomeTitle())
	b.WriteString("\n\n")

	// 2. Core Service Runtime & System Information
	roleName := "Server"
	if cfg != nil && cfg.Role == config.RoleGateway {
		roleName = "Gateway"
	}

	controlMode := state.ControlMode
	if controlMode == "" {
		controlMode = state.InitSystem
	}
	if controlMode == "systemd" {
		if state.IsRoot {
			controlMode = "Systemd (Root)"
		} else {
			controlMode = "Systemd (User)"
		}
	} else if controlMode == "nohup" {
		controlMode = "Nohup (Fallback)"
	}

	coreRows := [][]string{
		{"Core Service", statusStyle.Render(statusStr)},
		{"Control Mode", controlMode},
		{"Role", roleName},
		{"Direct Traffic", HumanizeBytes(summary.Direct)},
		{"Relay Traffic", HumanizeBytes(summary.Relay)},
	}
	if cfg != nil {
		coreRows = append(coreRows,
			[]string{"Global UUID", cfg.UUID},
			[]string{"API Inbound", fmt.Sprintf("127.0.0.1:%d", cfg.APIInbound)},
		)
	}

	for _, r := range coreRows {
		b.WriteString(fmt.Sprintf("%-16s %s\n", r[0]+":", r[1]))
	}

	// 3. Traffic Usage Breakdowns
	appendOrderedInboundStats(&b, "\nInbound Presets Traffic", cfg, summary.InboundStats)
	appendNamedStats(&b, "\nOutbound Relays Traffic", summary.RelayStats)
	appendNamedStats(&b, "\nGuests Traffic", summary.GuestStats)

	return lipgloss.NewStyle().Padding(0, 1).Render(b.String())
}

// BuildStatusReport generates a clean plain-text status report for clipboard copying.
func BuildStatusReport(cfg *config.UserConfig, state xray.ServiceState, allStats map[string]int64) string {
	statusStr := "Inactive (Stopped)"
	if state.Active {
		if state.PID > 0 {
			statusStr = fmt.Sprintf("Active (PID: %d)", state.PID)
		} else {
			statusStr = "Active"
		}
	}

	summary := trafficstats.Summarize(allStats)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Xray-Proxya v%s Status Report\n", buildinfo.Version))
	b.WriteString("=====================================\n")
	b.WriteString(fmt.Sprintf("Main Service:     %s\n", statusStr))
	b.WriteString(fmt.Sprintf("Control Mode:     %s\n", state.ControlMode))
	if cfg != nil {
		b.WriteString(fmt.Sprintf("Role:             %s\n", cfg.Role))
		b.WriteString(fmt.Sprintf("Global UUID:      %s\n", cfg.UUID))
		b.WriteString(fmt.Sprintf("API Inbound:      127.0.0.1:%d\n", cfg.APIInbound))
		b.WriteString(fmt.Sprintf("Config Path:      %s\n", config.GetConfigPath()))
	}
	b.WriteString(fmt.Sprintf("Direct Outbound:  %s\n", HumanizeBytes(summary.Direct)))
	b.WriteString(fmt.Sprintf("Relay Outbound:   %s\n", HumanizeBytes(summary.Relay)))

	appendOrderedPlainInboundStats(&b, "\nInbound Usage:", cfg, summary.InboundStats)
	appendPlainNamedStats(&b, "\nRelay Usage:", summary.RelayStats)
	appendPlainNamedStats(&b, "\nGuest Usage:", summary.GuestStats)
	return strings.TrimSpace(b.String())
}

func appendOrderedInboundStats(b *strings.Builder, title string, cfg *config.UserConfig, stats map[string]int64) {
	if len(stats) == 0 {
		return
	}
	rows := orderedInboundRows(cfg, stats)
	if len(rows) == 0 {
		return
	}
	b.WriteString(title)
	b.WriteString("\n")
	for _, row := range rows {
		b.WriteString(fmt.Sprintf("  %-20s %s\n", row.name, HumanizeBytes(row.value)))
	}
}

func appendNamedStats(b *strings.Builder, title string, stats map[string]int64) {
	if len(stats) == 0 {
		return
	}
	b.WriteString(title)
	b.WriteString("\n")
	keys := sortedKeys(stats)
	for _, key := range keys {
		b.WriteString(fmt.Sprintf("  %-20s %s\n", key, HumanizeBytes(stats[key])))
	}
}

func renderHomeTitle() string {
	lines := []string{
		"__  __                  ___                           ",
		"\\ \\/ /_ __ __ _ _   _  / _ \\_ __ _____  ___   _  __ _ ",
		" \\  /| '__/ _` | | | |/ /_)/ '__/ _ \\ \\/ / | | |/ _` |",
		" /  \\| | | (_| | |_| / ___/| | | (_) >  <| |_| | (_| |",
		"/_/\\_\\_|  \\__,_|\\__, \\/    |_|  \\___/_/\\_\\\\__, |\\__,_|",
		"                |___/                     |___/       " + lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render("v"+buildinfo.Version),
	}
	return strings.Join(lines, "\n")
}

func appendOrderedPlainInboundStats(b *strings.Builder, title string, cfg *config.UserConfig, stats map[string]int64) {
	if len(stats) == 0 {
		return
	}
	rows := orderedInboundRows(cfg, stats)
	if len(rows) == 0 {
		return
	}
	b.WriteString(title)
	b.WriteString("\n")
	for _, row := range rows {
		b.WriteString(fmt.Sprintf("  %-22s %s\n", row.name, HumanizeBytes(row.value)))
	}
}

func appendPlainNamedStats(b *strings.Builder, title string, stats map[string]int64) {
	if len(stats) == 0 {
		return
	}
	b.WriteString(title)
	b.WriteString("\n")
	keys := sortedKeys(stats)
	for _, key := range keys {
		b.WriteString(fmt.Sprintf("  %-22s %s\n", key, HumanizeBytes(stats[key])))
	}
}

func sortedKeys(stats map[string]int64) []string {
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func orderedInboundRows(cfg *config.UserConfig, stats map[string]int64) []namedStatRow {
	if len(stats) == 0 {
		return nil
	}
	rows := make([]namedStatRow, 0, len(stats))
	seen := make(map[string]bool, len(stats))
	if cfg != nil {
		for _, mode := range cfg.Presets {
			if !mode.Enabled {
				continue
			}
			key := string(mode.Mode)
			val, ok := stats[key]
			if !ok {
				continue
			}
			rows = append(rows, namedStatRow{name: key, value: val})
			seen[key] = true
		}
	}
	for _, key := range sortedKeys(stats) {
		if seen[key] {
			continue
		}
		rows = append(rows, namedStatRow{name: key, value: stats[key]})
	}
	return rows
}

func HumanizeBytes(b int64) string {
	return units.FormatIEC(b)
}
