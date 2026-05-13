package tui

import (
	"fmt"
	"sort"
	"strings"
	"xray-proxya/internal/buildinfo"
	"xray-proxya/internal/config"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"

	"github.com/charmbracelet/lipgloss"
)

type namedStatRow struct {
	name  string
	value int64
}

func RenderStatus(cfg *config.UserConfig, active bool, pid int, allStats map[string]int64) string {
	statusStr := "Inactive"
	uptimeStr := "-"
	statusStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	if active {
		statusStr = fmt.Sprintf("Active (PID: %d)", pid)
		statusStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))
		uptimeStr = xray.GetXrayUptime(pid)
	}

	summary := trafficstats.Summarize(allStats)
	var b strings.Builder
	b.WriteString(renderHomeTitle())
	b.WriteString("\n\n")
	b.WriteString("Proxy control surface\n")
	b.WriteString(strings.Repeat("─", 24))
	b.WriteString("\n\n")

	rows := [][]string{
		{"Core", statusStyle.Render(statusStr)},
		{"Uptime", uptimeStr},
		{"Direct Traffic", HumanizeBytes(summary.Direct)},
		{"Relay Traffic", HumanizeBytes(summary.Relay)},
	}
	if cfg != nil {
		rows = append(rows,
			[]string{"Global UUID", cfg.UUID},
			[]string{"API Inbound", fmt.Sprintf("127.0.0.1:%d", cfg.APIInbound)},
			[]string{"Test Inbound", fmt.Sprintf("127.0.0.1:%d", cfg.TestInbound)},
			[]string{"Config Path", config.GetConfigPath()},
		)
	}

	for _, r := range rows {
		b.WriteString(fmt.Sprintf("%-16s %s\n", r[0]+":", r[1]))
	}

	appendOrderedInboundStats(&b, "\nInbound Usage", cfg, summary.InboundStats)
	appendNamedStats(&b, "\nService Usage", summary.ServiceStats)
	appendNamedStats(&b, "\nRelay Usage", summary.RelayStats)
	appendNamedStats(&b, "\nGuest Usage", summary.GuestStats)

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func buildStatusReport(cfg *config.UserConfig, active bool, pid int, allStats map[string]int64) string {
	statusStr := "Inactive"
	uptimeStr := "-"
	if active {
		statusStr = fmt.Sprintf("Active (PID %d)", pid)
		uptimeStr = xray.GetXrayUptime(pid)
	}

	summary := trafficstats.Summarize(allStats)
	var b strings.Builder
	b.WriteString("proxya\n")
	b.WriteString(fmt.Sprintf("version %s\n", buildinfo.Version))
	b.WriteString("============\n")
	b.WriteString(fmt.Sprintf("Xray Core: %s\n", statusStr))
	b.WriteString(fmt.Sprintf("UpTime: %s\n", uptimeStr))
	b.WriteString(fmt.Sprintf("Direct Outbound: %s\n", HumanizeBytes(summary.Direct)))
	b.WriteString(fmt.Sprintf("Relay Outbound: %s\n", HumanizeBytes(summary.Relay)))
	if cfg != nil {
		b.WriteString(fmt.Sprintf("Global UUID: %s\n", cfg.UUID))
		b.WriteString(fmt.Sprintf("API Inbound: 127.0.0.1:%d\n", cfg.APIInbound))
		b.WriteString(fmt.Sprintf("Test Inbound: 127.0.0.1:%d\n", cfg.TestInbound))
		b.WriteString(fmt.Sprintf("Config Path: %s\n", config.GetConfigPath()))
	}
	appendOrderedPlainInboundStats(&b, "\nInbound Usage:", cfg, summary.InboundStats)
	appendPlainNamedStats(&b, "\nService Usage:", summary.ServiceStats)
	appendPlainNamedStats(&b, "\nRelay Usage:", summary.RelayStats)
	appendPlainNamedStats(&b, "\nGuest Usage:", summary.GuestStats)
	return b.String()
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
		"                |___/                     |___/       " + lipgloss.NewStyle().Bold(true).Render("v"+buildinfo.Version),
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
		for _, mode := range cfg.ActiveModes {
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
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
