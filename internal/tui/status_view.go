package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"github.com/charmbracelet/lipgloss"
)

func RenderStatus(cfg *config.UserConfig, direct int64, relay int64, active bool, pid int) string {
	statusStr := "Inactive"
	uptimeStr := "-"
	statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("1")) // Red
	
	if active {
		statusStr = fmt.Sprintf("Active (PID: %d)", pid)
		statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // Green
		uptimeStr = xray.GetXrayUptime(pid)
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render(" SYSTEM OVERVIEW "))
	b.WriteString("\n\n")

	rows := [][]string{
		{"Xray Core:", statusStyle.Render(statusStr)},
		{"UpTime:", uptimeStr},
		{"Traffic (Direct):", HumanizeBytes(direct)},
		{"Traffic (Relay):", HumanizeBytes(relay)},
		{"Global UUID:", cfg.UUID},
		{"API Inbound:", fmt.Sprintf("127.0.0.1:%d", cfg.APIInbound)},
		{"Test Inbound:", fmt.Sprintf("127.0.0.1:%d", cfg.TestInbound)},
		{"Config Path:", config.GetConfigPath()},
	}

	for _, r := range rows {
		b.WriteString(fmt.Sprintf("%-18s %s\n", r[0], r[1]))
	}

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func HumanizeBytes(b int64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
