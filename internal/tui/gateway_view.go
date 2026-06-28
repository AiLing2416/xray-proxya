package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"

	"github.com/charmbracelet/lipgloss"
)

func RenderGateway(active *config.UserConfig, staging *config.UserConfig, cursor int, width int, nft, tun, fwd bool) string {
	var b strings.Builder

	// 1. Block A: Compact Status Indicator
	statusLine := fmt.Sprintf("%sNFTABLES   %sTUN   %sFORWARD", 
		getStatusEmoji(nft), getStatusEmoji(tun), getStatusEmoji(fwd))
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(statusLine))
	b.WriteString("\n\n")

	// 2. Block B: Configuration & Master Options
	if staging == nil {
		b.WriteString("No configuration loaded.")
		return b.String()
	}

	isActive := nft && tun && fwd
	rows := []struct {
		label string
		val   string
	}{
		{"Local Proxy", getCheckboxText(staging.Gateway.LocalEnabled)},
		{"LAN Gateway", getCheckboxText(staging.Gateway.LANEnabled)},
		{"LAN Interface", staging.Gateway.LANInterface},
		{"Outbound Relay", staging.Gateway.RelayAlias},
		{"Gateway Rules", getCheckboxText(isActive)},
	}

	for i, r := range rows {
		valStr := r.val
		if valStr == "" {
			valStr = "none"
		}
		rowStr := fmt.Sprintf("  %-16s : %s", r.label, valStr)
		if i == cursor {
			b.WriteString(lipgloss.NewStyle().Reverse(true).Width(width).Render(rowStr))
		} else {
			b.WriteString(rowStr)
		}
		b.WriteString("\n")
	}

	return lipgloss.NewStyle().Padding(1, 1).Render(b.String())
}

func getStatusEmoji(val bool) string {
	if val {
		return "🟢"
	}
	return "🔴"
}

func getCheckboxText(val bool) string {
	if val {
		return "[X] enabled"
	}
	return "[ ] disabled"
}
