package tui

import (
	"fmt"
	"net"
	"strings"
	"xray-proxya/internal/config"

	"github.com/charmbracelet/lipgloss"
)

func RenderGateway(active *config.UserConfig, staging *config.UserConfig, cursor int, width int, nft, tun, fwd bool, localIP, lanIP string) string {
	var b strings.Builder

	if staging == nil {
		b.WriteString("No configuration loaded.")
		return b.String()
	}

	headers := []string{"  ", "OPTION", "INFO", "STATUS", "TEST IP"}

	// Staging change check helper
	isMod := func(rowIdx int) bool {
		if active == nil {
			return true
		}
		switch rowIdx {
		case 0:
			return active.Gateway.State != staging.Gateway.State
		case 1:
			return active.Gateway.LocalEnabled != staging.Gateway.LocalEnabled
		case 2:
			return active.Gateway.LANEnabled != staging.Gateway.LANEnabled
		case 3:
			return active.Gateway.LANInterface != staging.Gateway.LANInterface
		case 4:
			return active.Gateway.RelayAlias != staging.Gateway.RelayAlias
		case 5:
			return !sliceEqual(active.Gateway.BypassCountries, staging.Gateway.BypassCountries)
		}
		return false
	}

	getIndicator := func(rowIdx int) string {
		if isMod(rowIdx) {
			return "*"
		}
		return " "
	}

	// Local Proxy (Bool)
	localInfo := getBoolText(staging.Gateway.LocalEnabled)
	localStatus := getBoolStatus(staging.Gateway.LocalEnabled)

	// LAN Gateway (Bool)
	lanInfo := getBoolText(staging.Gateway.LANEnabled)
	lanStatus := getBoolStatus(staging.Gateway.LANEnabled)

	// LAN Interface (Non-Bool)
	ifaceInfo := staging.Gateway.LANInterface
	if ifaceInfo == "" {
		ifaceInfo = "none"
	}
	ifaceStatus := "NON READY"
	if staging.Gateway.LANInterface != "" {
		if _, err := net.InterfaceByName(staging.Gateway.LANInterface); err == nil {
			ifaceStatus = "READY"
		}
	} else if staging.Gateway.LANEnabled {
		ifaceStatus = "NON READY"
	} else {
		ifaceStatus = "READY"
	}

	// Outbound Relay (Non-Bool)
	relayInfo := staging.Gateway.RelayAlias
	if relayInfo == "" {
		relayInfo = "none"
	}
	relayStatus := "NON READY"
	if staging.Gateway.RelayAlias != "" {
		for _, co := range staging.CustomOutbounds {
			if co.Alias == staging.Gateway.RelayAlias {
				if co.Enabled {
					relayStatus = "READY"
				}
				break
			}
		}
	}

	// Gateway Rules (Bool)
	isActiveRules := nft && tun && fwd
	rulesInfo := getBoolText(isActiveRules)
	rulesStatus := getBoolStatus(isActiveRules)

	// Gateway State (Non-Bool)
	stateInfo := strings.ToUpper(staging.Gateway.State)
	if stateInfo == "" {
		stateInfo = "DISABLED"
	}
	stateStatus := "READY"
	if stateInfo == "DISABLED" {
		stateStatus = "NON READY"
	}

	// Bypass Countries (Non-Bool)
	bypassInfo := strings.Join(staging.Gateway.BypassCountries, ", ")
	if bypassInfo == "" {
		bypassInfo = "none"
	}
	bypassStatus := "READY"

	rows := [][]string{
		{getIndicator(0), "Gateway State", stateInfo, stateStatus, ""},
		{" ", "Gateway Rules", rulesInfo, rulesStatus, ""},
		{getIndicator(1), "Local Proxy", localInfo, localStatus, localIP},
		{getIndicator(2), "LAN Gateway", lanInfo, lanStatus, lanIP},
		{getIndicator(3), "LAN Interface", ifaceInfo, ifaceStatus, ""},
		{getIndicator(4), "Outbound Relay", relayInfo, relayStatus, ""},
		{getIndicator(5), "Bypass Geo", bypassInfo, bypassStatus, ""},
	}

	widths := fitTableWidths(headers, rows, []int{3, 16, 12, 10, 20}, width)

	// Combine headers and status tags on the same line (right-aligned)
	res := renderRow(headers, widths, false)
	statusLine := fmt.Sprintf("%sNFTABLES   %sTUN   %sFORWARD",
		getStatusEmoji(nft), getStatusEmoji(tun), getStatusEmoji(fwd))

	spacing := width - lipgloss.Width(res) - lipgloss.Width(statusLine) - 2
	if spacing < 2 {
		spacing = 2
	}
	combinedHeaders := res + strings.Repeat(" ", spacing) + statusLine

	b.WriteString(headerStyle.Width(width).Render(combinedHeaders))
	b.WriteString("\n")

	for i, r := range rows {
		s := renderRow(r, widths, false)
		if i == cursor {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func getStatusEmoji(val bool) string {
	if val {
		return "🟢"
	}
	return "🔴"
}

func getBoolText(val bool) string {
	if val {
		return "ENABLE"
	}
	return "DISABLE"
}

func getBoolStatus(val bool) string {
	if val {
		return "UP"
	}
	return "DOWN"
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
