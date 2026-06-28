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

	// 1. Block A: Compact Status Indicator on the right of the table header
	title := "GATEWAY CONFIGURATION"
	statusLine := fmt.Sprintf("%sNFTABLES  %sTUN  %sFORWARD", 
		getStatusEmoji(nft), getStatusEmoji(tun), getStatusEmoji(fwd))
	
	spacing := width - lipgloss.Width(title) - lipgloss.Width(statusLine) - 2
	if spacing < 2 {
		spacing = 2
	}
	headerRow := title + strings.Repeat(" ", spacing) + statusLine
	b.WriteString(headerStyle.Width(width).Render(headerRow))
	b.WriteString("\n\n")

	// 2. Block B: Configuration Options in a Table Format
	if staging == nil {
		b.WriteString("No configuration loaded.")
		return b.String()
	}

	headers := []string{"  ", "OPTION", "INFO / VALUE", "STATUS"}
	
	localStatus := "DOWN"
	if staging.Gateway.LocalEnabled {
		localStatus = "UP"
	}
	lanStatus := "DOWN"
	if staging.Gateway.LANEnabled {
		lanStatus = "UP"
	}
	
	ifaceStatus := "DOWN"
	ifaceInfo := staging.Gateway.LANInterface
	if ifaceInfo == "" {
		ifaceInfo = "none"
	} else {
		if _, err := net.InterfaceByName(staging.Gateway.LANInterface); err == nil {
			ifaceStatus = "UP"
		}
	}
	
	relayStatus := "DOWN"
	relayInfo := staging.Gateway.RelayAlias
	if relayInfo == "" {
		relayInfo = "none"
	} else {
		for _, co := range staging.CustomOutbounds {
			if co.Alias == staging.Gateway.RelayAlias {
				if co.Enabled {
					relayStatus = "UP"
				}
				break
			}
		}
	}
	
	rulesStatus := "DOWN"
	if nft && tun && fwd {
		rulesStatus = "UP"
	}

	localInfo := getCheckboxText(staging.Gateway.LocalEnabled)
	if localIP != "" {
		localInfo += fmt.Sprintf(" (IP: %s)", localIP)
	} else if staging.Gateway.LocalEnabled {
		localInfo += " (Press [T] to test)"
	}
	
	lanInfo := getCheckboxText(staging.Gateway.LANEnabled)
	if lanIP != "" {
		lanInfo += fmt.Sprintf(" (IP: %s)", lanIP)
	} else if staging.Gateway.LANEnabled {
		lanInfo += " (Press [T] to test)"
	}

	rows := [][]string{
		{"  ", "Local Proxy", localInfo, localStatus},
		{"  ", "LAN Gateway", lanInfo, lanStatus},
		{"  ", "LAN Interface", ifaceInfo, ifaceStatus},
		{"  ", "Outbound Relay", relayInfo, relayStatus},
		{"  ", "Gateway Rules", "nftables & TUN running", rulesStatus},
	}

	widths := fitTableWidths(headers, rows, []int{3, 16, 26, 6}, width)

	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")

	for i, r := range rows {
		if i == cursor {
			r[0] = "-> "
		}
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

func getCheckboxText(val bool) string {
	if val {
		return "[X] enabled"
	}
	return "[ ] disabled"
}
