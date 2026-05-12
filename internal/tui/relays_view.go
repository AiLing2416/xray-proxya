package tui

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"strings"
	"xray-proxya/internal/config"
)

func RenderRelays(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int, results map[string]relayTestMsg) string {
	if staging == nil {
		return "No configuration found."
	}

	if width < 20 {
		width = 100
	}
	contentWidth := width - 15
	if contentWidth < 80 {
		contentWidth = 80
	}

	wIndicator := 4
	wState := 5
	wProto := 8
	wPort := 7
	wTCP := 16
	wUDP := 10
	wDNS := 10
	wIPv6 := 18
	wRemaining := contentWidth - wIndicator - wState - wProto - wPort - wTCP - wUDP - wDNS - wIPv6 - 9
	if wRemaining < 18 {
		wRemaining = 18
	}

	wAlias := int(float64(wRemaining) * 0.4)
	wIPv4 := wRemaining - wAlias

	headers := []string{"  ", "ALIAS", "STATE", "PROTO", "PORT", "TCP", "UDP", "DNS", "IPv4", "IPv6"}
	widths := []int{wIndicator, wAlias, wState, wProto, wPort, wTCP, wUDP, wDNS, wIPv4, wIPv6}

	var rows [][]string
	for _, co := range staging.CustomOutbounds {
		indicator := "   "
		isStaging := true
		if active != nil {
			for _, aco := range active.CustomOutbounds {
				if aco.Alias == co.Alias && aco.UserUUID == co.UserUUID {
					isStaging = false
					break
				}
			}
		}
		if isStaging {
			indicator = "[S]"
		}

		// Extract port from config
		port := "--"
		if vnext, ok := co.Config["settings"].(map[string]interface{})["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if p, ok := vnext[0].(map[string]interface{})["port"]; ok {
				port = fmt.Sprintf("%v", p)
			}
		} else if servers, ok := co.Config["settings"].(map[string]interface{})["servers"].([]interface{}); ok && len(servers) > 0 {
			if p, ok := servers[0].(map[string]interface{})["port"]; ok {
				port = fmt.Sprintf("%v", p)
			}
		}

		state := "OFF"
		if co.Enabled {
			state = "ON"
		}
		tcp, udp, dns, ipv4, ipv6 := "--", "--", "--", "--", "--"
		if res, ok := results[co.Alias]; ok {
			tcp, udp, dns, ipv4, ipv6 = res.tcp, res.udp, res.dns, res.ipv4, res.ipv6
		}

		row := []string{
			indicator,
			co.Alias,
			state,
			fmt.Sprintf("%v", co.Config["protocol"]),
			port,
			tcp,
			udp,
			dns,
			ipv4,
			ipv6,
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return lipgloss.NewStyle().Padding(2, 5).Render("No custom relays. Press [N] to add.")
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render(" CUSTOM RELAY MATRIX "))
	b.WriteString("\n\n")
	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")

	for i, r := range rows {
		s := renderRow(r, widths, false)
		if i == selectedIdx {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	return lipgloss.NewStyle().Padding(1, 1).Render(b.String())
}
