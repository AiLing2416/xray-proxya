package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"

	"github.com/charmbracelet/lipgloss"
)

func RenderRelays(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int, results map[string]relayTestMsg) string {
	if staging == nil {
		return "No configuration found."
	}

	headers := []string{"  ", "ALIAS", "STATE", "PROTO", "PORT", "TCP", "UDP", "DNS", "IPv4", "IPv6"}
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

	widths := fitTableWidths(headers, rows, []int{3, 8, 3, 5, 4, 6, 4, 4, 6, 6}, width)

	var b strings.Builder
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

	return b.String()
}
