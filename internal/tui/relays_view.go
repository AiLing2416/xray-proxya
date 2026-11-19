package tui

import (
	"xray-proxya/internal/config"
	"xray-proxya/internal/sharelink"

	"github.com/charmbracelet/lipgloss"
)

func RenderRelays(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int, results map[string]relayTestMsg) string {
	return RenderRelaysWindow(active, staging, selectedIdx, width, results, 0, 0)
}

func RenderRelaysWindow(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int, results map[string]relayTestMsg, maxHeight int, scrollOffset int) string {
	if staging == nil {
		return "No configuration found."
	}

	headers := []string{"  ", "ALIAS", "PRIVATE", "PROTO", "PORT", "TCP", "UDP", "DNS", "IPv4", "IPv6"}
	var rows [][]string
	for _, co := range staging.CustomOutbounds {
		indicator := "   "
		isStaging := true
		if active != nil {
			for _, aco := range active.CustomOutbounds {
				if aco.Alias == co.Alias && aco.UserUUID == co.UserUUID && aco.AllowPrivateTargets == co.AllowPrivateTargets {
					isStaging = false
					break
				}
			}
		}
		if isStaging {
			indicator = "[S]"
		}

		spec := sharelink.FromOutbound(co.Config)

		priv := "BLOCKED"
		if co.AllowPrivateTargets {
			priv = "ALLOWED"
		}
		tcp, udp, dns, ipv4, ipv6 := "--", "--", "--", "--", "--"
		if res, ok := results[co.Alias]; ok {
			tcp, udp, dns, ipv4, ipv6 = res.tcp, res.udp, res.dns, res.ipv4, res.ipv6
		}

		row := []string{
			indicator,
			co.Alias,
			priv,
			spec.DisplayProtocol(),
			spec.DisplayPort(),
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

	widths := fitTableWidths(headers, rows, []int{3, 8, 7, 5, 4, 6, 4, 4, 6, 6}, width)
	headerBlock := renderRow(headers, widths, true)
	return renderTableBody(headerBlock, rows, widths, nil, selectedIdx, width, maxHeight, scrollOffset)
}
