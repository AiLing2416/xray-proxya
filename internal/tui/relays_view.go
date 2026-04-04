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

	if width < 20 { width = 100 }
	contentWidth := width - 15
	if contentWidth < 80 { contentWidth = 80 }

	// Column widths
	wIndicator := 4
	wProto := 8
	wPort := 7
	wLat := 9
	wUDP := 10
	wDNS := 10
	wCountry := 5
	wRemaining := contentWidth - wIndicator - wProto - wPort - wLat - wUDP - wDNS - wCountry - 10
	if wRemaining < 20 { wRemaining = 20 }

	wAlias := int(float64(wRemaining) * 0.4)
	wIP := wRemaining - wAlias

	headers := []string{"  ", "ALIAS", "PROTO", "PORT", "TCP", "UDP", "DNS", "IP", "CC"}
	widths := []int{wIndicator, wAlias, wProto, wPort, wLat, wUDP, wDNS, wIP, wCountry}

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
		if isStaging { indicator = "[S]" }

		// Extract port from config
		port := "--"
		if vnext, ok := co.Config["settings"].(map[string]interface{})["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if p, ok := vnext[0].(map[string]interface{})["port"]; ok { port = fmt.Sprintf("%v", p) }
		} else if servers, ok := co.Config["settings"].(map[string]interface{})["servers"].([]interface{}); ok && len(servers) > 0 {
			if p, ok := servers[0].(map[string]interface{})["port"]; ok { port = fmt.Sprintf("%v", p) }
		}

		lat, udp, dns, ip, country := "--", "--", "--", "Unknown", "XX"
		if res, ok := results[co.Alias]; ok {
			lat, udp, dns, ip, country = res.latency, res.udp, res.dns, res.ip, res.country
		}

		row := []string{
			indicator,
			co.Alias,
			fmt.Sprintf("%v", co.Config["protocol"]),
			port,
			lat,
			udp,
			dns,
			ip,
			country,
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return lipgloss.NewStyle().Padding(2, 5).Render("No custom relays. Press [+] to add.")
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
