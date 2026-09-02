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

// HasGatewayStagedChanges reports whether the gateway configuration has unapplied changes in staging.
func HasGatewayStagedChanges(active, staging *config.UserConfig) bool {
	if staging == nil {
		return false
	}
	if active == nil {
		return true
	}
	return active.Gateway.State != staging.Gateway.State ||
		active.Gateway.LocalEnabled != staging.Gateway.LocalEnabled ||
		active.Gateway.LANEnabled != staging.Gateway.LANEnabled ||
		active.Gateway.LANInterface != staging.Gateway.LANInterface ||
		active.Gateway.RelayAlias != staging.Gateway.RelayAlias ||
		!sliceEqual(active.Gateway.BypassCountries, staging.Gateway.BypassCountries)
}

// BuildGatewayReport generates a structured detail report for the currently selected gateway row.
func BuildGatewayReport(active, staging *config.UserConfig, cursor int, nft, tun, fwd bool, localIP, lanIP string) string {
	if staging == nil {
		return "No configuration loaded."
	}

	var b strings.Builder
	gw := staging.Gateway

	switch cursor {
	case 0:
		b.WriteString(fmt.Sprintf("Option:      Gateway State (%s)\n", strings.ToUpper(gw.State)))
		switch gw.State {
		case "proxy":
			b.WriteString("Mode:        Full transparent proxying (TUN + nftables redirect to Xray)\n")
		case "forward-only":
			b.WriteString("Mode:        Direct kernel IP forwarding (bypasses Xray proxy)\n")
		case "disabled":
			b.WriteString("Mode:        Gateway routing tables and redirection rules are disabled\n")
		default:
			b.WriteString("Mode:        Unspecified state\n")
		}
		if active != nil && active.Gateway.State != gw.State {
			b.WriteString(fmt.Sprintf("Staged:      Pending apply (Active: %s => Staging: %s)\n", active.Gateway.State, gw.State))
		}

	case 1:
		rulesStatus := "DOWN"
		if nft && tun && fwd {
			rulesStatus = "UP (Active)"
		}
		b.WriteString(fmt.Sprintf("Option:      Gateway Rules (%s)\n", rulesStatus))
		nftStr := "Inactive"
		if nft {
			nftStr = "Active (proxya_prerouting, proxya_output)"
		}
		tunStr := "Down"
		if tun {
			tunStr = "Up (proxya-tun, 10.47.0.1/24)"
		}
		fwdStr := "Disabled"
		if fwd {
			fwdStr = "Enabled (net.ipv4.ip_forward = 1)"
		}
		b.WriteString(fmt.Sprintf("NFTables:    %s\n", nftStr))
		b.WriteString(fmt.Sprintf("TUN Adapter: %s\n", tunStr))
		b.WriteString(fmt.Sprintf("IP Forward:  %s\n", fwdStr))

	case 2:
		statusStr := "Disabled"
		if gw.LocalEnabled {
			statusStr = "Enabled"
		}
		b.WriteString(fmt.Sprintf("Option:      Local Proxy (%s)\n", statusStr))
		testStr := localIP
		if testStr == "" {
			testStr = "Not tested"
		}
		b.WriteString(fmt.Sprintf("Egress IP:   %s\n", testStr))
		b.WriteString("Routing:     Table 100 with FWMARK 0x1 routes local egress to proxya-tun\n")
		b.WriteString("Bypass:      SSH (port 22) and local subnet are excluded to prevent lockout\n")

	case 3:
		statusStr := "Disabled"
		if gw.LANEnabled {
			statusStr = "Enabled"
		}
		b.WriteString(fmt.Sprintf("Option:      LAN Gateway (%s)\n", statusStr))
		testStr := lanIP
		if testStr == "" {
			testStr = "Not tested"
		}
		b.WriteString(fmt.Sprintf("Egress IP:   %s\n", testStr))
		ifaceStr := gw.LANInterface
		if ifaceStr == "" {
			ifaceStr = "none (unassigned)"
		}
		b.WriteString(fmt.Sprintf("Interface:   %s\n", ifaceStr))
		b.WriteString("DNS Intercept: UDP/TCP port 53 redirected to Xray Dokodemo DNS inbound\n")

	case 4:
		ifaceStr := gw.LANInterface
		if ifaceStr == "" {
			ifaceStr = "none"
		}
		b.WriteString(fmt.Sprintf("Option:      LAN Interface (%s)\n", ifaceStr))
		if gw.LANInterface != "" {
			if iface, err := net.InterfaceByName(gw.LANInterface); err == nil {
				b.WriteString(fmt.Sprintf("MAC Address: %s\n", iface.HardwareAddr))
				b.WriteString(fmt.Sprintf("Flags:       %v\n", iface.Flags))
				b.WriteString(fmt.Sprintf("MTU:         %d\n", iface.MTU))
			} else {
				b.WriteString("Status:      Interface not found on current host\n")
			}
		} else {
			b.WriteString("Status:      No interface selected (LAN gateway will not forward clients)\n")
		}

	case 5:
		relayStr := gw.RelayAlias
		if relayStr == "" {
			relayStr = "direct"
		}
		b.WriteString(fmt.Sprintf("Option:      Outbound Relay (%s)\n", relayStr))
		if gw.RelayAlias != "" {
			found := false
			for _, co := range staging.CustomOutbounds {
				if co.Alias == gw.RelayAlias {
					found = true
					proto := "unknown"
					if p, ok := co.Config["protocol"].(string); ok && p != "" {
						proto = p
					}
					b.WriteString(fmt.Sprintf("Protocol:    %s\n", proto))
					stateStr := "Enabled"
					if !co.Enabled {
						stateStr = "Disabled"
					}
					b.WriteString(fmt.Sprintf("Node Status: %s\n", stateStr))
					break
				}
			}
			if !found {
				b.WriteString("Warning:     Relay alias not found in custom outbounds\n")
			}
		} else {
			b.WriteString("Routing:     Direct local network egress (no upstream relay)\n")
		}

	case 6:
		geoStr := strings.Join(gw.BypassCountries, ", ")
		if geoStr == "" {
			geoStr = "none"
		}
		b.WriteString(fmt.Sprintf("Option:      Bypass Geo (%s)\n", geoStr))
		b.WriteString("Rule:        Traffic destined to IP ranges in configured countries bypasses proxy\n")
		b.WriteString("Database:    Uses built-in GeoIP database loaded in Xray routing rules\n")
	}

	return strings.TrimSpace(b.String())
}

func validateCountryCodes(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	var codes []string
	for _, part := range parts {
		t := strings.ToUpper(strings.TrimSpace(part))
		if t == "" {
			continue
		}
		if len(t) != 2 || !isAlpha(t) {
			return nil, fmt.Errorf("invalid country code '%s': must be 2-letter ISO (e.g. CN, US)", t)
		}
		codes = append(codes, t)
	}
	return codes, nil
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}
