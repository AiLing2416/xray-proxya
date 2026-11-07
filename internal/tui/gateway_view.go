package tui

import (
	"fmt"
	"net"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"

	"github.com/charmbracelet/lipgloss"
)

func RenderGateway(active *config.UserConfig, staging *config.UserConfig, cursor int, width int, nft, tproxy, tun, fwd bool, localIP, lanIP string) string {
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
			return active.Gateway.EffectiveTUNEnabled() != staging.Gateway.EffectiveTUNEnabled()
		case 2:
			return active.Gateway.LocalEnabled != staging.Gateway.LocalEnabled
		case 3:
			return active.Gateway.LANEnabled != staging.Gateway.LANEnabled
		case 4:
			return !sliceEqual(active.Gateway.EffectiveLANInterfaces(), staging.Gateway.EffectiveLANInterfaces())
		case 5:
			return active.Gateway.RelayAlias != staging.Gateway.RelayAlias
		case 6:
			return !sliceEqual(active.Gateway.BypassCountries, staging.Gateway.BypassCountries)
		case 7:
			return normalizeWAN(active.Gateway.WANInterface) != normalizeWAN(staging.Gateway.WANInterface)
		case 8:
			return active.Gateway.NATDisabled != staging.Gateway.NATDisabled
		}
		return false
	}

	getIndicator := func(rowIdx int) string {
		if isMod(rowIdx) {
			return "*"
		}
		return " "
	}

	// Gateway State (Non-Bool) - Row 0
	stateInfo := strings.ToUpper(staging.Gateway.State)
	if stateInfo == "" {
		stateInfo = "DISABLED"
	}
	stateStatus := "READY"
	if stateInfo == "DISABLED" {
		stateStatus = "NON READY"
	}

	// TProxy Rules (Bool) - Row 1
	isActiveRules := nft && tproxy && fwd
	rulesInfo := getBoolText(isActiveRules)
	rulesStatus := getBoolStatus(isActiveRules)
	// Runtime rules are stale whenever any staged gateway change is pending.
	rulesIndicator := " "
	if active != nil && HasGatewayStagedChanges(active, staging) {
		rulesIndicator = "*"
	}

	// TUN Adapter (Bool) - Row 2 (Pure adapter without nftables rules)
	tunInfo := getBoolText(staging.Gateway.EffectiveTUNEnabled())
	tunStatus := "DISABLED"
	if staging.Gateway.EffectiveTUNEnabled() {
		if tun {
			tunStatus = "READY (UP)"
		} else {
			tunStatus = "PENDING"
		}
	}

	// Local Proxy (Bool) - Row 3
	localInfo := getBoolText(staging.Gateway.LocalEnabled)
	localStatus := getBoolStatus(staging.Gateway.LocalEnabled)

	// LAN Gateway (Bool) - Row 4
	lanInfo := getBoolText(staging.Gateway.LANEnabled)
	lanStatus := getBoolStatus(staging.Gateway.LANEnabled)

	// LAN Interface (multi-select) - Row 5
	lanIfaces := staging.Gateway.EffectiveLANInterfaces()
	ifaceInfo := strings.Join(lanIfaces, ", ")
	if ifaceInfo == "" {
		ifaceInfo = "none"
	}
	ifaceStatus := "READY"
	if len(lanIfaces) == 0 {
		if staging.Gateway.LANEnabled {
			ifaceStatus = "NON READY"
		}
	} else {
		for _, name := range lanIfaces {
			if _, err := net.InterfaceByName(name); err != nil {
				ifaceStatus = "NON READY"
				break
			}
		}
	}

	// WAN Interface (single-select, 'auto' detects default route) - Row 6a
	wanInfo, wanStatus := wanRowInfo(staging.Gateway.WANInterface)

	// NAT (Bool, stored inverted as NATDisabled) - Row 6b
	natEnabled := !staging.Gateway.NATDisabled
	natInfo := getBoolText(natEnabled)
	natStatus := "DISABLED"
	if natEnabled {
		natStatus = "READY"
	}

	// Rules (read-only summary) - Row 9
	rulesCount := len(staging.Gateway.Rules)
	ruleSummary := "none"
	if rulesCount > 0 {
		ruleSummary = fmt.Sprintf("%d rules", rulesCount)
	}

	// Outbound Relay (Non-Bool) - Row 6
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

	// Bypass Countries (Non-Bool) - Row 7
	bypassInfo := strings.Join(staging.Gateway.BypassCountries, ", ")
	if bypassInfo == "" {
		bypassInfo = "none"
	}
	bypassStatus := "READY"

	rows := [][]string{
		{getIndicator(0), "Gateway State", stateInfo, stateStatus, ""},
		{rulesIndicator, "TProxy Rules", rulesInfo, rulesStatus, ""},
		{getIndicator(1), "TUN Adapter", tunInfo, tunStatus, ""},
		{getIndicator(2), "Local Proxy", localInfo, localStatus, localIP},
		{getIndicator(3), "LAN Gateway", lanInfo, lanStatus, lanIP},
		{getIndicator(4), "LAN Interface", ifaceInfo, ifaceStatus, ""},
		{getIndicator(7), "WAN Interface", wanInfo, wanStatus, ""},
		{getIndicator(8), "NAT", natInfo, natStatus, ""},
		{getIndicator(5), "Outbound Relay", relayInfo, relayStatus, ""},
		{getIndicator(6), "Bypass Geo", bypassInfo, bypassStatus, ""},
		{" ", "Rules", ruleSummary, "READ ONLY", ""},
	}

	widths := fitTableWidths(headers, rows, []int{3, 16, 12, 10, 20}, width)

	// Combine headers and status tags on the same line (right-aligned)
	res := renderRow(headers, widths, false)
	statusLine := fmt.Sprintf("%sNFTABLES   %sTPROXY   %sTUN   %sFORWARD",
		getStatusEmoji(nft), getStatusEmoji(tproxy), getStatusEmoji(tun), getStatusEmoji(fwd))

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
		active.Gateway.EffectiveTUNEnabled() != staging.Gateway.EffectiveTUNEnabled() ||
		active.Gateway.LocalEnabled != staging.Gateway.LocalEnabled ||
		active.Gateway.LANEnabled != staging.Gateway.LANEnabled ||
		!sliceEqual(active.Gateway.EffectiveLANInterfaces(), staging.Gateway.EffectiveLANInterfaces()) ||
		normalizeWAN(active.Gateway.WANInterface) != normalizeWAN(staging.Gateway.WANInterface) ||
		active.Gateway.NATDisabled != staging.Gateway.NATDisabled ||
		active.Gateway.RelayAlias != staging.Gateway.RelayAlias ||
		!sliceEqual(active.Gateway.BypassCountries, staging.Gateway.BypassCountries)
}

// BuildGatewayReport generates a structured detail report for the currently selected gateway row.
func BuildGatewayReport(active, staging *config.UserConfig, cursor int, nft, tproxy, tun, fwd bool, localIP, lanIP string) string {
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
			b.WriteString("Mode:        Full transparent proxying (TProxy + Table 100 dev lo redirect to Xray)\n")
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
		if nft && tproxy && fwd {
			rulesStatus = "UP (Active)"
		}
		b.WriteString(fmt.Sprintf("Option:      TProxy Rules (%s)\n", rulesStatus))
		nftStr := "Inactive"
		if nft {
			nftStr = "Active (table inet xray_proxya)"
		}
		tproxyStr := "Down"
		if tproxy {
			tproxyStr = "Active (lo table 100)"
		}
		fwdStr := "Disabled"
		if fwd {
			fwdStr = "Enabled (net.ipv4.ip_forward = 1)"
		}
		b.WriteString(fmt.Sprintf("NFTables:    %s\n", nftStr))
		b.WriteString(fmt.Sprintf("TProxy:      %s\n", tproxyStr))
		b.WriteString(fmt.Sprintf("IP Forward:  %s\n", fwdStr))
		b.WriteString("Scope:       Primary transparent gateway mechanism for local and LAN traffic\n")

	case 2:
		tunEnabled := gw.EffectiveTUNEnabled()
		statusStr := "Disabled"
		if tunEnabled {
			statusStr = "Enabled"
		}
		b.WriteString(fmt.Sprintf("Option:      TUN Adapter (%s)\n", statusStr))
		b.WriteString("Interface:   proxya-tun (172.16.255.1/30 & fd00:eea:ff::1/126)\n")
		b.WriteString("Type:        Pure virtual TUN adapter without nftables/fwmark interception\n")
		b.WriteString("Purpose:     Supplementary compatibility adapter; external routing/scripts can direct traffic to proxya-tun\n")
		if active != nil && active.Gateway.EffectiveTUNEnabled() != tunEnabled {
			b.WriteString(fmt.Sprintf("Staged:      Pending apply (Active: %v => Staging: %v)\n", active.Gateway.EffectiveTUNEnabled(), tunEnabled))
		}

	case 3:
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
		b.WriteString("Routing:     Table 100 with FWMARK 0x1 routes local egress to lo (TProxy)\n")
		b.WriteString("Bypass:      SSH (port 22) and local subnet are excluded to prevent lockout\n")

	case 4:
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

	case 5:
		lanIfaces := gw.EffectiveLANInterfaces()
		ifaceStr := strings.Join(lanIfaces, ", ")
		if ifaceStr == "" {
			ifaceStr = "none"
		}
		b.WriteString(fmt.Sprintf("Option:      LAN Interface (%s)\n", ifaceStr))
		if len(lanIfaces) == 0 {
			b.WriteString("Status:      No interface selected (LAN gateway will not forward clients)\n")
		}
		for _, name := range lanIfaces {
			if iface, err := net.InterfaceByName(name); err == nil {
				b.WriteString(fmt.Sprintf("%-12s MAC %s, MTU %d, %v\n", name+":", iface.HardwareAddr, iface.MTU, iface.Flags))
			} else {
				b.WriteString(fmt.Sprintf("%-12s Interface not found on current host\n", name+":"))
			}
		}
		b.WriteString("Select:      Enter to pick one or more interfaces (Space toggles)\n")

	case 6:
		wanInfo, wanStatus := wanRowInfo(gw.WANInterface)
		b.WriteString(fmt.Sprintf("Option:      WAN Interface (%s)\n", wanInfo))
		b.WriteString(fmt.Sprintf("Status:      %s\n", wanStatus))
		b.WriteString("Purpose:     Egress interface used for NAT masquerade ('auto' follows the default route)\n")

	case 7:
		statusStr := "Enabled"
		if gw.NATDisabled {
			statusStr = "Disabled"
		}
		b.WriteString(fmt.Sprintf("Option:      NAT (%s)\n", statusStr))
		b.WriteString("Purpose:     Masquerade LAN client traffic leaving through the WAN interface\n")
		if !gw.NATDisabled && (normalizeWAN(gw.WANInterface) == "auto") && len(gw.EffectiveLANInterfaces()) == 0 {
			b.WriteString("Note:        Inactive until at least one LAN interface is selected\n")
		}
		if active != nil && active.Gateway.NATDisabled != gw.NATDisabled {
			b.WriteString(fmt.Sprintf("Staged:      Pending apply (Active NAT: %v => Staging NAT: %v)\n", !active.Gateway.NATDisabled, !gw.NATDisabled))
		}

	case 8:
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

	case 9:
		geoStr := strings.Join(gw.BypassCountries, ", ")
		if geoStr == "" {
			geoStr = "none"
		}
		b.WriteString(fmt.Sprintf("Option:      Bypass Geo (%s)\n", geoStr))
		b.WriteString("Rule:        Traffic destined to IP ranges in configured countries bypasses proxy\n")
		b.WriteString("Database:    Uses built-in GeoIP database loaded in Xray routing rules\n")

	case 10:
		rules := gw.Rules
		if len(rules) == 0 {
			b.WriteString("Option:      Rules (none)\n")
		} else {
			b.WriteString(fmt.Sprintf("Option:      Rules (%d)\n", len(rules)))
		}
		for i, r := range rules {
			b.WriteString(fmt.Sprintf("  [%d] %s -> %s\n", i, describeRuleMatch(r), r.Target))
		}
		b.WriteString("Manage:      Read-only here. Use CLI: xray-proxya gateway rule set|del|clear\n")
	}

	targetCfg := active
	if targetCfg == nil {
		targetCfg = staging
	}
	if targetCfg != nil {
		problems := gateway.Verify(targetCfg)
		if len(problems) > 0 {
			b.WriteString("\n⚠️ Runtime Problems Detected:\n")
			for _, p := range problems {
				b.WriteString(fmt.Sprintf("  • %s\n", p))
			}
		}
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
