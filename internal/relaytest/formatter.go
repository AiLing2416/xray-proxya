package relaytest

import (
	"encoding/json"
	"fmt"
	"strings"
	"xray-proxya/internal/ui"
)

// RenderTerminal formats test results for human-readable terminal display.
func RenderTerminal(results []*TestResult) string {
	return RenderTerminalStyled(results, ui.IsColorEnabled())
}

// RenderTerminalStyled formats test results with explicit color control.
func RenderTerminalStyled(results []*TestResult, colorEnabled bool) string {
	if len(results) == 0 {
		return ""
	}
	if len(results) == 1 {
		return RenderSingleCardStyled(results[0], colorEnabled)
	}
	return RenderTableStyled(results, colorEnabled)
}

// RenderSingleCard formats a single test result as an aligned card.
func RenderSingleCard(r *TestResult) string {
	return RenderSingleCardStyled(r, ui.IsColorEnabled())
}

// RenderSingleCardStyled formats a single test result with explicit color styling.
func RenderSingleCardStyled(r *TestResult, colorEnabled bool) string {
	if r == nil {
		return ""
	}

	var sb strings.Builder
	modeStr := "Simple"
	if r.Mode == ModeFull {
		modeStr = "Full Diagnostics"
	}
	sb.WriteString(fmt.Sprintf("[%s] (Mode: %s)\n", r.Alias, modeStr))

	if r.Error != "" && r.Transport.TCPStatus == StatusFail && r.Transport.UDPStatus == StatusFail {
		statusStr := ui.Red("FAIL: "+r.Error, colorEnabled)
		sb.WriteString(fmt.Sprintf("Status    : %s\n", statusStr))
		return sb.String()
	}

	// Transport line
	tcpStr := formatRTT(r.Transport.TCPStatus, r.Transport.TCPRTTMs, colorEnabled)
	udpStr := formatRTT(r.Transport.UDPStatus, r.Transport.UDPRTTMs, colorEnabled)
	sb.WriteString(fmt.Sprintf("Transport : TCP: %s | UDP: %s\n", tcpStr, udpStr))

	// Exit IP line
	v4Str := r.ExitIP.IPv4
	if r.ExitIP.IPv4Status != StatusPass || v4Str == "" {
		v4Str = ui.Red("FAIL", colorEnabled)
	}
	v6Str := r.ExitIP.IPv6
	if r.ExitIP.IPv6Status != StatusPass || v6Str == "" {
		v6Str = ui.Red("FAIL", colorEnabled)
	}
	sb.WriteString(fmt.Sprintf("Exit IP   : IPv4: %s | IPv6: %s\n", v4Str, v6Str))

	// Full mode extras
	if r.Mode == ModeFull {
		if r.ModernProtocols != nil {
			sb.WriteString(fmt.Sprintf("Modern Web: %s\n", formatCategoryCard(r.ModernProtocols, colorEnabled)))
		}
		if r.UDPCapabilities != nil {
			sb.WriteString(fmt.Sprintf("UDP Stack : %s\n", formatCategoryCard(r.UDPCapabilities, colorEnabled)))
		}
	}

	// Status line
	statusLabel := formatStatus(r.Status, colorEnabled)
	timeStr := ""
	if r.DurationMs > 0 {
		timeStr = fmt.Sprintf(" (Time: %dms)", r.DurationMs)
	}
	sb.WriteString(fmt.Sprintf("Status    : %s%s\n", statusLabel, timeStr))

	return sb.String()
}

// RenderTable formats multiple test results into a unified Style 3 Minimalist Clean table.
func RenderTable(results []*TestResult) string {
	return RenderTableStyled(results, ui.IsColorEnabled())
}

// RenderTableStyled formats multiple test results into a table with explicit color control.
func RenderTableStyled(results []*TestResult, colorEnabled bool) string {
	if len(results) == 0 {
		return ""
	}

	isFull := false
	for _, r := range results {
		if r != nil && r.Mode == ModeFull {
			isFull = true
			break
		}
	}

	var table *ui.Table
	if isFull {
		table = ui.NewTable("ALIAS", "STATUS", "TCP RTT", "UDP RTT", "IPV4 EXIT", "MODERN WEB", "UDP STACK")
		table.SetAlignment(1, ui.AlignCenter)
		table.SetAlignment(2, ui.AlignRight)
		table.SetAlignment(3, ui.AlignRight)
		table.SetAlignment(5, ui.AlignCenter)
		table.SetAlignment(6, ui.AlignCenter)
	} else {
		table = ui.NewTable("ALIAS", "STATUS", "TCP RTT", "UDP RTT", "IPV4 EXIT", "IPV6 EXIT")
		table.SetAlignment(1, ui.AlignCenter)
		table.SetAlignment(2, ui.AlignRight)
		table.SetAlignment(3, ui.AlignRight)
	}

	for _, r := range results {
		if r == nil {
			continue
		}

		statusStr := formatStatus(r.Status, colorEnabled)

		if r.Error != "" && r.Transport.TCPStatus == StatusFail && r.Transport.UDPStatus == StatusFail {
			failText := "FAIL: " + r.Error
			if colorEnabled {
				failText = ui.Red("FAIL: ", true) + r.Error
			}
			table.AddSpannedRow(failText, r.Alias, statusStr)
			continue
		}

		tcpStr := formatRTT(r.Transport.TCPStatus, r.Transport.TCPRTTMs, colorEnabled)
		udpStr := formatRTT(r.Transport.UDPStatus, r.Transport.UDPRTTMs, colorEnabled)

		v4Str := r.ExitIP.IPv4
		if r.ExitIP.IPv4Status != StatusPass || v4Str == "" {
			v4Str = ui.Red("FAIL", colorEnabled)
		}

		if isFull {
			modernStr := "-"
			if r.ModernProtocols != nil {
				modernStr = formatCategoryTable(r.ModernProtocols, colorEnabled)
			}
			udpStackStr := "-"
			if r.UDPCapabilities != nil {
				udpStackStr = formatCategoryTable(r.UDPCapabilities, colorEnabled)
			}
			table.AddRow(r.Alias, statusStr, tcpStr, udpStr, v4Str, modernStr, udpStackStr)
		} else {
			v6Str := r.ExitIP.IPv6
			if r.ExitIP.IPv6Status != StatusPass || v6Str == "" {
				v6Str = ui.Red("FAIL", colorEnabled)
			}
			table.AddRow(r.Alias, statusStr, tcpStr, udpStr, v4Str, v6Str)
		}
	}

	return table.Render()
}

// FormatDoneSummary returns a 1-line summary suitable for in-place completion locking.
func FormatDoneSummary(res *TestResult) string {
	if res == nil {
		return "Done"
	}
	if res.Error != "" && res.Transport.TCPStatus == StatusFail && res.Transport.UDPStatus == StatusFail {
		return "Failed: " + res.Error
	}

	var parts []string
	if res.Transport.TCPStatus == StatusPass {
		parts = append(parts, fmt.Sprintf("TCP %dms", res.Transport.TCPRTTMs))
	} else {
		parts = append(parts, "TCP FAIL")
	}

	if res.Transport.UDPStatus == StatusPass {
		parts = append(parts, fmt.Sprintf("UDP %dms", res.Transport.UDPRTTMs))
	} else {
		parts = append(parts, "UDP FAIL")
	}

	if res.ExitIP.IPv4Status == StatusPass && res.ExitIP.IPv4 != "" {
		parts = append(parts, "IPv4 OK")
	} else {
		parts = append(parts, "IPv4 FAIL")
	}

	if res.ExitIP.IPv6Status == StatusPass && res.ExitIP.IPv6 != "" {
		parts = append(parts, "IPv6 OK")
	}

	if res.Mode == ModeFull {
		if res.ModernProtocols != nil && res.ModernProtocols.Status == StatusPass {
			parts = append(parts, "Web OK")
		}
		if res.UDPCapabilities != nil && res.UDPCapabilities.Status == StatusPass {
			parts = append(parts, "Stack OK")
		}
	}

	return "Done: " + strings.Join(parts, " | ")
}

func formatStatus(s Status, colorEnabled bool) string {
	switch s {
	case StatusPass:
		return ui.Green(string(s), colorEnabled)
	case StatusWarn:
		return ui.Yellow(string(s), colorEnabled)
	case StatusFail:
		return ui.Red(string(s), colorEnabled)
	default:
		return string(s)
	}
}

func formatRTT(s Status, rtt int64, colorEnabled bool) string {
	if s == StatusPass {
		return fmt.Sprintf("%dms", rtt)
	}
	return ui.Red("FAIL", colorEnabled)
}

func formatCategoryCard(cat *CategoryResult, colorEnabled bool) string {
	if cat == nil {
		return ui.Red("FAIL", colorEnabled)
	}
	switch cat.Status {
	case StatusPass:
		return ui.Green(fmt.Sprintf("PASS (%dms)", cat.MaxRTTMs), colorEnabled)
	case StatusWarn:
		failedStr := strings.Join(cat.FailedItems, ", ")
		return ui.Yellow(fmt.Sprintf("WARN (%dms) [Failed: %s]", cat.MaxRTTMs, failedStr), colorEnabled)
	default:
		return ui.Red("FAIL", colorEnabled)
	}
}

func formatCategoryTable(cat *CategoryResult, colorEnabled bool) string {
	if cat == nil {
		return ui.Red("FAIL", colorEnabled)
	}
	switch cat.Status {
	case StatusPass:
		return ui.Green(fmt.Sprintf("PASS (%dms)", cat.MaxRTTMs), colorEnabled)
	case StatusWarn:
		return ui.Yellow("WARN", colorEnabled)
	default:
		return ui.Red("FAIL", colorEnabled)
	}
}

// RenderJSON serializes the test results into formatted JSON.
func RenderJSON(results interface{}) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
