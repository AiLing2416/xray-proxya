package relaytest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderTerminal formats test results for human-readable terminal display.
func RenderTerminal(results []*TestResult) string {
	if len(results) == 0 {
		return ""
	}

	if len(results) == 1 {
		return renderSingleResult(results[0])
	}

	var blocks []string
	for _, r := range results {
		block := fmt.Sprintf("[%s]\n%s", r.Alias, renderSingleResult(r))
		blocks = append(blocks, block)
	}
	return strings.Join(blocks, "\n\n") + "\n"
}

func renderSingleResult(r *TestResult) string {
	if r == nil {
		return ""
	}

	var lines []string

	// Line 1: Transport (TCP & UDP)
	tcpStr := "FAIL"
	if r.Transport.TCPStatus == StatusPass {
		tcpStr = fmt.Sprintf("%dms", r.Transport.TCPRTTMs)
	}
	udpStr := "FAIL"
	if r.Transport.UDPStatus == StatusPass {
		udpStr = fmt.Sprintf("%dms", r.Transport.UDPRTTMs)
	}
	lines = append(lines, fmt.Sprintf("TCP: %s | UDP: %s", tcpStr, udpStr))

	// Line 2: Exit IP
	if r.ExitIP.IPv4Status == StatusFail && r.ExitIP.IPv6Status == StatusFail {
		lines = append(lines, "FAIL")
	} else {
		v4 := "FAIL"
		if r.ExitIP.IPv4Status == StatusPass && r.ExitIP.IPv4 != "" {
			v4 = r.ExitIP.IPv4
		}
		v6 := "FAIL"
		if r.ExitIP.IPv6Status == StatusPass && r.ExitIP.IPv6 != "" {
			v6 = r.ExitIP.IPv6
		}
		lines = append(lines, fmt.Sprintf("IPv4: %s | IPv6: %s", v4, v6))
	}

	// If Full Mode: append Modern Web and UDP Stack lines
	if r.Mode == ModeFull {
		if r.ModernProtocols != nil {
			lines = append(lines, fmt.Sprintf("Modern Web: %s", formatCategoryStatus(r.ModernProtocols)))
		}
		if r.UDPCapabilities != nil {
			lines = append(lines, fmt.Sprintf("UDP Stack : %s", formatCategoryStatus(r.UDPCapabilities)))
		}
	}

	return strings.Join(lines, "\n")
}

func formatCategoryStatus(cat *CategoryResult) string {
	if cat == nil {
		return "FAIL"
	}
	switch cat.Status {
	case StatusPass:
		return fmt.Sprintf("PASS (%dms)", cat.MaxRTTMs)
	case StatusWarn:
		failedStr := strings.Join(cat.FailedItems, ", ")
		return fmt.Sprintf("WARN (%dms) [Failed: %s]", cat.MaxRTTMs, failedStr)
	default:
		return "FAIL"
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
