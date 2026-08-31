package doctor

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ANSI color escape codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// FormatStatus returns colored status without brackets.
func FormatStatus(s Status) string {
	switch s {
	case StatusPass:
		return colorGreen + string(s) + colorReset
	case StatusWarn:
		return colorYellow + string(s) + colorReset
	case StatusFail:
		return colorRed + string(s) + colorReset
	case StatusSkip:
		return colorGray + string(s) + colorReset
	default:
		return string(s)
	}
}

// RenderTerminal renders a clean aligned table of the diagnostic results.
func RenderTerminal(report *Report, verbose bool) string {
	var sb strings.Builder

	// Header
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%-22s %-32s %-8s %s\n", "CATEGORY", "CHECK ITEM", "STATUS", "DETAILS / REMEDIATION"))
	sb.WriteString(strings.Repeat("-", 108) + "\n")

	for _, r := range report.Results {
		detail := r.Detail
		if r.Remediation != "" && (r.Status == StatusFail || r.Status == StatusWarn) {
			detail += fmt.Sprintf(" (Fix: %s)", r.Remediation)
		}

		// Ensure 8-character spacing alignment for the 4-character colored status
		sb.WriteString(fmt.Sprintf("%-22s %-32s %s%-4s%s   %s\n",
			truncate(r.Category, 21),
			truncate(r.Name, 31),
			colorForStatus(r.Status),
			string(r.Status),
			colorReset,
			detail,
		))
	}

	sb.WriteString(strings.Repeat("-", 108) + "\n")

	// Summary footer
	sum := report.Summary
	summaryColor := colorGreen
	if sum.Failed > 0 {
		summaryColor = colorRed
	} else if sum.Warning > 0 {
		summaryColor = colorYellow
	}

	sb.WriteString(fmt.Sprintf("Summary: %s%d PASSED%s, %s%d WARNING%s, %s%d FAILED%s, %s%d SKIPPED%s (Total: %d)\n\n",
		colorGreen, sum.Passed, colorReset,
		colorYellow, sum.Warning, colorReset,
		colorRed, sum.Failed, colorReset,
		colorGray, sum.Skipped, colorReset,
		sum.Total,
	))
	_ = summaryColor

	return sb.String()
}

// RenderJSON serializes the report to a formatted JSON string.
func RenderJSON(report *Report) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func colorForStatus(s Status) string {
	switch s {
	case StatusPass:
		return colorGreen
	case StatusWarn:
		return colorYellow
	case StatusFail:
		return colorRed
	case StatusSkip:
		return colorGray
	default:
		return ""
	}
}

func truncate(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen-3] + "..."
}
