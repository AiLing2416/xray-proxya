package doctor

import (
	"encoding/json"
	"fmt"
	"strings"
	"xray-proxya/internal/ui"
)

// FormatStatus returns colored status without brackets.
func FormatStatus(s Status) string {
	color := ui.IsColorEnabled()
	switch s {
	case StatusPass:
		return ui.Green(string(s), color)
	case StatusWarn:
		return ui.Yellow(string(s), color)
	case StatusFail:
		return ui.Red(string(s), color)
	case StatusSkip:
		return ui.Gray(string(s), color)
	default:
		return string(s)
	}
}

// RenderTerminal renders a clean aligned table of the diagnostic results.
func RenderTerminal(report *Report, verbose bool) string {
	colorEnabled := ui.IsColorEnabled()
	t := ui.NewTable("CATEGORY", "CHECK ITEM", "STATUS", "DETAILS / REMEDIATION")
	t.SetAlignment(2, ui.AlignCenter)

	for _, r := range report.Results {
		detail := r.Detail
		if r.Remediation != "" && (r.Status == StatusFail || r.Status == StatusWarn) {
			detail += fmt.Sprintf(" (Fix: %s)", r.Remediation)
		}

		statusStr := string(r.Status)
		switch r.Status {
		case StatusPass:
			statusStr = ui.Green(string(r.Status), colorEnabled)
		case StatusWarn:
			statusStr = ui.Yellow(string(r.Status), colorEnabled)
		case StatusFail:
			statusStr = ui.Red(string(r.Status), colorEnabled)
		case StatusSkip:
			statusStr = ui.Gray(string(r.Status), colorEnabled)
		}

		t.AddRow(r.Category, r.Name, statusStr, detail)
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(t.Render())
	sb.WriteString("\n")

	// Summary footer
	sum := report.Summary
	sb.WriteString(fmt.Sprintf("Summary: %s %d Passed │ %s %d Warning │ %s %d Failed │ %s %d Skipped (Total: %d)\n\n",
		ui.Green(ui.SymCheck, colorEnabled), sum.Passed,
		ui.Yellow(ui.SymTriangle, colorEnabled), sum.Warning,
		ui.Red(ui.SymCross, colorEnabled), sum.Failed,
		ui.Gray(ui.SymHollow, colorEnabled), sum.Skipped,
		sum.Total,
	))

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
