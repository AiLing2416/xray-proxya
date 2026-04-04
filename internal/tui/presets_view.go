package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
	"github.com/charmbracelet/lipgloss"
)

var (
	headerStyle = lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	activeStyle = lipgloss.NewStyle().Reverse(true)
	faintStyle  = lipgloss.NewStyle().Faint(true)
)

func RenderPresets(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int) string {
	if staging == nil || len(staging.ActiveModes) == 0 {
		return "No presets found. Run 'init' first."
	}

	// Logic: We have 6 columns and 5 gaps (each 2 spaces). Total gap = 10.
	availableWidth := width - 10
	if availableWidth < 30 { availableWidth = 30 }

	wIndicator := 4
	wStatus := 6
	wPort := 6
	wNet := 6
	
	// Remaining for Preset Name and Security
	wRem := availableWidth - wIndicator - wStatus - wPort - wNet
	wPreset := int(float64(wRem) * 0.4)
	wSecurity := wRem - wPreset

	headers := []string{"  ", "PRESETS", "PORT", "NET", "SECURITY", "STATUS"}
	widths := []int{wIndicator, wPreset, wPort, wNet, wSecurity, wStatus}

	var b strings.Builder
	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")

	for i, m := range staging.ActiveModes {
		indicator := "   "
		isMod := false
		if m.RegenFlag { indicator = "[R]" } else if active != nil && i < len(active.ActiveModes) {
			a := active.ActiveModes[i]
			if m.Port != a.Port || m.Path != a.Path || m.SNI != a.SNI || m.Enabled != a.Enabled { isMod = true }
		} else if active == nil { isMod = true }
		if isMod && !m.RegenFlag { indicator = "[*]" }

		status := "UP"
		if !m.Enabled || isMod { status = "DOWN" } else if active == nil || i >= len(active.ActiveModes) || !active.ActiveModes[i].Enabled {
			status = "DOWN"
		}

		row := []string{indicator, string(m.Mode), fmt.Sprintf("%d", m.Port), getNetworkName(m.Mode), getSecurityName(m), status}
		s := renderRow(row, widths, false)
		if !m.Enabled { s = faintStyle.Render(s) }
		
		if i == selectedIdx {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func renderRow(cols []string, widths []int, isHeader bool) string {
	var line []string
	for i, c := range cols {
		w := widths[i]
		if w < 1 { w = 1 }
		if len(c) > w {
			if w > 3 { c = c[:w-3] + ".." } else { c = c[:w] }
		}
		padded := c + strings.Repeat(" ", w-len(c))
		line = append(line, padded)
	}
	res := strings.Join(line, "  ")
	if isHeader { return headerStyle.Render(res) }
	return res
}

func getSecurityName(m config.ModeInfo) string {
	switch m.Mode {
	case config.ModeVLESSReality, config.ModeVLESSVision:
		if m.Mode == config.ModeVLESSVision { return "Vision-Reality" }
		return "Reality"
	case config.ModeVLESSXHTTP: return "ML-KEM768"
	case config.ModeVMessWS: return "NONE"
	case config.ModeShadowsocksTCP: return m.Settings.Cipher
	}
	return "-"
}

func getNetworkName(m config.PresetMode) string {
	switch m {
	case config.ModeVLESSVision, config.ModeShadowsocksTCP: return "TCP"
	case config.ModeVLESSReality, config.ModeVLESSXHTTP: return "XHTTP"
	case config.ModeVMessWS: return "WS"
	}
	return "TCP"
}
