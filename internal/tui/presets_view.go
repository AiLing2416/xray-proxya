package tui

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"strings"
	"xray-proxya/internal/config"
)

var (
	headerStyle = lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	activeStyle = lipgloss.NewStyle().Reverse(true)
	faintStyle  = lipgloss.NewStyle().Faint(true)
)

func RenderPresets(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int) string {
	if staging == nil || len(staging.Presets) == 0 {
		return "No presets found. Run 'init' first."
	}

	headers := []string{"  ", "PRESETS", "PORT", "NET", "SECURITY", "STATUS"}
	rows := make([][]string, 0, len(staging.Presets))
	disabled := make([]bool, 0, len(staging.Presets))

	for i, m := range staging.Presets {
		indicator := "   "
		isMod := false
		if m.RegenFlag {
			indicator = "[R]"
		} else if active != nil && i < len(active.Presets) {
			a := active.Presets[i]
			if m.Port != a.Port || m.Path != a.Path || m.SNI != a.SNI || m.Enabled != a.Enabled {
				isMod = true
			}
		} else if active == nil {
			isMod = true
		}
		if isMod && !m.RegenFlag {
			indicator = "[*]"
		}

		status := "UP"
		if !m.Enabled || isMod {
			status = "DOWN"
		} else if active == nil || i >= len(active.Presets) || !active.Presets[i].Enabled {
			status = "DOWN"
		}

		row := []string{indicator, string(m.Mode), fmt.Sprintf("%d", m.Port), getNetworkName(m.Mode), getSecurityName(m), status}
		rows = append(rows, row)
		disabled = append(disabled, !m.Enabled)
	}

	widths := fitTableWidths(headers, rows, []int{3, 10, 4, 3, 8, 4}, width)

	var b strings.Builder
	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")

	for i, row := range rows {
		s := renderRow(row, widths, false)
		if disabled[i] {
			s = faintStyle.Render(s)
		}

		if i == selectedIdx {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func getSecurityName(m config.ModeInfo) string {
	switch m.Mode {
	case config.ModeVLESSReality, config.ModeVLESSVision:
		if m.Mode == config.ModeVLESSVision {
			return "Vision-Reality"
		}
		return "Reality"
	case config.ModeVLESSXHTTP:
		return "ML-KEM768"
	case config.ModeVMessWS:
		return "NONE"
	case config.ModeShadowsocksTCP:
		return m.Settings.Cipher
	}
	return "-"
}

func getNetworkName(m config.PresetMode) string {
	switch m {
	case config.ModeVLESSVision, config.ModeShadowsocksTCP:
		return "TCP"
	case config.ModeVLESSReality, config.ModeVLESSXHTTP:
		return "XHTTP"
	case config.ModeVMessWS:
		return "WS"
	}
	return "TCP"
}
