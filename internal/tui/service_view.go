package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/xray"
)

func RenderService(state xray.ServiceState, width int) string {
	availableWidth := width - 10
	if availableWidth < 56 {
		availableWidth = 56
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render(" SERVICE CONTROL "))
	b.WriteString("\n\n")
	b.WriteString(renderServiceSection("INSTALL", []string{
		"Runtime: " + serviceRuntimeLabel(state),
		"Init: " + state.InitSystem,
		"Installed: " + yesNo(state.UnitInstalled),
		"Service File: " + valueOrDash(state.ServiceFile),
	}, availableWidth))
	b.WriteString("\n\n")
	b.WriteString(renderServiceSection("RUNTIME", []string{
		"Status: " + serviceActiveLabel(state),
		"PID: " + servicePIDLabel(state),
		"Uptime: " + state.Uptime,
		"Hint: " + state.Hint,
	}, availableWidth))
	b.WriteString("\n\n")
	b.WriteString(renderServiceSection("DEPENDENCIES", []string{
		"Xray Binary: " + presentLabel(state.XrayPresent, state.XrayPath),
		"Xray Version: " + state.XrayVersion,
		"geoip.dat: " + presentLabel(state.GeoIPPresent, state.GeoIPPath),
		"GeoIP Feature: " + state.GeoIPFeature,
	}, availableWidth))
	b.WriteString("\n\n")
	b.WriteString(renderServiceSection("CONFIG", []string{
		"Config Path: " + state.ConfigPath,
		"Log Path: " + state.LogPath,
	}, availableWidth))

	return b.String()
}

func serviceRuntimeLabel(state xray.ServiceState) string {
	switch state.ControlMode {
	case "systemd":
		return "Root / Systemd"
	case "openrc":
		return "Root / OpenRC"
	case "nohup":
		if state.IsRoot {
			return "Root / Fallback-Nohup"
		}
		return "User / Nohup"
	default:
		return "-"
	}
}

func serviceActiveLabel(state xray.ServiceState) string {
	if state.Active {
		return "Running"
	}
	if state.Status == "" {
		return "Stopped"
	}
	return strings.ToUpper(state.Status[:1]) + state.Status[1:]
}

func servicePIDLabel(state xray.ServiceState) string {
	if state.PID <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", state.PID)
}

func yesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func presentLabel(ok bool, path string) string {
	if ok {
		return "present @ " + path
	}
	return "missing @ " + path
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func renderServiceSection(title string, lines []string, width int) string {
	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", minInt(width, maxInt(12, len([]rune(title))*2))))
	b.WriteString("\n")
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
