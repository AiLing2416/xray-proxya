package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/xray"
)

func RenderService(state xray.ServiceState, width int) string {
	rows := [][]string{
		{"Runtime", serviceRuntimeLabel(state)},
		{"Init", state.InitSystem},
		{"Installed", yesNo(state.UnitInstalled)},
		{"Service File", valueOrDash(state.ServiceFile)},
		{"Status", serviceActiveLabel(state)},
		{"PID", servicePIDLabel(state)},
		{"Uptime", valueOrDash(state.Uptime)},
		{"Hint", valueOrDash(state.Hint)},
		{"Xray Binary", presentLabel(state.XrayPresent, state.XrayPath)},
		{"Xray Version", valueOrDash(state.XrayVersion)},
		{"geoip.dat", presentLabel(state.GeoIPPresent, state.GeoIPPath)},
		{"GeoIP Feature", valueOrDash(state.GeoIPFeature)},
		{"Config Path", valueOrDash(state.ConfigPath)},
		{"Log Path", valueOrDash(state.LogPath)},
	}

	var b strings.Builder
	labelWidth := 0
	for _, row := range rows {
		labelWidth = max(labelWidth, runeLen(row[0]))
	}
	valueWidth := width - labelWidth - tableGap
	if valueWidth < 8 {
		valueWidth = 8
	}
	for i, row := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(row[0])
		b.WriteString(strings.Repeat(" ", labelWidth-runeLen(row[0])))
		b.WriteString("  ")
		b.WriteString(truncateRunes(row[1], valueWidth))
	}
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
