package tui

import (
	"fmt"
	"net"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"

	"github.com/charmbracelet/lipgloss"
)

// Gateway tab row indices (cursor positions).
const (
	gwRowState = iota
	gwRowRules // TProxy runtime rules (up/down)
	gwRowTUN
	gwRowLocal
	gwRowLAN
	gwRowLANIface
	gwRowWANIface
	gwRowNAT
	gwRowRelay
	gwRowBypass
	gwRowRuleList // read-only gateway rule summary
	gwRowMax      = gwRowRuleList
)

const (
	missingSuffix = " (missing)"
	wanAuto       = "auto"
)

// normalizeWAN maps the empty value to "auto".
func normalizeWAN(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return wanAuto
	}
	return v
}

// wanRowInfo returns the INFO and STATUS cells for the WAN interface row.
func wanRowInfo(wan string) (info, status string) {
	wan = normalizeWAN(wan)
	if wan == wanAuto {
		if name, err := gateway.DetectDefaultInterface(); err == nil && strings.TrimSpace(name) != "" {
			return wanAuto, "READY"
		}
		return wanAuto, "NON READY"
	}
	if _, err := net.InterfaceByName(wan); err == nil {
		return wan, "READY"
	}
	return wan, "NON READY"
}

// describeRuleMatch renders the match criteria of a gateway rule.
func describeRuleMatch(r config.GatewayRule) string {
	var parts []string
	if r.MAC != "" {
		parts = append(parts, "mac="+r.MAC)
	}
	if r.IP != "" {
		parts = append(parts, "ip="+r.IP)
	}
	if r.Interface != "" {
		parts = append(parts, "iface="+r.Interface)
	}
	if len(parts) == 0 {
		return "(any)"
	}
	return strings.Join(parts, " ")
}

// localInterfaceNames lists host interfaces suitable as gateway LAN/WAN candidates.
func localInterfaceNames() []string {
	ifaces, _ := net.Interfaces()
	var names []string
	for _, iface := range ifaces {
		switch iface.Name {
		case "lo", "proxya-tun", "path-tun":
			continue
		}
		names = append(names, iface.Name)
	}
	return names
}

// interfaceChoices merges host interfaces with already-configured ones that no
// longer exist on this host (labelled with missingSuffix, kept so they are not
// silently dropped). The returned checked map is keyed by choice index.
func interfaceChoices(base []string, current []string) (choices []string, checked map[int]bool) {
	checked = map[int]bool{}
	cur := map[string]bool{}
	for _, c := range current {
		cur[c] = true
	}
	present := map[string]bool{}
	choices = append(choices, base...)
	for i, name := range base {
		present[name] = true
		if cur[name] {
			checked[i] = true
		}
	}
	for _, c := range current {
		if c == "" || present[c] {
			continue
		}
		present[c] = true
		choices = append(choices, c+missingSuffix)
		checked[len(choices)-1] = true
	}
	return choices, checked
}

// trimMissing strips the display-only missing suffix.
func trimMissing(label string) string {
	return strings.TrimSuffix(label, missingSuffix)
}

// joinChecked joins checked choices (in list order) into raw interface names.
func joinChecked(choices []string, checked map[int]bool) []string {
	var out []string
	for i, c := range choices {
		if checked[i] {
			out = append(out, trimMissing(c))
		}
	}
	return out
}

// RenderMultiChoiceList renders a checkbox list ("[x]" / "[ ]") with a cursor and windowed viewport.
func RenderMultiChoiceList(choices []string, checked map[int]bool, cursor int, maxVisible int) []string {
	if len(choices) == 0 {
		return nil
	}
	start, end := 0, len(choices)
	if maxVisible > 0 && maxVisible < len(choices) {
		start = cursor - maxVisible/2
		if start < 0 {
			start = 0
		}
		end = start + maxVisible
		if end > len(choices) {
			end = len(choices)
			start = end - maxVisible
			if start < 0 {
				start = 0
			}
		}
	}
	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		box := "[ ]"
		if checked[i] {
			box = "[x]"
		}
		line := fmt.Sprintf("%s %s", box, choices[i])
		if i == cursor {
			lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("> "+line))
		} else {
			lines = append(lines, "  "+line)
		}
	}
	return lines
}
