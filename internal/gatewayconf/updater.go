package gatewayconf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"xray-proxya/internal/config"
)

// InPlaceUpdater modifies declarative gateway.conf content line by line,
// prioritizing in-place replacement of existing directives, appending new items
// at the end, and strictly preserving all comments, blank lines, and 'def' directives.

func matchSetKey(field, targetKey string) bool {
	f := strings.ToLower(strings.TrimSpace(field))
	t := strings.ToLower(strings.TrimSpace(targetKey))
	if f == t {
		return true
	}
	canon := func(k string) string {
		switch k {
		case "tun", "tun_enabled":
			return "tun"
		case "wan", "wan_interface":
			return "wan"
		case "tproxy_port", "tproxy":
			return "tproxy_port"
		case "relay", "relay_alias":
			return "relay"
		case "local", "local_enabled":
			return "local"
		case "lan", "lan_enabled":
			return "lan"
		case "lan_interfaces", "lan_interface":
			return "lan_interfaces"
		case "fail_open", "failopen":
			return "fail_open"
		default:
			return k
		}
	}
	return canon(f) == canon(t)
}

// UpdateSet updates or appends a 'set <key> <value>' directive.
func UpdateSet(content string, key string, value string) string {
	if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
		return content
	}
	targetKey := strings.ToLower(strings.TrimSpace(key))
	targetVal := strings.TrimSpace(value)
	if targetVal == "" {
		return DeleteSet(content, targetKey)
	}
	newLine := fmt.Sprintf("set %s %s", targetKey, targetVal)

	lines := splitLines(content)
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		// CLI/TUI must never touch any def directives
		if isDefLine(trimmed) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "set") && matchSetKey(fields[1], targetKey) {
			leadingWS := getLeadingWhitespace(line)
			lines[i] = leadingWS + fmt.Sprintf("set %s %s", strings.ToLower(fields[1]), targetVal)
			found = true
			break
		}
	}

	if !found {
		lines = appendNonEmptyLine(lines, newLine)
	}

	return joinLines(lines)
}

// UpdateSetIfExists updates an existing 'set <key> <value>' directive in-place.
// If the directive does not already exist, it returns content untouched without appending.
func UpdateSetIfExists(content string, key string, value string) string {
	if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
		return content
	}
	targetKey := strings.ToLower(strings.TrimSpace(key))
	targetVal := strings.TrimSpace(value)
	if targetVal == "" {
		return DeleteSet(content, targetKey)
	}

	lines := splitLines(content)
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "set") && matchSetKey(fields[1], targetKey) {
			leadingWS := getLeadingWhitespace(line)
			lines[i] = leadingWS + fmt.Sprintf("set %s %s", strings.ToLower(fields[1]), targetVal)
			found = true
			break
		}
	}
	if !found {
		return content
	}
	return joinLines(lines)
}

// DeleteSet removes any active 'set <key> ...' directive.
func DeleteSet(content string, key string) string {
	targetKey := strings.ToLower(strings.TrimSpace(key))
	lines := splitLines(content)
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			result = append(result, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "set") && matchSetKey(fields[1], targetKey) {
			continue
		}
		result = append(result, line)
	}
	return joinLines(result)
}

// UpdateDNSRecord updates or appends a 'dns <domain> -> <ips>' directive.
func UpdateDNSRecord(content string, domain string, ips []string) string {
	if strings.ContainsAny(domain, "\r\n") {
		return content
	}
	for _, ip := range ips {
		if strings.ContainsAny(ip, "\r\n") {
			return content
		}
	}
	targetDomain := strings.ToLower(strings.TrimSpace(domain))
	targetIPs := strings.Join(ips, ", ")
	newLine := fmt.Sprintf("dns %s -> %s", targetDomain, targetIPs)

	lines := splitLines(content)
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmed), "dns ") && !strings.HasPrefix(strings.ToLower(trimmed), "dns\t") {
			continue
		}
		arrowIdx := strings.Index(trimmed, "->")
		if arrowIdx < 0 {
			arrowIdx = strings.Index(trimmed, "=>")
		}
		if arrowIdx < 0 {
			continue
		}
		left := strings.TrimSpace(trimmed[:arrowIdx])
		leftFields := strings.Fields(left)
		if len(leftFields) == 2 && strings.EqualFold(leftFields[1], targetDomain) {
			leadingWS := getLeadingWhitespace(line)
			lines[i] = leadingWS + newLine
			found = true
			break
		}
	}

	if !found {
		lines = appendNonEmptyLine(lines, newLine)
	}

	return joinLines(lines)
}

// DeleteDNSRecord removes the active static record for the given domain.
func DeleteDNSRecord(content string, domain string) string {
	targetDomain := strings.ToLower(strings.TrimSpace(domain))
	lines := splitLines(content)
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			result = append(result, line)
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmed), "dns ") && !strings.HasPrefix(strings.ToLower(trimmed), "dns\t") {
			result = append(result, line)
			continue
		}
		arrowIdx := strings.Index(trimmed, "->")
		if arrowIdx < 0 {
			arrowIdx = strings.Index(trimmed, "=>")
		}
		if arrowIdx < 0 {
			result = append(result, line)
			continue
		}
		left := strings.TrimSpace(trimmed[:arrowIdx])
		leftFields := strings.Fields(left)
		if len(leftFields) == 2 && strings.EqualFold(leftFields[1], targetDomain) {
			continue
		}
		result = append(result, line)
	}
	return joinLines(result)
}

// ClearDNSRecords removes all active static DNS record lines.
func ClearDNSRecords(content string) string {
	lines := splitLines(content)
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			result = append(result, line)
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "dns ") || strings.HasPrefix(strings.ToLower(trimmed), "dns\t") {
			arrowIdx := strings.Index(trimmed, "->")
			if arrowIdx < 0 {
				arrowIdx = strings.Index(trimmed, "=>")
			}
			if arrowIdx >= 0 {
				continue
			}
		}
		result = append(result, line)
	}
	return joinLines(result)
}

// UpdateRule adds or updates a routing rule in place based on matching criteria (MAC, IP, Interface).
func UpdateRule(content string, rule config.GatewayRule) string {
	if strings.ContainsAny(rule.MAC, "\r\n") || strings.ContainsAny(rule.IP, "\r\n") || strings.ContainsAny(rule.Interface, "\r\n") || strings.ContainsAny(rule.Target, "\r\n") {
		return content
	}
	normRule, _ := config.ValidateGatewayRule(rule)
	formatted := formatGatewayRule(normRule)

	ctx := buildRuleParseContext(content)
	lines := splitLines(content)
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			continue
		}
		criteriaList, _ := parseRuleMatchCriteria(trimmed, ctx)
		for _, criteria := range criteriaList {
			if matchRuleEqual(criteria, normRule) {
				leadingWS := getLeadingWhitespace(line)
				lines[i] = leadingWS + formatted
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		lines = appendNonEmptyLine(lines, formatted)
	}

	return joinLines(lines)
}

// DeleteRule removes the matching routing rule line.
func DeleteRule(content string, rule config.GatewayRule) string {
	normRule := rule
	if normRule.MAC != "" {
		if norm, err := config.NormalizeMAC(normRule.MAC); err == nil {
			normRule.MAC = norm
		}
	}
	if normRule.IP != "" {
		if norm, err := config.NormalizeIPOrCIDR(normRule.IP); err == nil {
			normRule.IP = norm
		}
	}
	normRule.Interface = strings.TrimSpace(normRule.Interface)

	ctx := buildRuleParseContext(content)
	lines := splitLines(content)
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			result = append(result, line)
			continue
		}
		criteriaList, _ := parseRuleMatchCriteria(trimmed, ctx)
		matched := false
		for _, criteria := range criteriaList {
			if matchRuleEqual(criteria, normRule) {
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		result = append(result, line)
	}
	return joinLines(result)
}

// ClearRules removes all client rule lines (mac, ip, interface, rule, device, group, zone), preserving local rules and defs.
func ClearRules(content string) string {
	ctx := buildRuleParseContext(content)
	lines := splitLines(content)
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" || isDefLine(trimmed) {
			result = append(result, line)
			continue
		}
		_, isClient := parseRuleMatchCriteria(trimmed, ctx)
		if isClient {
			continue
		}
		result = append(result, line)
	}
	return joinLines(result)
}

// InPlaceUpdateFile reads path, applies updater function, and writes back safely and atomically.
func InPlaceUpdateFile(path string, fn func(string) string) error {
	var content string
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	}
	updated := fn(content)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmpFile := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, []byte(updated), 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, path)
}

// ModifyGatewayConf performs an in-place update on the staging gateway.conf file (gateway.conf.staging).
// If gateway.conf.staging does not exist, it loads active gateway.conf as initial base content.
func ModifyGatewayConf(fn func(string) string) error {
	stgPath := config.GetGatewayConfPathEx(true)
	var content string
	if data, err := os.ReadFile(stgPath); err == nil {
		content = string(data)
	} else if data, err := os.ReadFile(config.GetGatewayConfPathEx(false)); err == nil {
		content = string(data)
	}
	updated := fn(content)
	if err := os.MkdirAll(filepath.Dir(stgPath), 0700); err != nil {
		return err
	}
	tmpFile := fmt.Sprintf("%s.tmp.%d", stgPath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, []byte(updated), 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, stgPath)
}

// formatGatewayRule formats a config.GatewayRule into the appropriate gateway.conf line syntax.
func formatGatewayRule(r config.GatewayRule) string {
	target := r.Target
	if target == "" {
		target = "direct"
	}

	criteriaCount := 0
	if r.MAC != "" {
		criteriaCount++
	}
	if r.IP != "" {
		criteriaCount++
	}
	if r.Interface != "" {
		criteriaCount++
	}

	if criteriaCount > 1 {
		var parts []string
		if r.MAC != "" {
			parts = append(parts, "mac="+r.MAC)
		}
		if r.IP != "" {
			parts = append(parts, "ip="+r.IP)
		}
		if r.Interface != "" {
			parts = append(parts, "interface="+r.Interface)
		}
		return fmt.Sprintf("rule %s -> %s", strings.Join(parts, " "), target)
	}

	if r.MAC != "" {
		return fmt.Sprintf("mac %s -> %s", r.MAC, target)
	}
	if r.IP != "" {
		return fmt.Sprintf("ip %s -> %s", r.IP, target)
	}
	if r.Interface != "" {
		return fmt.Sprintf("interface %s -> %s", r.Interface, target)
	}
	return fmt.Sprintf("rule -> %s", target)
}

type ruleParseContext struct {
	devices map[string]*DeviceDef
	zones   map[string]*ZoneDef
	groups  map[string]*GroupDef
}

func buildRuleParseContext(content string) *ruleParseContext {
	ast, _ := Parse(content)
	ctx := &ruleParseContext{
		devices: make(map[string]*DeviceDef),
		zones:   make(map[string]*ZoneDef),
		groups:  make(map[string]*GroupDef),
	}
	if ast != nil {
		for i := range ast.Devices {
			ctx.devices[strings.ToLower(ast.Devices[i].Name)] = &ast.Devices[i]
		}
		for i := range ast.Zones {
			ctx.zones[strings.ToLower(ast.Zones[i].Name)] = &ast.Zones[i]
		}
		for i := range ast.Groups {
			ctx.groups[strings.ToLower(ast.Groups[i].Name)] = &ast.Groups[i]
		}
	}
	return ctx
}

// parseRuleMatchCriteria extracts match criteria (MAC, IP, Interface) and reports if it is a client rule.
func parseRuleMatchCriteria(line string, ctx *ruleParseContext) ([]config.GatewayRule, bool) {
	arrowIdx := strings.Index(line, "->")
	if arrowIdx < 0 {
		arrowIdx = strings.Index(line, "=>")
	}
	if arrowIdx < 0 {
		return nil, false
	}

	left := strings.TrimSpace(line[:arrowIdx])
	right := strings.TrimSpace(line[arrowIdx+2:])
	tokens := strings.Fields(left)
	if len(tokens) == 0 {
		return nil, false
	}

	kind := strings.ToLower(tokens[0])
	switch kind {
	case "rule":
		normTokens := normalizeKeyValueTokens(tokens[1:])
		var m, ip, iface string
		i := 0
		for i < len(normTokens) {
			tok := strings.TrimPrefix(strings.TrimPrefix(normTokens[i], "--"), "-")
			if strings.Contains(tok, "=") {
				parts := strings.SplitN(tok, "=", 2)
				k := strings.ToLower(parts[0])
				v := parts[1]
				switch k {
				case "mac":
					if n, err := config.NormalizeMAC(v); err == nil {
						m = n
					}
				case "ip":
					if n, err := config.NormalizeIPOrCIDR(v); err == nil {
						ip = n
					}
				case "interface", "iface", "i":
					iface = v
				}
				i++
			} else {
				k := strings.ToLower(tok)
				if i+1 < len(normTokens) {
					v := normTokens[i+1]
					switch k {
					case "mac":
						if n, err := config.NormalizeMAC(v); err == nil {
							m = n
						}
					case "ip":
						if n, err := config.NormalizeIPOrCIDR(v); err == nil {
							ip = n
						}
					case "interface", "iface", "i":
						iface = v
					}
					i += 2
				} else {
					i++
				}
			}
		}
		return []config.GatewayRule{{MAC: m, IP: ip, Interface: iface}}, true

	case "mac":
		if len(tokens) >= 2 {
			m, _ := config.NormalizeMAC(tokens[1])
			iface := extractInterfaceOption(right)
			return []config.GatewayRule{{MAC: m, Interface: iface}}, true
		}
	case "ip":
		if len(tokens) >= 2 {
			ip, _ := config.NormalizeIPOrCIDR(tokens[1])
			iface := extractInterfaceOption(right)
			return []config.GatewayRule{{IP: ip, Interface: iface}}, true
		}
	case "interface", "iface":
		if len(tokens) >= 2 {
			m := extractMACOption(right)
			return []config.GatewayRule{{Interface: tokens[1], MAC: m}}, true
		}
	case "device", "dev":
		if len(tokens) >= 2 {
			devName := strings.ToLower(tokens[1])
			optIface := extractInterfaceOption(right)
			if ctx != nil && ctx.devices[devName] != nil {
				d := ctx.devices[devName]
				var ifaces []string
				if optIface != "" {
					ifaces = append(ifaces, optIface)
				} else if d.Zone != "" && ctx.zones[strings.ToLower(d.Zone)] != nil {
					ifaces = append(ifaces, ctx.zones[strings.ToLower(d.Zone)].Interfaces...)
				}
				if len(ifaces) == 0 {
					return []config.GatewayRule{{MAC: d.MAC}}, true
				}
				var rules []config.GatewayRule
				for _, iface := range ifaces {
					rules = append(rules, config.GatewayRule{MAC: d.MAC, Interface: iface})
				}
				return rules, true
			}
			return []config.GatewayRule{{Interface: optIface}}, true
		}
	case "group":
		if len(tokens) >= 2 {
			grpName := strings.ToLower(tokens[1])
			optIface := extractInterfaceOption(right)
			if ctx != nil && ctx.groups[grpName] != nil {
				var resolveGroupDevs func(name string, visited map[string]bool) []*DeviceDef
				resolveGroupDevs = func(name string, visited map[string]bool) []*DeviceDef {
					k := strings.ToLower(name)
					if visited[k] {
						return nil
					}
					visited[k] = true
					g := ctx.groups[k]
					if g == nil {
						return nil
					}
					var res []*DeviceDef
					for _, item := range g.Items {
						itemLow := strings.ToLower(item)
						if d := ctx.devices[itemLow]; d != nil {
							res = append(res, d)
						} else if ctx.groups[itemLow] != nil {
							subVisited := make(map[string]bool, len(visited)+1)
							for vk, vv := range visited {
								subVisited[vk] = vv
							}
							res = append(res, resolveGroupDevs(itemLow, subVisited)...)
						}
					}
					return res
				}

				devs := resolveGroupDevs(grpName, make(map[string]bool))
				if len(devs) > 1 {
					return nil, true
				}
				var rules []config.GatewayRule
				seenMACs := make(map[string]bool)
				for _, d := range devs {
					if seenMACs[d.MAC] {
						continue
					}
					seenMACs[d.MAC] = true
					var ifaces []string
					if optIface != "" {
						ifaces = append(ifaces, optIface)
					} else if d.Zone != "" && ctx.zones[strings.ToLower(d.Zone)] != nil {
						ifaces = append(ifaces, ctx.zones[strings.ToLower(d.Zone)].Interfaces...)
					}
					if len(ifaces) == 0 {
						rules = append(rules, config.GatewayRule{MAC: d.MAC})
					} else {
						for _, iface := range ifaces {
							rules = append(rules, config.GatewayRule{MAC: d.MAC, Interface: iface})
						}
					}
				}
				return rules, true
			}
			return nil, true
		}
	case "zone":
		if len(tokens) >= 2 {
			zoneName := strings.ToLower(tokens[1])
			if ctx != nil && ctx.zones[zoneName] != nil {
				z := ctx.zones[zoneName]
				var rules []config.GatewayRule
				for _, iface := range z.Interfaces {
					rules = append(rules, config.GatewayRule{Interface: iface})
				}
				return rules, true
			}
			return nil, true
		}
	}
	return nil, false
}

func extractInterfaceOption(optsStr string) string {
	for _, tok := range strings.Fields(optsStr) {
		tokLow := strings.ToLower(tok)
		if strings.HasPrefix(tokLow, "interface=") {
			return strings.TrimPrefix(tok, tok[:len("interface=")])
		}
		if strings.HasPrefix(tokLow, "iface=") {
			return strings.TrimPrefix(tok, tok[:len("iface=")])
		}
	}
	return ""
}

func extractMACOption(optsStr string) string {
	for _, tok := range strings.Fields(optsStr) {
		tokLow := strings.ToLower(tok)
		if strings.HasPrefix(tokLow, "mac=") {
			v := strings.TrimPrefix(tok, tok[:len("mac=")])
			if norm, err := config.NormalizeMAC(v); err == nil {
				return norm
			}
			return v
		}
	}
	return ""
}

func matchRuleEqual(criteria, selector config.GatewayRule) bool {
	return strings.EqualFold(criteria.MAC, selector.MAC) &&
		strings.EqualFold(criteria.IP, selector.IP) &&
		strings.EqualFold(criteria.Interface, selector.Interface)
}

func isDefLine(line string) bool {
	low := strings.ToLower(line)
	return strings.HasPrefix(low, "def ") || strings.HasPrefix(low, "def\t")
}

func getLeadingWhitespace(line string) string {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return line[:i]
		}
	}
	return ""
}

func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	res := strings.Join(lines, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return res
}

func appendNonEmptyLine(lines []string, newLine string) []string {
	// Strip trailing empty lines before appending
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, newLine)
	return lines
}
