package gatewayconf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
)

// Parse parses a declarative gateway.conf from raw text string.
func Parse(text string) (*ConfigAST, error) {
	return ParseReader(strings.NewReader(text))
}

// ParseReader parses a declarative gateway.conf from an io.Reader.
func ParseReader(r io.Reader) (*ConfigAST, error) {
	scanner := bufio.NewScanner(r)
	ast := &ConfigAST{}
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()

		// 1. Strip comments starting with '#'
		line := rawLine
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 2. Check if this is a definition directive (def ...)
		if strings.HasPrefix(strings.ToLower(line), "def ") || strings.HasPrefix(strings.ToLower(line), "def\t") {
			if err := parseDef(line, lineNum, ast); err != nil {
				return nil, err
			}
			continue
		}

		// 3. Check if this is a port forwarding directive (forward ...)
		lowerLine := strings.ToLower(line)
		if lowerLine == "forward" || strings.HasPrefix(lowerLine, "forward ") || strings.HasPrefix(lowerLine, "forward\t") {
			if err := parseForward(line, lineNum, ast); err != nil {
				return nil, err
			}
			continue
		}

		// 4. Otherwise it must be a rule directive (... -> ... or ... => ...)
		if err := parseRule(line, lineNum, ast); err != nil {
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, &ParseError{Line: lineNum, Msg: fmt.Sprintf("read error: %v", err)}
	}

	return ast, nil
}

func parseDef(line string, lineNum int, ast *ConfigAST) error {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("incomplete def directive: %q", line)}
	}

	defType := strings.ToLower(fields[1])
	name := fields[2]

	switch defType {
	case "zone":
		return parseZoneDef(fields[3:], name, lineNum, ast)
	case "device":
		return parseDeviceDef(fields[3:], name, lineNum, ast)
	case "group":
		return parseGroupDef(fields[3:], name, lineNum, ast)
	default:
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unknown definition type %q (expected zone, device, or group)", defType)}
	}
}

func parseZoneDef(args []string, name string, lineNum int, ast *ConfigAST) error {
	if err := validateIdentifier(name); err != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid zone name %q: %v", name, err)}
	}
	if ast.FindZone(name) != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("duplicate zone definition %q", name)}
	}

	var ifaces []string
	var subnets []string

	for _, arg := range args {
		argTrim := strings.TrimSpace(arg)
		if argTrim == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(argTrim), "subnet=") {
			subnetVal := argTrim[len("subnet="):]
			parts := strings.Split(subnetVal, ",")
			for _, part := range parts {
				p := strings.TrimSpace(part)
				if p == "" {
					continue
				}
				if _, _, err := net.ParseCIDR(p); err != nil {
					return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid subnet CIDR format %q: %v", p, err)}
				}
				subnets = append(subnets, p)
			}
			continue
		}

		// Interfaces (may be comma-separated, e.g. eth1, vmbr0)
		parts := strings.Split(argTrim, ",")
		for _, part := range parts {
			iface := strings.TrimSpace(part)
			if iface == "" {
				continue
			}
			if err := config.ValidateInterfaceName(iface); err != nil {
				return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid interface name %q: %v", iface, err)}
			}
			ifaces = append(ifaces, iface)
		}
	}

	if len(ifaces) == 0 {
		return &ParseError{Line: lineNum, Msg: "def zone requires at least one interface"}
	}

	ast.Zones = append(ast.Zones, ZoneDef{
		Name:       name,
		Interfaces: ifaces,
		Subnets:    subnets,
		Line:       lineNum,
	})
	return nil
}

func parseDeviceDef(args []string, name string, lineNum int, ast *ConfigAST) error {
	if err := validateIdentifier(name); err != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid device name %q: %v", name, err)}
	}
	if ast.FindDevice(name) != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("duplicate device definition %q", name)}
	}

	// Normalize args: in case someone wrote "mac = xx", normalize tokens
	normalizedArgs := normalizeKeyValueTokens(args)

	var macStr, zoneStr, ipStr string
	for _, arg := range normalizedArgs {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("expected key=value in def device, got %q", arg)}
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "mac":
			normMAC, err := config.NormalizeMAC(val)
			if err != nil {
				return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid MAC address format %q: %v", val, err)}
			}
			macStr = normMAC
		case "zone":
			if err := validateIdentifier(val); err != nil {
				return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid zone name %q in device %q: %v", val, name, err)}
			}
			zoneStr = val
		case "ip":
			if parsed := net.ParseIP(val); parsed == nil {
				return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid IP address format %q", val)}
			}
			ipStr = val
		default:
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unknown device attribute %q (supported: mac, zone, ip)", key)}
		}
	}

	if macStr == "" {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("def device %q requires mac=<mac>", name)}
	}

	ast.Devices = append(ast.Devices, DeviceDef{
		Name: name,
		MAC:  macStr,
		Zone: zoneStr,
		IP:   ipStr,
		Line: lineNum,
	})
	return nil
}

func parseGroupDef(args []string, name string, lineNum int, ast *ConfigAST) error {
	if err := validateIdentifier(name); err != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid group name %q: %v", name, err)}
	}
	if ast.FindGroup(name) != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("duplicate group definition %q", name)}
	}

	// Group items may be comma-separated or whitespace-separated
	rawJoined := strings.Join(args, " ")
	parts := strings.Split(rawJoined, ",")
	var items []string
	for _, part := range parts {
		for _, item := range strings.Fields(part) {
			it := strings.TrimSpace(item)
			if it != "" {
				items = append(items, it)
			}
		}
	}

	if len(items) == 0 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("def group %q requires at least one member", name)}
	}

	ast.Groups = append(ast.Groups, GroupDef{
		Name:  name,
		Items: items,
		Line:  lineNum,
	})
	return nil
}

func parseRule(line string, lineNum int, ast *ConfigAST) error {
	arrowIdx := strings.Index(line, "->")
	arrowLen := 2
	if arrowIdx < 0 {
		arrowIdx = strings.Index(line, "=>")
	}
	if arrowIdx < 0 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unrecognized directive or missing '->' in %q", line)}
	}

	left := strings.TrimSpace(line[:arrowIdx])
	right := strings.TrimSpace(line[arrowIdx+arrowLen:])

	leftTokens := strings.Fields(left)
	if len(leftTokens) == 0 {
		return &ParseError{Line: lineNum, Msg: "missing subject before arrow"}
	}

	kindStr := strings.ToLower(leftTokens[0])
	var kind RuleSubjectKind
	var subjectVal string

	switch kindStr {
	case "local":
		if len(leftTokens) > 1 {
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unexpected arguments after 'local': %q", strings.Join(leftTokens[1:], " "))}
		}
		kind = SubjectLocal

	case "zone":
		if len(leftTokens) != 2 {
			return &ParseError{Line: lineNum, Msg: "zone rule requires zone name, e.g. 'zone lan -> ...'"}
		}
		kind = SubjectZone
		subjectVal = leftTokens[1]

	case "device":
		if len(leftTokens) != 2 {
			return &ParseError{Line: lineNum, Msg: "device rule requires device name, e.g. 'device tv -> ...'"}
		}
		kind = SubjectDevice
		subjectVal = leftTokens[1]

	case "group":
		if len(leftTokens) != 2 {
			return &ParseError{Line: lineNum, Msg: "group rule requires group name, e.g. 'group streaming -> ...'"}
		}
		kind = SubjectGroup
		subjectVal = leftTokens[1]

	case "mac":
		if len(leftTokens) != 2 {
			return &ParseError{Line: lineNum, Msg: "mac rule requires MAC address, e.g. 'mac 52:54:00:84:00:11 -> ...'"}
		}
		normMAC, err := config.NormalizeMAC(leftTokens[1])
		if err != nil {
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid MAC address format %q: %v", leftTokens[1], err)}
		}
		kind = SubjectMAC
		subjectVal = normMAC

	case "interface", "iface":
		if len(leftTokens) != 2 {
			return &ParseError{Line: lineNum, Msg: "interface rule requires interface name, e.g. 'interface eth1 -> ...'"}
		}
		if err := config.ValidateInterfaceName(leftTokens[1]); err != nil {
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid interface name %q: %v", leftTokens[1], err)}
		}
		kind = SubjectInterface
		subjectVal = leftTokens[1]

	case "ip":
		if len(leftTokens) != 2 {
			return &ParseError{Line: lineNum, Msg: "ip rule requires IP address or CIDR, e.g. 'ip 192.168.1.50 -> ...'"}
		}
		ipVal := leftTokens[1]
		if net.ParseIP(ipVal) == nil {
			if _, _, err := net.ParseCIDR(ipVal); err != nil {
				return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid IP address or CIDR %q", ipVal)}
			}
		}
		kind = SubjectIP
		subjectVal = ipVal

	default:
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unknown rule subject kind %q (expected local, zone, device, group, mac, interface, or ip)", leftTokens[0])}
	}

	rightTokens := strings.Fields(right)
	if len(rightTokens) == 0 {
		return &ParseError{Line: lineNum, Msg: "missing target after arrow"}
	}

	target := rightTokens[0]
	if strings.EqualFold(target, "direct") {
		target = "direct"
	} else if strings.EqualFold(target, "block") {
		target = "block"
	}

	normalizedOpts := normalizeKeyValueTokens(rightTokens[1:])
	var options []RuleOption
	for _, optToken := range normalizedOpts {
		if strings.Contains(optToken, "=") {
			parts := strings.SplitN(optToken, "=", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k == "" {
				return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid option format %q", optToken)}
			}
			options = append(options, RuleOption{Key: k, Value: v})
		} else {
			options = append(options, RuleOption{Key: optToken, Value: "true"})
		}
	}

	ast.Rules = append(ast.Rules, RuleAST{
		Kind:         kind,
		SubjectValue: subjectVal,
		Target:       target,
		Options:      options,
		Line:         lineNum,
	})
	return nil
}

func validateIdentifier(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("identifier cannot be empty")
	}
	if len(trimmed) > 32 {
		return fmt.Errorf("identifier %q too long (max 32 chars)", id)
	}
	for _, r := range trimmed {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("identifier %q contains invalid characters (only alphanumeric, '-' and '_' allowed)", id)
		}
	}
	return nil
}

// normalizeKeyValueTokens recombines tokens if someone separated '=' with spaces (e.g. ["mac", "=", "52:..."])
func normalizeKeyValueTokens(tokens []string) []string {
	var result []string
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		if i+2 < len(tokens) && tokens[i+1] == "=" {
			result = append(result, t+"="+tokens[i+2])
			i += 3
		} else if strings.HasSuffix(t, "=") && i+1 < len(tokens) {
			result = append(result, t+tokens[i+1])
			i += 2
		} else if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "=") {
			result = append(result, t+tokens[i+1])
			i += 2
		} else {
			result = append(result, t)
			i++
		}
	}
	return result
}

func parseForward(line string, lineNum int, ast *ConfigAST) error {
	arrowIdx := strings.Index(line, "->")
	arrowLen := 2
	if arrowIdx < 0 {
		arrowIdx = strings.Index(line, "=>")
	}
	if arrowIdx < 0 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unrecognized directive or missing '->' in %q", line)}
	}

	left := strings.TrimSpace(line[:arrowIdx])
	right := strings.TrimSpace(line[arrowIdx+arrowLen:])

	leftTokens := strings.Fields(left)
	if len(leftTokens) < 2 {
		return &ParseError{Line: lineNum, Msg: "forward directive requires WAN port before arrow, e.g. 'forward 80 -> ...' or 'forward wan:80 -> ...'"}
	}
	if len(leftTokens) > 2 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unexpected tokens in forward directive: %q", strings.Join(leftTokens[2:], " "))}
	}

	wanPortStr := leftTokens[1]
	if strings.HasPrefix(strings.ToLower(wanPortStr), "wan:") {
		wanPortStr = wanPortStr[len("wan:"):]
	}
	wanPort, err := strconv.Atoi(wanPortStr)
	if err != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid WAN port %q: must be a number", leftTokens[1])}
	}
	if wanPort < 1 || wanPort > 65535 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid WAN port %d: must be between 1 and 65535", wanPort)}
	}

	rightTokens := strings.Fields(right)
	if len(rightTokens) == 0 {
		return &ParseError{Line: lineNum, Msg: "missing target after arrow in forward directive"}
	}

	targetToken := rightTokens[0]
	targetHost, targetPortStr, splitErr := net.SplitHostPort(targetToken)
	if splitErr != nil {
		idx := strings.LastIndex(targetToken, ":")
		if idx <= 0 || idx == len(targetToken)-1 {
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid target %q: must be in format <target>:<port>", targetToken)}
		}
		targetHost = targetToken[:idx]
		targetPortStr = targetToken[idx+1:]
	}
	targetHost = strings.Trim(strings.TrimSpace(targetHost), "[]")
	if targetHost == "" {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid target %q: target cannot be empty", targetToken)}
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid target port %q: must be a number", targetPortStr)}
	}
	if targetPort < 1 || targetPort > 65535 {
		return &ParseError{Line: lineNum, Msg: fmt.Sprintf("invalid target port %d: must be between 1 and 65535", targetPort)}
	}

	proto := "tcp,udp"
	normalizedOpts := normalizeKeyValueTokens(rightTokens[1:])
	for _, optToken := range normalizedOpts {
		parts := strings.SplitN(optToken, "=", 2)
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		if k == "proto" {
			if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
				return &ParseError{Line: lineNum, Msg: "empty proto value in forward directive"}
			}
			normProto, pErr := config.NormalizePortForwardProto(parts[1])
			if pErr != nil {
				return &ParseError{Line: lineNum, Msg: pErr.Error()}
			}
			proto = normProto
		} else {
			return &ParseError{Line: lineNum, Msg: fmt.Sprintf("unknown option %q in forward directive (expected proto=...)", optToken)}
		}
	}

	ast.Forwards = append(ast.Forwards, ForwardAST{
		WANPort:    wanPort,
		Target:     targetHost,
		TargetPort: targetPort,
		Proto:      proto,
		Line:       lineNum,
	})
	return nil
}
