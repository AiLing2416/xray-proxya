package gatewayconf

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
)

// CompileOptions configure the behavior of the AST compiler.
type CompileOptions struct {
	UserConfig  *config.UserConfig
	ValidRelays []string
	DefaultMode string
}

// CompileOption is a function setting an option on CompileOptions.
type CompileOption func(*CompileOptions)

// WithUserConfig supplies an existing UserConfig for validating custom relay outbounds and mode.
func WithUserConfig(cfg *config.UserConfig) CompileOption {
	return func(o *CompileOptions) {
		o.UserConfig = cfg
		if cfg != nil {
			for _, co := range cfg.CustomOutbounds {
				if co.Enabled {
					o.ValidRelays = append(o.ValidRelays, co.Alias)
				}
			}
			if cfg.Gateway.Mode != "" {
				o.DefaultMode = cfg.Gateway.Mode
			}
		}
	}
}

// WithValidRelays supplies an explicit list of valid relay aliases.
func WithValidRelays(relays []string) CompileOption {
	return func(o *CompileOptions) {
		o.ValidRelays = append(o.ValidRelays, relays...)
	}
}

// WithDefaultMode sets the default gateway mode ("tproxy" or "tun").
func WithDefaultMode(mode string) CompileOption {
	return func(o *CompileOptions) {
		o.DefaultMode = mode
	}
}

// Compile compiles a ConfigAST into a config.GatewayConfig.
func Compile(ast *ConfigAST, opts ...CompileOption) (*config.GatewayConfig, error) {
	if ast == nil {
		return &config.GatewayConfig{Mode: "tproxy"}, nil
	}

	options := &CompileOptions{
		DefaultMode: "tproxy",
	}
	for _, opt := range opts {
		opt(options)
	}

	validRelaysMap := make(map[string]bool, len(options.ValidRelays))
	for _, r := range options.ValidRelays {
		validRelaysMap[r] = true
	}

	validateTarget := func(target string, line int) error {
		if target == "" {
			return &CompileError{Line: line, Msg: "rule target cannot be empty"}
		}
		if target == "direct" || target == "block" {
			return nil
		}
		if len(validRelaysMap) > 0 {
			if !validRelaysMap[target] {
				return &CompileError{Line: line, Msg: fmt.Sprintf("target relay %q does not exist or is disabled", target)}
			}
		}
		return nil
	}

	gwConfig := &config.GatewayConfig{
		Mode: options.DefaultMode,
	}
	if options.UserConfig != nil {
		orig := options.UserConfig.Gateway
		gwConfig.TUNEnabled = orig.TUNEnabled
		gwConfig.TProxyPort = orig.TProxyPort
		gwConfig.BypassDNS = orig.BypassDNS
		gwConfig.DNSListen = orig.DNSListen
		gwConfig.DNSStrategy = orig.DNSStrategy
		gwConfig.DNSServers = orig.DNSServers
		gwConfig.DNSRecords = orig.DNSRecords
		gwConfig.State = orig.State
		gwConfig.BypassCountries = orig.BypassCountries
		gwConfig.NATDisabled = orig.NATDisabled
	}

	// 1. Process Zones
	zoneMap := make(map[string]*ZoneDef, len(ast.Zones))
	for i := range ast.Zones {
		z := &ast.Zones[i]
		zoneMap[strings.ToLower(z.Name)] = z
	}

	if wanZone, ok := zoneMap["wan"]; ok && len(wanZone.Interfaces) > 0 {
		gwConfig.WANInterface = wanZone.Interfaces[0]
	}

	var lanInterfaces []string
	seenLAN := make(map[string]bool)
	var isolatedIfaces []string
	seenIsolated := make(map[string]bool)

	addIsolated := func(iface string, line int) error {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			return nil
		}
		if err := config.ValidateInterfaceName(iface); err != nil {
			return &CompileError{Line: line, Msg: fmt.Sprintf("invalid isolated interface name %q: %v", iface, err)}
		}
		if iface == gwConfig.WANInterface {
			return &CompileError{Line: line, Msg: fmt.Sprintf("WAN interface %q cannot be configured as an isolated interface", iface)}
		}
		if !seenIsolated[iface] {
			seenIsolated[iface] = true
			isolatedIfaces = append(isolatedIfaces, iface)
		}
		return nil
	}

	for i := range ast.Zones {
		z := &ast.Zones[i]
		if strings.EqualFold(z.Name, "wan") {
			if z.Isolate {
				return nil, &CompileError{Line: z.Line, Msg: "WAN zone cannot be configured as an isolated zone"}
			}
			continue
		}
		for _, iface := range z.Interfaces {
			if !seenLAN[iface] {
				seenLAN[iface] = true
				lanInterfaces = append(lanInterfaces, iface)
			}
		}
		if z.Isolate {
			for _, iface := range z.Interfaces {
				if err := addIsolated(iface, z.Line); err != nil {
					return nil, err
				}
			}
		}
	}
	gwConfig.LANInterfaces = lanInterfaces
	if len(lanInterfaces) > 0 {
		gwConfig.LANInterface = lanInterfaces[0]
	}

	if gwConfig.WANInterface != "" {
		for _, lan := range gwConfig.LANInterfaces {
			if lan == gwConfig.WANInterface {
				wanLine := 0
				if wz := zoneMap["wan"]; wz != nil {
					wanLine = wz.Line
				}
				return nil, &CompileError{Line: wanLine, Msg: fmt.Sprintf("WAN interface %q cannot also be configured as a LAN interface", lan)}
			}
		}
	}

	// 2. Process Devices
	devMap := make(map[string]*DeviceDef, len(ast.Devices))
	for i := range ast.Devices {
		dev := &ast.Devices[i]
		devMap[strings.ToLower(dev.Name)] = dev
		if dev.Zone != "" {
			z := zoneMap[strings.ToLower(dev.Zone)]
			if z == nil {
				return nil, &CompileError{Line: dev.Line, Msg: fmt.Sprintf("device %q references undefined zone %q", dev.Name, dev.Zone)}
			}
			if strings.EqualFold(dev.Zone, "wan") {
				return nil, &CompileError{Line: dev.Line, Msg: fmt.Sprintf("device %q cannot belong to WAN zone", dev.Name)}
			}
		}
	}

	// 3. Process Groups
	groupMap := make(map[string]*GroupDef, len(ast.Groups))
	for i := range ast.Groups {
		grp := &ast.Groups[i]
		groupMap[strings.ToLower(grp.Name)] = grp
	}

	var expandGroup func(grpName string, visited map[string]bool, line int) ([]*DeviceDef, error)
	expandGroup = func(grpName string, visited map[string]bool, line int) ([]*DeviceDef, error) {
		grpKey := strings.ToLower(grpName)
		if visited[grpKey] {
			return nil, &CompileError{Line: line, Msg: fmt.Sprintf("circular group reference detected involving %q", grpName)}
		}
		visited[grpKey] = true

		grp := groupMap[grpKey]
		if grp == nil {
			return nil, &CompileError{Line: line, Msg: fmt.Sprintf("undefined group %q", grpName)}
		}

		var devs []*DeviceDef
		for _, item := range grp.Items {
			itemKey := strings.ToLower(item)
			if d, ok := devMap[itemKey]; ok {
				devs = append(devs, d)
			} else if g, ok := groupMap[itemKey]; ok {
				subVisited := make(map[string]bool, len(visited)+1)
				for k, v := range visited {
					subVisited[k] = v
				}
				subDevs, err := expandGroup(g.Name, subVisited, line)
				if err != nil {
					return nil, err
				}
				devs = append(devs, subDevs...)
			} else {
				return nil, &CompileError{Line: line, Msg: fmt.Sprintf("group %q references undefined item %q", grp.Name, item)}
			}
		}
		return devs, nil
	}

	// Pre-validate all groups for circular references or missing devices
	for i := range ast.Groups {
		grp := &ast.Groups[i]
		if _, err := expandGroup(grp.Name, make(map[string]bool), grp.Line); err != nil {
			return nil, err
		}
	}

	// 4. Process Rules
	var rules []config.GatewayRule
	addRule := func(r config.GatewayRule, line int) error {
		norm, err := config.ValidateGatewayRule(r)
		if err != nil {
			return &CompileError{Line: line, Msg: err.Error()}
		}
		rules = append(rules, norm)
		gwConfig.LANEnabled = true
		if gwConfig.RelayAlias == "" && norm.Target != "direct" && norm.Target != "block" {
			gwConfig.RelayAlias = norm.Target
		}
		return nil
	}

	for _, r := range ast.Rules {
		if err := validateTarget(r.Target, r.Line); err != nil {
			return nil, err
		}

		isIsolate := false
		if isoVal, ok := r.Option("isolate"); ok {
			isoVal = strings.ToLower(strings.TrimSpace(isoVal))
			if isoVal == "true" || isoVal == "" || isoVal == "1" || isoVal == "yes" {
				isIsolate = true
			} else if isoVal != "false" && isoVal != "0" && isoVal != "no" {
				return nil, &CompileError{Line: r.Line, Msg: fmt.Sprintf("invalid isolate value %q: expected true or false", isoVal)}
			}
		}

		if isIsolate {
			switch r.Kind {
			case SubjectZone:
				zoneName := strings.ToLower(r.SubjectValue)
				z := zoneMap[zoneName]
				if z == nil {
					return nil, &CompileError{Line: r.Line, Msg: fmt.Sprintf("rule references undefined zone %q", r.SubjectValue)}
				}
				if zoneName == "wan" {
					return nil, &CompileError{Line: r.Line, Msg: "cannot apply isolate to WAN zone"}
				}
				for _, iface := range z.Interfaces {
					if err := addIsolated(iface, r.Line); err != nil {
						return nil, err
					}
				}
			case SubjectInterface:
				if err := addIsolated(r.SubjectValue, r.Line); err != nil {
					return nil, err
				}
			default:
				return nil, &CompileError{Line: r.Line, Msg: fmt.Sprintf("isolate option is only supported on zone or interface rules, got %s", r.Kind)}
			}
		}

		switch r.Kind {
		case SubjectRule:
			if err := addRule(config.GatewayRule{
				MAC:       r.MAC,
				IP:        r.IP,
				Interface: r.Interface,
				Target:    r.Target,
			}, r.Line); err != nil {
				return nil, err
			}

		case SubjectLocal:
			if r.Target != "direct" && r.Target != "block" {
				gwConfig.LocalEnabled = true
				if gwConfig.RelayAlias == "" {
					gwConfig.RelayAlias = r.Target
				}
			} else if r.Target == "direct" || r.Target == "block" {
				gwConfig.LocalEnabled = false
			}

		case SubjectZone:
			zoneName := strings.ToLower(r.SubjectValue)
			z := zoneMap[zoneName]
			if z == nil {
				return nil, &CompileError{Line: r.Line, Msg: fmt.Sprintf("rule references undefined zone %q", r.SubjectValue)}
			}
			if zoneName == "wan" {
				return nil, &CompileError{Line: r.Line, Msg: "cannot apply gateway routing rule to WAN zone"}
			}

			if zoneName == "lan" {
				if r.Target != "direct" && r.Target != "block" {
					gwConfig.LANEnabled = true
					if gwConfig.RelayAlias == "" {
						gwConfig.RelayAlias = r.Target
					}
				} else if r.Target == "direct" {
					gwConfig.LANEnabled = false
				}
			}

			if r.Target == "direct" || r.Target == "block" || (gwConfig.RelayAlias != "" && r.Target != gwConfig.RelayAlias) {
				for _, iface := range z.Interfaces {
					if err := addRule(config.GatewayRule{Interface: iface, Target: r.Target}, r.Line); err != nil {
						return nil, err
					}
				}
			}

		case SubjectDevice:
			d := devMap[strings.ToLower(r.SubjectValue)]
			if d == nil {
				return nil, &CompileError{Line: r.Line, Msg: fmt.Sprintf("undefined device %q", r.SubjectValue)}
			}
			ruleIface, _ := r.Option("interface")
			if ruleIface == "" {
				ruleIface, _ = r.Option("iface")
			}
			if err := addRule(config.GatewayRule{MAC: d.MAC, Interface: ruleIface, Target: r.Target}, r.Line); err != nil {
				return nil, err
			}

		case SubjectGroup:
			devs, err := expandGroup(r.SubjectValue, make(map[string]bool), r.Line)
			if err != nil {
				return nil, err
			}
			ruleIface, _ := r.Option("interface")
			if ruleIface == "" {
				ruleIface, _ = r.Option("iface")
			}
			seenMACs := make(map[string]bool)
			for _, d := range devs {
				if seenMACs[d.MAC] {
					continue
				}
				seenMACs[d.MAC] = true
				if err := addRule(config.GatewayRule{MAC: d.MAC, Interface: ruleIface, Target: r.Target}, r.Line); err != nil {
					return nil, err
				}
			}

		case SubjectMAC:
			ruleIface, _ := r.Option("interface")
			if ruleIface == "" {
				ruleIface, _ = r.Option("iface")
			}
			if err := addRule(config.GatewayRule{MAC: r.SubjectValue, Interface: ruleIface, Target: r.Target}, r.Line); err != nil {
				return nil, err
			}

		case SubjectInterface:
			macVal, _ := r.Option("mac")
			if err := addRule(config.GatewayRule{Interface: r.SubjectValue, MAC: macVal, Target: r.Target}, r.Line); err != nil {
				return nil, err
			}

		case SubjectIP:
			ipStr := r.SubjectValue
			// 1. Exact match with a device IP
			var matchedDev *DeviceDef
			for _, d := range devMap {
				if d.IP == ipStr {
					matchedDev = d
					break
				}
			}
			if matchedDev != nil {
				ruleIface, _ := r.Option("interface")
				if ruleIface == "" {
					ruleIface, _ = r.Option("iface")
				}
				if err := addRule(config.GatewayRule{MAC: matchedDev.MAC, Interface: ruleIface, Target: r.Target}, r.Line); err != nil {
					return nil, err
				}
				continue
			}

			// 2. Exact match with a zone subnet
			var matchedZone *ZoneDef
			for _, z := range zoneMap {
				for _, s := range z.Subnets {
					if s == ipStr {
						matchedZone = z
						break
					}
				}
				if matchedZone != nil {
					break
				}
			}
			if matchedZone != nil {
				for _, iface := range matchedZone.Interfaces {
					if err := addRule(config.GatewayRule{Interface: iface, Target: r.Target}, r.Line); err != nil {
						return nil, err
					}
				}
				continue
			}

			// 3. CIDR match containing device IPs
			if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
				var matchedDevices []*DeviceDef
				for _, d := range devMap {
					if d.IP != "" {
						if parsed := net.ParseIP(d.IP); parsed != nil && ipNet.Contains(parsed) {
							matchedDevices = append(matchedDevices, d)
						}
					}
				}
				if len(matchedDevices) > 0 {
					seenMACs := make(map[string]bool)
					for _, d := range matchedDevices {
						if seenMACs[d.MAC] {
							continue
						}
						seenMACs[d.MAC] = true
						if err := addRule(config.GatewayRule{MAC: d.MAC, Target: r.Target}, r.Line); err != nil {
							return nil, err
						}
					}
					continue
				}
			}

			// 4. Native L3 IP or CIDR rule (not bound to any device MAC)
			ruleIface, _ := r.Option("interface")
			if ruleIface == "" {
				ruleIface, _ = r.Option("iface")
			}
			if err := addRule(config.GatewayRule{IP: ipStr, Interface: ruleIface, Target: r.Target}, r.Line); err != nil {
				return nil, err
			}
			continue

		default:
			return nil, &CompileError{Line: r.Line, Msg: fmt.Sprintf("unsupported rule kind %q", r.Kind)}
		}
	}

	gwConfig.Rules = rules
	sort.Strings(isolatedIfaces)
	gwConfig.IsolatedInterfaces = isolatedIfaces

	// 5. Process Global Settings (set ...)
	for _, s := range ast.Sets {
		k := strings.ToLower(strings.TrimSpace(s.Key))
		v := strings.TrimSpace(s.Value)
		switch k {
		case "state":
			vLower := strings.ToLower(v)
			if vLower != "disabled" && vLower != "forward-only" && vLower != "proxy" {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid gateway state %q (allowed: disabled, forward-only, proxy)", v)}
			}
			gwConfig.State = vLower
		case "mode":
			vLower := strings.ToLower(v)
			if vLower != "tproxy" && vLower != "tun" {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid gateway mode %q (allowed: tproxy, tun)", v)}
			}
			gwConfig.Mode = vLower
			if vLower == "tun" {
				gwConfig.TUNEnabled = true
			}
		case "tun", "tun_enabled":
			b, err := parseBoolValue(v)
			if err != nil {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid tun value %q: %v", v, err)}
			}
			gwConfig.TUNEnabled = b
		case "nat":
			b, err := parseBoolValue(v)
			if err != nil {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid nat value %q: %v", v, err)}
			}
			gwConfig.NATDisabled = !b
		case "nat_disabled":
			b, err := parseBoolValue(v)
			if err != nil {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid nat_disabled value %q: %v", v, err)}
			}
			gwConfig.NATDisabled = b
		case "wan", "wan_interface":
			if strings.EqualFold(v, "auto") || v == "" {
				gwConfig.WANInterface = ""
			} else {
				if err := config.ValidateInterfaceName(v); err != nil {
					return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid wan interface %q: %v", v, err)}
				}
				gwConfig.WANInterface = v
			}
		case "tproxy_port", "tproxy":
			port, err := strconv.Atoi(v)
			if err != nil || port < 1 || port > 65535 {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid tproxy_port %q: must be between 1 and 65535", v)}
			}
			gwConfig.TProxyPort = port
		case "bypass_countries":
			parts := strings.Split(v, ",")
			var countries []string
			for _, p := range parts {
				for _, c := range strings.Fields(p) {
					c = strings.ToUpper(strings.TrimSpace(c))
					if c != "" {
						countries = append(countries, c)
					}
				}
			}
			gwConfig.BypassCountries = countries
		case "bypass_dns":
			parts := strings.Split(v, ",")
			var bypass []string
			for _, p := range parts {
				for _, item := range strings.Fields(p) {
					item = strings.TrimSpace(item)
					if item != "" {
						bypass = append(bypass, item)
					}
				}
			}
			gwConfig.BypassDNS = bypass
		case "dns_listen":
			if strings.EqualFold(v, "off") || strings.EqualFold(v, "none") || strings.EqualFold(v, "disabled") || v == "" {
				gwConfig.DNSListen = ""
			} else {
				_, _, norm, err := config.ParseDNSListen(v)
				if err != nil {
					return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid dns_listen %q: %v", v, err)}
				}
				gwConfig.DNSListen = norm
			}
		case "dns_strategy":
			norm, ok := config.NormalizeDNSQueryStrategy(v)
			if !ok {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid dns_strategy %q (must be UseIP, UseIPv4, or UseIPv6)", v)}
			}
			gwConfig.DNSStrategy = norm
		case "dns_servers":
			parts := strings.Split(v, ",")
			var servers []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				norm, err := config.ValidateDNSServerEntry(p)
				if err != nil {
					return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid dns_server %q: %v", p, err)}
				}
				servers = append(servers, norm)
			}
			gwConfig.DNSServers = servers
		case "relay", "relay_alias":
			gwConfig.RelayAlias = v
		case "local", "local_enabled":
			b, err := parseBoolValue(v)
			if err != nil {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid local value %q: %v", v, err)}
			}
			gwConfig.LocalEnabled = b
		case "lan", "lan_enabled":
			b, err := parseBoolValue(v)
			if err != nil {
				return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid lan value %q: %v", v, err)}
			}
			gwConfig.LANEnabled = b
		case "lan_interfaces", "lan_interface":
			parts := strings.Split(v, ",")
			var ifaces []string
			for _, p := range parts {
				iface := strings.TrimSpace(p)
				if iface == "" {
					continue
				}
				if err := config.ValidateInterfaceName(iface); err != nil {
					return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("invalid lan interface %q: %v", iface, err)}
				}
				ifaces = append(ifaces, iface)
			}
			gwConfig.LANInterfaces = ifaces
			if len(ifaces) > 0 {
				gwConfig.LANInterface = ifaces[0]
			}
		default:
			return nil, &CompileError{Line: s.Line, Msg: fmt.Sprintf("unknown configuration parameter %q in set directive", s.Key)}
		}
	}

	if gwConfig.WANInterface != "" {
		for _, lan := range gwConfig.LANInterfaces {
			if lan == gwConfig.WANInterface {
				return nil, &CompileError{Msg: fmt.Sprintf("WAN interface %q cannot also be configured as a LAN interface", lan)}
			}
		}
	}

	// 6. Process Static DNS Records
	if len(ast.DNSRecords) > 0 {
		if gwConfig.DNSRecords == nil {
			gwConfig.DNSRecords = make(map[string][]string)
		}
		for _, d := range ast.DNSRecords {
			gwConfig.DNSRecords[d.Domain] = d.IPs
		}
	}

	// 7. Process Port Forwarding Rules
	var portForwards []config.PortForwardRule
	for _, f := range ast.Forwards {
		var targetIP string
		// 1. Check if target is a defined device
		if d, ok := devMap[strings.ToLower(f.Target)]; ok {
			if strings.TrimSpace(d.IP) == "" {
				return nil, &CompileError{Line: f.Line, Msg: fmt.Sprintf("device %q referenced in port forward has no ip configured (add ip=<address> to def device)", d.Name)}
			}
			parsedIP := net.ParseIP(strings.TrimSpace(d.IP))
			if parsedIP == nil {
				return nil, &CompileError{Line: f.Line, Msg: fmt.Sprintf("device %q has invalid ip %q", d.Name, d.IP)}
			}
			targetIP = parsedIP.String()
		} else {
			// 2. Target must be a valid single IP
			parsedIP := net.ParseIP(strings.TrimSpace(f.Target))
			if parsedIP == nil {
				return nil, &CompileError{Line: f.Line, Msg: fmt.Sprintf("port forward target %q is neither a defined device nor a valid IP address", f.Target)}
			}
			targetIP = parsedIP.String()
		}

		if f.WANPort < 1 || f.WANPort > 65535 {
			return nil, &CompileError{Line: f.Line, Msg: fmt.Sprintf("invalid WAN port %d: must be between 1 and 65535", f.WANPort)}
		}
		if f.TargetPort < 1 || f.TargetPort > 65535 {
			return nil, &CompileError{Line: f.Line, Msg: fmt.Sprintf("invalid target port %d: must be between 1 and 65535", f.TargetPort)}
		}

		proto, err := config.NormalizePortForwardProto(f.Proto)
		if err != nil {
			return nil, &CompileError{Line: f.Line, Msg: err.Error()}
		}

		// Check for duplicate WAN port + proto conflict
		for _, prev := range portForwards {
			if prev.WANPort == f.WANPort && config.PortForwardProtoOverlap(prev.Proto, proto) {
				return nil, &CompileError{
					Line: f.Line,
					Msg:  fmt.Sprintf("duplicate port forward on WAN port %d with conflicting proto (%s vs %s)", f.WANPort, proto, prev.Proto),
				}
			}
		}

		portForwards = append(portForwards, config.PortForwardRule{
			WANPort:    f.WANPort,
			TargetIP:   targetIP,
			TargetPort: f.TargetPort,
			Proto:      proto,
		})
	}
	gwConfig.PortForwards = portForwards

	// Final verification if UserConfig was provided
	if options.UserConfig != nil {
		testUserCfg := *options.UserConfig
		testUserCfg.Gateway = *gwConfig
		if err := config.ValidateGatewayInterfaces(&testUserCfg); err != nil {
			return nil, err
		}
		if err := config.ValidateGatewayRulesForMode(&testUserCfg); err != nil {
			return nil, err
		}
		if err := config.ValidateGatewayPorts(&testUserCfg); err != nil {
			return nil, err
		}
	}

	return gwConfig, nil
}

func parseBoolValue(v string) (bool, error) {
	vLower := strings.ToLower(strings.TrimSpace(v))
	switch vLower {
	case "true", "1", "yes", "on", "enabled", "enable":
		return true, nil
	case "false", "0", "no", "off", "disabled", "disable":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", v)
	}
}
