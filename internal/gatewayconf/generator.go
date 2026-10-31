package gatewayconf

import (
	"fmt"
	"sort"
	"strings"
	"xray-proxya/internal/config"
)

// Generate formats and exports a GatewayConfig into a human-readable, annotated gateway.conf text.
func Generate(gw *config.GatewayConfig) string {
	if gw == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("# ==============================================================================\n")
	b.WriteString("# Xray-Proxya Gateway Configuration (gateway.conf)\n")
	b.WriteString("# ==============================================================================\n")
	b.WriteString("# Quick Reference & Syntax Guide:\n")
	b.WriteString("#\n")
	b.WriteString("# 1. Zone Definitions:\n")
	b.WriteString("#    def zone wan <interface>                                     # WAN interface (e.g. eth0)\n")
	b.WriteString("#    def zone lan <interfaces...> [subnet=<cidr>] [isolate=true]  # LAN interfaces (e.g. eth1, vmbr0)\n")
	b.WriteString("#\n")
	b.WriteString("# 2. Device & Group Aliases:\n")
	b.WriteString("#    def device <name> mac=<mac> [zone=<zone>]    # Bind friendly alias to a MAC address\n")
	b.WriteString("#    def group  <name> <item1>, <item2>...        # Group multiple devices together\n")
	b.WriteString("#\n")
	b.WriteString("# 3. Outbound Routing Rules:\n")
	b.WriteString("#    local              -> <target>               # Host machine outbound policy\n")
	b.WriteString("#    zone <name>        -> <target>               # Zone default outbound policy (e.g. zone lan -> hk)\n")
	b.WriteString("#    device <name>      -> <target>               # Specific device outbound (overrides zone default)\n")
	b.WriteString("#    group <name>       -> <target>               # Group outbound policy\n")
	b.WriteString("#    mac <mac>          -> <target>               # Single device rule by MAC\n")
	b.WriteString("#    interface <iface>  -> <target>               # Interface default rule\n")
	b.WriteString("#    ip <ip/cidr>       -> <target>               # Single IP or subnet rule\n")
	b.WriteString("#    * <target> can be 'direct', 'block', or an active relay alias.\n")
	b.WriteString("#\n")
	b.WriteString("# 4. Port Forwarding Rules:\n")
	b.WriteString("#    forward <wan_port> -> <target>:<port> [proto=tcp|udp]\n")
	b.WriteString("#    forward wan:<wan_port> -> <target>:<port> [proto=tcp|udp]\n")
	b.WriteString("#\n")
	b.WriteString("# 5. Apply & Verify:\n")
	b.WriteString("#    After editing, run 'xray-proxya apply' to compile and apply changes.\n")
	b.WriteString("#    Run 'xray-proxya gateway check' to inspect active runtime rules.\n")
	b.WriteString("# ==============================================================================\n\n")

	// 1. Zone Definitions
	b.WriteString("# ------------------------------------------------------------------------------\n")
	b.WriteString("# Zone Definitions\n")
	b.WriteString("# ------------------------------------------------------------------------------\n")
	hasZones := false
	if gw.WANInterface != "" {
		b.WriteString(fmt.Sprintf("def zone wan %s\n", gw.WANInterface))
		hasZones = true
	}
	lanIfaces := gw.EffectiveLANInterfaces()
	isoSet := make(map[string]bool)
	for _, iface := range gw.EffectiveIsolatedInterfaces() {
		isoSet[iface] = true
	}

	var normalLAN []string
	var isoLAN []string
	for _, iface := range lanIfaces {
		if isoSet[iface] {
			isoLAN = append(isoLAN, iface)
		} else {
			normalLAN = append(normalLAN, iface)
		}
	}

	if len(normalLAN) > 0 {
		b.WriteString(fmt.Sprintf("def zone lan %s\n", strings.Join(normalLAN, ", ")))
		hasZones = true
	}
	if len(isoLAN) > 0 {
		zoneName := "guest"
		if len(normalLAN) == 0 {
			zoneName = "lan"
		}
		b.WriteString(fmt.Sprintf("def zone %s %s isolate=true\n", zoneName, strings.Join(isoLAN, ", ")))
		hasZones = true
	}
	if !hasZones {
		b.WriteString("# (no zones defined)\n")
	}
	b.WriteString("\n")

	// 2. Global Parameters
	b.WriteString("# ------------------------------------------------------------------------------\n")
	b.WriteString("# Global Parameters\n")
	b.WriteString("# ------------------------------------------------------------------------------\n")
	hasGlobal := false
	if gw.State != "" {
		b.WriteString(fmt.Sprintf("set state %s\n", gw.State))
		hasGlobal = true
	}
	mode := strings.ToLower(strings.TrimSpace(gw.Mode))
	if mode == "" {
		mode = "tproxy"
	}
	b.WriteString(fmt.Sprintf("set mode %s\n", mode))
	hasGlobal = true
	if gw.LocalEnabled {
		b.WriteString("set local true\n")
		hasGlobal = true
	} else {
		b.WriteString("set local false\n")
		hasGlobal = true
	}
	if gw.LANEnabled {
		b.WriteString("set lan true\n")
		hasGlobal = true
	} else {
		b.WriteString("set lan false\n")
		hasGlobal = true
	}
	if gw.RelayAlias != "" {
		b.WriteString(fmt.Sprintf("set relay %s\n", gw.RelayAlias))
		hasGlobal = true
	}
	if gw.TUNEnabled {
		b.WriteString("set tun true\n")
		hasGlobal = true
	}
	if gw.NATDisabled {
		b.WriteString("set nat false\n")
		hasGlobal = true
	}
	if gw.TProxyPort > 0 && gw.TProxyPort != config.DefaultTProxyPort {
		b.WriteString(fmt.Sprintf("set tproxy_port %d\n", gw.TProxyPort))
		hasGlobal = true
	}
	if len(gw.BypassCountries) > 0 {
		b.WriteString(fmt.Sprintf("set bypass_countries %s\n", strings.Join(gw.BypassCountries, ",")))
		hasGlobal = true
	}
	if len(gw.BypassDNS) > 0 {
		b.WriteString(fmt.Sprintf("set bypass_dns %s\n", strings.Join(gw.BypassDNS, ",")))
		hasGlobal = true
	}
	if gw.DNSListen != "" {
		b.WriteString(fmt.Sprintf("set dns_listen %s\n", gw.DNSListen))
		hasGlobal = true
	}
	if gw.DNSStrategy != "" {
		b.WriteString(fmt.Sprintf("set dns_strategy %s\n", gw.DNSStrategy))
		hasGlobal = true
	}
	if len(gw.DNSServers) > 0 {
		b.WriteString(fmt.Sprintf("set dns_servers %s\n", strings.Join(gw.DNSServers, ", ")))
		hasGlobal = true
	}
	if !hasGlobal {
		b.WriteString("# (defaults active)\n")
	}
	b.WriteString("\n")

	// 3. Outbound Rules
	b.WriteString("# ------------------------------------------------------------------------------\n")
	b.WriteString("# Outbound Routing Rules\n")
	b.WriteString("# ------------------------------------------------------------------------------\n")

	// Local rule
	if gw.LocalEnabled && gw.RelayAlias != "" {
		b.WriteString(fmt.Sprintf("local -> %s\n", gw.RelayAlias))
	} else {
		b.WriteString("local -> direct\n")
	}

	// LAN rule
	if len(lanIfaces) > 0 {
		if gw.LANEnabled && gw.RelayAlias != "" {
			b.WriteString(fmt.Sprintf("zone lan -> %s\n", gw.RelayAlias))
		} else {
			b.WriteString("zone lan -> direct\n")
		}
	}
	b.WriteString("\n")

	// 4. Static DNS Records
	if len(gw.DNSRecords) > 0 {
		b.WriteString("# ------------------------------------------------------------------------------\n")
		b.WriteString("# Static DNS Records\n")
		b.WriteString("# ------------------------------------------------------------------------------\n")
		keys := make([]string, 0, len(gw.DNSRecords))
		for k := range gw.DNSRecords {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(fmt.Sprintf("dns %s -> %s\n", k, strings.Join(gw.DNSRecords[k], ", ")))
		}
		b.WriteString("\n")
	}

	// 5. Client & Interface Specific Rules
	b.WriteString("# ------------------------------------------------------------------------------\n")
	b.WriteString("# Client & Interface Specific Rules\n")
	b.WriteString("# ------------------------------------------------------------------------------\n")
	if len(gw.Rules) == 0 {
		b.WriteString("# (no client rules configured)\n")
	} else {
		for _, rule := range gw.Rules {
			target := rule.Target
			if target == "" {
				target = "direct"
			}

			if rule.MAC != "" && rule.IP != "" && rule.Interface != "" {
				b.WriteString(fmt.Sprintf("rule mac=%s ip=%s interface=%s -> %s\n", rule.MAC, rule.IP, rule.Interface, target))
			} else if rule.MAC != "" && rule.IP != "" {
				b.WriteString(fmt.Sprintf("rule mac=%s ip=%s -> %s\n", rule.MAC, rule.IP, target))
			} else if rule.MAC != "" && rule.Interface != "" {
				b.WriteString(fmt.Sprintf("mac %s -> %s interface=%s\n", rule.MAC, target, rule.Interface))
			} else if rule.MAC != "" {
				b.WriteString(fmt.Sprintf("mac %s -> %s\n", rule.MAC, target))
			} else if rule.IP != "" && rule.Interface != "" {
				b.WriteString(fmt.Sprintf("ip %s -> %s interface=%s\n", rule.IP, target, rule.Interface))
			} else if rule.IP != "" {
				b.WriteString(fmt.Sprintf("ip %s -> %s\n", rule.IP, target))
			} else if rule.Interface != "" {
				b.WriteString(fmt.Sprintf("interface %s -> %s\n", rule.Interface, target))
			}
		}
	}

	// 4. Port Forwarding Rules
	if len(gw.PortForwards) > 0 {
		b.WriteString("\n# ------------------------------------------------------------------------------\n")
		b.WriteString("# Port Forwarding Rules\n")
		b.WriteString("# ------------------------------------------------------------------------------\n")
		for _, pf := range gw.PortForwards {
			proto := pf.Proto
			if proto == "" {
				proto = "tcp,udp"
			}
			target := fmt.Sprintf("%s:%d", pf.TargetIP, pf.TargetPort)
			if strings.Contains(pf.TargetIP, ":") {
				target = fmt.Sprintf("[%s]:%d", pf.TargetIP, pf.TargetPort)
			}
			b.WriteString(fmt.Sprintf("forward %d -> %s proto=%s\n", pf.WANPort, target, proto))
		}
	}

	return b.String()
}

// GenerateFromUserConfig exports a gateway.conf formatted string from a UserConfig,
// including comments listing available relays.
func GenerateFromUserConfig(userCfg *config.UserConfig) string {
	if userCfg == nil {
		return ""
	}

	body := Generate(&userCfg.Gateway)
	if len(userCfg.CustomOutbounds) == 0 {
		return body
	}

	// Insert available outbounds list right after the quick reference header (before Zone Definitions)
	headerEnd := strings.Index(body, "# Zone Definitions")
	if headerEnd >= 0 {
		sepIdx := strings.LastIndex(body[:headerEnd], "# ---------")
		if sepIdx >= 0 {
			var b strings.Builder
			b.WriteString(body[:sepIdx])
			b.WriteString("# ------------------------------------------------------------------------------\n")
			b.WriteString("# Available Outbound Relays:\n")
			b.WriteString("# ------------------------------------------------------------------------------\n")
			for _, co := range userCfg.CustomOutbounds {
				status := "enabled"
				if !co.Enabled {
					status = "disabled"
				}
				b.WriteString(fmt.Sprintf("#   - %-16s (%s)\n", co.Alias, status))
			}
			b.WriteString("\n")
			b.WriteString(body[sepIdx:])
			return b.String()
		}
	}
	return body
}

// GenerateFromAST serializes a ConfigAST back into formatted declarative gateway.conf text.
func GenerateFromAST(ast *ConfigAST) string {
	if ast == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("# ==============================================================================\n")
	b.WriteString("# Xray-Proxya Declarative Gateway Configuration\n")
	b.WriteString("# ==============================================================================\n\n")

	if len(ast.Zones) > 0 {
		b.WriteString("# --- Zone Definitions ---\n")
		for _, z := range ast.Zones {
			b.WriteString(fmt.Sprintf("def zone %s %s", z.Name, strings.Join(z.Interfaces, ", ")))
			if len(z.Subnets) > 0 {
				b.WriteString(fmt.Sprintf(" subnet=%s", strings.Join(z.Subnets, ",")))
			}
			if z.Isolate {
				b.WriteString(" isolate=true")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(ast.Devices) > 0 {
		b.WriteString("# --- Device Definitions ---\n")
		for _, d := range ast.Devices {
			b.WriteString(fmt.Sprintf("def device %s mac=%s", d.Name, d.MAC))
			if d.Zone != "" {
				b.WriteString(fmt.Sprintf(" zone=%s", d.Zone))
			}
			if d.IP != "" {
				b.WriteString(fmt.Sprintf(" ip=%s", d.IP))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(ast.Groups) > 0 {
		b.WriteString("# --- Group Definitions ---\n")
		for _, g := range ast.Groups {
			b.WriteString(fmt.Sprintf("def group %s %s\n", g.Name, strings.Join(g.Items, ", ")))
		}
		b.WriteString("\n")
	}

	if len(ast.Sets) > 0 {
		b.WriteString("# --- Global Parameters ---\n")
		for _, s := range ast.Sets {
			b.WriteString(fmt.Sprintf("set %s %s\n", s.Key, s.Value))
		}
		b.WriteString("\n")
	}

	if len(ast.DNSRecords) > 0 {
		b.WriteString("# --- Static DNS Records ---\n")
		for _, d := range ast.DNSRecords {
			b.WriteString(fmt.Sprintf("dns %s -> %s\n", d.Domain, strings.Join(d.IPs, ", ")))
		}
		b.WriteString("\n")
	}

	if len(ast.Rules) > 0 {
		b.WriteString("# --- Routing Rules ---\n")
		for _, r := range ast.Rules {
			var subject string
			switch r.Kind {
			case SubjectRule:
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
				subject = "rule " + strings.Join(parts, " ")
			case SubjectLocal:
				subject = "local"
			case SubjectZone:
				subject = "zone " + r.SubjectValue
			case SubjectDevice:
				subject = "device " + r.SubjectValue
			case SubjectGroup:
				subject = "group " + r.SubjectValue
			case SubjectMAC:
				subject = "mac " + r.SubjectValue
			case SubjectInterface:
				subject = "interface " + r.SubjectValue
			case SubjectIP:
				subject = "ip " + r.SubjectValue
			default:
				subject = string(r.Kind)
			}

			b.WriteString(fmt.Sprintf("%s -> %s", subject, r.Target))
			for _, opt := range r.Options {
				b.WriteString(fmt.Sprintf(" %s=%s", opt.Key, opt.Value))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(ast.Forwards) > 0 {
		b.WriteString("# --- Port Forwarding Rules ---\n")
		for _, f := range ast.Forwards {
			proto := f.Proto
			if proto == "" {
				proto = "tcp,udp"
			}
			target := fmt.Sprintf("%s:%d", f.Target, f.TargetPort)
			if strings.Contains(f.Target, ":") {
				target = fmt.Sprintf("[%s]:%d", f.Target, f.TargetPort)
			}
			b.WriteString(fmt.Sprintf("forward %d -> %s proto=%s\n", f.WANPort, target, proto))
		}
	}

	return b.String()
}
