package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// DiffUserConfig compares active and staging UserConfigs and returns human-readable diff lines.
// If active is nil, all elements in staging are reported as initial additions.
func DiffUserConfig(active, staging *UserConfig) []string {
	if staging == nil {
		return nil
	}

	var lines []string

	// 1. Initial configuration if active is nil
	if active == nil {
		lines = append(lines, fmt.Sprintf("[General] Initialized as role: %s", staging.Role))
		if len(staging.Presets) > 0 {
			lines = append(lines, fmt.Sprintf("[Presets] %d preset slots configured", len(staging.Presets)))
		}
		if len(staging.CustomOutbounds) > 0 {
			lines = append(lines, fmt.Sprintf("[Relays] %d relay node(s) configured", len(staging.CustomOutbounds)))
		}
		if len(staging.Guests) > 0 {
			lines = append(lines, fmt.Sprintf("[Guests] %d guest(s) configured", len(staging.Guests)))
		}
		return lines
	}

	// 2. Role & General
	if active.Role != staging.Role {
		lines = append(lines, fmt.Sprintf("[General] Role: %s -> %s", active.Role, staging.Role))
	}
	if active.UUID != staging.UUID {
		lines = append(lines, "[General] Root UUID modified")
	}
	if active.APIInbound != staging.APIInbound {
		lines = append(lines, fmt.Sprintf("[General] API Port: %d -> %d", active.APIInbound, staging.APIInbound))
	}

	// 3. Presets
	var presetDiffs []string
	for i := 0; i < len(staging.Presets); i++ {
		stg := staging.Presets[i]
		if i >= len(active.Presets) {
			presetDiffs = append(presetDiffs, fmt.Sprintf("  + Slot %d (%s): added (port %d)", i+1, stg.Mode, stg.Port))
			continue
		}
		act := active.Presets[i]
		var slotChanges []string
		if act.Enabled != stg.Enabled {
			statusAct := "OFF"
			if act.Enabled {
				statusAct = "ON"
			}
			statusStg := "OFF"
			if stg.Enabled {
				statusStg = "ON"
			}
			slotChanges = append(slotChanges, fmt.Sprintf("Status %s -> %s", statusAct, statusStg))
		}
		if act.Port != stg.Port {
			slotChanges = append(slotChanges, fmt.Sprintf("Port %d -> %d", act.Port, stg.Port))
		}
		if act.SNI != stg.SNI {
			slotChanges = append(slotChanges, fmt.Sprintf("SNI %q -> %q", act.SNI, stg.SNI))
		}
		if act.Dest != stg.Dest {
			slotChanges = append(slotChanges, fmt.Sprintf("Dest %q -> %q", act.Dest, stg.Dest))
		}
		if act.Skin != stg.Skin {
			slotChanges = append(slotChanges, fmt.Sprintf("Skin %q -> %q", act.Skin, stg.Skin))
		}
		if len(slotChanges) > 0 {
			presetDiffs = append(presetDiffs, fmt.Sprintf("  ~ Slot %d (%s): %s", i+1, stg.Mode, strings.Join(slotChanges, ", ")))
		}
	}
	if len(presetDiffs) > 0 {
		lines = append(lines, "[Presets]")
		lines = append(lines, presetDiffs...)
	}

	// 4. Custom Outbounds (Relays)
	var relayDiffs []string
	activeRelays := make(map[string]CustomOutbound, len(active.CustomOutbounds))
	for _, co := range active.CustomOutbounds {
		activeRelays[co.Alias] = co
	}
	stagingRelays := make(map[string]CustomOutbound, len(staging.CustomOutbounds))
	for _, co := range staging.CustomOutbounds {
		stagingRelays[co.Alias] = co
	}

	for _, co := range staging.CustomOutbounds {
		act, exists := activeRelays[co.Alias]
		if !exists {
			proto := "unknown"
			if p, ok := co.Config["protocol"].(string); ok {
				proto = p
			}
			relayDiffs = append(relayDiffs, fmt.Sprintf("  + Added relay %q (protocol: %s)", co.Alias, proto))
		} else {
			var mods []string
			if act.AllowPrivateTargets != co.AllowPrivateTargets {
				mods = append(mods, fmt.Sprintf("Private Targets %v -> %v", act.AllowPrivateTargets, co.AllowPrivateTargets))
			}
			if act.InternalProxyPort != co.InternalProxyPort {
				mods = append(mods, fmt.Sprintf("Local SOCKS Port %d -> %d", act.InternalProxyPort, co.InternalProxyPort))
			}
			if act.DNSStrategy != co.DNSStrategy {
				mods = append(mods, fmt.Sprintf("DNS Strategy %q -> %q", act.DNSStrategy, co.DNSStrategy))
			}
			if !reflect.DeepEqual(act.DNSServers, co.DNSServers) {
				mods = append(mods, fmt.Sprintf("DNS Servers %v -> %v", act.DNSServers, co.DNSServers))
			}
			if !reflect.DeepEqual(act.Path, co.Path) {
				mods = append(mods, "PathLink credentials changed")
			}
			if !reflect.DeepEqual(act.Config, co.Config) {
				mods = append(mods, "Core outbound config changed")
			}
			if len(mods) > 0 {
				relayDiffs = append(relayDiffs, fmt.Sprintf("  ~ Modified relay %q: %s", co.Alias, strings.Join(mods, ", ")))
			}
		}
	}
	for _, co := range active.CustomOutbounds {
		if _, exists := stagingRelays[co.Alias]; !exists {
			relayDiffs = append(relayDiffs, fmt.Sprintf("  - Removed relay %q", co.Alias))
		}
	}
	if len(relayDiffs) > 0 {
		lines = append(lines, "[Relays]")
		lines = append(lines, relayDiffs...)
	}

	// 5. Guests
	var guestDiffs []string
	activeGuests := make(map[string]GuestConfig, len(active.Guests))
	for _, g := range active.Guests {
		activeGuests[g.Alias] = g
	}
	stagingGuests := make(map[string]GuestConfig, len(staging.Guests))
	for _, g := range staging.Guests {
		stagingGuests[g.Alias] = g
	}

	for _, g := range staging.Guests {
		act, exists := activeGuests[g.Alias]
		if !exists {
			guestDiffs = append(guestDiffs, fmt.Sprintf("  + Added guest %q (Quota: %.1f GB, ResetDay: %d)", g.Alias, g.QuotaGB, g.ResetDay))
		} else {
			var mods []string
			if act.QuotaGB != g.QuotaGB {
				mods = append(mods, fmt.Sprintf("Quota %.1f GB -> %.1f GB", act.QuotaGB, g.QuotaGB))
			}
			if act.ResetDay != g.ResetDay {
				mods = append(mods, fmt.Sprintf("ResetDay %d -> %d", act.ResetDay, g.ResetDay))
			}
			if act.OutboundLink != g.OutboundLink {
				mods = append(mods, fmt.Sprintf("Relay %q -> %q", act.OutboundLink, g.OutboundLink))
			}
			if act.Endpoint != g.Endpoint {
				mods = append(mods, fmt.Sprintf("Endpoint %q -> %q", act.Endpoint, g.Endpoint))
			}
			if act.Enabled != g.Enabled {
				statusAct := "Enabled"
				if !act.Enabled {
					statusAct = "Disabled"
				}
				statusG := "Enabled"
				if !g.Enabled {
					statusG = "Disabled"
				}
				mods = append(mods, fmt.Sprintf("Status %s -> %s", statusAct, statusG))
			}
			if len(mods) > 0 {
				guestDiffs = append(guestDiffs, fmt.Sprintf("  ~ Modified guest %q: %s", g.Alias, strings.Join(mods, ", ")))
			}
		}
	}
	for _, g := range active.Guests {
		if _, exists := stagingGuests[g.Alias]; !exists {
			guestDiffs = append(guestDiffs, fmt.Sprintf("  - Removed guest %q", g.Alias))
		}
	}
	if len(guestDiffs) > 0 {
		lines = append(lines, "[Guests]")
		lines = append(lines, guestDiffs...)
	}

	// 6. Gateway
	var gwDiffs []string
	if active.Gateway.State != staging.Gateway.State {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ State: %s -> %s", active.Gateway.State, staging.Gateway.State))
	}
	if active.Gateway.Mode != staging.Gateway.Mode {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Mode: %s -> %s", active.Gateway.Mode, staging.Gateway.Mode))
	}
	if active.Gateway.EffectiveTUNEnabled() != staging.Gateway.EffectiveTUNEnabled() {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ TUN Adapter: %v -> %v", active.Gateway.EffectiveTUNEnabled(), staging.Gateway.EffectiveTUNEnabled()))
	}
	if active.Gateway.RelayAlias != staging.Gateway.RelayAlias {
		actR := active.Gateway.RelayAlias
		if actR == "" {
			actR = "direct"
		}
		stgR := staging.Gateway.RelayAlias
		if stgR == "" {
			stgR = "direct"
		}
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Relay: %s -> %s", actR, stgR))
	}
	if active.Gateway.LocalEnabled != staging.Gateway.LocalEnabled {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Local Proxy: %v -> %v", active.Gateway.LocalEnabled, staging.Gateway.LocalEnabled))
	}
	if active.Gateway.LANEnabled != staging.Gateway.LANEnabled {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ LAN Proxy: %v -> %v", active.Gateway.LANEnabled, staging.Gateway.LANEnabled))
	}
	if !reflect.DeepEqual(active.Gateway.EffectiveLANInterfaces(), staging.Gateway.EffectiveLANInterfaces()) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ LAN Interfaces: %v -> %v", active.Gateway.EffectiveLANInterfaces(), staging.Gateway.EffectiveLANInterfaces()))
	} else if active.Gateway.LANInterface != staging.Gateway.LANInterface {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ LAN Interface: %q -> %q", active.Gateway.LANInterface, staging.Gateway.LANInterface))
	}
	if !reflect.DeepEqual(active.Gateway.EffectiveIsolatedInterfaces(), staging.Gateway.EffectiveIsolatedInterfaces()) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Isolated Interfaces: %v -> %v", active.Gateway.EffectiveIsolatedInterfaces(), staging.Gateway.EffectiveIsolatedInterfaces()))
	}
	if active.Gateway.WANInterface != staging.Gateway.WANInterface {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ WAN Interface: %q -> %q", active.Gateway.WANInterface, staging.Gateway.WANInterface))
	}
	if active.Gateway.NATDisabled != staging.Gateway.NATDisabled {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ NAT Masquerade: %v -> %v", !active.Gateway.NATDisabled, !staging.Gateway.NATDisabled))
	}
	if !reflect.DeepEqual(active.Gateway.Rules, staging.Gateway.Rules) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Gateway Rules: %d rule(s) -> %d rule(s)", len(active.Gateway.Rules), len(staging.Gateway.Rules)))
		activeUsed := make([]bool, len(active.Gateway.Rules))
		var ruleDiffs []string

		for _, stg := range staging.Gateway.Rules {
			stgKey := gatewayRuleSelectorKey(stg)
			matchedIdx := -1
			for i, act := range active.Gateway.Rules {
				if !activeUsed[i] && gatewayRuleSelectorKey(act) == stgKey && act.Target == stg.Target {
					matchedIdx = i
					break
				}
			}
			if matchedIdx == -1 {
				for i, act := range active.Gateway.Rules {
					if !activeUsed[i] && gatewayRuleSelectorKey(act) == stgKey {
						matchedIdx = i
						break
					}
				}
			}

			if matchedIdx != -1 {
				activeUsed[matchedIdx] = true
				act := active.Gateway.Rules[matchedIdx]
				actTarget := act.Target
				if actTarget == "" {
					actTarget = "direct"
				}
				stgTarget := stg.Target
				if stgTarget == "" {
					stgTarget = "direct"
				}
				if actTarget != stgTarget {
					ruleDiffs = append(ruleDiffs, fmt.Sprintf("    ~ Rule: %s (target: %s -> %s)", formatRuleSelector(stg), actTarget, stgTarget))
				}
			} else {
				ruleDiffs = append(ruleDiffs, fmt.Sprintf("    + Rule: %s", formatGatewayRuleDesc(stg)))
			}
		}

		for i, act := range active.Gateway.Rules {
			if !activeUsed[i] {
				ruleDiffs = append(ruleDiffs, fmt.Sprintf("    - Rule: %s", formatGatewayRuleDesc(act)))
			}
		}

		if len(ruleDiffs) == 0 && len(active.Gateway.Rules) > 0 {
			ruleDiffs = append(ruleDiffs, "    ~ Rule order changed")
		}
		gwDiffs = append(gwDiffs, ruleDiffs...)
	}
	if !reflect.DeepEqual(active.Gateway.PortForwards, staging.Gateway.PortForwards) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Port Forwarding: %d rule(s) -> %d rule(s)", len(active.Gateway.PortForwards), len(staging.Gateway.PortForwards)))
		activeUsed := make([]bool, len(active.Gateway.PortForwards))
		var pfDiffs []string

		for _, stg := range staging.Gateway.PortForwards {
			stgKey := portForwardSelectorKey(stg)
			stgTarget := formatPortForwardTarget(stg)
			matchedIdx := -1
			for i, act := range active.Gateway.PortForwards {
				if !activeUsed[i] && portForwardSelectorKey(act) == stgKey && formatPortForwardTarget(act) == stgTarget {
					matchedIdx = i
					break
				}
			}
			if matchedIdx == -1 {
				for i, act := range active.Gateway.PortForwards {
					if !activeUsed[i] && portForwardSelectorKey(act) == stgKey {
						matchedIdx = i
						break
					}
				}
			}

			if matchedIdx != -1 {
				activeUsed[matchedIdx] = true
				act := active.Gateway.PortForwards[matchedIdx]
				actTarget := formatPortForwardTarget(act)
				if actTarget != stgTarget {
					proto, err := NormalizePortForwardProto(stg.Proto)
					if err != nil || proto == "" {
						proto = stg.Proto
						if proto == "" {
							proto = "tcp,udp"
						}
					}
					pfDiffs = append(pfDiffs, fmt.Sprintf("    ~ Forward: wan:%d (proto: %s): target %s -> %s", stg.WANPort, proto, actTarget, stgTarget))
				}
			} else {
				pfDiffs = append(pfDiffs, fmt.Sprintf("    + Forward: %s", formatPortForwardDesc(stg)))
			}
		}

		for i, act := range active.Gateway.PortForwards {
			if !activeUsed[i] {
				pfDiffs = append(pfDiffs, fmt.Sprintf("    - Forward: %s", formatPortForwardDesc(act)))
			}
		}

		if len(pfDiffs) == 0 && len(active.Gateway.PortForwards) > 0 {
			pfDiffs = append(pfDiffs, "    ~ Forward rule order changed")
		}
		gwDiffs = append(gwDiffs, pfDiffs...)
	}
	if !reflect.DeepEqual(active.Gateway.BypassCountries, staging.Gateway.BypassCountries) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Bypass Countries: %v -> %v", active.Gateway.BypassCountries, staging.Gateway.BypassCountries))
	}
	if !reflect.DeepEqual(active.Gateway.BypassDNS, staging.Gateway.BypassDNS) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ Bypass DNS: %v -> %v", active.Gateway.BypassDNS, staging.Gateway.BypassDNS))
	}
	if active.Gateway.DNSListen != staging.Gateway.DNSListen {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ DNS Listen: %q -> %q", active.Gateway.DNSListen, staging.Gateway.DNSListen))
	}
	if active.Gateway.DNSStrategy != staging.Gateway.DNSStrategy {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ DNS Strategy: %q -> %q", active.Gateway.DNSStrategy, staging.Gateway.DNSStrategy))
	}
	if !reflect.DeepEqual(active.Gateway.DNSServers, staging.Gateway.DNSServers) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ DNS Servers: %v -> %v", active.Gateway.DNSServers, staging.Gateway.DNSServers))
	}
	if !reflect.DeepEqual(active.Gateway.DNSRecords, staging.Gateway.DNSRecords) {
		gwDiffs = append(gwDiffs, fmt.Sprintf("  ~ DNS Records: %v -> %v", active.Gateway.DNSRecords, staging.Gateway.DNSRecords))
	}
	if len(gwDiffs) > 0 {
		lines = append(lines, "[Gateway]")
		lines = append(lines, gwDiffs...)
	}

	// 7. Pathd (Server)
	if !reflect.DeepEqual(active.Path, staging.Path) {
		var pathDiffs []string
		if active.Path.Listen != staging.Path.Listen {
			pathDiffs = append(pathDiffs, fmt.Sprintf("  ~ Listen: %s -> %s", active.Path.Listen, staging.Path.Listen))
		}
		if active.Path.IdleSeconds != staging.Path.IdleSeconds {
			pathDiffs = append(pathDiffs, fmt.Sprintf("  ~ Idle Seconds: %d -> %d", active.Path.IdleSeconds, staging.Path.IdleSeconds))
		}
		if active.Path.Token != staging.Path.Token {
			pathDiffs = append(pathDiffs, "  ~ Shared token updated")
		}
		if len(pathDiffs) > 0 {
			lines = append(lines, "[Pathd]")
			lines = append(lines, pathDiffs...)
		}
	}

	// 8. Endpoints
	var epDiffs []string
	for name, stgEp := range staging.Endpoints {
		actEp, exists := active.Endpoints[name]
		if !exists {
			epDiffs = append(epDiffs, fmt.Sprintf("  + Added endpoint %q (%s)", name, stgEp.Type))
		} else if !reflect.DeepEqual(actEp, stgEp) {
			epDiffs = append(epDiffs, fmt.Sprintf("  ~ Modified endpoint %q (%s -> %s)", name, actEp.Type, stgEp.Type))
		}
	}
	for name := range active.Endpoints {
		if _, exists := staging.Endpoints[name]; !exists {
			epDiffs = append(epDiffs, fmt.Sprintf("  - Removed endpoint %q", name))
		}
	}
	if len(epDiffs) > 0 {
		sort.Strings(epDiffs)
		lines = append(lines, "[Endpoints]")
		lines = append(lines, epDiffs...)
	}

	return lines
}

func formatRuleSelector(r GatewayRule) string {
	var parts []string
	if r.MAC != "" {
		parts = append(parts, "mac "+r.MAC)
	}
	if r.IP != "" {
		parts = append(parts, "ip "+r.IP)
	}
	if r.Interface != "" {
		parts = append(parts, "interface "+r.Interface)
	}
	if len(parts) == 0 {
		return "(all)"
	}
	return strings.Join(parts, " ")
}

func formatGatewayRuleDesc(r GatewayRule) string {
	target := r.Target
	if target == "" {
		target = "direct"
	}
	return fmt.Sprintf("%s -> %s", formatRuleSelector(r), target)
}

func gatewayRuleSelectorKey(r GatewayRule) string {
	mac := strings.ToLower(strings.TrimSpace(r.MAC))
	if norm, err := NormalizeMAC(mac); err == nil {
		mac = norm
	}
	ip := strings.ToLower(strings.TrimSpace(r.IP))
	if norm, err := NormalizeIPOrCIDR(ip); err == nil {
		ip = norm
	}
	iface := strings.TrimSpace(r.Interface)
	return fmt.Sprintf("mac=%s|ip=%s|iface=%s", mac, ip, iface)
}

func formatPortForwardTarget(pf PortForwardRule) string {
	ip := strings.Trim(strings.TrimSpace(pf.TargetIP), "[]")
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, pf.TargetPort)
	}
	return fmt.Sprintf("%s:%d", ip, pf.TargetPort)
}

func formatPortForwardDesc(pf PortForwardRule) string {
	proto, err := NormalizePortForwardProto(pf.Proto)
	if err != nil || proto == "" {
		proto = pf.Proto
		if proto == "" {
			proto = "tcp,udp"
		}
	}
	return fmt.Sprintf("wan:%d -> %s (proto: %s)", pf.WANPort, formatPortForwardTarget(pf), proto)
}

func portForwardSelectorKey(pf PortForwardRule) string {
	proto, err := NormalizePortForwardProto(pf.Proto)
	if err != nil || proto == "" {
		proto = strings.ToLower(strings.TrimSpace(pf.Proto))
		if proto == "" {
			proto = "tcp,udp"
		}
	}
	return fmt.Sprintf("wan=%d|proto=%s", pf.WANPort, proto)
}

