package endpoint

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

// Target represents a resolved endpoint address paired with its origin endpoint alias or address.
type Target struct {
	Alias   string
	Address string
}

func isValidHost(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if !strings.Contains(h, ".") {
		return false
	}
	if len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// ResolveTargets resolves an endpoint specification (single endpoint name, comma-separated list of
// endpoints/IPs/domains) into ordered Target objects.
func ResolveTargets(cfg *config.UserConfig, endpointSpec string, consumer string, forSubscription bool) ([]Target, error) {
	spec := strings.TrimSpace(endpointSpec)
	if spec == "" {
		spec = "default"
	}

	parts := strings.Split(spec, ",")
	var targets []Target

	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			return nil, fmt.Errorf("invalid endpoint list: contains empty item")
		}

		if cfg != nil && cfg.Endpoints != nil {
			if ep, exists := cfg.Endpoints[token]; exists {
				switch ep.Type {
				case config.EndpointTypeStatic:
					subParts := strings.Split(ep.Host, ",")
					var staticAddrs []string
					for _, sp := range subParts {
						sAddr := strings.TrimSpace(sp)
						if sAddr != "" {
							staticAddrs = append(staticAddrs, sAddr)
						}
					}
					if len(staticAddrs) == 0 {
						return nil, fmt.Errorf("endpoint '%s' (static) has no valid host configured", token)
					}
					for _, sAddr := range staticAddrs {
						targets = append(targets, Target{Alias: token, Address: sAddr})
					}
					continue

				case config.EndpointTypeAuto:
					var ip string
					if strings.EqualFold(ep.Family, "v6") {
						ip = utils.GetSmartIP(true)
					} else {
						ip = utils.GetSmartIP(false)
					}
					if ip == "" {
						return nil, fmt.Errorf("failed to detect public IP for auto endpoint '%s'", token)
					}
					targets = append(targets, Target{Alias: token, Address: ip})
					continue

				case config.EndpointTypeDynamicV6:
					addr, err := ResolveDynamicV6Address(token, ep, consumer, forSubscription)
					if err != nil {
						if ep.Host != "" {
							subParts := strings.Split(ep.Host, ",")
							for _, sp := range subParts {
								sAddr := strings.TrimSpace(sp)
								if sAddr != "" {
									targets = append(targets, Target{Alias: token, Address: sAddr})
								}
							}
							continue
						}
						return nil, fmt.Errorf("failed to resolve dynamic-v6 endpoint '%s': %w", token, err)
					}
					targets = append(targets, Target{Alias: token, Address: addr})
					continue

				default:
					if ep.Host != "" {
						targets = append(targets, Target{Alias: token, Address: strings.TrimSpace(ep.Host)})
						continue
					}
					return nil, fmt.Errorf("unsupported endpoint type '%s' for endpoint '%s'", ep.Type, token)
				}
			}
		}

		if token == "default" {
			ip := utils.GetSmartIP(false)
			if ip == "" {
				ip = "127.0.0.1"
			}
			targets = append(targets, Target{Alias: "default", Address: ip})
			continue
		}

		// Not a configured endpoint name; verify if it is a raw IP or valid domain name
		if isValidHost(token) {
			targets = append(targets, Target{Alias: token, Address: token})
			continue
		}

		if strings.Contains(token, ".") {
			return nil, fmt.Errorf("unknown endpoint or invalid address '%s'", token)
		}
		return nil, fmt.Errorf("endpoint '%s' not found", token)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("endpoint '%s' resolved to no addresses", spec)
	}
	return targets, nil
}

// Resolve resolves the target address(es) for an endpoint specification (endpoint name,
// comma-separated list of endpoints/IPs/domains) from config.
func Resolve(cfg *config.UserConfig, endpointSpec string, forSubscription ...bool) ([]string, error) {
	isSub := len(forSubscription) > 0 && forSubscription[0]
	targets, err := ResolveTargets(cfg, endpointSpec, "", isSub)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, t := range targets {
		addrs = append(addrs, t.Address)
	}
	return addrs, nil
}

// GetTargetDescription returns a human-readable summary of the target configuration for the endpoint.
func GetTargetDescription(ep config.EndpointConfig) string {
	switch ep.Type {
	case config.EndpointTypeStatic:
		if ep.Host != "" {
			return ep.Host
		}
		return "(none)"
	case config.EndpointTypeAuto:
		if strings.EqualFold(ep.Family, "v6") {
			return "auto (v6)"
		}
		return "auto (v4)"
	case config.EndpointTypeDynamicV6:
		if ep.Subnet != "" {
			return ep.Subnet
		}
		return "dynamic-v6"
	default:
		if ep.Host != "" {
			return ep.Host
		}
		return string(ep.Type)
	}
}

// FormatDisplayResolvedIP returns a concise display representation of a resolved IP.
// For dynamic-v6 endpoints with a configured subnet, it extracts the rotatable host portion
// formatted with a leading '::' (e.g. '::a7d7:2136:b3b0:11ea').
func FormatDisplayResolvedIP(ep config.EndpointConfig, ipStr string) string {
	cleanIP := strings.TrimSpace(ipStr)
	if ep.Type != config.EndpointTypeDynamicV6 || strings.TrimSpace(ep.Subnet) == "" {
		return cleanIP
	}

	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(ep.Subnet))
	if err != nil {
		return cleanIP
	}

	parsedIP := net.ParseIP(cleanIP)
	if parsedIP == nil || parsedIP.To4() != nil {
		return cleanIP
	}

	ip16 := parsedIP.To16()
	if ip16 == nil || !ipNet.Contains(ip16) {
		return cleanIP
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 128 || ones <= 0 || ones >= 128 {
		return cleanIP
	}

	hostIP := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		hostIP[i] = ip16[i] & (^ipNet.Mask[i])
	}
	res := hostIP.String()
	if !strings.HasPrefix(res, "::") {
		return "::" + res
	}
	return res
}

// FormatDisplayResolvedIPs maps FormatDisplayResolvedIP across a slice of resolved IPs.
func FormatDisplayResolvedIPs(ep config.EndpointConfig, ips []string) []string {
	if len(ips) == 0 {
		return []string{}
	}
	res := make([]string, len(ips))
	for i, ip := range ips {
		res[i] = FormatDisplayResolvedIP(ep, ip)
	}
	return res
}

// FindReferences finds references to an endpoint across guests and subscriptions.
func FindReferences(cfg *config.UserConfig, endpointName string) []string {
	if cfg == nil {
		return nil
	}
	var refs []string

	containsEndpoint := func(spec string, name string) bool {
		spec = strings.TrimSpace(spec)
		if name == "default" && (spec == "" || spec == "default") {
			return true
		}
		for _, part := range strings.Split(spec, ",") {
			if strings.TrimSpace(part) == name {
				return true
			}
		}
		return false
	}

	// Check admin sub
	if containsEndpoint(cfg.AdminSub.Endpoint, endpointName) {
		if cfg.AdminSub.Token != "" {
			refs = append(refs, "sub:admin")
		}
	}

	// Check subscription instances
	var instNames []string
	for instName := range cfg.SubscriptionInstances {
		if instName != "default" {
			instNames = append(instNames, instName)
		}
	}
	sort.Strings(instNames)
	for _, instName := range instNames {
		inst := cfg.SubscriptionInstances[instName]
		if containsEndpoint(inst.Endpoint, endpointName) {
			if inst.Token != "" {
				refs = append(refs, fmt.Sprintf("sub:%s", instName))
			}
		}
	}

	// Check guests
	for _, g := range cfg.Guests {
		if containsEndpoint(g.Endpoint, endpointName) {
			refs = append(refs, fmt.Sprintf("guest:%s", g.Alias))
		}
	}

	return refs
}
