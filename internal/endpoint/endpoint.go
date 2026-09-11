package endpoint

import (
	"fmt"
	"sort"
	"strings"

	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

// Resolve resolves the target address(es) for a named endpoint from config.
// If forSubscription is true and the endpoint is dynamic-v6, it slides to a new address.
func Resolve(cfg *config.UserConfig, endpointName string, forSubscription ...bool) ([]string, error) {
	if endpointName == "" {
		endpointName = "default"
	}
	if cfg == nil || cfg.Endpoints == nil {
		return nil, fmt.Errorf("endpoint '%s' not found", endpointName)
	}

	ep, exists := cfg.Endpoints[endpointName]
	if !exists {
		return nil, fmt.Errorf("endpoint '%s' not found", endpointName)
	}

	switch ep.Type {
	case config.EndpointTypeStatic:
		parts := strings.Split(ep.Host, ",")
		var addrs []string
		for _, part := range parts {
			addr := strings.TrimSpace(part)
			if addr != "" {
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("endpoint '%s' (static) has no valid host configured", endpointName)
		}
		return addrs, nil

	case config.EndpointTypeAuto:
		var ip string
		if strings.EqualFold(ep.Family, "v6") {
			ip = utils.GetSmartIP(true)
		} else {
			ip = utils.GetSmartIP(false)
		}
		if ip == "" {
			return nil, fmt.Errorf("failed to detect public IP for auto endpoint '%s'", endpointName)
		}
		return []string{ip}, nil

	case config.EndpointTypeDynamicV6:
		isSub := len(forSubscription) > 0 && forSubscription[0]
		if isSub {
			newIP, err := NextAddress(endpointName, ep)
			if err != nil {
				return nil, err
			}
			return []string{newIP}, nil
		}

		// Normal query: return latest active IP, or allocate if pool is empty
		st, _ := LoadRotationState(endpointName)
		if st != nil && len(st.ActivePool) > 0 {
			latest := st.ActivePool[len(st.ActivePool)-1].Address
			return []string{latest}, nil
		}

		// Pool is empty, allocate once
		newIP, err := NextAddress(endpointName, ep)
		if err != nil {
			if ep.Host != "" {
				parts := strings.Split(ep.Host, ",")
				var addrs []string
				for _, part := range parts {
					addr := strings.TrimSpace(part)
					if addr != "" {
						addrs = append(addrs, addr)
					}
				}
				if len(addrs) > 0 {
					return addrs, nil
				}
			}
			return nil, fmt.Errorf("dynamic-v6 endpoint '%s' has no active address: %w", endpointName, err)
		}
		return []string{newIP}, nil

	default:
		if ep.Host != "" {
			return []string{strings.TrimSpace(ep.Host)}, nil
		}
		return nil, fmt.Errorf("unsupported endpoint type '%s' for endpoint '%s'", ep.Type, endpointName)
	}
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
			return fmt.Sprintf("dynamic-v6 (%s)", ep.Subnet)
		}
		return "dynamic-v6"
	default:
		if ep.Host != "" {
			return ep.Host
		}
		return string(ep.Type)
	}
}

// FindReferences finds references to an endpoint across guests and subscriptions.
func FindReferences(cfg *config.UserConfig, endpointName string) []string {
	if cfg == nil {
		return nil
	}
	var refs []string

	// Check admin sub
	if (endpointName == "default" && (cfg.AdminSub.Endpoint == "" || cfg.AdminSub.Endpoint == "default")) ||
		(endpointName != "default" && cfg.AdminSub.Endpoint == endpointName) {
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
		if (endpointName == "default" && (inst.Endpoint == "" || inst.Endpoint == "default")) ||
			(endpointName != "default" && inst.Endpoint == endpointName) {
			if inst.Token != "" {
				refs = append(refs, fmt.Sprintf("sub:%s", instName))
			}
		}
	}

	// Check guests
	for _, g := range cfg.Guests {
		if (endpointName == "default" && (g.Endpoint == "" || g.Endpoint == "default")) ||
			(endpointName != "default" && g.Endpoint == endpointName) {
			refs = append(refs, fmt.Sprintf("guest:%s", g.Alias))
		}
	}

	return refs
}
