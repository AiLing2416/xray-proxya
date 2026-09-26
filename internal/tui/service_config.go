package tui

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"

	"github.com/charmbracelet/lipgloss"
)

// ServicePropType classifies properties into text input, selection choice, or boolean toggle.
type ServicePropType int

const (
	PropInput ServicePropType = iota
	PropChoice
	PropBool
)

// ServiceProperty defines a single configurable field of a managed service.
type ServiceProperty struct {
	Key     string
	Label   string
	Value   string
	Type    ServicePropType
	Choices []string
	BoolVal bool
}

// extractSubInstance retrieves the instance name from a systemd unit name like "xray-proxya-sub@default.service".
func extractSubInstance(unitName string) string {
	s := strings.TrimSuffix(unitName, ".service")
	inst := strings.TrimPrefix(s, "xray-proxya-sub@")
	if inst == "xray-proxya-sub" || inst == "" {
		return "default"
	}
	return inst
}

// isConfigurableService reports whether the service exposes configurable parameters in the SERVICE tab.
func isConfigurableService(item ManagedServiceItem) bool {
	if item.DisplayName == "Core" {
		return false
	}
	if item.DisplayName == "Pathd" || item.DisplayName == "Sub" || strings.HasPrefix(item.DisplayName, "Sub@") {
		return true
	}
	return false
}

var currentPathRelay string

func getSelectedPathRelay(cfg *config.UserConfig) string {
	if cfg == nil || len(cfg.CustomOutbounds) == 0 {
		return ""
	}
	if currentPathRelay != "" {
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == currentPathRelay {
				return currentPathRelay
			}
		}
	}
	if cfg.Gateway.RelayAlias != "" {
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == cfg.Gateway.RelayAlias {
				currentPathRelay = co.Alias
				return currentPathRelay
			}
		}
	}
	currentPathRelay = cfg.CustomOutbounds[0].Alias
	return currentPathRelay
}

func getGatewayRelayPathConfig(cfg *config.UserConfig, relay string) config.PathConfig {
	if cfg != nil {
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == relay {
				if co.Path != nil {
					p := *co.Path
					if p.Listen == "" {
						p.Listen = pathd.DefaultListenAddress
					}
					if p.IdleSeconds <= 0 {
						p.IdleSeconds = 20
					}
					return p
				}
				break
			}
		}
	}
	return config.PathConfig{Listen: pathd.DefaultListenAddress, IdleSeconds: 20}
}

func setGatewayRelayPathConfig(cfg *config.UserConfig, relay string, p config.PathConfig) error {
	if cfg == nil {
		return nil
	}
	if relay == "" || relay == "(none)" {
		return fmt.Errorf("no relay selected; add a relay first")
	}
	for i := range cfg.CustomOutbounds {
		if cfg.CustomOutbounds[i].Alias == relay {
			if p.Token == "" {
				cfg.CustomOutbounds[i].Path = nil
				return nil
			}
			if p.Listen == "" {
				p.Listen = pathd.DefaultListenAddress
			}
			if p.IdleSeconds <= 0 {
				p.IdleSeconds = 20
			}
			endpoint := p
			cfg.CustomOutbounds[i].Path = &endpoint
			return nil
		}
	}
	return fmt.Errorf("relay %q not found", relay)
}

func getPathdConfig(cfg *config.UserConfig) config.PathConfig {
	if cfg == nil {
		return config.PathConfig{Listen: pathd.DefaultListenAddress, IdleSeconds: 20}
	}
	p := cfg.Path
	if p.Listen == "" {
		p.Listen = pathd.DefaultListenAddress
	}
	if p.IdleSeconds <= 0 {
		p.IdleSeconds = 20
	}
	return p
}

func setPathdConfig(cfg *config.UserConfig, p config.PathConfig) {
	if cfg != nil {
		cfg.Path = p
	}
}

func getSubConfig(cfg *config.UserConfig, instance string) config.AdminSubConfig {
	if cfg == nil {
		return config.AdminSubConfig{Listen: "127.0.0.1", Port: 8443, TargetType: "direct"}
	}
	if cfg.SubscriptionInstances != nil {
		if sub, ok := cfg.SubscriptionInstances[instance]; ok {
			if sub.Listen == "" {
				sub.Listen = "127.0.0.1"
			}
			if sub.TargetType == "" {
				sub.TargetType = "direct"
			}
			return sub
		}
	}
	if instance == "default" {
		sub := cfg.AdminSub
		if sub.Port <= 0 && cfg.SubPort > 0 {
			sub.Port = cfg.SubPort
		}
		if sub.Listen == "" {
			sub.Listen = "127.0.0.1"
		}
		if sub.TargetType == "" {
			sub.TargetType = "direct"
		}
		return sub
	}
	return config.AdminSubConfig{Listen: "127.0.0.1", Port: 8443, TargetType: "direct"}
}

func setSubConfig(cfg *config.UserConfig, instance string, sub config.AdminSubConfig) {
	if cfg == nil {
		return
	}
	if cfg.SubscriptionInstances == nil {
		cfg.SubscriptionInstances = make(map[string]config.AdminSubConfig)
	}
	cfg.SubscriptionInstances[instance] = sub
	if instance == "default" {
		cfg.AdminSub = sub
		cfg.SubPort = sub.Port
	}
}

// loadServiceProperties builds the list of editable properties for a configurable service.
func loadServiceProperties(cfg *config.UserConfig, item ManagedServiceItem) []ServiceProperty {
	var props []ServiceProperty

	switch {
	case item.DisplayName == "Pathd":
		if cfg != nil && cfg.Role == config.RoleGateway {
			var relayChoices []string
			for _, co := range cfg.CustomOutbounds {
				relayChoices = append(relayChoices, co.Alias)
			}
			if len(relayChoices) == 0 {
				relayChoices = []string{"(none)"}
			}
			selectedRelay := getSelectedPathRelay(cfg)
			if selectedRelay == "" {
				selectedRelay = "(none)"
			}

			props = append(props, ServiceProperty{
				Key:     "Relay",
				Label:   "Target Relay",
				Value:   selectedRelay,
				Type:    PropChoice,
				Choices: relayChoices,
			})

			p := getGatewayRelayPathConfig(cfg, selectedRelay)
			props = append(props, ServiceProperty{
				Key:   "Token",
				Label: "Auth Token",
				Value: p.Token,
				Type:  PropInput,
			})
			props = append(props, ServiceProperty{
				Key:   "Listen",
				Label: "Listen Address",
				Value: p.Listen,
				Type:  PropInput,
			})
			props = append(props, ServiceProperty{
				Key:   "Idle",
				Label: "Idle Timeout (s)",
				Value: strconv.Itoa(p.IdleSeconds),
				Type:  PropInput,
			})
			return props
		}

		p := getPathdConfig(cfg)
		props = append(props, ServiceProperty{
			Key:   "Listen",
			Label: "Listen Address",
			Value: p.Listen,
			Type:  PropInput,
		})
		props = append(props, ServiceProperty{
			Key:   "Token",
			Label: "Auth Token",
			Value: p.Token,
			Type:  PropInput,
		})
		props = append(props, ServiceProperty{
			Key:   "Idle",
			Label: "Idle Timeout (s)",
			Value: strconv.Itoa(p.IdleSeconds),
			Type:  PropInput,
		})

	case item.DisplayName == "Sub" || strings.HasPrefix(item.DisplayName, "Sub@"):
		inst := extractSubInstance(item.UnitName)
		sub := getSubConfig(cfg, inst)

		portStr := ""
		if sub.Port > 0 {
			portStr = strconv.Itoa(sub.Port)
		}
		props = append(props, ServiceProperty{
			Key:   "Port",
			Label: "Port",
			Value: portStr,
			Type:  PropInput,
		})
		props = append(props, ServiceProperty{
			Key:   "Listen",
			Label: "Listen Address",
			Value: sub.Listen,
			Type:  PropInput,
		})
		gateURL := sub.AddressSub
		if gateURL == "" && cfg != nil {
			gateURL = cfg.GateURL
		}
		props = append(props, ServiceProperty{
			Key:   "GateURL",
			Label: "Gate URL",
			Value: gateURL,
			Type:  PropInput,
		})
		ttVal := sub.TargetType
		if ttVal == "outbound" {
			ttVal = "relay"
		}
		props = append(props, ServiceProperty{
			Key:     "TargetType",
			Label:   "Target Type",
			Value:   ttVal,
			Type:    PropChoice,
			Choices: []string{"direct", "relay", "guest"},
		})

		// Target choice depends on TargetType
		var targetChoices []string
		targetVal := sub.TargetAlias
		if ttVal == "relay" || sub.TargetType == "outbound" {
			if cfg != nil {
				for _, co := range cfg.CustomOutbounds {
					targetChoices = append(targetChoices, co.Alias)
				}
			}
			if len(targetChoices) == 0 {
				targetChoices = []string{"(none)"}
			}
		} else if ttVal == "guest" {
			if cfg != nil {
				for _, g := range cfg.Guests {
					targetChoices = append(targetChoices, g.Alias)
				}
			}
			if len(targetChoices) == 0 {
				targetChoices = []string{"(none)"}
			}
		} else {
			targetChoices = []string{"-"}
			targetVal = "-"
		}
		props = append(props, ServiceProperty{
			Key:     "Target",
			Label:   "Target Node",
			Value:   targetVal,
			Type:    PropChoice,
			Choices: targetChoices,
		})

		var epChoices []string
		if cfg != nil {
			for name := range cfg.Endpoints {
				epChoices = append(epChoices, name)
			}
		}
		sort.Strings(epChoices)
		if len(epChoices) == 0 {
			epChoices = []string{"default"}
		}
		epVal := sub.Endpoint
		if epVal == "" {
			epVal = "default"
		}
		props = append(props, ServiceProperty{
			Key:     "Endpoint",
			Label:   "Endpoint",
			Value:   epVal,
			Type:    PropChoice,
			Choices: epChoices,
		})
		props = append(props, ServiceProperty{
			Key:   "Token",
			Label: "Access Token",
			Value: sub.Token,
			Type:  PropInput,
		})
	}

	return props
}

// validateAndApplyServiceProp validates the given value for a property and persists it into staging config.
func validateAndApplyServiceProp(cfg *config.UserConfig, item ManagedServiceItem, prop ServiceProperty, newVal string) error {
	newVal = strings.TrimSpace(newVal)

	switch {
	case item.DisplayName == "Pathd":
		if cfg != nil && cfg.Role == config.RoleGateway {
			selectedRelay := getSelectedPathRelay(cfg)
			switch prop.Key {
			case "Relay":
				if newVal != "" && newVal != "(none)" {
					currentPathRelay = newVal
				}
				return nil
			case "Token":
				if selectedRelay == "" || selectedRelay == "(none)" {
					return fmt.Errorf("no relay available to configure; add a relay in RELAYS tab first")
				}
				if newVal == "-" || newVal == "(none)" {
					return setGatewayRelayPathConfig(cfg, selectedRelay, config.PathConfig{})
				}
				if newVal == "" {
					return fmt.Errorf("token cannot be empty")
				}
				p := getGatewayRelayPathConfig(cfg, selectedRelay)
				p.Token = newVal
				return setGatewayRelayPathConfig(cfg, selectedRelay, p)
			case "Listen":
				if selectedRelay == "" || selectedRelay == "(none)" {
					return fmt.Errorf("no relay available to configure")
				}
				if err := pathd.ValidateListenAddress(newVal); err != nil {
					return err
				}
				p := getGatewayRelayPathConfig(cfg, selectedRelay)
				if p.Token == "" {
					return fmt.Errorf("configure Auth Token first")
				}
				p.Listen = newVal
				return setGatewayRelayPathConfig(cfg, selectedRelay, p)
			case "Idle":
				if selectedRelay == "" || selectedRelay == "(none)" {
					return fmt.Errorf("no relay available to configure")
				}
				v, err := strconv.Atoi(newVal)
				if err != nil || v <= 0 {
					return fmt.Errorf("idle timeout must be positive seconds")
				}
				p := getGatewayRelayPathConfig(cfg, selectedRelay)
				if p.Token == "" {
					return fmt.Errorf("configure Auth Token first")
				}
				p.IdleSeconds = v
				return setGatewayRelayPathConfig(cfg, selectedRelay, p)
			}
			return nil
		}

		p := getPathdConfig(cfg)
		switch prop.Key {
		case "Listen":
			if err := pathd.ValidateListenAddress(newVal); err != nil {
				return err
			}
			p.Listen = newVal
		case "Token":
			if newVal == "-" || newVal == "(none)" {
				setPathdConfig(cfg, config.PathConfig{})
				return nil
			}
			if newVal == "" {
				return fmt.Errorf("token cannot be empty")
			}
			p.Token = newVal
		case "Idle":
			v, err := strconv.Atoi(newVal)
			if err != nil || v <= 0 {
				return fmt.Errorf("idle timeout must be positive seconds")
			}
			p.IdleSeconds = v
		}
		setPathdConfig(cfg, p)

	case item.DisplayName == "Sub" || strings.HasPrefix(item.DisplayName, "Sub@"):
		inst := extractSubInstance(item.UnitName)
		sub := getSubConfig(cfg, inst)
		switch prop.Key {
		case "Port":
			p, err := strconv.Atoi(newVal)
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("port must be 1-65535")
			}
			sub.Port = p
		case "Listen":
			if newVal == "" {
				return fmt.Errorf("listen address cannot be empty")
			}
			sub.Listen = newVal
		case "GateURL":
			sub.AddressSub = newVal
			if cfg != nil {
				cfg.AddressSub = newVal
				cfg.GateURL = newVal
			}
		case "TargetType":
			sub.TargetType = newVal
			if sub.TargetType == "direct" {
				sub.TargetAlias = ""
			}
		case "Target":
			if newVal == "-" || newVal == "(none)" {
				sub.TargetAlias = ""
			} else {
				sub.TargetAlias = newVal
			}
		case "Endpoint":
			sub.Endpoint = newVal
		case "Token":
			if newVal == "" {
				return fmt.Errorf("token cannot be empty")
			}
			sub.Token = newVal
		}
		setSubConfig(cfg, inst, sub)
	}

	return nil
}

// serviceHasStagedChanges reports whether the specified service item has unapplied changes in staging.
func serviceHasStagedChanges(active, staging *config.UserConfig, item ManagedServiceItem) bool {
	if staging == nil {
		return false
	}
	switch {
	case item.DisplayName == "Pathd":
		if staging.Role == config.RoleGateway {
			if active == nil {
				for _, co := range staging.CustomOutbounds {
					if co.Path != nil && co.Path.Token != "" {
						return true
					}
				}
				return false
			}
			activeByAlias := make(map[string]*config.PathConfig, len(active.CustomOutbounds))
			for i := range active.CustomOutbounds {
				activeByAlias[active.CustomOutbounds[i].Alias] = active.CustomOutbounds[i].Path
			}
			for _, co := range staging.CustomOutbounds {
				activePath, had := activeByAlias[co.Alias]
				if !had && co.Path != nil {
					return true
				}
				if !reflect.DeepEqual(activePath, co.Path) {
					return true
				}
			}
			if len(active.CustomOutbounds) != len(staging.CustomOutbounds) {
				stagingByAlias := make(map[string]*config.PathConfig, len(staging.CustomOutbounds))
				for i := range staging.CustomOutbounds {
					stagingByAlias[staging.CustomOutbounds[i].Alias] = staging.CustomOutbounds[i].Path
				}
				for _, aco := range active.CustomOutbounds {
					if _, exists := stagingByAlias[aco.Alias]; !exists && aco.Path != nil {
						return true
					}
				}
			}
			return false
		}

		pStaging := getPathdConfig(staging)
		if active == nil {
			return pStaging.Token != ""
		}
		pActive := getPathdConfig(active)
		return pStaging.Listen != pActive.Listen || pStaging.Token != pActive.Token || pStaging.IdleSeconds != pActive.IdleSeconds

	case item.DisplayName == "Sub" || strings.HasPrefix(item.DisplayName, "Sub@"):
		inst := extractSubInstance(item.UnitName)
		sStaging := getSubConfig(staging, inst)
		if active == nil {
			return sStaging.Port > 0 || sStaging.Token != ""
		}
		sActive := getSubConfig(active, inst)
		return sStaging.Port != sActive.Port ||
			sStaging.Listen != sActive.Listen ||
			sStaging.AddressSub != sActive.AddressSub ||
			sStaging.TargetType != sActive.TargetType ||
			sStaging.TargetAlias != sActive.TargetAlias ||
			sStaging.Endpoint != sActive.Endpoint ||
			sStaging.Token != sActive.Token
	}

	return false
}

// hasAnyServiceStagedChanges checks if any service in the list has pending staging changes.
func hasAnyServiceStagedChanges(active, staging *config.UserConfig, services []ManagedServiceItem) bool {
	for _, item := range services {
		if serviceHasStagedChanges(active, staging, item) {
			return true
		}
	}
	return false
}

// RenderServicePropertyList renders the property list for the in-bar tree view.
func RenderServicePropertyList(props []ServiceProperty, selectedIdx int, width int) []string {
	lines := make([]string, 0, len(props))
	for i, p := range props {
		valStr := p.Value
		if p.Type == PropBool {
			if p.BoolVal {
				valStr = "On"
			} else {
				valStr = "Off"
			}
		}
		if valStr == "" {
			valStr = "(not set)"
		}

		line := fmt.Sprintf("%-20s %s", p.Label+":", valStr)
		if i == selectedIdx {
			line = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("> " + line)
		} else {
			line = "  " + line
		}
		lines = append(lines, line)
	}
	return lines
}

func boolToString(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

// RenderVerticalChoiceList renders a vertical list of choices with cursor indicator and windowed viewport.
func RenderVerticalChoiceList(choices []string, selectedIdx int, maxVisible int) []string {
	if len(choices) == 0 {
		return nil
	}
	if maxVisible <= 0 || maxVisible >= len(choices) {
		lines := make([]string, 0, len(choices))
		for i, c := range choices {
			if i == selectedIdx {
				lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("> "+c))
			} else {
				lines = append(lines, "  "+c)
			}
		}
		return lines
	}

	// Calculate scrolling window
	start := selectedIdx - maxVisible/2
	if start < 0 {
		start = 0
	}
	end := start + maxVisible
	if end > len(choices) {
		end = len(choices)
		start = end - maxVisible
		if start < 0 {
			start = 0
		}
	}

	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		c := choices[i]
		if i == selectedIdx {
			lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("> "+c))
		} else {
			lines = append(lines, "  "+c)
		}
	}
	return lines
}
