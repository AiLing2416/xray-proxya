package service

import (
	"fmt"
	"os"
	"strings"
	"xray-proxya/internal/config"
)

// ValidateServiceStart checks prerequisites before starting, restarting, or enabling a unit.
func ValidateServiceStart(unit string) error {
	normalized, err := NormalizeUnitName(unit)
	if err != nil {
		return err
	}

	switch normalized {
	case MainUnit:
		if os.Geteuid() != 0 {
			cfg, err := config.LoadConfig()
			if err == nil && cfg.Role == config.RoleGateway {
				return fmt.Errorf("gateway role requires a direct-root system service; user services are non-privileged")
			}
		}
		return nil

	case PathdUnit:
		if os.Geteuid() != 0 {
			return fmt.Errorf("xray-proxya-pathd requires a root system service")
		}
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active Pathd configuration: %w", err)
		}
		if cfg.Role != config.RoleServer {
			return fmt.Errorf("xray-proxya-pathd can run only on a Server")
		}
		return nil

	case SubUnit:
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active subscription configuration: %w", err)
		}
		if cfg.Role != config.RoleServer {
			return fmt.Errorf("%s can run only on a Server", unit)
		}
		entry := cfg.AdminSub
		if entry.Token == "" && cfg.SubscriptionInstances != nil {
			if def, ok := cfg.SubscriptionInstances["default"]; ok {
				entry = def
			}
		}
		port := entry.Port
		if port <= 0 {
			port = cfg.SubPort
		}
		if entry.Token == "" || port <= 0 {
			return fmt.Errorf("configure subscription first with 'sub set', then apply")
		}
		if entry.IPv6Rotation != "" && os.Geteuid() != 0 {
			return fmt.Errorf("IPv6-rotate subscriptions require a root system service")
		}
		return nil

	case RotateUnit:
		if os.Geteuid() != 0 {
			return fmt.Errorf("xray-proxya-ipv6-rotate requires a root system service")
		}
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active IPv6 rotation configuration: %w", err)
		}
		if cfg.Role != config.RoleServer {
			return fmt.Errorf("xray-proxya-ipv6-rotate can run only on a Server")
		}
		rotation := cfg.IPv6Rotation
		if rotation.Subnet == "" && cfg.IPv6Rotations != nil {
			rotation = cfg.IPv6Rotations["default"]
		}
		if rotation.Interface == "" || rotation.Subnet == "" {
			return fmt.Errorf("IPv6 rotation is not configured; use 'ipv6-rotate set', then apply")
		}
		return nil

	default:
		if strings.HasPrefix(unit, "xray-proxya-sub@") {
			return ValidateServiceStart(SubUnit)
		}
		return nil
	}
}
