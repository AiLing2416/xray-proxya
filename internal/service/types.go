package service

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
)

const (
	MainUnit          = "xray-proxya.service"
	PathdUnit         = "xray-proxya-pathd.service"
	SubUnit           = "xray-proxya-sub.service"
	SubTemplateUnit   = "xray-proxya-sub@.service"
	RotateUnit        = "xray-proxya-ipv6-rotate.service"
	RootManagerBinary = "/root/.local/bin/xray-proxya"
)

// Status represents the complete state of a managed systemd unit.
type Status struct {
	UnitName    string `json:"unit_name"`
	DisplayName string `json:"display_name"` // "Core", "Pathd", "IPv6-Rotate", "Sub"
	Active      bool   `json:"active"`
	PID         int    `json:"pid"`
	State       string `json:"state"` // "Running", "Stopped", "Failed", "Not Installed"
	Enabled     bool   `json:"enabled"`
	Installed   bool   `json:"installed"`
	UnitPath    string `json:"unit_path"`
	Description string `json:"description"`
}

// Controller defines the unified interface for managing systemd service units.
type Controller interface {
	Install(cfg *config.UserConfig) error
	Uninstall() error
	Start(unit string) error
	Stop(unit string) error
	Restart(unit string) error
	Enable(unit string, now bool) error
	Disable(unit string, now bool) error
	GetStatus(unit string) (Status, error)
	ListManaged(cfg *config.UserConfig) ([]Status, error)
	IsActive(unit string) bool
	IsEnabled(unit string) bool
	IsInstalled(unit string) bool
}

// NormalizeUnitName standardizes various aliases (e.g. "xray-proxya", "core", "sub")
// into canonical systemd unit names.
func NormalizeUnitName(input string) (string, error) {
	clean := strings.TrimSpace(input)
	if clean == "" || clean == "xray-proxya" || clean == "core" || clean == MainUnit {
		return MainUnit, nil
	}
	if clean == "xray-proxya-pathd" || clean == "pathd" || clean == PathdUnit {
		return PathdUnit, nil
	}
	if clean == "xray-proxya-ipv6-rotate" || clean == "ipv6-rotate" || clean == "rotate" || clean == RotateUnit {
		return RotateUnit, nil
	}
	name := strings.TrimSuffix(clean, ".service")
	if name == "xray-proxya-sub" || name == "sub" || strings.HasPrefix(name, "xray-proxya-sub@") {
		return SubUnit, nil
	}
	return "", fmt.Errorf("unit must be xray-proxya, xray-proxya-pathd, xray-proxya-ipv6-rotate, or xray-proxya-sub")
}
