package purge

import (
	"fmt"
	"strings"
)

// TargetType represents a category of resource or file to purge.
type TargetType string

const (
	TypeConfig     TargetType = "config"
	TypeCert       TargetType = "cert"
	TypeCore       TargetType = "core"
	TypeService    TargetType = "service"
	TypeBin        TargetType = "bin"
	TypeData       TargetType = "data"
	TypeCache      TargetType = "cache"
	TypeBackup     TargetType = "backup"
	TypeCompletion TargetType = "completion"
	TypeProfile    TargetType = "profile"
	TypeAll        TargetType = "all"
)

// AllTargetTypes lists all canonical target types for display and validation.
var AllTargetTypes = []TargetType{
	TypeConfig,
	TypeCert,
	TypeCore,
	TypeService,
	TypeBin,
	TypeData,
	TypeCache,
	TypeBackup,
	TypeCompletion,
	TypeProfile,
	TypeAll,
}

// TargetDescriptions provides human-readable summaries for each target type.
var TargetDescriptions = map[TargetType]string{
	TypeConfig:     "Configuration files (config.json, staging, routing, tune rules)",
	TypeCert:       "TLS certificates and private keys (certs/ directory)",
	TypeCore:       "Downloaded Xray-core binary and geo assets (geoip/geosite)",
	TypeService:    "Systemd service units (stops services, removes unit files, flushes rules)",
	TypeBin:        "Executable binaries (xray-proxya and pathd)",
	TypeData:       "Runtime data directory (~/.local/share/xray-proxya)",
	TypeCache:      "Temporary cache directory (~/.cache/xray-proxya)",
	TypeBackup:     "Configuration backup archives (.tar.gz)",
	TypeCompletion: "Shell autocompletion files and profile hooks",
	TypeProfile:    "Shell profile PATH export entries (~/.bashrc, ~/.zshrc)",
	TypeAll:        "All of the above (complete purge)",
}

// NormalizeTarget normalizes user input into a canonical TargetType.
func NormalizeTarget(raw string) (TargetType, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "config", "configs":
		return TypeConfig, nil
	case "cert", "certs", "certificate", "certificates":
		return TypeCert, nil
	case "core", "xray", "xray-core":
		return TypeCore, nil
	case "service", "services", "systemd":
		return TypeService, nil
	case "bin", "binary", "binaries":
		return TypeBin, nil
	case "data", "share":
		return TypeData, nil
	case "cache":
		return TypeCache, nil
	case "backup", "backups":
		return TypeBackup, nil
	case "completion", "completions":
		return TypeCompletion, nil
	case "profile", "profiles", "path-env", "env":
		return TypeProfile, nil
	case "all", "purge":
		return TypeAll, nil
	case "path":
		return "", fmt.Errorf("ambiguous target %q: use 'profile' for shell PATH export, or 'service'/'data' for PathLink", raw)
	default:
		return "", fmt.Errorf("unknown target type %q (valid: config, cert, core, service, bin, data, cache, backup, completion, profile, all)", raw)
	}
}

const (
	ActionStop            = "stop"
	ActionDisable         = "disable"
	ActionRemove          = "remove"
	ActionReload          = "reload"
	ActionFlush           = "flush"
	ActionCleanCompletion = "clean-completion"
	ActionCleanPath       = "clean-path"
)

// ParseTargets parses and validates a slice of raw strings (possibly comma-separated).
func ParseTargets(inputs []string) (map[TargetType]bool, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no target types specified")
	}

	targets := make(map[TargetType]bool)
	for _, input := range inputs {
		for _, part := range strings.Split(input, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			t, err := NormalizeTarget(part)
			if err != nil {
				return nil, err
			}
			if t == TypeAll {
				targets[TypeConfig] = true
				targets[TypeCert] = true
				targets[TypeCore] = true
				targets[TypeService] = true
				targets[TypeBin] = true
				targets[TypeData] = true
				targets[TypeCache] = true
				targets[TypeBackup] = true
				targets[TypeCompletion] = true
				targets[TypeProfile] = true
				targets[TypeAll] = true
			} else {
				targets[t] = true
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no target types specified")
	}
	return targets, nil
}

// ActionCategory groups plan items for clear terminal output.
type ActionCategory string

const (
	CatService ActionCategory = "Services & Network Rules"
	CatFile    ActionCategory = "Files & Directories"
	CatProfile ActionCategory = "Shell Environment"
	CatBinary  ActionCategory = "Self Binary"
)

// PlanItem describes an atomic action in the purge plan.
type PlanItem struct {
	Category ActionCategory
	Action   string // e.g. "stop", "remove", "clean", "flush"
	Target   string // path or unit name
	Detail   string // extra context
}

// Plan contains all planned actions and preserved paths.
type Plan struct {
	Targets   map[TargetType]bool
	Items     []PlanItem
	Preserved []string
}

// Options provides configuration parameters for plan building.
type Options struct {
	Targets    []string
	DryRun     bool
	Force      bool
	HomeDir    string
	ConfigDir  string
	InstallDir string
}
