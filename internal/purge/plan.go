package purge

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/service"
	"xray-proxya/internal/tune"
)

// BuildPlan constructs an ordered list of actions based on selected targets.
func BuildPlan(opts Options) (*Plan, error) {
	targets, err := ParseTargets(opts.Targets)
	if err != nil {
		return nil, err
	}

	homeDir := opts.HomeDir
	if homeDir == "" {
		homeDir = config.GetHomeDir()
	}
	configDir := opts.ConfigDir
	if configDir == "" {
		configDir = config.GetConfigDir()
	}
	installDir := opts.InstallDir
	if installDir == "" {
		installDir = filepath.Join(homeDir, ".local", "bin")
	}

	// 1. Privileged service check: enforce direct root shell per AGENTS.md rules
	if targets[TypeService] && os.Geteuid() == 0 {
		if err := service.DirectRootServiceError(); err != nil {
			return nil, err
		}
	}

	// 2. Active services check: disallow purging underlying configs/binaries while services run
	activeUnits, _ := service.ActiveManagedUnits()
	if len(activeUnits) > 0 && !targets[TypeService] {
		if targets[TypeConfig] || targets[TypeCore] || targets[TypeBin] || targets[TypeData] {
			return nil, fmt.Errorf("active managed services detected (%s); stop them first or include 'service' in -i/--include", strings.Join(activeUnits, ", "))
		}
	}

	plan := &Plan{
		Targets: targets,
	}

	// 1. SERVICES & NETWORK RULES
	if targets[TypeService] {
		// Stop running services (iterate directly over all active units, including template instances)
		for _, u := range activeUnits {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatService,
				Action:   ActionStop,
				Target:   u,
				Detail:   "active systemd service",
			})
		}

		// Flush network firewall / rules if root and rules/table exist
		if os.Geteuid() == 0 {
			hasNftTable := false
			if _, err := exec.LookPath("nft"); err == nil {
				if exec.Command("nft", "list", "table", "inet", "xray_proxya").Run() == nil ||
					exec.Command("nft", "list", "table", "inet", "xray-proxya").Run() == nil {
					hasNftTable = true
				}
			}
			hasPolicyRules := false
			if _, err := os.Stat(filepath.Join(configDir, "gateway.policy-rules.json")); err == nil {
				hasPolicyRules = true
			}
			hasTuneState := false
			if state, err := tune.LoadRuntimeState(); err == nil && state != nil {
				hasTuneState = true
			}

			if hasNftTable || hasPolicyRules || hasTuneState {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatService,
					Action:   ActionFlush,
					Target:   "nftables table inet xray_proxya & routing table 100",
					Detail:   "gateway transparent proxy rules & kernel tune",
				})
			}
		}

		// Disable and remove unit files
		managedUnits := []string{
			service.MainUnit,
			service.GatewayRestoreUnit,
			service.PathdUnit,
			service.SubUnit,
			service.SubTemplateUnit,
			"xray-proxya-ipv6-rotate.service",
		}
		if os.Geteuid() == 0 {
			if matches, _ := filepath.Glob(filepath.Join(service.UnitDirectory(), "he-tunnel*.service")); len(matches) > 0 {
				for _, m := range matches {
					managedUnits = append(managedUnits, filepath.Base(m))
				}
			}
		}
		unitSet := make(map[string]bool)
		for _, u := range managedUnits {
			unitSet[u] = true
		}
		for _, u := range activeUnits {
			unitSet[u] = true
		}

		for u := range unitSet {
			unitPath := service.ManagedUnitPath(u)
			if _, err := os.Stat(unitPath); err == nil {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatService,
					Action:   ActionDisable,
					Target:   u,
					Detail:   "disable systemd unit",
				})
				plan.Items = append(plan.Items, PlanItem{
					Category: CatService,
					Action:   ActionRemove,
					Target:   unitPath,
					Detail:   "systemd unit file",
				})
			}
		}

		// SELinux policy module and file contexts cleanup if root and module exists
		if os.Geteuid() == 0 {
			if _, err := exec.LookPath("semodule"); err == nil {
				if out, err := exec.Command("semodule", "-l").Output(); err == nil && strings.Contains(string(out), "xray_proxya") {
					plan.Items = append(plan.Items, PlanItem{
						Category: CatService,
						Action:   ActionCleanSELinux,
						Target:   "xray_proxya",
						Detail:   "SELinux policy module and file contexts",
					})
				}
			}
		}

		if os.Geteuid() == 0 {
			nmConf := "/etc/NetworkManager/conf.d/99-xray-proxya.conf"
			if _, err := os.Stat(nmConf); err == nil {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatService,
					Action:   ActionRemove,
					Target:   nmConf,
					Detail:   "NetworkManager unmanaged configuration",
				})
			}
		}

		plan.Items = append(plan.Items, PlanItem{
			Category: CatService,
			Action:   ActionReload,
			Target:   "systemd daemon",
			Detail:   "systemctl daemon-reload",
		})
	}

	// 2. SHELL PROFILE & COMPLETIONS
	if targets[TypeCompletion] {
		completionFiles := []string{
			filepath.Join(homeDir, ".local", "share", "bash-completion", "completions", "xray-proxya"),
			filepath.Join(homeDir, ".local", "share", "zsh", "site-functions", "_xray-proxya"),
			filepath.Join(homeDir, ".config", "fish", "completions", "xray-proxya.fish"),
		}
		for _, f := range completionFiles {
			if _, err := os.Stat(f); err == nil {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatProfile,
					Action:   ActionRemove,
					Target:   f,
					Detail:   "shell completion script",
				})
			}
		}

		profiles := candidateProfiles(homeDir)
		for _, p := range profiles {
			if fileContainsMarker(p, "# >>> xray-proxya completion >>>") {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatProfile,
					Action:   ActionCleanCompletion,
					Target:   p,
					Detail:   "remove completion loader block",
				})
			}
		}
	}

	if targets[TypeProfile] {
		profiles := candidateProfiles(homeDir)
		for _, p := range profiles {
			if fileContainsPathExport(p, installDir) {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatProfile,
					Action:   ActionCleanPath,
					Target:   p,
					Detail:   "remove PATH export line",
				})
			}
		}
	}

	// 3. CACHE DIRECTORY
	if targets[TypeCache] {
		cacheDir := filepath.Join(homeDir, ".cache", "xray-proxya")
		if _, err := os.Stat(cacheDir); err == nil {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatFile,
				Action:   ActionRemove,
				Target:   cacheDir,
				Detail:   "temporary cache directory",
			})
		}
	}

	// 4. DATA / CORE
	shareDir := filepath.Join(homeDir, ".local", "share", "xray-proxya")
	if targets[TypeData] {
		if _, err := os.Stat(shareDir); err == nil {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatFile,
				Action:   ActionRemove,
				Target:   shareDir,
				Detail:   "runtime data and assets directory",
			})
		}
	} else if targets[TypeCore] {
		coreFiles := []string{
			filepath.Join(shareDir, "bin", "xray"),
			filepath.Join(shareDir, "bin", "geoip.dat"),
			filepath.Join(shareDir, "bin", "geosite.dat"),
		}
		for _, f := range coreFiles {
			if _, err := os.Stat(f); err == nil {
				plan.Items = append(plan.Items, PlanItem{
					Category: CatFile,
					Action:   ActionRemove,
					Target:   f,
					Detail:   "Xray core / geo asset",
				})
			}
		}
	}

	// 5. CONFIG, CERTS, BACKUPS
	certsDir := filepath.Join(configDir, "certs")
	hasCerts := false
	if _, err := os.Stat(certsDir); err == nil {
		hasCerts = true
	}

	hasBackups := false
	var backupFiles []string
	if entries, err := os.ReadDir(configDir); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "xray-proxya-backup-") && strings.HasSuffix(entry.Name(), ".tar.gz") {
				hasBackups = true
				backupFiles = append(backupFiles, filepath.Join(configDir, entry.Name()))
			}
		}
	}

	// Certs
	if targets[TypeCert] {
		if hasCerts {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatFile,
				Action:   ActionRemove,
				Target:   certsDir,
				Detail:   "TLS certificates & private keys",
			})
		}
	} else if hasCerts {
		plan.Preserved = append(plan.Preserved, certsDir+" (TLS certificates)")
	}

	// Backups
	if targets[TypeBackup] {
		for _, bf := range backupFiles {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatFile,
				Action:   ActionRemove,
				Target:   bf,
				Detail:   "configuration backup archive",
			})
		}
	} else if hasBackups {
		plan.Preserved = append(plan.Preserved, configDir+" (xray-proxya-backup-*.tar.gz files)")
	}

	// Configs
	if targets[TypeConfig] {
		if entries, err := os.ReadDir(configDir); err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if name == "certs" {
					continue // Handled above by TypeCert
				}
				if strings.HasPrefix(name, "xray-proxya-backup-") && strings.HasSuffix(name, ".tar.gz") {
					continue // Handled above by TypeBackup
				}
				fullPath := filepath.Join(configDir, name)
				plan.Items = append(plan.Items, PlanItem{
					Category: CatFile,
					Action:   ActionRemove,
					Target:   fullPath,
					Detail:   "configuration file/entry",
				})
			}
		}
	}

	// 6. BINARIES
	mainBin := filepath.Join(installDir, "xray-proxya")
	pathdBin := filepath.Join(shareDir, "bin", "pathd")
	currentExec, _ := os.Executable()

	if targets[TypeBin] {
		if _, err := os.Stat(mainBin); err == nil {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatBinary,
				Action:   ActionRemove,
				Target:   mainBin,
				Detail:   "CLI binary",
			})
		}
		if _, err := os.Stat(pathdBin); err == nil && !targets[TypeData] {
			plan.Items = append(plan.Items, PlanItem{
				Category: CatBinary,
				Action:   ActionRemove,
				Target:   pathdBin,
				Detail:   "pathd companion binary",
			})
		}
		if currentExec != "" && currentExec != mainBin && currentExec != pathdBin {
			// Protection: only remove current executable if it is an actual xray-proxya binary,
			// never remove test runners (*.test) or unrelated executables.
			base := filepath.Base(currentExec)
			if (base == "xray-proxya" || base == "proxya-testing") && !strings.HasSuffix(base, ".test") {
				if _, err := os.Stat(currentExec); err == nil {
					plan.Items = append(plan.Items, PlanItem{
						Category: CatBinary,
						Action:   ActionRemove,
						Target:   currentExec,
						Detail:   "current running executable",
					})
				}
			}
		}
	} else {
		if _, err := os.Stat(mainBin); err == nil {
			plan.Preserved = append(plan.Preserved, mainBin+" (executable)")
		}
	}

	return plan, nil
}

func candidateProfiles(homeDir string) []string {
	var profiles []string
	candidates := []string{
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".zshrc"),
		filepath.Join(homeDir, ".config", "fish", "config.fish"),
	}
	seen := make(map[string]bool)
	for _, c := range candidates {
		if !seen[c] {
			seen[c] = true
			if _, err := os.Stat(c); err == nil {
				profiles = append(profiles, c)
			}
		}
	}
	return profiles
}

func fileContainsMarker(path, marker string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(content), marker)
}

func fileContainsPathExport(path, installDir string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return isPathExportLinePresent(string(content), installDir)
}

func isPathExportLinePresent(content, installDir string) bool {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if isXrayProxyaPathLine(line, installDir) {
			return true
		}
	}
	return false
}

func isXrayProxyaPathLine(line, installDir string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "export PATH=") {
		return false
	}
	val := strings.TrimPrefix(trimmed, "export PATH=")
	val = strings.Trim(val, `"'`)
	parts := strings.Split(val, ":")
	for _, part := range parts {
		if filepath.Clean(part) == filepath.Clean(installDir) {
			return true
		}
	}
	return false
}
