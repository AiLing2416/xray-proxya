package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	presetOff         bool
	presetOn          bool
	presetPort        int
	presetRegen       bool
	presetSNIAWS      bool
	presetSNIGCP      bool
	presetSNIOracle   bool
	presetSNIVendor   string
	presetSNIManual   string
	presetSNIForce    bool
	presetSNICheck    bool
	presetSNI         string
	presetDest        string
	presetMinVer      string
	presetSkin        string
	presetSkinDomain  string
)

var promptConfirmFunc = func(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

func supportsReality(m config.PresetMode) bool {
	return m == config.ModeVLESSVision || m == config.ModeVLESSReality
}

func supportsSkin(m config.PresetMode) bool {
	return m == config.ModeVLESSVision || m == config.ModeVLESSReality
}

var checkTargetAvailability = func(target string) error {
	_, err := config.ValidateRealityTarget(target, 5*time.Second)
	return err
}

func validateManualTarget(sni, target string) error {
	if target == "" {
		target = net.JoinHostPort(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(sni)), "."), "443")
	}
	return checkTargetAvailability(target)
}

var presetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all available preset slots and their status",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		fmt.Printf("\n%-3s | %-25s | %-8s | %-6s | %-26s | %-12s | %-12s | %-s\n",
			"ID", "TECHNICAL COMBINATION", "STATUS", "PORT", "SNI", "SKIN", "MIN VER", "DEST / PATH")
		fmt.Println("-----------------------------------------------------------------------------------------------------------------------------")
		for i, mode := range cfg.Presets {
			status := "OFF"
			if mode.Enabled {
				status = "ON"
			}
			sni := "-"
			if mode.SNI != "" {
				sni = mode.SNI
			}
			skin := "-"
			if mode.Skin != "" {
				skin = mode.Skin
			}
			minVer := "-"
			if supportsReality(mode.Mode) {
				minVer = config.ResolveMinClientVersion(&mode)
			}
			destOrPath := "-"
			if mode.Dest != "" {
				destOrPath = mode.Dest
			} else if mode.Path != "" {
				destOrPath = mode.Path
			}
			fmt.Printf("%-3d | %-25s | %-8s | %-6d | %-26s | %-12s | %-12s | %-s\n",
				i+1, mode.Mode, status, mode.Port, sni, skin, minVer, destOrPath)
		}
		fmt.Println()
	},
}

var presetsSkinCmd = &cobra.Command{
	Use:   "skin",
	Short: "Manage Web camouflage skins for presets",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var presetsSkinListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List available Web camouflage skins and their characteristics",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("\nAVAILABLE WEB CAMOUFLAGE SKINS:")
		fmt.Println("--------------------------------------------------------------------------------------")
		fmt.Println("nextcloud   - Official Nextcloud Hub login replica with /status.php & auth rejection")
		fmt.Println("filebrowser - Modern Vue-based File Browser login replica with /manifest.json & 403 rejection")
		fmt.Println("seafile     - Seafile Seahub login replica with /api2/ping & 200 error banner")
		fmt.Println("off / none  - Disable Web camouflage skin")
		fmt.Println()
	},
}

var presetsSetCmd = &cobra.Command{
	Use:   "set [id]",
	Short: "Configure a specific preset slot (STAGING)",
	Long: strings.TrimSpace(`
Configure or toggle features for a specific preset slot in the STAGING config.

You can enable/disable modes, change ports, regenerate secrets/paths,
select or validate REALITY destination SNI and targets, and configure
high-fidelity Web camouflage skins (Nextcloud, File Browser, Seafile).

REALITY target selection highlights:
  - REALITY requires a qualified destination site matching the advertised SNI.
  - Candidate targets must pass strict TLS 1.3, X25519, HTTP/2, certificate, and non-redirect validation.
  - Select candidate targets from safe cloud vendor pools (AWS, GCP, Oracle) via --sni-aws, etc.
  - Supports manual domain selection with mandatory online validation via --sni.

Web camouflage skin highlights:
  - Set authentic login replicas with realistic credential rejection: --skin <type>
  - Must provide a domain with a valid certificate: --skin-domain <domain>
`),
	Example: strings.TrimSpace(`
  # Enable slot 1 and select qualified domain from AWS pool
  xray-proxya presets set 1 --on --port 443 --sni-aws

  # Manually set arbitrary REALITY domain with validation
  xray-proxya presets set 1 --sni pkg.go.dev

  # Configure Seafile login skin with managed certificate
  xray-proxya presets set 1 --skin seafile --skin-domain sea.ailing.dev

  # Disable Web skin
  xray-proxya presets set 1 --skin off
`),
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, _ := strconv.Atoi(args[0])
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		if id < 1 || id > len(cfg.Presets) {
			fmt.Printf("❌ Invalid ID: %d\n", id)
			return
		}

		idx := id - 1
		m := &cfg.Presets[idx]

		selectors := 0
		if presetSNIAWS {
			selectors++
		}
		if presetSNIGCP {
			selectors++
		}
		if presetSNIOracle {
			selectors++
		}
		if presetSNIVendor != "" {
			selectors++
		}
		if presetSNIManual != "" || presetSNI != "" {
			selectors++
		}

		if selectors > 1 {
			fmt.Println("❌ Error: Conflicting SNI target flags specified. Please specify only one target selection option.")
			return
		}

		hasRealityReq := presetSNICheck || selectors > 0 || presetDest != ""
		if hasRealityReq && !supportsReality(m.Mode) {
			fmt.Printf("❌ Error: Mode [%s] does not support REALITY target/SNI configuration (requires VLESS Reality or Vision).\n", m.Mode)
			return
		}

		if presetOff {
			m.Enabled = false
		}
		if presetOn {
			m.Enabled = true
		}
		if presetPort > 0 {
			m.Port = presetPort
		}
		if presetRegen {
			m.RegenFlag = true
		}

		// 1. Manual SNI mode
		if presetSNIManual != "" || presetSNI != "" {
			manualDomain := presetSNIManual
			if manualDomain == "" {
				manualDomain = presetSNI
			}
			normHost, _, _, err := config.NormalizeRealityTarget(manualDomain)
			if err != nil {
				fmt.Printf("❌ Error: Invalid domain %q: %v\n", manualDomain, err)
				return
			}
			dest := presetDest
			if dest == "" {
				dest = net.JoinHostPort(normHost, "443")
			} else {
				destHost, _, normDest, err := config.NormalizeRealityTarget(dest)
				if err != nil {
					fmt.Printf("❌ Error: Invalid --dest %q: %v\n", dest, err)
					return
				}
				if destHost != normHost {
					fmt.Printf("❌ Error: --dest host (%s) must match --sni host (%s)\n", destHost, normHost)
					return
				}
				dest = normDest
			}

			// Security risk inspection
			if isRisky, reason := config.InspectRealityDomainRisk(normHost); isRisky {
				fmt.Printf("⚠️  WARNING: Target domain %q is flagged as risky:\n    -> %s\n", normHost, reason)
				if !presetSNIForce {
					confirmed := promptConfirmFunc(fmt.Sprintf("⚠️  Do you want to proceed with risky target %s? [y/N]: ", normHost))
					if !confirmed {
						fmt.Printf("❌ Target configuration aborted. Use '--sni-force' to bypass this safety check.\n")
						return
					}
					fmt.Println("⚠️  Proceeding with risky target as confirmed by user.")
				} else {
					fmt.Println("⚠️  Bypassing safety check via '--sni-force'.")
				}
			}

			fmt.Printf("🔍 Validating manual REALITY target %s (%s)...\n", normHost, dest)
			if err := validateManualTarget(normHost, dest); err != nil {
				fmt.Printf("❌ Error: Target %s failed qualification: %v\n", dest, err)
				return
			}
			m.SNI = normHost
			m.Dest = dest
			fmt.Printf("🎯 Validated manual REALITY target: %s (%s)\n", normHost, dest)
		} else if selectors > 0 {
			// 2. Specific Cloud Vendor Pool
			vendor := config.VendorAWS
			if presetSNIGCP {
				vendor = config.VendorGCP
			} else if presetSNIOracle {
				vendor = config.VendorOracle
			} else if presetSNIVendor != "" {
				vendor = config.NormalizeVendor(presetSNIVendor)
			}

			if !config.IsValidCloudVendor(vendor) {
				fmt.Printf("❌ Error: Unknown cloud vendor %q\n", presetSNIVendor)
				return
			}

			domains, err := config.GetCloudVendorDomains(vendor)
			if err != nil {
				fmt.Printf("❌ Error obtaining [%s] domain pool: %v\n", vendor, err)
				return
			}
			fmt.Printf("🔍 Probing and benchmarking [%s] candidate pool (%d domains)...\n", vendor, len(domains))
			bestDomain, rtt, err := config.BenchmarkDomains(domains, 5*time.Second)
			if err != nil {
				fmt.Printf("❌ Error benchmarking [%s] domains: %v\n", vendor, err)
				return
			}
			m.SNI = bestDomain
			m.Dest = net.JoinHostPort(bestDomain, "443")
			fmt.Printf("🎯 Selected [%s] REALITY target: %s (RTT: %.1fms, TLS 1.3 OK)\n", vendor, bestDomain, float64(rtt.Microseconds())/1000.0)
		} else if presetDest != "" {
			// 3. Adjust dest port only for existing SNI
			if m.SNI == "" {
				fmt.Println("❌ Error: Current preset has no SNI configured. Please specify --sni.")
				return
			}
			destHost, _, normDest, err := config.NormalizeRealityTarget(presetDest)
			if err != nil {
				fmt.Printf("❌ Error: Invalid --dest %q: %v\n", presetDest, err)
				return
			}
			if destHost != m.SNI {
				fmt.Printf("❌ Error: --dest host (%s) must match current SNI (%s)\n", destHost, m.SNI)
				return
			}

			if isRisky, reason := config.InspectRealityDomainRisk(destHost); isRisky {
				fmt.Printf("⚠️  WARNING: Target destination %q is flagged as risky:\n    -> %s\n", destHost, reason)
				if !presetSNIForce {
					confirmed := promptConfirmFunc(fmt.Sprintf("⚠️  Do you want to proceed with risky target %s? [y/N]: ", destHost))
					if !confirmed {
						fmt.Printf("❌ Target configuration aborted. Use '--sni-force' to bypass this safety check.\n")
						return
					}
					fmt.Println("⚠️  Proceeding with risky target as confirmed by user.")
				} else {
					fmt.Println("⚠️  Bypassing safety check via '--sni-force'.")
				}
			}

			fmt.Printf("🔍 Validating REALITY destination %s...\n", normDest)
			if err := checkTargetAvailability(normDest); err != nil {
				fmt.Printf("❌ Error: Target %s failed qualification: %v\n", normDest, err)
				return
			}
			m.Dest = normDest
			fmt.Printf("🎯 Validated REALITY destination: %s\n", normDest)
		} else if presetSNICheck {
			// 4. Validate current SNI/Dest without changing
			if m.SNI == "" {
				fmt.Println("❌ Error: Current preset has no SNI configured.")
				return
			}
			target := m.Dest
			if target == "" {
				target = net.JoinHostPort(m.SNI, "443")
			}
			fmt.Printf("🔍 Validating current REALITY target %s (%s)...\n", m.SNI, target)
			if err := checkTargetAvailability(target); err != nil {
				fmt.Printf("❌ Error: Current REALITY target %s failed qualification: %v\n", target, err)
				return
			}
			m.Dest = target
			fmt.Printf("🎯 Validated current REALITY target: %s (%s)\n", m.SNI, target)
		}

		// 5. Web camouflage skin configuration
		if cmd.Flags().Changed("skin") && presetSkin != "" {
			if !supportsSkin(m.Mode) {
				fmt.Printf("❌ Error: Mode [%s] does not support Web camouflage skin.\n", m.Mode)
				return
			}
			st := strings.ToLower(strings.TrimSpace(presetSkin))
			if st == "off" || st == "none" {
				m.Skin = ""
				m.SkinDomain = ""
				if strings.HasPrefix(m.Dest, "127.0.0.1:") && m.SNI != "" {
					m.Dest = net.JoinHostPort(m.SNI, "443")
				}
				fmt.Printf("🎨 Disabled Web Skin for preset [%s].\n", m.Mode)
			} else {
				if !config.IsValidSkin(st) {
					fmt.Printf("❌ Error: Unknown skin %q. Available skins: %s\n", presetSkin, strings.Join(config.SupportedSkins, ", "))
					return
				}
				effectiveDomain := presetSkinDomain
				if effectiveDomain == "" {
					if m.SkinDomain != "" {
						effectiveDomain = m.SkinDomain
					} else if m.SNI != "" {
						effectiveDomain = m.SNI
					}
				}
				effectiveDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(effectiveDomain)), ".")
				if effectiveDomain == "" {
					fmt.Println("❌ Error: Setting --skin requires a valid domain. Please specify --skin-domain <domain> or run 'xray-proxya cert add <domain>' first.")
					return
				}
				cert := cfg.FindCert(effectiveDomain)
				if cert == nil {
					fmt.Printf("❌ Error: Domain %q has no valid certificate. Run 'xray-proxya cert add %s' first.\n", effectiveDomain, effectiveDomain)
					return
				}
				m.Skin = st
				m.SkinDomain = effectiveDomain
				if supportsReality(m.Mode) {
					m.SNI = effectiveDomain
					m.Dest = "127.0.0.1:9443"
				}
				fmt.Printf("🎨 Configured Web Skin [%s] bound to domain %s (Cert valid until %s).\n",
					m.Skin, m.SkinDomain, cert.ExpiresAt.Format("2006-01-02"))
			}
		} else if cmd.Flags().Changed("skin-domain") {
			if m.Skin == "" {
				fmt.Println("❌ Error: Cannot set --skin-domain without setting --skin.")
				return
			}
			effectiveDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(presetSkinDomain)), ".")
			cert := cfg.FindCert(effectiveDomain)
			if cert == nil {
				fmt.Printf("❌ Error: Domain %q has no valid certificate. Run 'xray-proxya cert add %s' first.\n", effectiveDomain, effectiveDomain)
				return
			}
			m.SkinDomain = effectiveDomain
			if supportsReality(m.Mode) {
				m.SNI = effectiveDomain
			}
			fmt.Printf("🎨 Updated Web Skin domain to %s (Cert valid until %s).\n", m.SkinDomain, cert.ExpiresAt.Format("2006-01-02"))
		}

		if cmd.Flags().Changed("min-ver") {
			if !supportsReality(m.Mode) {
				fmt.Printf("❌ Error: Mode [%s] does not support REALITY min-ver configuration (requires VLESS Reality or Vision).\n", m.Mode)
				return
			}
			normVer, err := config.NormalizeMinClientVersion(presetMinVer)
			if err != nil {
				fmt.Printf("❌ Error: Invalid --min-ver %q: %v\n", presetMinVer, err)
				return
			}
			m.MinClientVer = normVer
		}

		cfg.SaveEx(true)
		status := "OFF"
		if m.Enabled {
			status = "ON"
		}
		extraInfo := ""
		if supportsReality(m.Mode) {
			extraInfo = fmt.Sprintf(", MinVer: %s", config.ResolveMinClientVersion(m))
		}
		skinInfo := ""
		if m.Skin != "" {
			skinInfo = fmt.Sprintf(", Skin: %s (%s)", m.Skin, m.SkinDomain)
		}
		fmt.Printf("✅ Updated [%s] -> Status: %s, Port: %d, SNI: %s, Dest: %s%s%s [STAGING]\n",
			m.Mode, status, m.Port, m.SNI, m.Dest, extraInfo, skinInfo)
		fmt.Println("🚀 Run 'apply' to commit changes.")
	},
}

func getPresetIDs() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		return nil
	}
	ids := make([]string, 0, len(cfg.Presets))
	for i, m := range cfg.Presets {
		desc := string(m.Mode)
		if desc != "" {
			ids = append(ids, fmt.Sprintf("%d\t%s", i+1, desc))
		} else {
			ids = append(ids, strconv.Itoa(i+1))
		}
	}
	return ids
}

func init() {
	presetsSetCmd.Flags().BoolVar(&presetOff, "off", false, "Disable this mode")
	presetsSetCmd.Flags().BoolVar(&presetOn, "on", false, "Enable this mode")
	presetsSetCmd.Flags().IntVarP(&presetPort, "port", "p", 0, "Set specific port")
	presetsSetCmd.Flags().BoolVarP(&presetRegen, "regen", "r", false, "Regenerate secrets/paths for this mode on apply")

	// SNI flags (migrated from skin)
	presetsSetCmd.Flags().StringVar(&presetSNI, "sni", "", "Manually set and validate REALITY SNI domain")
	presetsSetCmd.Flags().BoolVar(&presetSNIAWS, "sni-aws", false, "Benchmark and select qualified target from AWS pool")
	presetsSetCmd.Flags().BoolVar(&presetSNIGCP, "sni-gcp", false, "Benchmark and select qualified target from GCP pool")
	presetsSetCmd.Flags().BoolVar(&presetSNIOracle, "sni-oracle", false, "Benchmark and select qualified target from Oracle Cloud pool")
	presetsSetCmd.Flags().StringVar(&presetSNIVendor, "sni-vendor", "", "Benchmark and select qualified target from a specific cloud vendor")
	presetsSetCmd.Flags().BoolVar(&presetSNIForce, "sni-force", false, "Force using a risky REALITY target without interactive confirmation")
	presetsSetCmd.Flags().BoolVar(&presetSNICheck, "sni-check", false, "Validate current REALITY target without changing SNI")

	// Backward compatibility aliases for old skin-* SNI flags
	presetsSetCmd.Flags().BoolVar(&presetSNIAWS, "skin-aws", false, "Alias for --sni-aws")
	presetsSetCmd.Flags().BoolVar(&presetSNIGCP, "skin-gcp", false, "Alias for --sni-gcp")
	presetsSetCmd.Flags().BoolVar(&presetSNIOracle, "skin-oracle", false, "Alias for --sni-oracle")
	presetsSetCmd.Flags().StringVar(&presetSNIVendor, "skin-vendor", "", "Alias for --sni-vendor")
	presetsSetCmd.Flags().StringVar(&presetSNIManual, "skin-manual", "", "Alias for --sni")
	presetsSetCmd.Flags().BoolVar(&presetSNIForce, "skin-manual-force", false, "Alias for --sni-force")
	_ = presetsSetCmd.Flags().MarkHidden("skin-aws")
	_ = presetsSetCmd.Flags().MarkHidden("skin-gcp")
	_ = presetsSetCmd.Flags().MarkHidden("skin-oracle")
	_ = presetsSetCmd.Flags().MarkHidden("skin-vendor")
	_ = presetsSetCmd.Flags().MarkHidden("skin-manual")
	_ = presetsSetCmd.Flags().MarkHidden("skin-manual-force")

	// Web camouflage skin flags
	presetsSetCmd.Flags().StringVar(&presetSkin, "skin", "", "Configure Web camouflage skin (nextcloud, filebrowser, seafile, off)")
	presetsSetCmd.Flags().StringVar(&presetSkinDomain, "skin-domain", "", "Specify domain for Web camouflage skin (must have valid cert in cert list)")

	presetsSetCmd.Flags().StringVar(&presetDest, "dest", "", "Set REALITY destination host:port (host must match SNI)")
	presetsSetCmd.Flags().StringVar(&presetMinVer, "min-ver", "", "Set minimum Xray client version required for REALITY (e.g. 26.3.27, or 0.0.0 to disable)")

	presetsSetCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getPresetIDs(), cobra.ShellCompDirectiveNoFileComp
	}

	presetsSetCmd.RegisterFlagCompletionFunc("sni-vendor", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllCloudVendors(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("sni", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllRealityDomains(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("skin", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"nextcloud\tNextcloud Hub login replica with /status.php",
			"filebrowser\tFile Browser Vue SPA login replica with 403 rejection",
			"seafile\tSeafile login replica with /api2/ping",
			"off\tDisable Web camouflage skin",
		}, cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("skin-domain", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		domains := make([]string, 0, len(cfg.Certs))
		for _, c := range cfg.Certs {
			domains = append(domains, c.Domain)
		}
		return domains, cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("min-ver", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"26.3.27\tShadowrocket latest & Xray default",
			"0.0.0\tDisable check (Sing-Box/Clash compatible)",
			"1.8.0\tLegacy compatibility",
		}, cobra.ShellCompDirectiveNoFileComp
	})

	presetsSkinCmd.AddCommand(presetsSkinListCmd)
	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd, presetsSkinCmd)
	rootCmd.AddCommand(presetsCmd)
}
