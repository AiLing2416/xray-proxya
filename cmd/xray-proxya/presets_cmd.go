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
	presetOff               bool
	presetOn                bool
	presetPort              int
	presetRegen             bool
	presetSkin              bool
	presetUnskin            bool
	presetSkinAWS           bool
	presetSkinGCP           bool
	presetSkinOracle        bool
	presetSkinVendor        string
	presetSkinManual        string
	presetSkinManualForce   bool
	presetSNI               string
	presetDest              string
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

func supportsSkin(m config.PresetMode) bool {
	return m == config.ModeVLESSVision || m == config.ModeVLESSReality
}

var checkTargetAvailability = func(target string) error {
	_, err := config.ValidateSkinTarget(target, 5*time.Second)
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

		fmt.Printf("\n%-3s | %-25s | %-8s | %-6s | %-30s | %-s\n", "ID", "TECHNICAL COMBINATION", "STATUS", "PORT", "SNI", "DEST / PATH")
		fmt.Println("------------------------------------------------------------------------------------------------")
		for i, mode := range cfg.Presets {
			status := "OFF"
			if mode.Enabled {
				status = "ON"
			}
			sni := "-"
			if mode.SNI != "" {
				sni = mode.SNI
			}
			destOrPath := "-"
			if mode.Dest != "" {
				destOrPath = mode.Dest
			} else if mode.Path != "" {
				destOrPath = mode.Path
			}
			fmt.Printf("%-3d | %-25s | %-8s | %-6d | %-30s | %-s\n", i+1, mode.Mode, status, mode.Port, sni, destOrPath)
		}
		fmt.Println()
	},
}

var presetsSetCmd = &cobra.Command{
	Use:   "set [id]",
	Short: "Configure a specific preset slot (STAGING)",
	Long: strings.TrimSpace(`
Configure or toggle features for a specific preset slot in the STAGING config.

You can enable/disable modes, change ports, regenerate secrets/paths, and
select or validate REALITY destination SNI and targets.

REALITY target selection highlights:
  - REALITY requires a qualified destination site matching the advertised SNI.
  - Candidate targets must pass strict TLS 1.3, X25519, HTTP/2, certificate, and non-redirect validation.
  - Select candidate targets from safe cloud vendor pools (AWS, GCP, Oracle).
  - Supports manual domain selection with mandatory online validation and risk safety checks.
`),
	Example: strings.TrimSpace(`
  # Enable slot 1 and validate current REALITY target
  xray-proxya presets set 1 --on --port 443 --skin

  # Benchmark and select best domain from GCP or AWS cloud pool
  xray-proxya presets set 1 --skin-gcp
  xray-proxya presets set 1 --skin-aws

  # Manually set arbitrary REALITY domain with validation
  xray-proxya presets set 1 --skin-manual pkg.go.dev
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

		if presetUnskin {
			fmt.Println("❌ Error: REALITY target cannot be disabled; select another SNI or disable the preset.")
			return
		}

		selectors := 0
		if presetSkinAWS {
			selectors++
		}
		if presetSkinGCP {
			selectors++
		}
		if presetSkinOracle {
			selectors++
		}
		if presetSkinVendor != "" {
			selectors++
		}
		if presetSkinManual != "" || presetSNI != "" {
			selectors++
		}

		if selectors > 1 {
			fmt.Println("❌ Error: Conflicting skin target flags specified. Please specify only one target selection option.")
			return
		}

		hasRealityReq := presetSkin || selectors > 0 || presetDest != ""
		if hasRealityReq && !supportsSkin(m.Mode) {
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

		// 1. Manual Skin mode
		if presetSkinManual != "" || presetSNI != "" {
			manualDomain := presetSkinManual
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
				if !presetSkinManualForce {
					confirmed := promptConfirmFunc(fmt.Sprintf("⚠️  Do you want to proceed with risky target %s? [y/N]: ", normHost))
					if !confirmed {
						fmt.Printf("❌ Target configuration aborted. Use '--skin-manual-force' to bypass this safety check.\n")
						return
					}
					fmt.Println("⚠️  Proceeding with risky target as confirmed by user.")
				} else {
					fmt.Println("⚠️  Bypassing safety check via '--skin-manual-force'.")
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
			if presetSkinGCP {
				vendor = config.VendorGCP
			} else if presetSkinOracle {
				vendor = config.VendorOracle
			} else if presetSkinVendor != "" {
				vendor = config.NormalizeVendor(presetSkinVendor)
			}

			if !config.IsValidCloudVendor(vendor) {
				fmt.Printf("❌ Error: Unknown cloud vendor %q\n", presetSkinVendor)
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
				if !presetSkinManualForce {
					confirmed := promptConfirmFunc(fmt.Sprintf("⚠️  Do you want to proceed with risky target %s? [y/N]: ", destHost))
					if !confirmed {
						fmt.Printf("❌ Target configuration aborted. Use '--skin-manual-force' to bypass this safety check.\n")
						return
					}
					fmt.Println("⚠️  Proceeding with risky target as confirmed by user.")
				} else {
					fmt.Println("⚠️  Bypassing safety check via '--skin-manual-force'.")
				}
			}

			fmt.Printf("🔍 Validating REALITY destination %s...\n", normDest)
			if err := checkTargetAvailability(normDest); err != nil {
				fmt.Printf("❌ Error: Target %s failed qualification: %v\n", normDest, err)
				return
			}
			m.Dest = normDest
			fmt.Printf("🎯 Validated REALITY destination: %s\n", normDest)
		} else if presetSkin {
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

		cfg.SaveEx(true)
		status := "OFF"
		if m.Enabled {
			status = "ON"
		}
		fmt.Printf("✅ Updated [%s] -> Status: %s, Port: %d, SNI: %s, Dest: %s [STAGING]\n",
			m.Mode, status, m.Port, m.SNI, m.Dest)
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
	presetsSetCmd.Flags().BoolVar(&presetSkin, "skin", false, "Validate current REALITY target without changing SNI")
	presetsSetCmd.Flags().BoolVar(&presetUnskin, "unskin", false, "Deprecated: REALITY target cannot be disabled")
	presetsSetCmd.Flags().BoolVar(&presetSkinAWS, "skin-aws", false, "Benchmark and select qualified target from AWS pool")
	presetsSetCmd.Flags().BoolVar(&presetSkinGCP, "skin-gcp", false, "Benchmark and select qualified target from GCP pool")
	presetsSetCmd.Flags().BoolVar(&presetSkinOracle, "skin-oracle", false, "Benchmark and select qualified target from Oracle Cloud pool")
	presetsSetCmd.Flags().StringVar(&presetSkinVendor, "skin-vendor", "", "Benchmark and select qualified target from a specific cloud vendor")
	presetsSetCmd.Flags().StringVar(&presetSkinManual, "skin-manual", "", "Manually set and validate arbitrary REALITY target domain")
	presetsSetCmd.Flags().BoolVar(&presetSkinManualForce, "skin-manual-force", false, "Force using a risky REALITY target without interactive confirmation")
	presetsSetCmd.Flags().StringVar(&presetSNI, "sni", "", "Manually set and validate REALITY SNI domain")
	presetsSetCmd.Flags().StringVar(&presetDest, "dest", "", "Set REALITY destination host:port (host must match SNI)")

	presetsSetCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getPresetIDs(), cobra.ShellCompDirectiveNoFileComp
	}

	presetsSetCmd.RegisterFlagCompletionFunc("skin-vendor", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllCloudVendors(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("sni", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllRealityDomains(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("skin-manual", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllRealityDomains(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd)
	rootCmd.AddCommand(presetsCmd)
}
