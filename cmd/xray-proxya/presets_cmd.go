package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	presetOff            bool
	presetOn             bool
	presetPort           int
	presetRegen          bool
	presetSkin           bool
	presetUnskin         bool
	presetSkinAWS        bool
	presetSkinGCP        bool
	presetSkinAzure      bool
	presetSkinCloudflare bool
	presetSkinOracle     bool
	presetSkinVendor     string
	presetSkinManual     string
	presetSNI            string
	presetDest           string
)

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

func supportsSkin(m config.PresetMode) bool {
	return m == config.ModeVLESSVision || m == config.ModeVLESSReality
}

// configureSkinTarget keeps Reality's fallback indistinguishable from a direct
// connection to the advertised SNI. TLS must stay end-to-end with that site;
// terminating it locally would expose a substitute certificate and fingerprint.
func configureSkinTarget(m *config.ModeInfo, explicitDest bool) error {
	sni := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m.SNI)), ".")
	if sni == "" || net.ParseIP(sni) != nil {
		return fmt.Errorf("skin requires a domain SNI")
	}

	if !explicitDest {
		m.Dest = net.JoinHostPort(sni, "443")
		return nil
	}

	host, _, err := net.SplitHostPort(m.Dest)
	if err != nil || host == "" {
		return fmt.Errorf("skin destination must use host:port format")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host != sni {
		return fmt.Errorf("skin requires --dest host (%s) to match --sni (%s)", host, sni)
	}
	return nil
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

		fmt.Printf("\n%-3s | %-25s | %-8s | %-6s | %-6s | %-s\n", "ID", "TECHNICAL COMBINATION", "STATUS", "PORT", "SKIN", "SNI/PATH")
		fmt.Println("------------------------------------------------------------------------------------------------")
		for i, mode := range cfg.Presets {
			status := "OFF"
			if mode.Enabled {
				status = "ON"
			}
			skin := "n/A"
			if supportsSkin(mode.Mode) {
				skin = "OFF"
				if mode.Skin {
					skin = "ON"
				}
			}
			extra := mode.SNI
			if mode.Path != "" {
				extra = mode.Path
			}
			fmt.Printf("%-3d | %-25s | %-8s | %-6d | %-6s | %-s\n", i+1, mode.Mode, status, mode.Port, skin, extra)
		}
		fmt.Println()
	},
}

var presetsSetCmd = &cobra.Command{
	Use:   "set [id]",
	Short: "Configure a specific preset slot (STAGING)",
	Long: strings.TrimSpace(`
Configure or toggle features for a specific preset slot in the STAGING config.

You can enable/disable modes, change ports, and toggle TLS-preserving
camouflage (Skin) for supported Reality/Vision protocols.

TLS-preserving camouflage (Skin) highlights:
  - Proxies authenticated users normally.
  - Sends unauthenticated Reality fallbacks directly to the advertised site.
  - Preserves the target site's certificate, TLS fingerprint, and live response.
  - Auto-detects server cloud provider (AWS, GCP, Azure, Cloudflare, Oracle) and selects the lowest-latency matching domain.
  - Supports manual domain selection with mandatory TLS 1.3 and certificate qualification.
`),
	Example: strings.TrimSpace(`
  # Enable slot 1 and auto-select best skin domain based on cloud/latency
  xray-proxya presets set 1 --on --port 443 --skin

  # Benchmark and select best domain from GCP or AWS cloud pool
  xray-proxya presets set 1 --skin-gcp
  xray-proxya presets set 1 --skin-aws

  # Manually set arbitrary skin domain with validation
  xray-proxya presets set 1 --skin-manual cdnjs.cloudflare.com

  # Disable camouflage
  xray-proxya presets set 1 --unskin
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

		hasSkinReq := presetSkin || presetSkinAWS || presetSkinGCP || presetSkinAzure ||
			presetSkinCloudflare || presetSkinOracle || presetSkinVendor != "" ||
			presetSkinManual != "" || presetSNI != ""

		if hasSkinReq && !supportsSkin(m.Mode) {
			fmt.Printf("❌ Error: Mode [%s] does not support TLS-preserving camouflage (requires VLESS Reality or Vision).\n", m.Mode)
			return
		}

		// 1. Manual Skin mode
		if presetSkinManual != "" || presetSNI != "" {
			manualDomain := presetSkinManual
			if manualDomain == "" {
				manualDomain = presetSNI
			}
			manualDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(manualDomain)), ".")
			dest := presetDest
			if dest == "" {
				dest = net.JoinHostPort(manualDomain, "443")
			}

			fmt.Printf("🔍 Validating manual skin target %s (%s)...\n", manualDomain, dest)
			if err := validateManualTarget(manualDomain, dest); err != nil {
				fmt.Printf("❌ Error: Target %s failed qualification: %v\n", dest, err)
				return
			}
			m.Skin = true
			m.SNI = manualDomain
			m.Dest = dest
			fmt.Printf("🎯 Validated manual skin target: %s (%s)\n", manualDomain, dest)
		} else if presetSkinAWS || presetSkinGCP || presetSkinAzure || presetSkinCloudflare || presetSkinOracle || presetSkinVendor != "" {
			// 2. Specific Cloud Vendor Pool
			vendor := config.VendorAWS
			if presetSkinGCP {
				vendor = config.VendorGCP
			} else if presetSkinAzure {
				vendor = config.VendorAzure
			} else if presetSkinCloudflare {
				vendor = config.VendorCloudflare
			} else if presetSkinOracle {
				vendor = config.VendorOracle
			} else if presetSkinVendor != "" {
				vendor = config.NormalizeVendor(presetSkinVendor)
			}

			domains := config.GetCloudVendorDomains(vendor)
			fmt.Printf("🔍 Probing and benchmarking [%s] candidate pool (%d domains)...\n", vendor, len(domains))
			bestDomain, rtt, err := config.BenchmarkDomains(domains, 3*time.Second)
			if err != nil {
				fmt.Printf("❌ Error benchmarking [%s] domains: %v\n", vendor, err)
				return
			}
			m.Skin = true
			m.SNI = bestDomain
			m.Dest = net.JoinHostPort(bestDomain, "443")
			fmt.Printf("🎯 Selected [%s] skin target: %s (RTT: %.1fms, TLS 1.3 OK)\n", vendor, bestDomain, float64(rtt.Microseconds())/1000.0)
		} else if presetSkin {
			// 3. Auto-detected Cloud Provider / Latency Benchmark
			fmt.Printf("🔍 Auto-detecting cloud provider for server...\n")
			detectedVendor := config.DetectCloudVendor()
			var domains []string
			label := detectedVendor
			if detectedVendor != "" {
				fmt.Printf("☁️  Detected cloud provider: [%s]\n", detectedVendor)
				domains = config.GetCloudVendorDomains(detectedVendor)
			} else {
				fmt.Printf("ℹ️  Cloud provider not recognized or non-cloud IP. Using generic global domain pool.\n")
				domains = config.GetCloudVendorDomains(config.VendorGeneric)
				label = "generic"
			}

			fmt.Printf("🔍 Benchmarking candidate pool (%d domains)...\n", len(domains))
			bestDomain, rtt, err := config.BenchmarkDomains(domains, 3*time.Second)
			if err != nil {
				fmt.Printf("❌ Error benchmarking candidate domains: %v\n", err)
				return
			}
			m.Skin = true
			m.SNI = bestDomain
			m.Dest = net.JoinHostPort(bestDomain, "443")
			fmt.Printf("🎯 Auto-selected [%s] skin target: %s (RTT: %.1fms, TLS 1.3 OK)\n", label, bestDomain, float64(rtt.Microseconds())/1000.0)
		}

		if presetDest != "" && presetSkinManual == "" && presetSNI == "" {
			m.Dest = presetDest
		}

		if presetUnskin {
			m.Skin = false
		}

		if m.Skin {
			if err := configureSkinTarget(m, presetDest != ""); err != nil {
				fmt.Printf("❌ Error: %v.\n", err)
				return
			}
		}

		cfg.SaveEx(true)
		status := "OFF"
		if m.Enabled {
			status = "ON"
		}
		skinStatus := "n/A"
		if supportsSkin(m.Mode) {
			skinStatus = "DISABLED"
			if m.Skin {
				skinStatus = "ENABLED"
			}
		}
		fmt.Printf("✅ Updated [%s] -> Status: %s, Port: %d, Skin: %s (SNI: %s, Dest: %s) [STAGING]\n",
			m.Mode, status, m.Port, skinStatus, m.SNI, m.Dest)
		fmt.Println("🚀 Run 'apply' to commit changes.")
	},
}

func getPresetIDs() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		return nil
	}
	ids := make([]string, 0, len(cfg.Presets))
	for i := range cfg.Presets {
		ids = append(ids, strconv.Itoa(i+1))
	}
	return ids
}

func init() {
	presetsSetCmd.Flags().BoolVar(&presetOff, "off", false, "Disable this mode")
	presetsSetCmd.Flags().BoolVar(&presetOn, "on", false, "Enable this mode")
	presetsSetCmd.Flags().IntVarP(&presetPort, "port", "p", 0, "Set specific port")
	presetsSetCmd.Flags().BoolVarP(&presetRegen, "regen", "r", false, "Regenerate secrets/paths for this mode on apply")
	presetsSetCmd.Flags().BoolVar(&presetSkin, "skin", false, "Auto-select best camouflage domain based on detected cloud or latency")
	presetsSetCmd.Flags().BoolVar(&presetUnskin, "unskin", false, "Disable TLS-preserving camouflage")
	presetsSetCmd.Flags().BoolVar(&presetSkinAWS, "skin-aws", false, "Benchmark and pick best camouflage domain from AWS pool")
	presetsSetCmd.Flags().BoolVar(&presetSkinGCP, "skin-gcp", false, "Benchmark and pick best camouflage domain from GCP pool")
	presetsSetCmd.Flags().BoolVar(&presetSkinAzure, "skin-azure", false, "Benchmark and pick best camouflage domain from Azure pool")
	presetsSetCmd.Flags().BoolVar(&presetSkinCloudflare, "skin-cloudflare", false, "Benchmark and pick best camouflage domain from Cloudflare pool")
	presetsSetCmd.Flags().BoolVar(&presetSkinOracle, "skin-oracle", false, "Benchmark and pick best camouflage domain from Oracle Cloud pool")
	presetsSetCmd.Flags().StringVar(&presetSkinVendor, "skin-vendor", "", "Benchmark and pick best domain from a specific cloud vendor (aws/gcp/azure/cloudflare/oracle/generic)")
	presetsSetCmd.Flags().StringVar(&presetSkinManual, "skin-manual", "", "Manually set and validate arbitrary camouflage domain")
	presetsSetCmd.Flags().StringVar(&presetSNI, "sni", "", "Manually set SNI (e.g., cdnjs.cloudflare.com)")
	presetsSetCmd.Flags().StringVar(&presetDest, "dest", "", "Manually set Destination (e.g., cdnjs.cloudflare.com:443)")

	presetsSetCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getPresetIDs(), cobra.ShellCompDirectiveNoFileComp
	}

	presetsSetCmd.RegisterFlagCompletionFunc("skin-vendor", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllCloudVendors(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsSetCmd.RegisterFlagCompletionFunc("sni", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllRealityDomains(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd)
	rootCmd.AddCommand(presetsCmd)
}
