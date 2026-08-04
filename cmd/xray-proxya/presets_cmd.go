package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	presetOff    bool
	presetOn     bool
	presetPort   int
	presetRegen  bool
	presetSkin   bool
	presetUnskin bool
	presetSNI    string
	presetDest   string
)

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

func supportsSkin(m config.PresetMode) bool {
	return m == config.ModeVLESSVision || m == config.ModeVLESSReality
}

// configureSkinTarget keeps Reality's fallback indistinguishable from a direct
// connection to the advertised SNI.  TLS must stay end-to-end with that site;
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
  - Uses SNI:443 as the fallback unless --dest is explicitly supplied.
`),
	Example: strings.TrimSpace(`
  # Enable slot 1 and set port to 443
  xray-proxya presets set 1 --on --port 443

  # Enable web camouflage (Skin) for slot 1
  xray-proxya presets set 1 --skin

  # Manually override the camouflage target site
  xray-proxya presets set 1 --sni www.intel.com --dest www.intel.com:443

  # Reset/Regenerate secrets for slot 2
  xray-proxya presets set 2 --regen
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
		if presetSNI != "" {
			m.SNI = presetSNI
		}
		if presetDest != "" {
			m.Dest = presetDest
		}
		if presetSkin {
			if !supportsSkin(m.Mode) {
				fmt.Printf("❌ Error: Mode [%s] does not support TLS-preserving camouflage (requires VLESS Reality or Vision).\n", m.Mode)
				return
			}
			if err := configureSkinTarget(m, presetDest != ""); err != nil {
				fmt.Printf("❌ Error: %v.\n", err)
				return
			}
			m.Skin = true
		}
		if presetUnskin {
			m.Skin = false
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
		fmt.Printf("✅ Updated [%s] -> Status: %s, Port: %d, Skin: %s (STAGING)\n", m.Mode, status, m.Port, skinStatus)
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
	presetsSetCmd.Flags().BoolVar(&presetSkin, "skin", false, "Enable TLS-preserving camouflage")
	presetsSetCmd.Flags().BoolVar(&presetUnskin, "unskin", false, "Disable TLS-preserving camouflage")
	presetsSetCmd.Flags().StringVar(&presetSNI, "sni", "", "Manually set SNI (e.g., www.intel.com)")
	presetsSetCmd.Flags().StringVar(&presetDest, "dest", "", "Manually set Destination (e.g., www.intel.com:443)")

	presetsSetCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getPresetIDs(), cobra.ShellCompDirectiveNoFileComp
	}

	// Add completion for --sni from our domain pool
	presetsSetCmd.RegisterFlagCompletionFunc("sni", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return config.GetAllRealityDomains(), cobra.ShellCompDirectiveNoFileComp
	})

	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd)
	rootCmd.AddCommand(presetsCmd)
}
