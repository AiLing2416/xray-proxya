package main

import (
	"fmt"
	"strconv"
	"strings"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	presetOff     bool
	presetOn      bool
	presetPort    int
	presetRegen   bool
	presetSkin    bool
	presetUnskin  bool
	presetSNI     string
	presetDest    string
)

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

func supportsSkin(m config.PresetMode) bool {
	return m == config.ModeVLESSVision || m == config.ModeVLESSReality
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
		for i, mode := range cfg.ActiveModes {
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

You can enable/disable modes, change ports, and toggle the Smart Mirroring 
camouflage (Skin) for supported Reality/Vision protocols.

Smart Mirroring (Skin) highlights:
  - Proxies requests normally for authenticated users.
  - Redirects probes (access via IP) to a local camouflage server.
  - Returns target site's real error page for IP probes (e.g. 403/Invalid URL).
  - Returns target site's home page for SNI probes (Mirroring).
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
		if id < 1 || id > len(cfg.ActiveModes) {
			fmt.Printf("❌ Invalid ID: %d\n", id)
			return
		}

		idx := id - 1
		m := &cfg.ActiveModes[idx]

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
		if presetSkin {
			if !supportsSkin(m.Mode) {
				fmt.Printf("❌ Error: Mode [%s] does not support web camouflage (requires VLESS Reality or Vision).\n", m.Mode)
				return
			}
			m.Skin = true
		}
		if presetUnskin {
			m.Skin = false
		}
		if presetSNI != "" {
			m.SNI = presetSNI
		}
		if presetDest != "" {
			m.Dest = presetDest
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
	ids := make([]string, 0, len(cfg.ActiveModes))
	for i := range cfg.ActiveModes {
		ids = append(ids, strconv.Itoa(i+1))
	}
	return ids
}

func init() {
	presetsSetCmd.Flags().BoolVar(&presetOff, "off", false, "Disable this mode")
	presetsSetCmd.Flags().BoolVar(&presetOn, "on", false, "Enable this mode")
	presetsSetCmd.Flags().IntVarP(&presetPort, "port", "p", 0, "Set specific port")
	presetsSetCmd.Flags().BoolVarP(&presetRegen, "regen", "r", false, "Regenerate secrets/paths for this mode on apply")
	presetsSetCmd.Flags().BoolVar(&presetSkin, "skin", false, "Enable web camouflage (mirroring)")
	presetsSetCmd.Flags().BoolVar(&presetUnskin, "unskin", false, "Disable web camouflage")
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
