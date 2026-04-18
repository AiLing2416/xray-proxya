package main

import (
	"fmt"
	"strconv"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	presetOff   bool
	presetOn    bool
	presetPort  int
	presetRegen bool
)

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

var presetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all available preset slots and their status",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		fmt.Printf("\n%-3s | %-25s | %-8s | %-6s | %-s\n", "ID", "TECHNICAL COMBINATION", "STATUS", "PORT", "SNI/PATH")
		fmt.Println("-----------------------------------------------------------------------------------------")
		for i, mode := range cfg.ActiveModes {
			status := "OFF"
			if mode.Enabled {
				status = "ON"
			}
			extra := mode.SNI
			if mode.Path != "" {
				extra = mode.Path
			}
			fmt.Printf("%-3d | %-25s | %-8s | %-6d | %-s\n", i+1, mode.Mode, status, mode.Port, extra)
		}
		fmt.Println()
	},
}

var presetsSetCmd = &cobra.Command{
	Use:   "set [id]",
	Short: "Configure a specific preset slot",
	Args:  cobra.ExactArgs(1),
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

		cfg.SaveEx(true)
		status := "OFF"
		if m.Enabled {
			status = "ON"
		}
		fmt.Printf("✅ Updated [%s] -> Status: %s, Port: %d (STAGING)\n", m.Mode, status, m.Port)
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
	presetsSetCmd.Flags().BoolVar(&presetRegen, "regen", false, "Regenerate keys/paths for this mode")
	presetsSetCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getPresetIDs(), cobra.ShellCompDirectiveNoFileComp
	}

	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd)
	rootCmd.AddCommand(presetsCmd)
}
