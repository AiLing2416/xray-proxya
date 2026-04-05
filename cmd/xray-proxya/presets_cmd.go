package main

import (
	"fmt"
	"strconv"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

// Fixed Priority Order for v0.1.3+
var presetOrder = []config.PresetMode{
	config.ModeVLESSVision,
	config.ModeVLESSReality,
	config.ModeVLESSXHTTP,
	config.ModeVMessWS,
	config.ModeShadowsocksTCP,
}

var roleMap = map[string]config.PresetMode{
	"1": config.ModeVLESSVision,    "v": config.ModeVLESSVision,    "vision":  config.ModeVLESSVision,
	"2": config.ModeVLESSReality,   "r": config.ModeVLESSReality,   "reality": config.ModeVLESSReality,
	"3": config.ModeVLESSXHTTP,     "q": config.ModeVLESSXHTTP,     "quantum": config.ModeVLESSXHTTP,
	"4": config.ModeVMessWS,        "c": config.ModeVMessWS,        "classic": config.ModeVMessWS,
	"5": config.ModeShadowsocksTCP, "s": config.ModeShadowsocksTCP, "socks":   config.ModeShadowsocksTCP,
}

var techLabels = map[config.PresetMode]string{
	config.ModeVLESSVision:    "VLess-Vision-Reality-TCP",
	config.ModeVLESSReality:   "VLess-Reality-XHTTP",
	config.ModeVLESSXHTTP:     "VLess-XHTTP-KEM768",
	config.ModeVMessWS:        "VMess-WS-Chacha20",
	config.ModeShadowsocksTCP: "SS-TCP-AES256GCM",
}

var presetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all preset inbounds in priority order",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleServer {
			fmt.Printf("❌ Command 'presets' is only available in 'server' mode.\n")
			return
		}

		fmt.Printf("\n%-3s | %-25s | %-8s | %-6s | %-s\n", "ID", "TECHNICAL COMBINATION", "STATUS", "PORT", "SNI/PATH")
		fmt.Println("-----------------------------------------------------------------------------------------")
		
		// Display based on fixed presetOrder
		for i, targetMode := range presetOrder {
			for _, m := range cfg.ActiveModes {
				if m.Mode == targetMode {
					status := "OFF"; if m.Enabled { status = "ON" }
					label := techLabels[m.Mode]
					details := m.Path; if m.SNI != "" { details = m.SNI }
					fmt.Printf("%-3d | %-25s | %-8s | %-6d | %-s\n", i+1, label, status, m.Port, details)
					break
				}
			}
		}
	},
}

func findPreset(cfg *config.UserConfig, input string) int {
	// 1. Try Alias/Direct Mode Match
	if targetMode, ok := roleMap[input]; ok {
		for i, m := range cfg.ActiveModes {
			if m.Mode == targetMode { return i }
		}
	}
	
	// 2. Try Numeric ID Match (Strictly based on presetOrder index)
	if id, err := strconv.Atoi(input); err == nil && id >= 1 && id <= len(presetOrder) {
		targetMode := presetOrder[id-1]
		for i, m := range cfg.ActiveModes {
			if m.Mode == targetMode { return i }
		}
	}
	return -1
}

var presetsSetCmd = &cobra.Command{
	Use:   "set [ID|Role]",
	Short: "Modify preset parameters (port, state, secrets)",
	ValidArgs: []string{"1", "2", "3", "4", "5", "v", "r", "q", "c", "s", "vision", "reality", "quantum", "classic", "socks"},
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }

		idx := findPreset(cfg, args[0])
		if idx != -1 {
			port, _ := cmd.Flags().GetInt("port")
			if port != 0 { cfg.ActiveModes[idx].Port = port }
			if cmd.Flags().Changed("on") { cfg.ActiveModes[idx].Enabled = true }
			if cmd.Flags().Changed("off") { cfg.ActiveModes[idx].Enabled = false }
			regen, _ := cmd.Flags().GetBool("regen")
			if regen { cfg.ActiveModes[idx].RegenFlag = true }
			
			cfg.SaveEx(true)
			status := "OFF"; if cfg.ActiveModes[idx].Enabled { status = "ON" }
			fmt.Printf("✅ Updated [%s] -> Status: %s, Port: %d (STAGING)\n", 
				techLabels[cfg.ActiveModes[idx].Mode], status, cfg.ActiveModes[idx].Port)
		} else {
			fmt.Printf("❌ Preset identifier '%s' not found.\n", args[0])
		}
	},
}

func init() {
	presetsSetCmd.Flags().IntP("port", "p", 0, "Set new port")
	presetsSetCmd.Flags().Bool("on", false, "Enable the preset")
	presetsSetCmd.Flags().Bool("off", false, "Disable the preset")
	presetsSetCmd.Flags().BoolP("regen", "r", false, "Regenerate secrets on apply")
	
	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd)
	rootCmd.AddCommand(presetsCmd)
}
