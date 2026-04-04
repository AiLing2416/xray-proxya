package main

import (
	"fmt"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Manage preset inbound slots (STAGING)",
}

var roleMap = map[string]config.PresetMode{
	"1": config.ModeVLESSReality, "r": config.ModeVLESSReality, "reality": config.ModeVLESSReality,
	"2": config.ModeVLESSVision,  "v": config.ModeVLESSVision,  "vision":  config.ModeVLESSVision,
	"3": config.ModeVLESSXHTTP,   "q": config.ModeVLESSXHTTP,   "quantum": config.ModeVLESSXHTTP,
	"4": config.ModeVMessWS,      "c": config.ModeVMessWS,      "classic": config.ModeVMessWS,
	"5": config.ModeShadowsocksTCP, "s": config.ModeShadowsocksTCP, "socks": config.ModeShadowsocksTCP,
}

var techLabels = map[config.PresetMode]string{
	config.ModeVLESSReality:   "VLess-Reality-XHTTP",
	config.ModeVLESSVision:    "VLess-Vision-Reality-TCP",
	config.ModeVLESSXHTTP:     "VLess-XHTTP-KEM768",
	config.ModeVMessWS:        "VMess-WS-Chacha20",
	config.ModeShadowsocksTCP: "SS-TCP-AES256GCM",
}

var presetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all preset inbounds with technical details",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleServer {
			fmt.Printf("❌ Command 'presets' is only available in 'server' mode (Current: %s).\n", cfg.Role)
			return
		}

		fmt.Printf("\n%-3s | %-25s | %-8s | %-6s | %-s\n", "ID", "TECHNICAL COMBINATION", "STATUS", "PORT", "SNI/PATH")
		fmt.Println("-----------------------------------------------------------------------------------------")
		for i, m := range cfg.ActiveModes {
			status := "OFF"
			if m.Enabled { status = "ON" }
			label := techLabels[m.Mode]
			
			details := m.Path
			if m.SNI != "" { details = m.SNI }
			fmt.Printf("%-3d | %-25s | %-8s | %-6d | %-s\n", i+1, label, status, m.Port, details)
		}
	},
}

func findPreset(cfg *config.UserConfig, input string) int {
	if targetMode, ok := roleMap[input]; ok {
		for i, m := range cfg.ActiveModes {
			if m.Mode == targetMode { return i }
		}
	}
	return -1
}

var presetsSetCmd = &cobra.Command{
	Use:   "set [ID|Role]",
	Short: "Modify preset parameters (port, state, secrets)",
	ValidArgs: []string{"1", "2", "3", "4", "5", "r", "v", "q", "c", "s", "reality", "vision", "quantum", "classic", "socks"},
	Long: `Modify a preset inbound in STAGING area.
Examples:
  xray-proxya presets set 1 --port 8443 --on
  xray-proxya presets set quantum --off
  xray-proxya presets set 3 -r (flag for secret regeneration on next apply)`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		if cfg.Role != config.RoleServer {
			fmt.Printf("❌ Command 'presets' is only available in 'server' mode.\n")
			return
		}

		idx := findPreset(cfg, args[0])
		if idx != -1 {
			// 1. Handle Port
			port, _ := cmd.Flags().GetInt("port")
			if port != 0 { cfg.ActiveModes[idx].Port = port }
			
			// 2. Handle State
			if cmd.Flags().Changed("on") { cfg.ActiveModes[idx].Enabled = true }
			if cmd.Flags().Changed("off") { cfg.ActiveModes[idx].Enabled = false }
			
			// 3. Handle Regeneration
			regen, _ := cmd.Flags().GetBool("regen")
			if regen { cfg.ActiveModes[idx].RegenFlag = true }
			
			cfg.SaveEx(true)
			status := "OFF"
			if cfg.ActiveModes[idx].Enabled { status = "ON" }
			fmt.Printf("✅ Updated slot %d [%s] -> Status: %s, Port: %d (STAGING)\n", 
				idx+1, techLabels[cfg.ActiveModes[idx].Mode], status, cfg.ActiveModes[idx].Port)
			if regen { fmt.Println("✨ Secrets will be regenerated on next 'apply'.") }
		} else {
			fmt.Printf("❌ Preset identifier '%s' not found.\n", args[0])
		}
	},
}

func init() {
	presetsSetCmd.Flags().IntP("port", "p", 0, "Set new port")
	presetsSetCmd.Flags().Bool("on", false, "Enable the preset")
	presetsSetCmd.Flags().Bool("off", false, "Disable the preset")
	presetsSetCmd.Flags().BoolP("regen", "r", false, "Regenerate secrets (keys/passwords) on apply")
	
	presetsCmd.AddCommand(presetsListCmd, presetsSetCmd)
	rootCmd.AddCommand(presetsCmd)
}
