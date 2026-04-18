package main

import (
	"fmt"
	"os"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	forceInit bool
	roleStr   string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Xray-Proxya with a specific role (server or gateway)",
	Run: func(cmd *cobra.Command, args []string) {
		configPath := config.GetConfigPath()
		if _, err := os.Stat(configPath); err == nil && !forceInit {
			fmt.Println("⚠️  Configuration already exists at", configPath)
			fmt.Println("🚀 Use '--force' to overwrite (this will reset ALL settings, keys, and UUIDs).")
			return
		}

		role := config.RoleServer
		if roleStr == "gateway" { role = config.RoleGateway }
		fmt.Printf("🚀 Initializing Xray-Proxya as %s...\n", role)

		xrayPath := xray.GetXrayBinaryPath()
		if _, err := os.Stat(xrayPath); os.IsNotExist(err) {
			fmt.Println("⬇️  Xray core not found. Downloading...")
			if err := xray.DownloadXray(); err != nil {
				fmt.Printf("❌ Failed to download Xray: %v\n", err)
				return
			}
			fmt.Println("✅ Xray core downloaded.")
		}

		cfg := &config.UserConfig{Role: role, UUID: uuid.New().String()}
		cfg.APIInbound = 10085
		cfg.TestInbound = 10086
		fmt.Printf("📡 Internal Ports: API=%d, Test=%d\n", cfg.APIInbound, cfg.TestInbound)

		if role == config.RoleGateway {
			cfg.Gateway.LocalEnabled = true; cfg.Gateway.LANEnabled = true; cfg.Gateway.Mode = "tun"
			cfg.Gateway.LANInterface = "eth0"
			fmt.Println("✅ Gateway (Local & LAN) enabled by default.")
		}

		// COMMON PRESET INITIALIZATION
		pk, pub, _ := xray.GenerateX25519()
		enc, dec, _ := xray.GenerateMLKEM()
		isRoot := os.Geteuid() == 0; offset := 0; if !isRoot { offset = 10000 }
		
		specs := []struct{mode config.PresetMode; base int}{
			{config.ModeVLESSVision, 443}, {config.ModeVLESSReality, 8443},
			{config.ModeVLESSXHTTP, 8080}, {config.ModeVMessWS, 8081}, {config.ModeShadowsocksTCP, 8082},
		}

		for _, s := range specs {
			actualPort := s.base + offset
			if !utils.IsPortFree(actualPort) { for { p, _ := xray.GetFreePort(); if p >= 10000 { actualPort = p; break } } }
			
			// For Gateway role, we default to ENABLED: FALSE to avoid port conflicts
			m := config.ModeInfo{Mode: s.mode, Enabled: (role == config.RoleServer), Port: actualPort}
			
			switch s.mode {
			case config.ModeVLESSVision:
				m.SNI = config.GetRandomRealityDomain(); m.Dest = "www.google.com:443"
				m.Settings.PrivateKey, m.Settings.PublicKey, m.Settings.ShortID = pk, pub, utils.GenerateRandomString(4)
			case config.ModeVLESSReality:
				m.SNI = config.GetRandomRealityDomain(); m.Dest = "www.google.com:443"
				m.Path = "/" + utils.GenerateRandomString(8)
				m.Settings.PrivateKey, m.Settings.PublicKey, m.Settings.ShortID = pk, pub, utils.GenerateRandomString(4)
			case config.ModeVLESSXHTTP:
				m.Path = "/" + utils.GenerateRandomString(8); m.Settings.Password, m.Settings.PrivateKey = enc, dec
			case config.ModeVMessWS: m.Path = "/" + utils.GenerateRandomString(8)
			case config.ModeShadowsocksTCP:
				m.Settings.Cipher, m.Settings.Password = "aes-256-gcm", utils.GenerateRandomString(16)
			}
			cfg.ActiveModes = append(cfg.ActiveModes, m)
		}

		if err := cfg.SaveEx(true); err != nil { fmt.Printf("❌ Failed: %v\n", err); return }
		fmt.Println("🚀 First-time automatic apply...")
		config.CommitStaging()
		
		fmt.Println("✨ Initialization complete. Service is ready but NOT started.")
		fmt.Println("🚀 Use 'service start' to run manually when ready.")
	},
}

func init() {
	initCmd.Flags().StringVarP(&roleStr, "role", "r", "server", "Application role: server or gateway")
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Force initialization (overwrites existing config)")
	rootCmd.AddCommand(initCmd)
}
