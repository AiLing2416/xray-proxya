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

var roleStr string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Xray-Proxya with a specific role (server or gateway)",
	Run: func(cmd *cobra.Command, args []string) {
		role := config.RoleServer
		if roleStr == "gateway" { role = config.RoleGateway }
		fmt.Printf("🚀 Initializing Xray-Proxya as %s...\n", role)

		xrayPath := xray.GetXrayBinaryPath()
		if _, err := os.Stat(xrayPath); os.IsNotExist(err) {
			fmt.Println("⬇️ Xray core not found, downloading...")
			if err := xray.DownloadXray(); err != nil { fmt.Printf("❌ Failed: %v\n", err); return }
			fmt.Println("✅ Xray core downloaded.")
		}

		uid := uuid.New().String()
		cfg := &config.UserConfig{Role: role, UUID: uid}

		// Randomize internal ports
		for { p, _ := xray.GetFreePort(); if p >= 10000 { cfg.APIInbound = p; break } }
		for { p, _ := xray.GetFreePort(); if p >= 10000 && p != cfg.APIInbound { cfg.TestInbound = p; break } }
		fmt.Printf("📡 Internal Ports: API=%d, Test=%d\n", cfg.APIInbound, cfg.TestInbound)

		if role == config.RoleGateway {
			cfg.Gateway.LocalEnabled = true; cfg.Gateway.LANEnabled = true; cfg.Gateway.Mode = "tun"
			fmt.Println("✅ Gateway (Local & LAN) enabled by default.")
		} else {
			fmt.Println("🔑 Generating Reality keys...")
			pk, pub, _ := xray.GenerateX25519()
			fmt.Println("🔑 Generating ML-KEM keys...")
			enc, dec, _ := xray.GenerateMLKEM()

			isRoot := os.Geteuid() == 0; offset := 0; if !isRoot { offset = 10000 }
			specs := []struct{mode config.PresetMode; base int}{
				{config.ModeVLESSVision, 443}, {config.ModeVLESSReality, 8443},
				{config.ModeVLESSXHTTP, 8080}, {config.ModeVMessWS, 8081}, {config.ModeShadowsocksTCP, 8082},
			}
			for _, s := range specs {
				actualPort := s.base + offset
				if !utils.IsPortFree(actualPort) { for { p, _ := xray.GetFreePort(); if p >= 10000 { actualPort = p; break } } }
				m := config.ModeInfo{Mode: s.mode, Enabled: true, Port: actualPort}
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
		}

		if err := cfg.SaveEx(true); err != nil { fmt.Printf("❌ Failed: %v\n", err); return }
		fmt.Println("🚀 First-time automatic apply...")
		if err := config.CommitStaging(); err != nil { fmt.Printf("❌ Failed: %v\n", err); return }
		if err := xray.RestartXrayService(); err != nil { fmt.Printf("⚠️ Service failed to start: %v\n", err) } else { fmt.Println("✨ Initialization complete. Service is running.") }
	},
}

func init() {
	initCmd.Flags().StringVarP(&roleStr, "role", "r", "server", "Application role: server or gateway")
	rootCmd.AddCommand(initCmd)
}
