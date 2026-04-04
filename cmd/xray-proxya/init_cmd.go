package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
		if roleStr == "gateway" {
			role = config.RoleGateway
		}
		fmt.Printf("🚀 Initializing Xray-Proxya as %s...\n", role)

		home, _ := os.UserHomeDir()
		localBin := filepath.Join(home, ".local", "bin")
		os.MkdirAll(localBin, 0755)

		xrayPath := xray.GetXrayBinaryPath()
		if _, err := os.Stat(xrayPath); os.IsNotExist(err) {
			fmt.Println("⬇️ Xray core not found, downloading...")
			if err := downloadXray(xrayPath); err != nil {
				fmt.Printf("❌ Failed to download Xray: %v\n", err)
				return
			}
			os.Chmod(xrayPath, 0755)
			fmt.Println("✅ Xray core downloaded.")
		}

		uid := uuid.New().String()
		cfg := &config.UserConfig{
			Role:        role,
			UUID:        uid,
			APIInbound:  10085,
			TestInbound: 10086,
		}

		if role == config.RoleGateway {
			cfg.Gateway.Enabled = true
			cfg.Gateway.Mode = "tun"
			fmt.Println("✅ Gateway mode enabled by default.")
		} else {
			fmt.Println("🔑 Generating Reality keys...")
			pk, pub, _ := xray.GenerateX25519()

			// 1. VLESS-Reality-XHTTP
			mode1 := config.ModeInfo{
				Mode:    config.ModeVLESSReality,
				Enabled: true,
				Port:    4433,
				SNI:     config.GetRandomRealityDomain(),
				Dest:    "www.google.com:443",
				Path:    "/" + utils.GenerateRandomString(8),
			}
			mode1.Settings.PrivateKey = pk
			mode1.Settings.PublicKey = pub
			mode1.Settings.ShortID = utils.GenerateRandomString(4)
			cfg.ActiveModes = append(cfg.ActiveModes, mode1)

			// 2. VLESS-Vision-Reality-TCP
			mode2 := config.ModeInfo{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    4434,
				SNI:     config.GetRandomRealityDomain(),
				Dest:    "www.google.com:443",
			}
			mode2.Settings.PrivateKey = pk
			mode2.Settings.PublicKey = pub
			mode2.Settings.ShortID = utils.GenerateRandomString(4)
			cfg.ActiveModes = append(cfg.ActiveModes, mode2)

			// 3. VLESS-XHTTP-KEM
			fmt.Println("🔑 Generating ML-KEM keys...")
			enc, dec, _ := xray.GenerateMLKEM()
			mode3 := config.ModeInfo{
				Mode:    config.ModeVLESSXHTTP,
				Enabled: true,
				Port:    4435,
				Path:    "/" + utils.GenerateRandomString(8),
			}
			mode3.Settings.Password = enc
			mode3.Settings.PrivateKey = dec
			cfg.ActiveModes = append(cfg.ActiveModes, mode3)

			// 4. VMess-WS
			mode4 := config.ModeInfo{
				Mode:    config.ModeVMessWS,
				Enabled: true,
				Port:    4436,
				Path:    "/" + utils.GenerateRandomString(8),
			}
			cfg.ActiveModes = append(cfg.ActiveModes, mode4)

			// 5. Shadowsocks-TCP
			mode5 := config.ModeInfo{
				Mode:    config.ModeShadowsocksTCP,
				Enabled: true,
				Port:    4437,
			}
			mode5.Settings.Cipher = "aes-256-gcm"
			mode5.Settings.Password = utils.GenerateRandomString(16)
			cfg.ActiveModes = append(cfg.ActiveModes, mode5)
		}

		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to save initial config to staging: %v\n", err)
			return
		}

		fmt.Println("🚀 First-time automatic apply...")
		if err := config.CommitStaging(); err != nil {
			fmt.Printf("❌ Initial commit failed: %v\n", err)
			return
		}
		
		if err := xray.RestartXrayService(); err != nil {
			fmt.Printf("⚠️ Service failed to start: %v\n", err)
		} else {
			fmt.Println("✨ Initialization complete. Service is running.")
		}
	},
}

func downloadXray(dest string) error {
	arch := runtime.GOARCH
	var xrayArch string
	if arch == "arm64" {
		xrayArch = "arm64-v8a"
	} else {
		xrayArch = "64"
	}
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip", xrayArch)
	resp, err := http.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()

	tmpZip, _ := os.CreateTemp("", "xray-*.zip")
	defer os.Remove(tmpZip.Name())
	io.Copy(tmpZip, resp.Body)
	tmpZip.Close()

	r, err := zip.OpenReader(tmpZip.Name())
	if err != nil { return err }
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "xray" {
			rc, _ := f.Open()
			outFile, _ := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			io.Copy(outFile, rc)
			outFile.Close()
			rc.Close()
			return nil
		}
	}
	return fmt.Errorf("xray binary not found in zip")
}

func init() {
	initCmd.Flags().StringVarP(&roleStr, "role", "r", "server", "Application role: server or gateway")
	rootCmd.AddCommand(initCmd)
}
