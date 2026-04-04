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
			fmt.Println("🔑 Generating ML-KEM keys...")
			enc, dec, _ := xray.GenerateMLKEM()

			isRoot := os.Geteuid() == 0
			offset := 0
			if !isRoot { offset = 10000 }

			// Desired Port Map (Role -> BasePort)
			type portSpec struct {
				mode config.PresetMode
				base int
			}
			specs := []portSpec{
				{config.ModeVLESSVision, 443},
				{config.ModeVLESSReality, 8443},
				{config.ModeVLESSXHTTP, 8080},
				{config.ModeVMessWS, 8081},
				{config.ModeShadowsocksTCP, 8082},
			}

			var portWarnings []string

			for _, s := range specs {
				targetPort := s.base + offset
				actualPort := targetPort
				
				if !utils.IsPortFree(actualPort) {
					// Fallback: Random 10000-65535
					for {
						p, _ := xray.GetFreePort()
						if p >= 10000 {
							actualPort = p
							break
						}
					}
					portWarnings = append(portWarnings, fmt.Sprintf("⚠️  Port %d was busy, switched %s to %d", targetPort, s.mode, actualPort))
				}

				m := config.ModeInfo{
					Mode:    s.mode,
					Enabled: true,
					Port:    actualPort,
				}

				// Assign technical specific fields
				switch s.mode {
				case config.ModeVLESSVision:
					m.SNI = config.GetRandomRealityDomain()
					m.Dest = "www.google.com:443"
					m.Settings.PrivateKey = pk
					m.Settings.PublicKey = pub
					m.Settings.ShortID = utils.GenerateRandomString(4)
				case config.ModeVLESSReality:
					m.SNI = config.GetRandomRealityDomain()
					m.Dest = "www.google.com:443"
					m.Path = "/" + utils.GenerateRandomString(8)
					m.Settings.PrivateKey = pk
					m.Settings.PublicKey = pub
					m.Settings.ShortID = utils.GenerateRandomString(4)
				case config.ModeVLESSXHTTP:
					m.Path = "/" + utils.GenerateRandomString(8)
					m.Settings.Password = enc
					m.Settings.PrivateKey = dec
				case config.ModeVMessWS:
					m.Path = "/" + utils.GenerateRandomString(8)
				case config.ModeShadowsocksTCP:
					m.Settings.Cipher = "aes-256-gcm"
					m.Settings.Password = utils.GenerateRandomString(16)
				}
				cfg.ActiveModes = append(cfg.ActiveModes, m)
			}

			// Print warnings at the end
			for _, w := range portWarnings { fmt.Println(w) }
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
