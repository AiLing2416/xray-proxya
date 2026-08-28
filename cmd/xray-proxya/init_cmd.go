package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	forceInit bool
	roleStr   string
)

var (
	prepareFreshInitFunc = prepareFreshInit
	ensureXrayBinaryFunc = func() error {
		xrayPath := xray.GetXrayBinaryPath()
		if _, err := os.Stat(xrayPath); os.IsNotExist(err) {
			fmt.Println("⬇️  Xray core not found. Downloading...")
			if err := xray.DownloadXray(); err != nil {
				return err
			}
			fmt.Println("✅ Xray core downloaded.")
		}
		return nil
	}
	realityTargetSelector = selectServerRealityTarget
)

func selectServerRealityTarget() (string, string, error) {
	fmt.Printf("🔍 Auto-detecting cloud provider for server...\n")
	detectedVendor := config.DetectCloudVendor()
	if detectedVendor != "" {
		fmt.Printf("☁️  Detected cloud provider: [%s]\n", detectedVendor)
		domains, err := config.GetCloudVendorDomains(detectedVendor)
		if err == nil && len(domains) > 0 {
			fmt.Printf("🔍 Benchmarking [%s] candidate pool (%d domains)...\n", detectedVendor, len(domains))
			bestDomain, rtt, err := config.BenchmarkDomains(domains, 5*time.Second)
			if err == nil {
				dest := net.JoinHostPort(bestDomain, "443")
				fmt.Printf("🎯 Selected [%s] REALITY target: %s (RTT: %.1fms, TLS 1.3 OK)\n", detectedVendor, bestDomain, float64(rtt.Microseconds())/1000.0)
				return bestDomain, dest, nil
			}
			fmt.Printf("⚠️  Candidate domains in provider [%s] failed qualification: %v. Falling back to generic pool.\n", detectedVendor, err)
		} else {
			fmt.Printf("⚠️  No candidate domains available for detected provider [%s]. Falling back to generic pool.\n", detectedVendor)
		}
	} else {
		fmt.Printf("ℹ️  Cloud provider not recognized or non-cloud IP. Using generic global domain pool.\n")
	}

	genericDomains, err := config.GetCloudVendorDomains(config.VendorGeneric)
	if err != nil || len(genericDomains) == 0 {
		return "", "", fmt.Errorf("no generic candidate domains available: %w", err)
	}

	fmt.Printf("🔍 Benchmarking generic candidate pool (%d domains)...\n", len(genericDomains))
	bestDomain, rtt, err := config.BenchmarkDomains(genericDomains, 5*time.Second)
	if err != nil {
		return "", "", fmt.Errorf("all candidate REALITY domains failed qualification: %w", err)
	}
	dest := net.JoinHostPort(bestDomain, "443")
	fmt.Printf("🎯 Selected generic REALITY target: %s (RTT: %.1fms, TLS 1.3 OK)\n", bestDomain, float64(rtt.Microseconds())/1000.0)
	return bestDomain, dest, nil
}

func runInit(cmd *cobra.Command, args []string) error {
	configPath := config.GetConfigPath()
	if _, err := os.Stat(configPath); err == nil && !forceInit {
		fmt.Println("⚠️  Configuration already exists at", configPath)
		fmt.Println("🚀 Use '--force' to overwrite (this will reset ALL settings, keys, and UUIDs).")
		return nil
	}

	role := config.RoleServer
	if roleStr == "gateway" {
		role = config.RoleGateway
	}

	var selectedSNI, selectedDest string
	if role == config.RoleServer {
		var err error
		selectedSNI, selectedDest, err = realityTargetSelector()
		if err != nil {
			fmt.Printf("❌ Failed to select qualified REALITY target: %v\n", err)
			return err
		}
	}

	// Preflight succeeded; now prepare fresh init and ensure binary exists
	prepareFreshInitFunc()
	fmt.Printf("🚀 Initializing Xray-Proxya as %s...\n", role)

	if err := ensureXrayBinaryFunc(); err != nil {
		fmt.Printf("❌ Failed to ensure Xray binary: %v\n", err)
		return err
	}

	cfg := &config.UserConfig{Role: role, UUID: uuid.New().String()}
	cfg.APIInbound, _ = utils.GetFreePort()
	cfg.TestInbound, _ = utils.GetFreePort()
	fmt.Printf("📡 Internal Ports: API=%d, Test=%d\n", cfg.APIInbound, cfg.TestInbound)

	if role == config.RoleGateway {
		cfg.Gateway.LocalEnabled = true
		cfg.Gateway.LANEnabled = true
		cfg.Gateway.Mode = "tun"
		if iface, err := gateway.DetectDefaultInterface(); err == nil {
			cfg.Gateway.LANInterface = iface
		}
		fmt.Println("✅ Gateway (Local & LAN) enabled by default.")
	}

	// COMMON PRESET INITIALIZATION
	pk, pub, _ := xray.GenerateX25519()
	enc, dec, _ := xray.GenerateMLKEM()
	isRoot := os.Geteuid() == 0
	offset := 0
	if !isRoot {
		offset = 10000
	}

	specs := []struct {
		mode config.PresetMode
		base int
	}{
		{config.ModeVLESSVision, 443},
		{config.ModeVLESSReality, 8443},
		{config.ModeVLESSXHTTP, 8080},
		{config.ModeVMessWS, 8081},
		{config.ModeShadowsocksTCP, 8082},
	}

	for _, s := range specs {
		actualPort := s.base + offset
		if !utils.IsPortFree(actualPort) {
			for {
				p, _ := xray.GetFreePort()
				if p >= 10000 {
					actualPort = p
					break
				}
			}
		}

		// Server role defaults to ENABLED only for Preset 1 (ModeVLESSVision).
		// Gateway role defaults to all disabled.
		enabled := (role == config.RoleServer && s.mode == config.ModeVLESSVision)
		m := config.ModeInfo{Mode: s.mode, Enabled: enabled, Port: actualPort}

		switch s.mode {
		case config.ModeVLESSVision:
			m.SNI = selectedSNI
			m.Dest = selectedDest
			if role == config.RoleServer {
				fp, err := config.GetRandomRealityFingerprint()
				if err != nil {
					return fmt.Errorf("generate reality fingerprint: %w", err)
				}
				m.Fingerprint = fp
			}
			m.Settings.PrivateKey, m.Settings.PublicKey, m.Settings.ShortID = pk, pub, utils.GenerateRandomString(4)
		case config.ModeVLESSReality:
			m.SNI = selectedSNI
			m.Dest = selectedDest
			m.Path = "/" + utils.GenerateRandomString(8)
			if role == config.RoleServer {
				fp, err := config.GetRandomRealityFingerprint()
				if err != nil {
					return fmt.Errorf("generate reality fingerprint: %w", err)
				}
				m.Fingerprint = fp
			}
			m.Settings.PrivateKey, m.Settings.PublicKey, m.Settings.ShortID = pk, pub, utils.GenerateRandomString(4)
		case config.ModeVLESSXHTTP:
			m.Path = "/" + utils.GenerateRandomString(8)
			m.Settings.Password, m.Settings.PrivateKey = enc, dec
		case config.ModeVMessWS:
			m.Path = "/" + utils.GenerateRandomString(8)
		case config.ModeShadowsocksTCP:
			m.Settings.Cipher, m.Settings.Password = "aes-256-gcm", utils.GenerateRandomString(16)
		}
		cfg.Presets = append(cfg.Presets, m)
	}

	if err := cfg.SaveEx(true); err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		return err
	}
	fmt.Println("🚀 First-time automatic apply...")
	config.CommitStaging()

	fmt.Println("✨ Initialization complete. Service is ready but NOT started.")
	fmt.Println("🚀 Use 'service start' to run manually when ready.")
	return nil
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Xray-Proxya with a specific role (server or gateway)",
	Run: func(cmd *cobra.Command, args []string) {
		_ = runInit(cmd, args)
	},
}

func prepareFreshInit() {
	if os.Geteuid() == 0 {
		if err := gateway.CleanupFirewall(); err != nil {
			fmt.Printf("⚠️ Failed to clean gateway firewall: %v\n", err)
		}
		_ = xray.ManageSystemdUnit("stop", xray.MainServiceUnit)
	} else {
		_ = xray.ManageSystemdUnit("stop", xray.MainServiceUnit)
	}
	for _, name := range []string{
		"config.active.json",
		"pathd.json",
		"gateway.policy-rules.json",
		"gateway.tun.disabled",
		"gateway.path-tun.disabled",
		"tune.runtime.json",
		".tune_state",
	} {
		_ = os.Remove(filepath.Join(config.GetConfigDir(), name))
	}
}

func init() {
	initCmd.Flags().StringVarP(&roleStr, "role", "r", "server", "Application role: server or gateway")
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Force initialization (overwrites existing config)")
	initCmd.RegisterFlagCompletionFunc("role", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"server", "gateway"}, cobra.ShellCompDirectiveNoFileComp
	})
	rootCmd.AddCommand(initCmd)
}

