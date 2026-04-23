package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"xray-proxya/internal/camouflage"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	runAudit bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Xray core in foreground",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("❌ Failed to load config. Please run 'init' first.")
			return
		}

		// v0.2.4 Port Policy:
		// By default (especially as a service), we are STRICT.
		// We only allow port drift if --audit is explicitly provided.
		changed := false
		auditPort := func(label string, current *int) {
			if *current <= 0 {
				return
			}
			if !utils.IsPortFree(*current) {
				if runAudit {
					newP, _ := xray.GetFreePort()
					fmt.Printf("⚠️  Warning: %s Port %d occupied, switched to %d\n", label, *current, newP)
					*current = newP
					changed = true
				} else {
					fmt.Printf("❌ Error: %s Port %d is occupied. Use --audit to allow dynamic port selection.\n", label, *current)
					os.Exit(1)
				}
			}
		}

		auditPort("API", &cfg.APIInbound)
		for i := range cfg.ActiveModes {
			if cfg.ActiveModes[i].Enabled {
				auditPort(string(cfg.ActiveModes[i].Mode), &cfg.ActiveModes[i].Port)
			}
		}

		if changed {
			cfg.Save()
		}

		// Camouflage Setup
		camoPort := 0
		hasSkin := false
		for _, m := range cfg.ActiveModes {
			if m.Enabled && m.Skin {
				hasSkin = true
				break
			}
		}
		if hasSkin {
			camoPort, _ = xray.GetFreePort()
			fmt.Printf("🎭 Starting Camouflage server (TLS) on 127.0.0.1:%d...\n", camoPort)

			// Generate temporary self-signed certs for camouflage
			certPath := filepath.Join(config.GetConfigDir(), "camo.crt")
			keyPath := filepath.Join(config.GetConfigDir(), "camo.key")
			if err := utils.GenerateSelfSignedCert(certPath, keyPath); err != nil {
				fmt.Printf("⚠️  Failed to generate camouflage certs: %v\n", err)
			}

			camoMgr := camouflage.NewManager(cfg.ActiveModes)
			go func() {
				if err := http.ListenAndServeTLS(fmt.Sprintf("127.0.0.1:%d", camoPort), certPath, keyPath, camoMgr); err != nil {
					fmt.Printf("⚠️  Camouflage server error: %v\n", err)
				}
			}()
		}

		fmt.Println("🔍 Generating configuration...")
		overrides := make(map[string]int)
		if camoPort > 0 {
			overrides["camouflage"] = camoPort
		}
		jsonData, err := xray.GenerateXrayJSON(cfg, overrides, "")
		if err != nil {
			fmt.Printf("❌ Failed to generate config: %v\n", err)
			return
		}

		confPath := filepath.Join(config.GetConfigDir(), "config.active.json")
		os.WriteFile(confPath, jsonData, 0644)

		fmt.Println("🚀 Starting Xray core in foreground...")
		process, err := xray.StartXray(confPath)
		if err != nil {
			fmt.Printf("❌ Failed to start Xray: %v\n", err)
			return
		}

		pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
		os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", process.Process.Pid)), 0600)

		cleanup := func() {
			os.Remove(pidPath)
		}

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- process.Wait()
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		select {
		case sig := <-sigChan:
			fmt.Printf("\n🛑 Stopping Xray (%s)...\n", sig)
			process.Process.Signal(syscall.SIGTERM)
			<-waitCh
			cleanup()
		case err := <-waitCh:
			cleanup()
			if err != nil {
				fmt.Printf("\n❌ Xray core exited unexpectedly: %v\n", err)
				if exitErr, ok := err.(*exec.ExitError); ok {
					if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
						os.Exit(status.ExitStatus())
					}
				}
				os.Exit(1)
			}
			fmt.Println("\nℹ️ Xray core exited normally.")
		}
	},
}

func init() {
	runCmd.Flags().BoolVar(&runAudit, "audit", false, "Enable dynamic port negotiation if configured ports are occupied")
	rootCmd.AddCommand(runCmd)
}
