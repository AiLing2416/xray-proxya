package main

import (
	"fmt"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Validate staging changes, commit, and restart service",
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Load Staging
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Println("❌ No pending changes in staging area. Modify presets or outbounds first.")
			return
		}

		fmt.Println("🔍 Stage 1: Static Validation...")
		jsonData, err := xray.GenerateXrayJSON(cfg, nil)
		if err != nil {
			fmt.Printf("❌ JSON Generation failed: %v\n", err)
			return
		}
		if err := xray.ValidateConfig(jsonData); err != nil {
			fmt.Printf("❌ Static validation failed: %v\n", err)
			return
		}
		fmt.Println("✅ Syntax OK.")

		fmt.Println("🔍 Stage 2: Runtime Isolation Test...")
		overrides := make(map[string]int)
		p1, _ := xray.GetFreePort(); overrides["api"] = p1
		p2, _ := xray.GetFreePort(); overrides["test-socks"] = p2
		for _, m := range cfg.ActiveModes {
			if m.Enabled {
				p, _ := xray.GetFreePort()
				overrides[string(m.Mode)] = p
			}
		}
		if cfg.Gateway.Enabled {
			pD, _ := xray.GetFreePort(); overrides["dns-in"] = pD
			if cfg.Gateway.Mode == "tproxy" {
				pT, _ := xray.GetFreePort(); overrides["tproxy-in"] = pT
			}
		}

		testJSON, err := xray.GenerateXrayJSON(cfg, overrides)
		if err != nil {
			fmt.Printf("❌ Failed to generate test JSON: %v\n", err)
			return
		}

		_, cleanup, err := xray.StartXrayTemp(testJSON)
		if err != nil {
			fmt.Printf("❌ Runtime isolation test failed: %v\n", err)
			return
		}
		time.Sleep(1 * time.Second)
		cleanup()
		fmt.Println("✅ Runtime isolation test passed (using randomized ports).")

		fmt.Println("🚀 Stage 3: Committing changes...")
		if err := config.CommitStaging(); err != nil {
			fmt.Printf("❌ Failed to commit config: %v\n", err)
			return
		}

		if err := xray.RestartXrayService(); err != nil {
			fmt.Printf("⚠️ Config committed but restart failed: %v\n", err)
		} else {
			fmt.Println("✅ All changes applied and service updated.")
		}
	},
}

var undoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Discard pending changes in staging area",
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.ClearStaging(); err != nil {
			fmt.Println("ℹ️ Staging area was already clean.")
		} else {
			fmt.Println("✅ Staging area cleared. Your pending changes were discarded.")
		}
	},
}

func init() {
	rootCmd.AddCommand(applyCmd, undoCmd)
}
