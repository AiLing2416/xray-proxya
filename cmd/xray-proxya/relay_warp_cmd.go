package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"xray-proxya/internal/applyops"
	"xray-proxya/internal/config"
	"xray-proxya/internal/relaytest"
	"xray-proxya/internal/warp"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	relayWarpEndpoint string
	relayWarpApply    bool
	relayWarpNoTest   bool
	relayWarpJSON     bool
)

var relayWarpCmd = &cobra.Command{
	Use:   "warp",
	Short: "Quickly generate and import Cloudflare WARP relay node (STAGING)",
	Long: strings.TrimSpace(`
Automatically generate a free Cloudflare WARP WireGuard account and import it
as a relay node named 'CF_WARP' into STAGING configuration.

If a relay node named 'CF_WARP' already exists, its WireGuard credentials and endpoint
will be overwritten while preserving custom routing assignments.
`),
	RunE: runRelayWarp,
}

func runRelayWarp(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = cmd.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !relayWarpJSON {
		fmt.Println("⚡ Generating Cloudflare WARP free account...")
	}

	info, err := warp.RegisterFreeAccount(ctx, relayWarpEndpoint)
	if err != nil {
		return fmt.Errorf("❌ Failed to register Cloudflare WARP account: %w", err)
	}

	if !relayWarpJSON {
		fmt.Printf("  ✔ WireGuard keypair generated (Curve25519)\n")
		fmt.Printf("  ✔ Free device registered via Cloudflare API\n")
		if info.IPv4 != "" {
			fmt.Printf("  ✔ Assigned IPv4: %s/32\n", info.IPv4)
		}
		if info.IPv6 != "" {
			fmt.Printf("  ✔ Assigned IPv6: %s/128\n", info.IPv6)
		}
		if len(info.Reserved) == 3 {
			fmt.Printf("  ✔ Reserved client ID: %v\n", info.Reserved)
		}
		fmt.Printf("  ✔ Endpoint: %s\n", info.Endpoint)
	}

	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer}
	}

	outboundMap := warp.BuildOutboundConfig(info)

	var foundIndex = -1
	for i, co := range cfg.CustomOutbounds {
		if co.Alias == warp.DefaultWarpAlias {
			foundIndex = i
			break
		}
	}

	if foundIndex >= 0 {
		if !relayWarpJSON {
			fmt.Printf("🔄 Overwriting existing '%s' relay in STAGING...\n", warp.DefaultWarpAlias)
		}
		cfg.CustomOutbounds[foundIndex].Config = outboundMap
		cfg.CustomOutbounds[foundIndex].Enabled = true
	} else {
		if !relayWarpJSON {
			fmt.Printf("➕ Adding '%s' relay to STAGING...\n", warp.DefaultWarpAlias)
		}
		newCO := config.CustomOutbound{
			Alias:    warp.DefaultWarpAlias,
			Enabled:  true,
			UserUUID: uuid.New().String(),
			Config:   outboundMap,
		}
		cfg.CustomOutbounds = append(cfg.CustomOutbounds, newCO)
	}

	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}

	if !relayWarpNoTest && !relayWarpJSON {
		fmt.Printf("🔍 Testing node '%s' connectivity...\n", warp.DefaultWarpAlias)
		res, err := relaytest.RunTest(ctx, cfg, warp.DefaultWarpAlias, relaytest.ModeSimple)
		if err != nil || res == nil {
			fmt.Printf("⚠️  Test check notice: %v\n", err)
		} else {
			fmt.Print(relaytest.RenderTerminal([]*relaytest.TestResult{res}))
			fmt.Println()
		}
	}

	if relayWarpJSON {
		resPayload := map[string]interface{}{
			"alias":      warp.DefaultWarpAlias,
			"status":     "success",
			"id":         info.ID,
			"ipv4":       info.IPv4,
			"ipv6":       info.IPv6,
			"endpoint":   info.Endpoint,
			"client_id":  info.ClientID,
			"reserved":   info.Reserved,
			"created_at": info.CreatedAt,
		}
		data, err := json.MarshalIndent(resPayload, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to serialize JSON output: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	if relayWarpApply {
		fmt.Println("🚀 Applying staging configuration...")
		lines, err := applyops.ApplyPending(applyops.Options{Start: true})
		for _, line := range lines {
			fmt.Println(line)
		}
		if err != nil {
			return fmt.Errorf("❌ Apply failed: %w", err)
		}
		fmt.Printf("✅ Cloudflare WARP relay '%s' applied and active.\n", warp.DefaultWarpAlias)
	} else {
		fmt.Printf("✅ Cloudflare WARP relay '%s' saved to STAGING.\n", warp.DefaultWarpAlias)
		fmt.Println("💡 Run 'xray-proxya apply' to commit changes, or 'xray-proxya relay warp --apply' next time.")
	}

	return nil
}

func init() {
	relayWarpCmd.Flags().StringVarP(&relayWarpEndpoint, "endpoint", "e", "", "WireGuard endpoint (defaults to Cloudflare engage.cloudflareclient.com:2408)")
	relayWarpCmd.Flags().BoolVarP(&relayWarpApply, "apply", "a", false, "Commit changes directly to active configuration")
	relayWarpCmd.Flags().BoolVar(&relayWarpNoTest, "no-test", false, "Skip node connectivity testing after registration")
	relayWarpCmd.Flags().BoolVar(&relayWarpJSON, "json", false, "Output registration details in JSON format")

	outboundCmd.AddCommand(relayWarpCmd)
}
