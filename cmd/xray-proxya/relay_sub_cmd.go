package main

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/relaysub"
	"xray-proxya/internal/relaytest"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	relaySubTest bool
)

var relaySubCmd = &cobra.Command{
	Use:     "sub",
	Aliases: []string{"subscription", "subs"},
	Short:   "Manage upstream subscription links for relay nodes in STAGING",
}

func getRelaySubNames() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil || len(cfg.RelaySubs) == 0 {
		return nil
	}
	var names []string
	for name := range cfg.RelaySubs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func completeRelaySubNamesArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return getRelaySubNames(), cobra.ShellCompDirectiveNoFileComp
}

var relaySubAddCmd = &cobra.Command{
	Use:   "add [airport-name] [subscription-url]",
	Short: "Add and pull relay nodes from a subscription link into STAGING",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name := strings.TrimSpace(args[0])
		subURL := strings.TrimSpace(args[1])

		if name == "" || strings.Contains(name, "/") || strings.Contains(name, " ") {
			fmt.Println("❌ Invalid airport name. It must not be empty or contain '/' or spaces.")
			return
		}

		u, err := url.Parse(subURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			fmt.Println("❌ Invalid subscription URL. It must start with http:// or https://.")
			return
		}

		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer}
		}
		if cfg.RelaySubs == nil {
			cfg.RelaySubs = make(map[string]string)
		}

		if _, exists := cfg.RelaySubs[name]; exists {
			fmt.Printf("⚠️  Subscription '%s' already exists. Use 'relay sub update %s' to refresh, or remove it first.\n", name, name)
			return
		}

		fmt.Printf("🌐 Fetching subscription '%s'...\n", name)
		body, err := relaysub.FetchSubscription(context.Background(), subURL)
		if err != nil {
			fmt.Printf("❌ Failed to fetch subscription: %v\n", err)
			return
		}

		nodes, skipped, err := relaysub.ParseSubscription(name, body)
		if err != nil {
			fmt.Printf("❌ Failed to parse subscription payload: %v\n", err)
			return
		}

		if len(nodes) == 0 {
			fmt.Printf("❌ No valid proxy nodes (VLESS, VMess, Shadowsocks) found in subscription. (%d skipped)\n", skipped)
			return
		}

		// Preview Information
		fmt.Printf("📥 Subscription parsed successfully:\n")
		fmt.Printf("   • Valid proxy nodes: %d\n", len(nodes))
		if skipped > 0 {
			fmt.Printf("   • Skipped lines:     %d (unsupported protocols or announcements)\n", skipped)
		}
		fmt.Println("\n📋 Previewing nodes to import into STAGING:")
		previewLimit := 10
		if len(nodes) < previewLimit {
			previewLimit = len(nodes)
		}
		for i := 0; i < previewLimit; i++ {
			n := nodes[i]
			proto, _ := n.Config["protocol"].(string)
			fmt.Printf("   %2d. %-32s (%s)\n", i+1, n.Alias, proto)
		}
		if len(nodes) > previewLimit {
			fmt.Printf("   ... and %d more nodes\n", len(nodes)-previewLimit)
		}
		fmt.Println()

		// Add nodes to staging
		for _, n := range nodes {
			co := config.CustomOutbound{
				Alias:    n.Alias,
				Enabled:  true,
				UserUUID: uuid.New().String(),
				Config:   n.Config,
			}
			cfg.CustomOutbounds = append(cfg.CustomOutbounds, co)
		}
		cfg.RelaySubs[name] = subURL

		if relaySubTest {
			fmt.Println("🔍 Running connectivity tests for imported nodes...")
			var aliases []string
			for _, n := range nodes {
				aliases = append(aliases, n.Alias)
			}
			results, err := relaytest.RunTests(context.Background(), cfg, aliases, relaytest.ModeSimple, 4)
			if err != nil {
				fmt.Printf("⚠️  Test encountered error: %v\n", err)
			} else {
				fmt.Print(relaytest.RenderTerminal(results))
				fmt.Println()
			}
		}

		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to save STAGING configuration: %v\n", err)
			return
		}

		fmt.Printf("✅ Added %d relay nodes for '%s' to STAGING.\n", len(nodes), name)
		fmt.Println("🚀 Run 'xray-proxya apply' to commit changes.")
	},
}

var relaySubUpdateCmd = &cobra.Command{
	Use:               "update [airport-name]",
	Short:             "Refresh relay nodes from subscription link(s) into STAGING",
	ValidArgsFunction: completeRelaySubNamesArg,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			fmt.Println("❌ Failed to load STAGING configuration.")
			return
		}
		if len(cfg.RelaySubs) == 0 {
			fmt.Println("❌ No subscription sources configured. Use 'relay sub add <name> <url>' first.")
			return
		}

		var targets []string
		if len(args) > 0 {
			target := strings.TrimSpace(args[0])
			if _, ok := cfg.RelaySubs[target]; !ok {
				fmt.Printf("❌ Subscription '%s' not found.\n", target)
				return
			}
			targets = append(targets, target)
		} else {
			for name := range cfg.RelaySubs {
				targets = append(targets, name)
			}
			sort.Strings(targets)
		}

		ctx := context.Background()
		totalAdded, totalUpdated, totalRemoved := 0, 0, 0

		for _, name := range targets {
			subURL := cfg.RelaySubs[name]
			fmt.Printf("🔄 Updating subscription '%s'...\n", name)

			body, err := relaysub.FetchSubscription(ctx, subURL)
			if err != nil {
				fmt.Printf("❌ Failed to fetch '%s': %v\n", name, err)
				continue
			}

			nodes, skipped, err := relaysub.ParseSubscription(name, body)
			if err != nil {
				fmt.Printf("❌ Failed to parse payload for '%s': %v\n", name, err)
				continue
			}

			diff := relaysub.ComputeDiff(name, cfg.CustomOutbounds, nodes)

			// Print diff comparison
			fmt.Printf("📊 Comparison result for '%s':\n", name)
			fmt.Printf("   ➕ Added:     %d\n", len(diff.Added))
			fmt.Printf("   🔄 Changed:   %d\n", len(diff.Updated))
			fmt.Printf("   ⏹️  Unchanged: %d\n", len(diff.Unchanged))
			fmt.Printf("   ➖ Removed:   %d\n", len(diff.Removed))
			if skipped > 0 {
				fmt.Printf("   • Skipped:   %d non-proxy/unsupported items\n", skipped)
			}

			if len(diff.Added) > 0 {
				fmt.Println("   New nodes:")
				for _, a := range diff.Added {
					fmt.Printf("     + %s\n", a.Alias)
				}
			}
			if len(diff.Updated) > 0 {
				fmt.Println("   Changed nodes:")
				for _, u := range diff.Updated {
					fmt.Printf("     ~ %s\n", u.Alias)
				}
			}
			if len(diff.Removed) > 0 {
				fmt.Println("   Removed nodes:")
				for _, r := range diff.Removed {
					fmt.Printf("     - %s\n", r.Alias)
					// Check active gateway relay protection
					if cfg.Gateway.RelayAlias == r.Alias {
						fmt.Printf("       ⚠️  Active gateway relay '%s' was removed upstream!\n", r.Alias)
					}
				}
			}

			cfg.CustomOutbounds = diff.MergedOutbounds
			totalAdded += len(diff.Added)
			totalUpdated += len(diff.Updated)
			totalRemoved += len(diff.Removed)

			if relaySubTest && len(nodes) > 0 {
				fmt.Printf("🔍 Testing connectivity for '%s' nodes...\n", name)
				var aliases []string
				for _, n := range nodes {
					aliases = append(aliases, n.Alias)
				}
				results, err := relaytest.RunTests(ctx, cfg, aliases, relaytest.ModeSimple, 4)
				if err != nil {
					fmt.Printf("⚠️  Test error: %v\n", err)
				} else {
					fmt.Print(relaytest.RenderTerminal(results))
					fmt.Println()
				}
			}
		}

		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to save STAGING configuration: %v\n", err)
			return
		}

		fmt.Printf("\n✅ Subscription update complete in STAGING (Total Added: %d, Changed: %d, Removed: %d).\n", totalAdded, totalUpdated, totalRemoved)
		fmt.Println("🚀 Run 'xray-proxya apply' to commit changes.")
	},
}

var relaySubListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured subscription sources and node statistics",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil || len(cfg.RelaySubs) == 0 {
			fmt.Println("No subscription sources configured.")
			return
		}

		activeCfg, _ := config.LoadConfigEx(false)

		var names []string
		for name := range cfg.RelaySubs {
			names = append(names, name)
		}
		sort.Strings(names)

		fmt.Printf("\n%-16s | %-8s | %-8s | %s\n", "AIRPORT", "STAGING", "ACTIVE", "SUBSCRIPTION URL")
		fmt.Println("-----------------+----------+----------+------------------------------------------------")
		for _, name := range names {
			prefix := name + "/"
			stagingCount := 0
			for _, co := range cfg.CustomOutbounds {
				if strings.HasPrefix(co.Alias, prefix) {
					stagingCount++
				}
			}
			activeCount := 0
			if activeCfg != nil {
				for _, co := range activeCfg.CustomOutbounds {
					if strings.HasPrefix(co.Alias, prefix) {
						activeCount++
					}
				}
			}

			subURL := cfg.RelaySubs[name]
			maskedURL := maskURL(subURL)
			fmt.Printf("%-16s | %-8d | %-8d | %s\n", name, stagingCount, activeCount, maskedURL)
		}
		fmt.Println()
	},
}

var relaySubRemoveCmd = &cobra.Command{
	Use:               "remove [airport-name]",
	Aliases:           []string{"rm", "delete", "del"},
	Short:             "Remove a subscription source and its relay nodes from STAGING",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelaySubNamesArg,
	Run: func(cmd *cobra.Command, args []string) {
		name := strings.TrimSpace(args[0])
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			fmt.Println("❌ Failed to load STAGING configuration.")
			return
		}

		if _, exists := cfg.RelaySubs[name]; !exists {
			fmt.Printf("❌ Subscription '%s' not found.\n", name)
			return
		}

		delete(cfg.RelaySubs, name)
		prefix := name + "/"
		newCOs := make([]config.CustomOutbound, 0, len(cfg.CustomOutbounds))
		removedCount := 0
		for _, co := range cfg.CustomOutbounds {
			if strings.HasPrefix(co.Alias, prefix) {
				removedCount++
				if cfg.Gateway.RelayAlias == co.Alias {
					fmt.Printf("⚠️  Removed relay '%s' was the configured gateway relay!\n", co.Alias)
				}
			} else {
				newCOs = append(newCOs, co)
			}
		}
		cfg.CustomOutbounds = newCOs

		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to save STAGING configuration: %v\n", err)
			return
		}

		fmt.Printf("✅ Removed subscription '%s' and %d associated relay node(s) from STAGING.\n", name, removedCount)
		fmt.Println("🚀 Run 'xray-proxya apply' to commit changes.")
	},
}

func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	modified := false
	for k := range q {
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "token") || strings.Contains(lowerK, "key") || strings.Contains(lowerK, "pass") {
			val := q.Get(k)
			if len(val) > 8 {
				q.Set(k, val[:3]+"***"+val[len(val)-3:])
			} else if len(val) > 0 {
				q.Set(k, "***")
			}
			modified = true
		}
	}
	if !modified {
		return raw
	}
	rawQuery := q.Encode()
	rawQuery = strings.ReplaceAll(rawQuery, "%2A", "*")
	u.RawQuery = rawQuery
	return u.String()
}

func init() {
	relaySubAddCmd.Flags().BoolVarP(&relaySubTest, "test", "t", false, "Test connectivity of imported nodes")
	relaySubUpdateCmd.Flags().BoolVarP(&relaySubTest, "test", "t", false, "Test connectivity of updated nodes")

	relaySubCmd.AddCommand(relaySubAddCmd, relaySubUpdateCmd, relaySubListCmd, relaySubRemoveCmd)
	outboundCmd.AddCommand(relaySubCmd)
}
