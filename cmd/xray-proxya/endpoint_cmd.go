package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/endpoint"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	endpointListJSON     bool
	endpointShowJSON     bool
	endpointTestJSON     bool
	endpointRotateJSON   bool
	endpointSetHost      string
	endpointSetAuto      bool
	endpointSetV4        bool
	endpointSetV6        bool
	endpointSetType      string
	endpointSetSubnet    string
	endpointSetInterface string
	endpointSetMax       int
	endpointSetNDP       bool
	endpointSetNoNDP     bool

	endpointRequireRoot = func(operation string) error {
		return utils.RequireRootShell(operation)
	}
)

type EndpointListView struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Target      string   `json:"target"`
	ResolvedIPs []string `json:"resolved_ips"`
	References  []string `json:"references"`
}

type EndpointDetailView struct {
	Name           string                  `json:"name"`
	Type           string                  `json:"type"`
	Target         string                  `json:"target,omitempty"`
	Host           string                  `json:"host,omitempty"`
	Family         string                  `json:"family,omitempty"`
	Subnet         string                  `json:"subnet,omitempty"`
	Interface      string                  `json:"interface,omitempty"`
	MaxAddresses   int                     `json:"max_addresses,omitempty"`
	EnableNDP      *bool                   `json:"enable_ndp,omitempty"`
	ResolvedIP     string                  `json:"resolved_ip"`
	ActivePool     []endpoint.AddressEntry `json:"active_pool,omitempty"`
	DeprecatedPool []endpoint.AddressEntry `json:"deprecated_pool,omitempty"`
	References     []string                `json:"references"`
}

type EndpointTestResult struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Address string `json:"address"`
	Status  string `json:"status"` // "PASS" or "FAIL"
	RTTMs   int64  `json:"rtt_ms,omitempty"`
	Error   string `json:"error,omitempty"`
}

type EndpointRotateResult struct {
	Name            string `json:"name"`
	RotatedAddress  string `json:"rotated_address"`
	ActiveCount     int    `json:"active_count"`
	DeprecatedCount int    `json:"deprecated_count"`
}

var endpointCmd = &cobra.Command{
	Use:     "endpoint",
	Aliases: []string{"address", "ep"},
	Short:   "Manage connection endpoints and address providers for proxy nodes (STAGING)",
}

func completeEndpointNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil || len(cfg.Endpoints) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for name, ep := range cfg.Endpoints {
		names = append(names, fmt.Sprintf("%s\t%s", name, endpoint.GetTargetDescription(ep)))
	}
	sort.Strings(names)
	return names, cobra.ShellCompDirectiveNoFileComp
}

func runEndpointList(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load configuration: %w", err)
	}
	if cfg.Endpoints == nil {
		cfg.Endpoints = make(map[string]config.EndpointConfig)
	}

	var names []string
	for name := range cfg.Endpoints {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == "default" {
			return true
		}
		if names[j] == "default" {
			return false
		}
		return names[i] < names[j]
	})

	var views []EndpointListView
	for _, name := range names {
		ep := cfg.Endpoints[name]
		resolved, _ := endpoint.Resolve(cfg, name)
		if resolved == nil {
			resolved = []string{}
		}
		refs := endpoint.FindReferences(cfg, name)
		if refs == nil {
			refs = []string{}
		}
		views = append(views, EndpointListView{
			Name:        name,
			Type:        string(ep.Type),
			Target:      endpoint.GetTargetDescription(ep),
			ResolvedIPs: resolved,
			References:  refs,
		})
	}

	if endpointListJSON {
		if views == nil {
			views = []EndpointListView{}
		}
		data, err := json.MarshalIndent(views, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to serialize JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n%-15s | %-12s | %-28s | %-25s | %-s\n", "NAME", "TYPE", "TARGET", "RESOLVED IP(S)", "REFERENCES")
	fmt.Println("-------------------------------------------------------------------------------------------------------------")
	for _, v := range views {
		ep := cfg.Endpoints[v.Name]
		displayIPs := endpoint.FormatDisplayResolvedIPs(ep, v.ResolvedIPs)
		resolvedStr := strings.Join(displayIPs, ", ")
		if resolvedStr == "" {
			resolvedStr = "-"
		}
		refsStr := strings.Join(v.References, ", ")
		if refsStr == "" {
			refsStr = "-"
		}
		fmt.Printf("%-15s | %-12s | %-28s | %-25s | %-s\n", v.Name, v.Type, v.Target, resolvedStr, refsStr)
	}
	fmt.Println()
	return nil
}

var endpointListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all configured endpoints",
	RunE:    runEndpointList,
}

func runEndpointSet(cmd *cobra.Command, args []string) error {
	defer func() {
		for _, fName := range []string{"host", "auto", "v4", "v6", "type", "subnet", "interface", "max", "ndp", "no-ndp"} {
			if f := cmd.Flags().Lookup(fName); f != nil {
				f.Changed = false
				_ = f.Value.Set(f.DefValue)
			}
		}
		endpointSetHost = ""
		endpointSetAuto = false
		endpointSetV4 = false
		endpointSetV6 = false
		endpointSetType = ""
		endpointSetSubnet = ""
		endpointSetInterface = ""
		endpointSetMax = 6
		endpointSetNDP = false
		endpointSetNoNDP = false
	}()

	name := "default"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		name = strings.TrimSpace(args[0])
	}

	hasHost := cmd.Flags().Changed("host")
	hasAuto := cmd.Flags().Changed("auto")
	hasV4 := cmd.Flags().Changed("v4")
	hasV6 := cmd.Flags().Changed("v6")
	hasType := cmd.Flags().Changed("type")
	hasSubnet := cmd.Flags().Changed("subnet")
	hasNDP := cmd.Flags().Changed("ndp")
	hasNoNDP := cmd.Flags().Changed("no-ndp")

	if !hasHost && !hasAuto && !hasV4 && !hasV6 && !hasType && !hasSubnet {
		return fmt.Errorf("❌ Error: No parameter supplied")
	}

	targetType := strings.ToLower(strings.TrimSpace(endpointSetType))
	if targetType == "" {
		if hasSubnet {
			targetType = string(config.EndpointTypeDynamicV6)
		} else if hasHost {
			targetType = string(config.EndpointTypeStatic)
		} else if hasAuto || hasV4 || hasV6 {
			targetType = string(config.EndpointTypeAuto)
		}
	}

	var ep config.EndpointConfig
	switch targetType {
	case string(config.EndpointTypeDynamicV6):
		if hasHost {
			return fmt.Errorf("❌ Error: Cannot specify --host for dynamic-v6 endpoint")
		}
		subnetVal := strings.TrimSpace(endpointSetSubnet)
		if subnetVal == "" {
			return fmt.Errorf("❌ Error: dynamic-v6 endpoint requires --subnet")
		}
		if _, _, err := net.ParseCIDR(subnetVal); err != nil {
			return fmt.Errorf("❌ Error: Invalid IPv6 subnet '%s': %w", subnetVal, err)
		}

		ifaceVal := strings.TrimSpace(endpointSetInterface)
		if ifaceVal == "" {
			ifaceVal = "he-ipv6"
		}

		maxVal := endpointSetMax
		if maxVal <= 0 {
			maxVal = 6
		}

		var enableNDP bool
		if hasNoNDP {
			enableNDP = false
		} else if hasNDP {
			enableNDP = true
		} else {
			// Auto-guard: sit* or he-* tunnels skip Proxy NDP by default
			lowerIface := strings.ToLower(ifaceVal)
			if strings.Contains(lowerIface, "sit") || strings.Contains(lowerIface, "he-") || strings.Contains(lowerIface, "tun") {
				enableNDP = false
			} else {
				enableNDP = true
			}
		}

		ep = config.EndpointConfig{
			Type:         config.EndpointTypeDynamicV6,
			Subnet:       subnetVal,
			Interface:    ifaceVal,
			MaxAddresses: maxVal,
			EnableNDP:    enableNDP,
		}

	case string(config.EndpointTypeStatic):
		if hasAuto || hasV4 || hasV6 {
			return fmt.Errorf("❌ Error: Cannot specify both --host and --auto")
		}
		hostVal := strings.TrimSpace(endpointSetHost)
		if hostVal == "" {
			return fmt.Errorf("❌ Error: Host cannot be empty")
		}
		ep = config.EndpointConfig{
			Type: config.EndpointTypeStatic,
			Host: hostVal,
		}

	case string(config.EndpointTypeAuto):
		if hasHost {
			return fmt.Errorf("❌ Error: Cannot specify both --host and --auto")
		}
		family := "v4"
		if endpointSetV6 || (hasV6 && !hasV4) {
			family = "v6"
		}
		ep = config.EndpointConfig{
			Type:   config.EndpointTypeAuto,
			Family: family,
		}

	default:
		return fmt.Errorf("❌ Error: Unsupported endpoint type '%s' (valid types: static, auto, dynamic-v6)", targetType)
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %w", err)
	}
	if cfg.Endpoints == nil {
		cfg.Endpoints = make(map[string]config.EndpointConfig)
	}
	cfg.Endpoints[name] = ep

	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}

	fmt.Printf("✅ Endpoint '%s' configured in STAGING. Run 'apply' to commit.\n", name)
	return nil
}

var endpointSetCmd = &cobra.Command{
	Use:               "set [name]",
	Short:             "Create or update an endpoint in STAGING",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeEndpointNames,
	RunE:              runEndpointSet,
}

func runEndpointRemove(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	if name == "default" {
		return fmt.Errorf("❌ Error: Cannot delete reserved 'default' endpoint")
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %w", err)
	}
	if _, exists := cfg.Endpoints[name]; !exists {
		return fmt.Errorf("❌ Error: Endpoint '%s' not found", name)
	}

	refs := endpoint.FindReferences(cfg, name)
	if len(refs) > 0 {
		fmt.Printf("⚠️  Warning: Endpoint '%s' is currently referenced by: %s\n", name, strings.Join(refs, ", "))
	}

	delete(cfg.Endpoints, name)
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}

	fmt.Printf("✅ Endpoint '%s' removed from STAGING. Run 'apply' to commit.\n", name)
	return nil
}

var endpointRemoveCmd = &cobra.Command{
	Use:               "remove [name]",
	Aliases:           []string{"rm", "del", "delete"},
	Short:             "Remove an endpoint from STAGING",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeEndpointNames,
	RunE:              runEndpointRemove,
}

func runEndpointShow(cmd *cobra.Command, args []string) error {
	name := "default"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		name = strings.TrimSpace(args[0])
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %w", err)
	}
	ep, exists := cfg.Endpoints[name]
	if !exists {
		return fmt.Errorf("❌ Error: Endpoint '%s' not found", name)
	}

	resolved, err := endpoint.Resolve(cfg, name)
	resolvedStr := strings.Join(resolved, ", ")
	if err != nil {
		resolvedStr = fmt.Sprintf("(resolution failed: %v)", err)
	}

	refs := endpoint.FindReferences(cfg, name)
	if refs == nil {
		refs = []string{}
	}

	var activePool, deprecatedPool []endpoint.AddressEntry
	if ep.Type == config.EndpointTypeDynamicV6 {
		st, _ := endpoint.LoadRotationState(name)
		if st != nil {
			activePool = st.ActivePool
			deprecatedPool = st.DeprecatedPool
		}
	}

	if endpointShowJSON {
		detail := EndpointDetailView{
			Name:           name,
			Type:           string(ep.Type),
			Target:         endpoint.GetTargetDescription(ep),
			Host:           ep.Host,
			Family:         ep.Family,
			Subnet:         ep.Subnet,
			Interface:      ep.Interface,
			MaxAddresses:   ep.MaxAddresses,
			ResolvedIP:     resolvedStr,
			ActivePool:     activePool,
			DeprecatedPool: deprecatedPool,
			References:     refs,
		}
		if ep.Type == config.EndpointTypeDynamicV6 {
			detail.EnableNDP = &ep.EnableNDP
		}
		data, err := json.MarshalIndent(detail, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to serialize JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	refsStr := strings.Join(refs, ", ")
	if len(refs) == 0 {
		refsStr = "none"
	}

	fmt.Printf("\n--- Endpoint: %s ---\n", name)
	fmt.Printf("Type:        %s\n", ep.Type)

	if ep.Type == config.EndpointTypeDynamicV6 {
		ndpStr := "disabled"
		if ep.EnableNDP {
			ndpStr = "enabled"
		}
		fmt.Printf("Subnet:      %s\n", ep.Subnet)
		fmt.Printf("Interface:   %s\n", ep.Interface)
		fmt.Printf("Proxy NDP:   %s\n", ndpStr)
		fmt.Printf("Max Addrs:   %d\n", ep.MaxAddresses)
		fmt.Printf("Resolved IP: %s\n", resolvedStr)
		fmt.Printf("References:  %s\n\n", refsStr)

		fmt.Printf("Active Pool (%d/%d):\n", len(activePool), ep.MaxAddresses)
		if len(activePool) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, act := range activePool {
				age := time.Since(act.CreatedAt).Round(time.Second)
				fmt.Printf("  * %s (created %s ago)\n", act.Address, age)
			}
		}

		fmt.Printf("\nDeprecated Pool (%d):\n", len(deprecatedPool))
		if len(deprecatedPool) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, dep := range deprecatedPool {
				remaining := 1*time.Hour - time.Since(dep.DeprecatedAt)
				if remaining < 0 {
					remaining = 0
				}
				fmt.Printf("  * %s (expires in %s)\n", dep.Address, remaining.Round(time.Second))
			}
		}
		fmt.Println()
		return nil
	}

	fmt.Printf("Target:      %s\n", endpoint.GetTargetDescription(ep))
	fmt.Printf("Resolved IP: %s\n", resolvedStr)
	fmt.Printf("References:  %s\n\n", refsStr)
	return nil
}

var endpointShowCmd = &cobra.Command{
	Use:               "show [name]",
	Short:             "Show details and current resolved IP for an endpoint",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeEndpointNames,
	RunE:              runEndpointShow,
}

func runEndpointTest(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load configuration: %w", err)
	}

	var targetNames []string
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" && strings.TrimSpace(args[0]) != "all" {
		targetName := strings.TrimSpace(args[0])
		if _, exists := cfg.Endpoints[targetName]; !exists {
			return fmt.Errorf("❌ Error: Endpoint '%s' not found", targetName)
		}
		targetNames = append(targetNames, targetName)
	} else {
		for n := range cfg.Endpoints {
			targetNames = append(targetNames, n)
		}
		sort.Strings(targetNames)
	}

	var results []EndpointTestResult

	for _, name := range targetNames {
		ep := cfg.Endpoints[name]
		var ipsToTest []string

		if ep.Type == config.EndpointTypeDynamicV6 {
			st, _ := endpoint.LoadRotationState(name)
			if st != nil && len(st.ActivePool) > 0 {
				for _, act := range st.ActivePool {
					ipsToTest = append(ipsToTest, act.Address)
				}
			}
		}

		if len(ipsToTest) == 0 {
			resolved, err := endpoint.Resolve(cfg, name)
			if err == nil {
				ipsToTest = append(ipsToTest, resolved...)
			}
		}

		if len(ipsToTest) == 0 {
			results = append(results, EndpointTestResult{
				Name:   name,
				Type:   string(ep.Type),
				Status: "FAIL",
				Error:  "no address could be resolved for testing",
			})
			continue
		}

		for _, testIP := range ipsToTest {
			cleanIP := strings.TrimSpace(testIP)
			if strings.Contains(cleanIP, ":") {
				// IPv6 probe
				ok, rtt, pErr := endpoint.TestIPv6Reachability(cleanIP, 3*time.Second)
				if ok {
					results = append(results, EndpointTestResult{
						Name:    name,
						Type:    string(ep.Type),
						Address: cleanIP,
						Status:  "PASS",
						RTTMs:   rtt.Milliseconds(),
					})
				} else {
					errMsg := "reachability check failed"
					if pErr != nil {
						errMsg = pErr.Error()
					}
					results = append(results, EndpointTestResult{
						Name:    name,
						Type:    string(ep.Type),
						Address: cleanIP,
						Status:  "FAIL",
						Error:   errMsg,
					})
				}
			} else {
				// IPv4 probe
				start := time.Now()
				conn, dialErr := net.DialTimeout("tcp", "1.1.1.1:53", 3*time.Second)
				if dialErr == nil {
					rtt := time.Since(start)
					conn.Close()
					results = append(results, EndpointTestResult{
						Name:    name,
						Type:    string(ep.Type),
						Address: cleanIP,
						Status:  "PASS",
						RTTMs:   rtt.Milliseconds(),
					})
				} else {
					results = append(results, EndpointTestResult{
						Name:    name,
						Type:    string(ep.Type),
						Address: cleanIP,
						Status:  "FAIL",
						Error:   dialErr.Error(),
					})
				}
			}
		}
	}

	if endpointTestJSON {
		if results == nil {
			results = []EndpointTestResult{}
		}
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to serialize JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println()
	currentName := ""
	for _, res := range results {
		if res.Name != currentName {
			currentName = res.Name
			fmt.Printf("🔍 Testing endpoint '%s' (%s):\n", res.Name, res.Type)
		}
		if res.Status == "PASS" {
			fmt.Printf("   ✅ [PASS] %s (RTT: %dms)\n", res.Address, res.RTTMs)
		} else {
			fmt.Printf("   ❌ [FAIL] %s (%s)\n", res.Address, res.Error)
		}
	}
	fmt.Println()
	return nil
}

var endpointTestCmd = &cobra.Command{
	Use:               "test [name]",
	Short:             "Perform live dual-stack Internet reachability probe on endpoints",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeEndpointNames,
	RunE:              runEndpointTest,
}

func runEndpointRotate(cmd *cobra.Command, args []string) error {
	name := "default"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		name = strings.TrimSpace(args[0])
	}

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load configuration: %w", err)
	}
	ep, exists := cfg.Endpoints[name]
	if !exists {
		return fmt.Errorf("❌ Error: Endpoint '%s' not found", name)
	}

	if ep.Type != config.EndpointTypeDynamicV6 {
		return fmt.Errorf("❌ Error: Endpoint '%s' has type '%s'; rotation only applies to 'dynamic-v6'", name, ep.Type)
	}

	if err := endpointRequireRoot("endpoint rotate"); err != nil {
		return err
	}

	newIP, err := endpoint.NextAddress(name, ep)
	if err != nil {
		return fmt.Errorf("❌ Failed to rotate endpoint '%s': %w", name, err)
	}

	st, _ := endpoint.LoadRotationState(name)
	activeCount := 1
	deprecatedCount := 0
	if st != nil {
		activeCount = len(st.ActivePool)
		deprecatedCount = len(st.DeprecatedPool)
	}

	if endpointRotateJSON {
		res := EndpointRotateResult{
			Name:            name,
			RotatedAddress:  newIP,
			ActiveCount:     activeCount,
			DeprecatedCount: deprecatedCount,
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n✅ Endpoint '%s' rotated successfully!\n", name)
	fmt.Printf("   - New Active Address: %s\n", newIP)
	fmt.Printf("   - Active Pool:        %d/%d\n", activeCount, ep.MaxAddresses)
	fmt.Printf("   - Deprecated Pool:    %d\n\n", deprecatedCount)
	return nil
}

var endpointRotateCmd = &cobra.Command{
	Use:               "rotate [name]",
	Short:             "Manually rotate and slide address pool for a dynamic-v6 endpoint",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeEndpointNames,
	RunE:              runEndpointRotate,
}

func init() {
	endpointListCmd.Flags().BoolVar(&endpointListJSON, "json", false, "Output in JSON format")

	endpointShowCmd.Flags().BoolVar(&endpointShowJSON, "json", false, "Output in JSON format")

	endpointTestCmd.Flags().BoolVar(&endpointTestJSON, "json", false, "Output in JSON format")

	endpointRotateCmd.Flags().BoolVar(&endpointRotateJSON, "json", false, "Output in JSON format")

	endpointSetCmd.Flags().Bool("help", false, "Help for set")
	endpointSetCmd.Flags().StringVarP(&endpointSetHost, "host", "h", "", "Static hostname(s) or IP(s), comma-separated")
	endpointSetCmd.Flags().BoolVar(&endpointSetAuto, "auto", false, "Automatically detect host public IP")
	endpointSetCmd.Flags().BoolVar(&endpointSetV4, "v4", false, "Detect IPv4 (with --auto)")
	endpointSetCmd.Flags().BoolVar(&endpointSetV6, "v6", false, "Detect IPv6 (with --auto)")
	endpointSetCmd.Flags().StringVar(&endpointSetType, "type", "", "Endpoint type (static, auto, dynamic-v6)")
	endpointSetCmd.Flags().StringVar(&endpointSetSubnet, "subnet", "", "IPv6 subnet prefix for dynamic-v6 (e.g. 2001:470:1f0b:692::/64)")
	endpointSetCmd.Flags().StringVarP(&endpointSetInterface, "interface", "i", "", "Interface for dynamic-v6 (e.g. he-ipv6)")
	endpointSetCmd.Flags().IntVarP(&endpointSetMax, "max", "m", 6, "Maximum active addresses for dynamic-v6 (default 6)")
	endpointSetCmd.Flags().BoolVar(&endpointSetNDP, "ndp", false, "Enable Proxy NDP")
	endpointSetCmd.Flags().BoolVar(&endpointSetNoNDP, "no-ndp", false, "Disable Proxy NDP")

	endpointCmd.AddCommand(endpointListCmd, endpointSetCmd, endpointRemoveCmd, endpointShowCmd, endpointTestCmd, endpointRotateCmd)
	rootCmd.AddCommand(endpointCmd)
}
