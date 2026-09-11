package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"xray-proxya/internal/config"
	"xray-proxya/internal/endpoint"

	"github.com/spf13/cobra"
)

var (
	endpointListJSON bool
	endpointSetHost  string
	endpointSetAuto  bool
	endpointSetV4    bool
	endpointSetV6    bool
)

type EndpointListView struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Target      string   `json:"target"`
	ResolvedIPs []string `json:"resolved_ips"`
	References  []string `json:"references"`
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

	fmt.Printf("\n%-15s | %-10s | %-25s | %-25s | %-s\n", "NAME", "TYPE", "TARGET", "RESOLVED IP(S)", "REFERENCES")
	fmt.Println("-------------------------------------------------------------------------------------------------------------")
	for _, v := range views {
		resolvedStr := strings.Join(v.ResolvedIPs, ", ")
		if resolvedStr == "" {
			resolvedStr = "-"
		}
		refsStr := strings.Join(v.References, ", ")
		if refsStr == "" {
			refsStr = "-"
		}
		fmt.Printf("%-15s | %-10s | %-25s | %-25s | %-s\n", v.Name, v.Type, v.Target, resolvedStr, refsStr)
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
		if f := cmd.Flags().Lookup("host"); f != nil {
			f.Changed = false
		}
		if f := cmd.Flags().Lookup("auto"); f != nil {
			f.Changed = false
		}
		if f := cmd.Flags().Lookup("v4"); f != nil {
			f.Changed = false
		}
		if f := cmd.Flags().Lookup("v6"); f != nil {
			f.Changed = false
		}
		endpointSetHost = ""
		endpointSetAuto = false
		endpointSetV4 = false
		endpointSetV6 = false
	}()

	name := "default"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		name = strings.TrimSpace(args[0])
	}

	hasHost := cmd.Flags().Changed("host")
	hasAuto := cmd.Flags().Changed("auto")
	hasV4 := cmd.Flags().Changed("v4")
	hasV6 := cmd.Flags().Changed("v6")

	if !hasHost && !hasAuto && !hasV4 && !hasV6 {
		return fmt.Errorf("❌ Error: No parameter supplied")
	}
	if hasHost && (hasAuto || hasV4 || hasV6) {
		return fmt.Errorf("❌ Error: Cannot specify both --host and --auto")
	}

	var ep config.EndpointConfig
	if hasHost {
		hostVal := strings.TrimSpace(endpointSetHost)
		if hostVal == "" {
			return fmt.Errorf("❌ Error: Host cannot be empty")
		}
		ep = config.EndpointConfig{
			Type: config.EndpointTypeStatic,
			Host: hostVal,
		}
	} else {
		family := "v4"
		if endpointSetV6 || (hasV6 && !hasV4) {
			family = "v6"
		}
		ep = config.EndpointConfig{
			Type:   config.EndpointTypeAuto,
			Family: family,
		}
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
	refsStr := strings.Join(refs, ", ")
	if len(refs) == 0 {
		refsStr = "none"
	}

	fmt.Printf("\n--- Endpoint: %s ---\n", name)
	fmt.Printf("Type:        %s\n", ep.Type)
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

func init() {
	endpointListCmd.Flags().BoolVar(&endpointListJSON, "json", false, "Output in JSON format")

	endpointSetCmd.Flags().Bool("help", false, "Help for set")
	endpointSetCmd.Flags().StringVarP(&endpointSetHost, "host", "h", "", "Static hostname(s) or IP(s), comma-separated")
	endpointSetCmd.Flags().BoolVar(&endpointSetAuto, "auto", false, "Automatically detect host public IP")
	endpointSetCmd.Flags().BoolVar(&endpointSetV4, "v4", false, "Detect IPv4 (with --auto)")
	endpointSetCmd.Flags().BoolVar(&endpointSetV6, "v6", false, "Detect IPv6 (with --auto)")

	endpointCmd.AddCommand(endpointListCmd, endpointSetCmd, endpointRemoveCmd, endpointShowCmd)
	rootCmd.AddCommand(endpointCmd)
}
