package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	gatewayRuleListJSON bool

	ruleSetMAC       string
	ruleSetInterface string
	ruleSetTo        string
	ruleSetTarget    string
	ruleSetForce     bool

	ruleDelMAC       string
	ruleDelInterface string
)

var (
	lookupInterfaceByIP = utils.GetInterfaceByIP
	lookupMACByIP       = utils.LookupMACByIP
)

var gatewayRuleCmd = &cobra.Command{
	Use:     "rule",
	Aliases: []string{"rules"},
	Short:   "Manage gateway per-MAC and per-interface routing rules (STAGING)",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayRuleList(cmd, args)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return utils.RequireRootShell("gateway rule")
	},
}

type GatewayRuleItemJSON struct {
	Index     int    `json:"index"`
	MAC       string `json:"mac,omitempty"`
	Interface string `json:"interface,omitempty"`
	Target    string `json:"target"`
}

type GatewayRulesStatusJSON struct {
	Active  []GatewayRuleItemJSON `json:"active"`
	Staging []GatewayRuleItemJSON `json:"staging"`
}

var gatewayRuleListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List active and staging gateway routing rules",
	Args:    cobra.NoArgs,
	RunE:    runGatewayRuleList,
}

func toRuleItemsJSON(rules []config.GatewayRule) []GatewayRuleItemJSON {
	items := make([]GatewayRuleItemJSON, len(rules))
	for i, r := range rules {
		items[i] = GatewayRuleItemJSON{
			Index:     i + 1,
			MAC:       r.MAC,
			Interface: r.Interface,
			Target:    r.Target,
		}
	}
	return items
}

func printRulesTable(header string, rules []config.GatewayRule) {
	fmt.Printf("%s:\n", header)
	if len(rules) == 0 {
		fmt.Println("  (no rules configured)")
		return
	}
	fmt.Printf("  %-5s  %-19s  %-12s  %s\n", "INDEX", "MAC ADDRESS", "INTERFACE", "TARGET")
	fmt.Printf("  %-5s  %-19s  %-12s  %s\n", "-----", "-------------------", "------------", "------")
	for i, r := range rules {
		mac := r.MAC
		if mac == "" {
			mac = "(any)"
		}
		iface := r.Interface
		if iface == "" {
			iface = "(any)"
		}
		fmt.Printf("  #%-4d  %-19s  %-12s  %s\n", i+1, mac, iface, r.Target)
	}
}

func runGatewayRuleList(cmd *cobra.Command, args []string) error {
	activeCfg, _ := config.LoadConfigEx(false)
	stagingCfg, _ := config.LoadConfigEx(true)
	if activeCfg == nil && stagingCfg == nil {
		return fmt.Errorf("❌ Failed to load gateway configuration")
	}

	if gatewayRuleListJSON {
		var activeRules, stagingRules []config.GatewayRule
		if activeCfg != nil {
			activeRules = activeCfg.Gateway.Rules
		}
		if stagingCfg != nil {
			stagingRules = stagingCfg.Gateway.Rules
		}
		out := GatewayRulesStatusJSON{
			Active:  toRuleItemsJSON(activeRules),
			Staging: toRuleItemsJSON(stagingRules),
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("\n🛰️ GATEWAY ROUTING RULES")
	fmt.Println("--------------------------------------------------")
	if activeCfg != nil {
		printRulesTable("ACTIVE", activeCfg.Gateway.Rules)
	} else {
		fmt.Println("ACTIVE: (not initialized)")
	}
	fmt.Println()
	if stagingCfg != nil {
		printRulesTable("STAGING", stagingCfg.Gateway.Rules)
	} else {
		fmt.Println("STAGING: (not initialized)")
	}
	return nil
}

var gatewayRuleSetCmd = &cobra.Command{
	Use:     "set",
	Aliases: []string{"add"},
	Short:   "Add or update a gateway routing rule in STAGING",
	Args:    cobra.NoArgs,
	RunE:    runGatewayRuleSet,
}

func detectLockoutRisk(targetRule config.GatewayRule) (bool, string) {
	if !strings.EqualFold(targetRule.Target, "block") {
		return false, ""
	}

	sshConn := strings.TrimSpace(os.Getenv("SSH_CONNECTION"))
	sshClient := strings.TrimSpace(os.Getenv("SSH_CLIENT"))

	var clientIP, serverIP string
	if sshConn != "" {
		fields := strings.Fields(sshConn)
		if len(fields) >= 4 {
			clientIP = fields[0]
			serverIP = fields[2]
		}
	}
	if clientIP == "" && sshClient != "" {
		fields := strings.Fields(sshClient)
		if len(fields) >= 1 {
			clientIP = fields[0]
		}
	}

	ruleMAC := strings.TrimSpace(targetRule.MAC)
	if ruleMAC != "" {
		if norm, err := config.NormalizeMAC(ruleMAC); err == nil {
			ruleMAC = norm
		}
	}
	ruleIface := strings.TrimSpace(targetRule.Interface)

	// No SSH session detected
	if clientIP == "" && serverIP == "" {
		// c) Without SSH env, whole-interface block is a potential lockout risk
		if ruleIface != "" && ruleMAC == "" {
			return true, fmt.Sprintf("Blocking entire interface %q without MAC filtering will drop all traffic on this interface, which poses a severe lockout risk.", ruleIface)
		}
		return false, ""
	}

	// SSH session detected: find inbound interface and client MAC
	var sshIface string
	if serverIP != "" {
		if iface, err := lookupInterfaceByIP(serverIP); err == nil && iface != "" {
			sshIface = iface
		}
	}
	if sshIface == "" && clientIP != "" {
		if iface, err := lookupInterfaceByIP(clientIP); err == nil && iface != "" {
			sshIface = iface
		}
	}

	var clientMAC string
	if clientIP != "" {
		if mac, err := lookupMACByIP(clientIP); err == nil && mac != "" {
			if norm, err := config.NormalizeMAC(mac); err == nil {
				clientMAC = norm
			} else {
				clientMAC = strings.ToUpper(mac)
			}
		}
	}

	// a) If targetRule.Interface matches current SSH inbound interface
	if sshIface != "" && ruleIface == sshIface {
		if ruleMAC == "" {
			return true, fmt.Sprintf("Blocking entire interface %q matches your active SSH inbound interface (server IP: %s, client IP: %s).", ruleIface, serverIP, clientIP)
		}
		if clientMAC != "" && strings.EqualFold(ruleMAC, clientMAC) {
			return true, fmt.Sprintf("Rule targets interface %q and MAC %q, matching your active SSH connection (client IP: %s, client MAC: %s).", ruleIface, ruleMAC, clientIP, clientMAC)
		}
		if clientMAC == "" {
			return true, fmt.Sprintf("Rule targets active SSH interface %q with MAC %q (client MAC could not be verified for %s).", ruleIface, ruleMAC, clientIP)
		}
	}

	// b) If targetRule.MAC matches current SSH client MAC
	if ruleMAC != "" && clientMAC != "" && strings.EqualFold(ruleMAC, clientMAC) {
		return true, fmt.Sprintf("Rule targets MAC %q, matching your active SSH client MAC (client IP: %s).", ruleMAC, clientIP)
	}

	// c fallback: If SSH is detected but inbound interface could not be resolved,
	// blocking an entire interface might be the SSH interface
	if sshIface == "" && ruleIface != "" && ruleMAC == "" {
		return true, fmt.Sprintf("Blocking entire interface %q without MAC filtering poses a severe lockout risk while an active SSH session is present.", ruleIface)
	}

	return false, ""
}

func runGatewayRuleSet(cmd *cobra.Command, args []string) error {
	force := ruleSetForce
	if cmd != nil && cmd.Flags() != nil {
		if f, err := cmd.Flags().GetBool("force"); err == nil && f {
			force = true
		}
	}
	defer func() {
		ruleSetForce = false
		if cmd != nil && cmd.Flags() != nil && cmd.Flags().Lookup("force") != nil {
			_ = cmd.Flags().Set("force", "false")
		}
	}()

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}

	target := ruleSetTo
	if target == "" {
		target = ruleSetTarget
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("❌ Target must be specified via --to / -t (allowed: direct, block, or an existing relay alias)")
	}

	rawRule := config.GatewayRule{
		MAC:       ruleSetMAC,
		Interface: ruleSetInterface,
		Target:    target,
	}

	normRule, err := config.ValidateGatewayRule(rawRule)
	if err != nil {
		return fmt.Errorf("❌ %w", err)
	}

	// Validate target against CustomOutbounds if not "direct" or "block"
	if normRule.Target != "direct" && normRule.Target != "block" {
		if cfg.Gateway.EffectiveMode() == "tun" {
			return fmt.Errorf("❌ TUN mode does not support per-client relay routing (rule targets relay %q); use 'tproxy' mode or change target to 'direct' or 'block'", normRule.Target)
		}
		found := false
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == normRule.Target {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("❌ Target relay %q not found in custom outbounds (allowed: direct, block, or an existing relay alias)", normRule.Target)
		}
	}

	// High-risk lockout risk detection
	hasRisk, warningMsg := detectLockoutRisk(normRule)
	if hasRisk {
		if force {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️  WARNING: High-risk block rule forced (--force specified): %s\n", warningMsg)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️  WARNING: High-risk block rule detected!\n")
			fmt.Fprintf(cmd.OutOrStdout(), "   %s\n", warningMsg)
			fmt.Fprintf(cmd.OutOrStdout(), "   Applying this rule may immediately sever your active SSH session and cause permanent management lockout.\n")
			fmt.Fprintf(cmd.OutOrStdout(), "Are you sure you want to proceed? [N/y]: ")

			reader := bufio.NewReader(cmd.InOrStdin())
			input, err := reader.ReadString('\n')
			if err != nil && len(input) == 0 {
				return fmt.Errorf("❌ Operation cancelled: failed to read confirmation (use --force to bypass)")
			}
			answer := strings.TrimSpace(input)
			if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
				return fmt.Errorf("❌ Operation cancelled by user (lockout protection)")
			}
		}
	}

	// Update in-place if matching (MAC, Interface) exists
	updated := false
	for i, r := range cfg.Gateway.Rules {
		if r.MAC == normRule.MAC && r.Interface == normRule.Interface {
			cfg.Gateway.Rules[i].Target = normRule.Target
			updated = true
			break
		}
	}
	if !updated {
		cfg.Gateway.Rules = append(cfg.Gateway.Rules, normRule)
	}

	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}

	macDesc := normRule.MAC
	if macDesc == "" {
		macDesc = "(any)"
	}
	ifaceDesc := normRule.Interface
	if ifaceDesc == "" {
		ifaceDesc = "(any)"
	}
	if updated {
		fmt.Printf("✅ Updated existing gateway rule in STAGING: MAC=%s, Interface=%s -> %s\n", macDesc, ifaceDesc, normRule.Target)
	} else {
		fmt.Printf("✅ Added new gateway rule in STAGING: MAC=%s, Interface=%s -> %s\n", macDesc, ifaceDesc, normRule.Target)
	}
	fmt.Println("ℹ️  Run 'xray-proxya apply' to commit changes.")
	return nil
}

var gatewayRuleDelCmd = &cobra.Command{
	Use:               "del [index]",
	Aliases:           []string{"rm", "remove"},
	Short:             "Delete a gateway routing rule from STAGING",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRuleIndicesArg,
	RunE:              runGatewayRuleDel,
}

func runGatewayRuleDel(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config: %v", err)
	}

	if len(cfg.Gateway.Rules) == 0 {
		return fmt.Errorf("❌ No gateway rules configured in STAGING")
	}

	if len(args) == 1 {
		idx, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil || idx < 1 || idx > len(cfg.Gateway.Rules) {
			return fmt.Errorf("❌ Invalid rule index %q (must be between 1 and %d)", args[0], len(cfg.Gateway.Rules))
		}
		deleted := cfg.Gateway.Rules[idx-1]
		cfg.Gateway.Rules = append(cfg.Gateway.Rules[:idx-1], cfg.Gateway.Rules[idx:]...)
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("❌ Failed to save staging config: %w", err)
		}
		fmt.Printf("✅ Deleted rule #%d (MAC=%s, Interface=%s -> %s) from STAGING.\n", idx, deleted.MAC, deleted.Interface, deleted.Target)
		fmt.Println("ℹ️  Run 'xray-proxya apply' to commit changes.")
		return nil
	}

	hasMAC := cmd.Flags().Changed("mac")
	hasIface := cmd.Flags().Changed("interface")
	if !hasMAC && !hasIface {
		return fmt.Errorf("❌ Must specify either a 1-based rule index (e.g. 'gateway rule del 1') or --mac / --interface flags")
	}

	targetMAC := strings.TrimSpace(ruleDelMAC)
	if hasMAC && targetMAC != "" {
		normMAC, err := config.NormalizeMAC(targetMAC)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		targetMAC = normMAC
	}
	targetIface := strings.TrimSpace(ruleDelInterface)

	var filtered []config.GatewayRule
	deletedCount := 0
	for _, r := range cfg.Gateway.Rules {
		match := true
		if hasMAC && r.MAC != targetMAC {
			match = false
		}
		if hasIface && r.Interface != targetIface {
			match = false
		}
		if match {
			deletedCount++
		} else {
			filtered = append(filtered, r)
		}
	}

	if deletedCount == 0 {
		return fmt.Errorf("❌ No rule matched criteria (MAC=%q, Interface=%q)", targetMAC, targetIface)
	}

	cfg.Gateway.Rules = filtered
	if err := cfg.SaveEx(true); err != nil {
		return fmt.Errorf("❌ Failed to save staging config: %w", err)
	}
	fmt.Printf("✅ Deleted %d matching rule(s) from STAGING.\n", deletedCount)
	fmt.Println("ℹ️  Run 'xray-proxya apply' to commit changes.")
	return nil
}

var gatewayRuleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all gateway routing rules in STAGING",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil || cfg == nil {
			return fmt.Errorf("❌ Failed to load staging config: %v", err)
		}
		count := len(cfg.Gateway.Rules)
		cfg.Gateway.Rules = nil
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("❌ Failed to save staging config: %w", err)
		}
		fmt.Printf("✅ Cleared %d gateway rule(s) in STAGING.\n", count)
		fmt.Println("ℹ️  Run 'xray-proxya apply' to commit changes.")
		return nil
	},
}

func completeRuleIndicesArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for i, r := range cfg.Gateway.Rules {
		desc := fmt.Sprintf("%d\tMAC=%s Iface=%s -> %s", i+1, r.MAC, r.Interface, r.Target)
		completions = append(completions, desc)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeRuleTargets(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return []string{"direct", "block"}, cobra.ShellCompDirectiveNoFileComp
	}
	targets := []string{"direct", "block"}
	for _, co := range cfg.CustomOutbounds {
		if co.Alias != "" {
			targets = append(targets, co.Alias)
		}
	}
	return targets, cobra.ShellCompDirectiveNoFileComp
}

func completeInterfaceNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, iface := range ifaces {
		if iface.Name != "" {
			names = append(names, iface.Name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	gatewayRuleCmd.Flags().BoolVar(&gatewayRuleListJSON, "json", false, "Output in JSON format")
	gatewayRuleListCmd.Flags().BoolVar(&gatewayRuleListJSON, "json", false, "Output in JSON format")

	gatewayRuleSetCmd.Flags().StringVarP(&ruleSetMAC, "mac", "m", "", "Client MAC address (e.g. 52:54:00:83:00:11)")
	gatewayRuleSetCmd.Flags().StringVarP(&ruleSetInterface, "interface", "i", "", "LAN interface name (e.g. eth1)")
	gatewayRuleSetCmd.Flags().StringVarP(&ruleSetTo, "to", "t", "", "Target destination ('direct', 'block', or relay alias)")
	gatewayRuleSetCmd.Flags().StringVar(&ruleSetTarget, "target", "", "Alias for --to")
	gatewayRuleSetCmd.Flags().BoolVarP(&ruleSetForce, "force", "f", false, "Force setting the rule even if it poses a lockout risk")

	_ = gatewayRuleSetCmd.RegisterFlagCompletionFunc("to", completeRuleTargets)
	_ = gatewayRuleSetCmd.RegisterFlagCompletionFunc("target", completeRuleTargets)
	_ = gatewayRuleSetCmd.RegisterFlagCompletionFunc("interface", completeInterfaceNames)

	gatewayRuleDelCmd.Flags().StringVarP(&ruleDelMAC, "mac", "m", "", "Client MAC address to match")
	gatewayRuleDelCmd.Flags().StringVarP(&ruleDelInterface, "interface", "i", "", "LAN interface name to match")

	_ = gatewayRuleDelCmd.RegisterFlagCompletionFunc("interface", completeInterfaceNames)

	gatewayRuleCmd.AddCommand(
		gatewayRuleListCmd,
		gatewayRuleSetCmd,
		gatewayRuleDelCmd,
		gatewayRuleClearCmd,
	)

	gatewayCmd.AddCommand(gatewayRuleCmd)
}
