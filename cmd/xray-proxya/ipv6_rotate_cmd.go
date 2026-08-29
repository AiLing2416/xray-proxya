package main

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/ipv6rotate"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var rotateInterface, rotateSubnet string
var rotateMax int
var rotateNDP bool

var ipv6RotateCmd = &cobra.Command{
	Use:   "ipv6-rotate",
	Short: "Configure the privileged IPv6 rotation service",
	Long: `Configure the root-level IPv6 address rotation allocator in STAGING.
The rotation service dynamically assigns and retires IPv6 addresses within your allocated subnet,
providing rotating endpoint IPs to subscription clients and mitigating static IP blacklisting.

Use 'xray-proxya apply' to commit staged changes, then control with 'xray-proxya service start xray-proxya-ipv6-rotate'.`,
}

func requireRootRotation(cfg *config.UserConfig) error {
	if err := requireServerSubscription(cfg); err != nil {
		return err
	}
	return utils.RequireRootShell("IPv6 rotation")
}

func getActiveRotation(cfg *config.UserConfig) (config.IPv6Config, error) {
	if cfg == nil {
		return config.IPv6Config{}, fmt.Errorf("IPv6 rotation is not configured")
	}
	if cfg.IPv6Rotation.Subnet != "" {
		return cfg.IPv6Rotation, nil
	}
	if cfg.IPv6Rotations != nil && cfg.IPv6Rotations["default"].Subnet != "" {
		return cfg.IPv6Rotations["default"], nil
	}
	return config.IPv6Config{}, fmt.Errorf("IPv6 rotation is not configured; use 'ipv6-rotate set', then apply")
}

var ipv6RotateSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set IPv6 rotation parameters in STAGING",
	Long: `Configure subnet, network interface, and active address limits for IPv6 rotation.
If --subnet or --interface are omitted, auto-detection will attempt to infer them from active interfaces.`,
	Example: `  # Configure IPv6 rotation on eth0 with a /64 pool keeping 6 active addresses
  xray-proxya ipv6-rotate set --interface eth0 --subnet 2001:db8:1234::/64 --max-addresses 6

  # Auto-detect subnet and interface
  xray-proxya ipv6-rotate set --max-addresses 4`,
	RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	rotation := cfg.IPv6Rotation
	if rotation.Subnet == "" && cfg.IPv6Rotations != nil {
		rotation = cfg.IPv6Rotations["default"]
	}
	if cmd.Flags().Changed("interface") {
		rotation.Interface = strings.TrimSpace(rotateInterface)
	}
	if cmd.Flags().Changed("subnet") {
		rotation.Subnet = strings.TrimSpace(rotateSubnet)
	}
	if cmd.Flags().Changed("max-addresses") {
		if rotateMax < 1 {
			return fmt.Errorf("max-addresses must be positive")
		}
		rotation.MaxAddresses = rotateMax
	}
	if cmd.Flags().Changed("ndp") {
		rotation.EnableNDP = rotateNDP
	}
	if rotation.Interface == "" || rotation.Subnet == "" {
		detectedSubnet, detectedIface, err := utils.AutoDetectIPv6Subnet()
		if err != nil {
			return fmt.Errorf("could not detect IPv6 subnet/interface; supply --subnet and --interface")
		}
		if rotation.Interface == "" {
			rotation.Interface = detectedIface
		}
		if rotation.Subnet == "" {
			rotation.Subnet = detectedSubnet
		}
	}
	if rotation.MaxAddresses <= 0 {
		rotation.MaxAddresses = 6
	}
	if err := ipv6rotate.Validate(rotation); err != nil {
		return err
	}
	cfg.IPv6Rotation = rotation
	if cfg.IPv6Rotations == nil {
		cfg.IPv6Rotations = map[string]config.IPv6Config{}
	}
	cfg.IPv6Rotations["default"] = rotation
	if err := cfg.SaveEx(true); err != nil {
		return err
	}
	fmt.Println("✅ IPv6 rotation configuration updated in STAGING. Run 'apply', then enable xray-proxya-ipv6-rotate.")
	return nil
}}

var ipv6RotateShowCmd = &cobra.Command{Use: "show", Short: "Show IPv6 rotation configuration", RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return err
	}
	rotation, err := getActiveRotation(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("Interface: %s\nSubnet: %s\nMax addresses: %d\nNDP: %t\n", rotation.Interface, rotation.Subnet, rotation.MaxAddresses, rotation.EnableNDP)
	return nil
}}

var ipv6RotateRunCmd = &cobra.Command{Use: "run", Hidden: true, RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	rotation, err := getActiveRotation(cfg)
	if err != nil {
		return err
	}
	return ipv6rotate.Serve("default", rotation)
}}

var ipv6RotateValidateCmd = &cobra.Command{Use: "validate", Hidden: true, RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	rotation, err := getActiveRotation(cfg)
	if err != nil {
		return err
	}
	return ipv6rotate.Validate(rotation)
}}

var ipv6RotateClearCmd = &cobra.Command{Use: "clear", Short: "Clear IPv6 rotation configuration in STAGING", RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	cfg.IPv6Rotation = config.IPv6Config{}
	cfg.IPv6Rotations = nil
	if cfg.AdminSub.IPv6Rotation != "" {
		cfg.AdminSub.IPv6Rotation = ""
	}
	if err := cfg.SaveEx(true); err != nil {
		return err
	}
	fmt.Println("✅ IPv6 rotation configuration cleared in STAGING. Run 'apply' to commit.")
	return nil
}}

func init() {
	ipv6RotateSetCmd.Flags().StringVarP(&rotateInterface, "interface", "i", "", "network interface")
	ipv6RotateSetCmd.Flags().StringVarP(&rotateSubnet, "subnet", "s", "", "IPv6 subnet")
	ipv6RotateSetCmd.Flags().IntVarP(&rotateMax, "max-addresses", "m", 0, "maximum active addresses")
	ipv6RotateSetCmd.Flags().BoolVar(&rotateNDP, "ndp", true, "configure NDP proxy")
	ipv6RotateSetCmd.RegisterFlagCompletionFunc("interface", completeNetworkInterfaces)
	ipv6RotateCmd.AddCommand(ipv6RotateSetCmd, ipv6RotateShowCmd, ipv6RotateRunCmd, ipv6RotateValidateCmd, ipv6RotateClearCmd)
	rootCmd.AddCommand(ipv6RotateCmd)
}
