package main

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/ipv6rotate"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var rotateInstance, rotateInterface, rotateSubnet string
var rotateMax int
var rotateNDP bool

var ipv6RotateCmd = &cobra.Command{Use: "ipv6-rotate", Short: "Configure the privileged IPv6 rotation service"}

func requireRootRotation(cfg *config.UserConfig) error {
	if err := requireServerSubscription(cfg); err != nil {
		return err
	}
	if !utils.IsRoot() {
		return fmt.Errorf("IPv6 rotation must be configured from a direct root shell")
	}
	return nil
}

func rotationFor(cfg *config.UserConfig, instance string) (config.IPv6Config, error) {
	if cfg == nil || cfg.IPv6Rotations == nil {
		return config.IPv6Config{}, fmt.Errorf("IPv6 rotation %q is not configured", instance)
	}
	rotation, ok := cfg.IPv6Rotations[instance]
	if !ok {
		return config.IPv6Config{}, fmt.Errorf("IPv6 rotation %q is not configured", instance)
	}
	return rotation, nil
}

var ipv6RotateSetCmd = &cobra.Command{Use: "set", Short: "Set IPv6 rotation parameters in STAGING", RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	if rotateInstance == "" {
		rotateInstance = defaultSubInstance
	}
	if rotateInstance != defaultSubInstance {
		return fmt.Errorf("IPv6 rotation instance %q is not supported", rotateInstance)
	}
	rotation := cfg.IPv6Rotations[rotateInstance]
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
	if cfg.IPv6Rotations == nil {
		cfg.IPv6Rotations = map[string]config.IPv6Config{}
	}
	cfg.IPv6Rotations[rotateInstance] = rotation
	if err := cfg.SaveEx(true); err != nil {
		return err
	}
	fmt.Println("✅ IPv6 rotation configuration updated in STAGING. Run 'apply', then enable xray-proxya-ipv6-rotate@default.")
	return nil
}}

var ipv6RotateShowCmd = &cobra.Command{Use: "show", Short: "Show IPv6 rotation configuration", RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return err
	}
	instance := rotateInstance
	if instance == "" {
		instance = defaultSubInstance
	}
	rotation, err := rotationFor(cfg, instance)
	if err != nil {
		return err
	}
	fmt.Printf("Instance: %s\nInterface: %s\nSubnet: %s\nMax addresses: %d\nNDP: %t\n", instance, rotation.Interface, rotation.Subnet, rotation.MaxAddresses, rotation.EnableNDP)
	return nil
}}

var ipv6RotateRunCmd = &cobra.Command{Use: "run <instance>", Hidden: true, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	rotation, err := rotationFor(cfg, args[0])
	if err != nil {
		return err
	}
	return ipv6rotate.Serve(args[0], rotation)
}}
var ipv6RotateValidateCmd = &cobra.Command{Use: "validate <instance>", Hidden: true, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if err := requireRootRotation(cfg); err != nil {
		return err
	}
	rotation, err := rotationFor(cfg, args[0])
	if err != nil {
		return err
	}
	return ipv6rotate.Validate(rotation)
}}

func init() {
	ipv6RotateSetCmd.Flags().StringVar(&rotateInstance, "instance", defaultSubInstance, "rotation instance")
	ipv6RotateSetCmd.Flags().StringVarP(&rotateInterface, "interface", "i", "", "network interface")
	ipv6RotateSetCmd.Flags().StringVarP(&rotateSubnet, "subnet", "s", "", "IPv6 subnet")
	ipv6RotateSetCmd.Flags().IntVarP(&rotateMax, "max-addresses", "m", 0, "maximum active addresses")
	ipv6RotateSetCmd.Flags().BoolVar(&rotateNDP, "ndp", true, "configure NDP proxy")
	ipv6RotateSetCmd.RegisterFlagCompletionFunc("interface", completeNetworkInterfaces)
	ipv6RotateShowCmd.Flags().StringVar(&rotateInstance, "instance", defaultSubInstance, "rotation instance")
	ipv6RotateCmd.AddCommand(ipv6RotateSetCmd, ipv6RotateShowCmd, ipv6RotateRunCmd, ipv6RotateValidateCmd)
	rootCmd.AddCommand(ipv6RotateCmd)
}
