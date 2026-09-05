package main

import (
	"os"
	"xray-proxya/internal/service"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

const (
	pathdServiceUnit  = service.PathdUnit
	subServiceUnit    = service.SubUnit
	subTemplateUnit   = service.SubTemplateUnit
	rotateServiceUnit = service.RotateUnit
	rootManagerBinary = service.RootManagerBinary
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install and control Xray-Proxya systemd units",
	Long: `Install, start, stop, restart, enable, disable, and query managed systemd units.

Managed units include:
  - xray-proxya:               Main Xray-Core proxy service
  - xray-proxya-pathd:         PathLink ICMP health & latency probe daemon
  - xray-proxya-ipv6-rotate:   Privileged IPv6 address rotation service
  - xray-proxya-sub:           Subscription server service`,
	Example: `  # Install unit files for current user or root
  xray-proxya service install

  # Start the main proxy service and subscription service
  xray-proxya service start xray-proxya
  xray-proxya service start xray-proxya-sub

  # Query status of all managed units
  xray-proxya service status`,
}

func managedUnitPath(unit string) string { return service.ManagedUnitPath(unit) }

func directRootServiceError() error { return service.DirectRootServiceError() }

func directRootServiceErrorFor(euid int, sudoUser, sudoUID, sudoCommand string) error {
	return service.DirectRootServiceErrorFor(euid, sudoUser, sudoUID, sudoCommand)
}

func buildSystemdServiceContent(binPath, workDir, assetDir, configDir, capabilities string, system, privateDevices bool) string {
	return service.BuildSystemdServiceContent(binPath, workDir, assetDir, configDir, capabilities, system, privateDevices)
}

func buildSubServiceContent(binPath, workDir, configDir, assetDir string, system bool) string {
	return service.BuildSubServiceContent(binPath, workDir, configDir, assetDir, system)
}

func buildIPv6RotateServiceContent(binPath, workDir, configDir, assetDir string) string {
	return service.BuildIPv6RotateServiceContent(binPath, workDir, configDir, assetDir)
}

func mainServiceActionNeedsGatewayRecovery(action string, now bool) bool {
	return action == "start" || (action == "enable" && now)
}

func normalizedManagedUnit(input string) (string, error) {
	return service.NormalizeUnitName(input)
}

func completeManagedServiceUnits(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	units := []string{
		"xray-proxya\tmain Xray-Proxya service",
		"xray-proxya-pathd\tPathLink ICMP agent",
		"xray-proxya-sub\tsubscription service",
		"xray-proxya-ipv6-rotate\tIPv6 rotation service",
	}
	return units, cobra.ShellCompDirectiveNoFileComp
}

func systemctlWrapper(action string) *cobra.Command {
	var now bool
	command := &cobra.Command{
		Use:   action + " [unit-name]",
		Short: "Run systemctl " + action + " for a managed unit",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() == 0 {
				if err := service.DirectRootServiceError(); err != nil {
					return err
				}
			}
			input := ""
			if len(args) == 1 {
				input = args[0]
			}
			unit, err := service.NormalizeUnitName(input)
			if err != nil {
				return err
			}
			if action == "status" {
				arguments := []string{"--no-pager", "status", unit}
				return xray.RunSystemd(arguments...)
			}
			return service.DefaultManager.ExecuteAction(action, unit, now)
		},
	}
	if action == "enable" || action == "disable" {
		command.Flags().BoolVar(&now, "now", false, "Start or stop the unit immediately")
	}
	return command
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Write managed systemd unit files without enabling or starting them",
	RunE:  func(cmd *cobra.Command, args []string) error { return service.Install(nil) },
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove stopped managed systemd unit files without disabling them",
	RunE:  func(cmd *cobra.Command, args []string) error { return service.Uninstall() },
}

func init() {
	enable := systemctlWrapper("enable")
	disable := systemctlWrapper("disable")
	serviceActions := []*cobra.Command{
		systemctlWrapper("start"),
		systemctlWrapper("stop"),
		systemctlWrapper("restart"),
		systemctlWrapper("status"),
		enable,
		disable,
	}
	for _, action := range serviceActions {
		action.ValidArgsFunction = completeManagedServiceUnits
	}
	serviceCmd.AddCommand(append([]*cobra.Command{serviceInstallCmd, serviceUninstallCmd}, serviceActions...)...)
	rootCmd.AddCommand(serviceCmd)
}
