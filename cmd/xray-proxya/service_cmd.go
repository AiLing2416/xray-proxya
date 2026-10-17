package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"xray-proxya/internal/service"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

const (
	pathdServiceUnit  = service.PathdUnit
	subServiceUnit    = service.SubUnit
	subTemplateUnit   = service.SubTemplateUnit
	rootManagerBinary = service.RootManagerBinary
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install and control Xray-Proxya system services (systemd / OpenRC / procd)",
	Long: `Install, start, stop, restart, enable, disable, and query managed services across systemd, OpenRC, and procd.

Managed units include:
  - core / xray-proxya:               Main Xray-Core proxy service
  - sub / xray-proxya-sub:             Subscription server service
  - pathd / xray-proxya-pathd:         PathLink ICMP health & latency probe daemon`,
	Example: `  # Install unit files for current user or root
  xray-proxya service install

  # Start the main proxy service and subscription service
  xray-proxya service start core
  xray-proxya service start sub

  # View service logs
  xray-proxya service logs core -n 50
  xray-proxya service logs sub -f

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

func mainServiceActionNeedsGatewayRecovery(action string, now bool) bool {
	return action == "start" || (action == "enable" && now)
}

func normalizedManagedUnit(input string) (string, error) {
	return service.NormalizeUnitName(input)
}

func completeManagedServiceUnits(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	units := []string{
		"core\tCore proxy service (xray-proxya)",
		"sub\tSubscription distribution service (xray-proxya-sub)",
		"pathd\tPathLink ICMP latency & health daemon (xray-proxya-pathd)",
		"xray-proxya\tCore proxy service (xray-proxya)",
		"xray-proxya-sub\tSubscription distribution service (xray-proxya-sub)",
		"xray-proxya-pathd\tPathLink ICMP latency & health daemon (xray-proxya-pathd)",
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
				p := service.CurrentProvider()
				if p.Type() == service.InitSystemd {
					arguments := []string{"--no-pager", "status", unit}
					if err := xray.RunSystemd(arguments...); err != nil {
						var exitErr *exec.ExitError
						if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
							return nil
						}
						return err
					}
					return nil
				}
				if p.Type() == service.InitOpenRC {
					name := service.BaseServiceName(unit)
					c := exec.Command("rc-service", name, "status")
					c.Stdout, c.Stderr = cmd.OutOrStdout(), cmd.ErrOrStderr()
					_ = c.Run()
					return nil
				}
				if p.Type() == service.InitProcd {
					path := p.UnitPath(unit)
					if _, err := os.Stat(path); err == nil {
						c := exec.Command(path, "status")
						c.Stdout, c.Stderr = cmd.OutOrStdout(), cmd.ErrOrStderr()
						_ = c.Run()
						return nil
					}
					st, _ := p.GetStatus(unit)
					fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (PID: %d, Installed: %v, Enabled: %v)\n",
						st.DisplayName, st.State, st.PID, st.Installed, st.Enabled)
					return nil
				}
				st, _ := service.GetStatus(unit)
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (PID: %d, Installed: %v, Enabled: %v)\n",
					st.DisplayName, st.State, st.PID, st.Installed, st.Enabled)
				return nil
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
	Short: "Write managed service files without enabling or starting them",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := service.Install(nil); err != nil {
			return err
		}
		initType := service.CurrentProvider().Type()
		fmt.Fprintf(cmd.OutOrStdout(), "✅ Managed %s service files installed.\n", initType)
		if os.Geteuid() != 0 && initType == service.InitSystemd {
			user := currentLingerUser()
			if enabled, err := checkLingerStatus(user); err == nil && !enabled {
				fmt.Fprintf(cmd.OutOrStdout(), "💡 Notice: User session lingering is disabled for %q.\n   Run 'xray-proxya doctor linger enable' to keep user services running after logout.\n", user)
			}
		}
		return nil
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove stopped managed service files without disabling them",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := service.Uninstall(); err != nil {
			return err
		}
		initType := service.CurrentProvider().Type()
		fmt.Fprintf(cmd.OutOrStdout(), "✅ Managed %s service files uninstalled.\n", initType)
		return nil
	},
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
