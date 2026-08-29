package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

const (
	pathdServiceUnit  = "xray-proxya-pathd.service"
	subTemplateUnit   = "xray-proxya-sub@.service"
	rotateServiceUnit = "xray-proxya-ipv6-rotate.service"
	rootManagerBinary = "/root/.local/bin/xray-proxya"
)

var systemdInstanceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install and control Xray-Proxya systemd units",
	Long: `Install, start, stop, restart, enable, disable, and query managed systemd units.

Managed units include:
  - xray-proxya:               Main Xray-Core proxy service
  - xray-proxya-pathd:         PathLink ICMP health & latency probe daemon
  - xray-proxya-ipv6-rotate:   Privileged IPv6 address rotation service
  - xray-proxya-sub@<inst>:    Subscription server instances (e.g. xray-proxya-sub@default)`,
	Example: `  # Install unit files for current user or root
  xray-proxya service install

  # Start the main proxy service and default subscription instance
  xray-proxya service start xray-proxya
  xray-proxya service start xray-proxya-sub@default

  # Query status of all managed units
  xray-proxya service status`,
}

func userSystemdUnitDir() string {
	return filepath.Join(config.GetHomeDir(), ".config", "systemd", "user")
}

func unitDirectory() string {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system"
	}
	return userSystemdUnitDir()
}

func managedUnitPath(unit string) string { return filepath.Join(unitDirectory(), unit) }

func directRootServiceError() error {
	return directRootServiceErrorFor(os.Geteuid(), os.Getenv("SUDO_USER"), os.Getenv("SUDO_UID"), os.Getenv("SUDO_COMMAND"))
}

func directRootServiceErrorFor(euid int, sudoUser, sudoUID, sudoCommand string) error {
	return utils.RequireRootShellFor(euid, sudoUser, sudoUID, sudoCommand, "system service")
}

func isRootShellCommand(command string) bool {
	return utils.IsRootShellCommand(command)
}

func validateRootManagerBinary() (string, error) {
	path, err := filepath.EvalSymlinks(xray.GetXrayProxyaPath())
	if err != nil {
		return "", fmt.Errorf("resolve manager binary: %w", err)
	}
	path = filepath.Clean(path)
	if path != rootManagerBinary {
		return "", fmt.Errorf("root service binary must be %s, got %s", rootManagerBinary, path)
	}
	return validateRootOwnedExecutable(path)
}

func validateRootOwnedExecutable(path string) (string, error) {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	path = filepath.Clean(path)
	for current := path; current != "/"; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return "", fmt.Errorf("inspect %s: %w", current, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", fmt.Errorf("%s must be owned by root", current)
		}
		if info.Mode().Perm()&0022 != 0 {
			return "", fmt.Errorf("%s must not be group- or world-writable", current)
		}
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular executable file", path)
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%s is not executable", path)
	}
	return path, nil
}

func mainUnitCapabilities(cfg *config.UserConfig) string {
	if cfg != nil && cfg.Role == config.RoleGateway {
		return "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW"
	}
	return "CAP_NET_BIND_SERVICE"
}

func buildSystemdServiceContent(binPath, workDir, assetDir, configDir, capabilities string, system, privateDevices bool) string {
	userLine := ""
	wantedBy := "default.target"
	capabilityLines := ""
	privateDevicesValue := "yes"
	if !privateDevices {
		privateDevicesValue = "no"
	}
	if system {
		userLine = "User=root\n"
		wantedBy = "multi-user.target"
		capabilityLines = fmt.Sprintf("CapabilityBoundingSet=%s\nAmbientCapabilities=%s\n", capabilities, capabilities)
	}
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya Service
After=network-online.target
Wants=network-online.target

[Service]
	Type=exec
%sExecStart=%s run
Restart=on-failure
RestartSec=2
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=%s
ReadWritePaths=%s %s
%s

[Install]
WantedBy=%s
`, userLine, binPath, workDir, assetDir, privateDevicesValue, configDir, assetDir, capabilityLines, wantedBy)
}

func buildSubTemplateServiceContent(binPath, workDir, configDir, assetDir string, system bool) string {
	userLine := ""
	wantedBy := "default.target"
	capabilityLines := ""
	if system {
		userLine = "User=root\n"
		wantedBy = "multi-user.target"
		capabilityLines = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
	}
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya Subscription Server (%%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%sExecStartPre=%s sub validate %%i
ExecStart=%s sub run %%i
Restart=on-failure
RestartSec=2
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=%s %s
%s

[Install]
WantedBy=%s
`, userLine, binPath, binPath, workDir, assetDir, configDir, assetDir, capabilityLines, wantedBy)
}

func buildIPv6RotateServiceContent(binPath, workDir, configDir, assetDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya IPv6 Rotation Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStartPre=%s ipv6-rotate validate
ExecStart=%s ipv6-rotate run
Restart=on-failure
RestartSec=2
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=%s %s
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, binPath, binPath, workDir, assetDir, configDir, assetDir)
}

func serviceInstall() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd is required for service installation: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := directRootServiceError(); err != nil {
			return err
		}
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	system := os.Geteuid() == 0
	if system {
		if err := directRootServiceError(); err != nil {
			return err
		}
	} else if cfg.Role == config.RoleGateway {
		return fmt.Errorf("gateway role requires a direct-root system service; user services are non-privileged")
	}

	binPath := xray.GetXrayProxyaPath()
	if system {
		if binPath, err = validateRootManagerBinary(); err != nil {
			return err
		}
	} else if binPath, err = filepath.Abs(binPath); err != nil {
		return fmt.Errorf("resolve manager binary: %w", err)
	}
	workDir := filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya")
	assetDir := filepath.Join(workDir, "bin")
	configDir := config.GetConfigDir()
	if err := os.MkdirAll(assetDir, 0700); err != nil {
		return fmt.Errorf("create asset directory: %w", err)
	}
	var pathdContent string
	if system {
		pathdPath, err := validateRootOwnedExecutable(pathdBinaryPath())
		if err != nil {
			return fmt.Errorf("pathd binary is unavailable: %w", err)
		}
		if cfg.Role == config.RoleServer && cfg.Path.Token != "" {
			if err := writePathdConfig(cfg); err != nil {
				return fmt.Errorf("write pathd configuration: %w", err)
			}
		}
		pathdContent = buildPathdSystemdServiceContent(pathdPath, pathdConfigPath())
	}
	if err := os.MkdirAll(unitDirectory(), 0700); err != nil {
		return fmt.Errorf("create systemd unit directory: %w", err)
	}
	privateDevices := cfg.Role != config.RoleGateway
	if err := os.WriteFile(managedUnitPath(xray.MainServiceUnit), []byte(buildSystemdServiceContent(binPath, workDir, assetDir, configDir, mainUnitCapabilities(cfg), system, privateDevices)), 0644); err != nil {
		return fmt.Errorf("write %s: %w", xray.MainServiceUnit, err)
	}
	if err := os.WriteFile(managedUnitPath(subTemplateUnit), []byte(buildSubTemplateServiceContent(binPath, workDir, configDir, assetDir, system)), 0644); err != nil {
		return fmt.Errorf("write %s: %w", subTemplateUnit, err)
	}
	if system {
		if err := os.WriteFile(managedUnitPath(rotateServiceUnit), []byte(buildIPv6RotateServiceContent(binPath, workDir, configDir, assetDir)), 0644); err != nil {
			return fmt.Errorf("write %s: %w", rotateServiceUnit, err)
		}
	}
	if pathdContent != "" {
		if err := os.WriteFile(managedUnitPath(pathdServiceUnit), []byte(pathdContent), 0644); err != nil {
			return fmt.Errorf("write %s: %w", pathdServiceUnit, err)
		}
	}
	if err := xray.ReloadSystemdDaemon(); err != nil {
		return err
	}
	return nil
}

func activeManagedUnits() ([]string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, fmt.Errorf("systemctl is required: %w", err)
	}
	args := append(xray.SystemdScopeArgs(), "--no-legend", "--plain", "--type=service", "--state=active", "list-units", xray.MainServiceUnit, pathdServiceUnit, "xray-proxya-sub@*.service", rotateServiceUnit)
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list active managed units: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var units []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			units = append(units, fields[0])
		}
	}
	return units, nil
}

func serviceUninstall() error {
	if os.Geteuid() == 0 {
		if err := directRootServiceError(); err != nil {
			return err
		}
	}
	active, err := activeManagedUnits()
	if err != nil {
		return err
	}
	if len(active) > 0 {
		return fmt.Errorf("stop all managed services before uninstalling: %s", strings.Join(active, ", "))
	}
	for _, unit := range []string{xray.MainServiceUnit, pathdServiceUnit, subTemplateUnit, rotateServiceUnit} {
		if err := os.Remove(managedUnitPath(unit)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", unit, err)
		}
	}
	return xray.ReloadSystemdDaemon()
}

func normalizedManagedUnit(input string) (string, error) {
	if input == "" || input == "xray-proxya" || input == xray.MainServiceUnit {
		return xray.MainServiceUnit, nil
	}
	if input == "xray-proxya-pathd" || input == pathdServiceUnit {
		return pathdServiceUnit, nil
	}
	if input == "xray-proxya-ipv6-rotate" || input == rotateServiceUnit {
		return rotateServiceUnit, nil
	}
	name := strings.TrimSuffix(input, ".service")
	if name == "xray-proxya-sub" {
		return "xray-proxya-sub@default.service", nil
	}
	if strings.HasPrefix(name, "xray-proxya-sub@") {
		instance := strings.TrimPrefix(name, "xray-proxya-sub@")
		if systemdInstanceName.MatchString(instance) {
			return "xray-proxya-sub@" + instance + ".service", nil
		}
	}
	return "", fmt.Errorf("unit must be xray-proxya, xray-proxya-pathd, xray-proxya-ipv6-rotate, or xray-proxya-sub@<instance>")
}

func completeManagedServiceUnits(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	units := []string{
		"xray-proxya\tmain Xray-Proxya service",
		"xray-proxya-pathd\tPathLink ICMP agent",
		"xray-proxya-ipv6-rotate\tIPv6 rotation service",
	}
	cfg, err := config.LoadConfigEx(true)
	if err == nil {
		if cfg.SubscriptionInstances != nil {
			for inst := range cfg.SubscriptionInstances {
				units = append(units, fmt.Sprintf("xray-proxya-sub@%s\tsubscription instance %s", inst, inst))
			}
		}
		if cfg.AdminSub.Token != "" && (cfg.SubscriptionInstances == nil || cfg.SubscriptionInstances["default"].Token == "") {
			units = append(units, "xray-proxya-sub@default\tsubscription instance default")
		}
	}
	if len(units) == 3 {
		units = append(units, "xray-proxya-sub@default\tsubscription instance")
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
				if err := directRootServiceError(); err != nil {
					return err
				}
			}
			input := ""
			if len(args) == 1 {
				input = args[0]
			}
			unit, err := normalizedManagedUnit(input)
			if err != nil {
				return err
			}
			if unit == xray.MainServiceUnit && os.Geteuid() == 0 {
				return manageMainServiceAction(action, now)
			}
			if unit == pathdServiceUnit && (action == "start" || action == "restart" || (action == "enable" && now)) {
				if err := validatePathdServiceStart(); err != nil {
					return err
				}
			}
			if strings.HasPrefix(unit, "xray-proxya-sub@") && (action == "start" || action == "restart" || (action == "enable" && now)) {
				if err := validateSubscriptionServiceStart(unit); err != nil {
					return err
				}
			}
			if unit == rotateServiceUnit && (action == "start" || action == "restart" || (action == "enable" && now)) {
				if err := validateIPv6RotateServiceStart(); err != nil {
					return err
				}
			}
			arguments := []string{"--no-pager", action}
			if now {
				arguments = append(arguments, "--now")
			}
			arguments = append(arguments, unit)
			return xray.RunSystemd(arguments...)
		},
	}
	if action == "enable" || action == "disable" {
		command.Flags().BoolVar(&now, "now", false, "Start or stop the unit immediately")
	}
	return command
}

func validatePathdServiceStart() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("xray-proxya-pathd requires a root system service")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("load active Pathd configuration: %w", err)
	}
	if cfg.Role != config.RoleServer {
		return fmt.Errorf("xray-proxya-pathd can run only on a Server")
	}
	return nil
}

func validateSubscriptionServiceStart(unit string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("load active subscription configuration: %w", err)
	}
	if cfg.Role != config.RoleServer {
		return fmt.Errorf("%s can run only on a Server", unit)
	}
	inst := strings.TrimSuffix(strings.TrimPrefix(unit, "xray-proxya-sub@"), ".service")
	var entry config.AdminSubConfig
	found := false
	if cfg.SubscriptionInstances != nil {
		if subEntry, ok := cfg.SubscriptionInstances[inst]; ok && subEntry.Token != "" {
			entry = subEntry
			found = true
		}
	}
	if !found && inst == defaultSubInstance && cfg.AdminSub.Token != "" {
		entry = cfg.AdminSub
		found = true
	}
	if !found || entry.Token == "" || entry.Port <= 0 {
		return fmt.Errorf("configure subscription instance %q first with 'sub set %s', then apply", inst, inst)
	}
	if entry.IPv6Rotation != "" && os.Geteuid() != 0 {
		return fmt.Errorf("IPv6-rotate subscriptions require a root system service")
	}
	return nil
}

func validateIPv6RotateServiceStart() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("xray-proxya-ipv6-rotate requires a root system service")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("load active IPv6 rotation configuration: %w", err)
	}
	if cfg.Role != config.RoleServer {
		return fmt.Errorf("xray-proxya-ipv6-rotate can run only on a Server")
	}
	rotation := cfg.IPv6Rotation
	if rotation.Subnet == "" && cfg.IPv6Rotations != nil {
		rotation = cfg.IPv6Rotations["default"]
	}
	if rotation.Interface == "" || rotation.Subnet == "" {
		return fmt.Errorf("IPv6 rotation is not configured; use 'ipv6-rotate set', then apply")
	}
	return nil
}

// manageMainServiceAction keeps generic systemctl operations from bypassing
// the gateway lifecycle lock.  A direct stop must remove interception before
// the TUN file descriptors disappear; restart uses the registered recovery
// hook so the freshly-created TUN receives its managed routes and firewall.
func manageMainServiceAction(action string, now bool) error {
	if action == "restart" {
		return xray.RestartXrayService()
	}
	if action == "stop" || (action == "disable" && now) {
		return config.WithLifecycleLock(func() error {
			cleanupErr := gateway.CleanupFirewall()
			arguments := []string{"--no-pager", action}
			if now {
				arguments = append(arguments, "--now")
			}
			arguments = append(arguments, xray.MainServiceUnit)
			return errors.Join(cleanupErr, xray.RunSystemd(arguments...))
		})
	}
	arguments := []string{"--no-pager", action}
	if now {
		arguments = append(arguments, "--now")
	}
	arguments = append(arguments, xray.MainServiceUnit)
	if err := xray.RunSystemd(arguments...); err != nil {
		return err
	}
	// systemd Type=exec confirms only that the manager binary was executed;
	// the Xray child creates proxya-tun asynchronously.  Wait for the same
	// locked runtime repair used by a restart before reporting a gateway start
	// as successful.  This also covers `enable --now`.
	if mainServiceActionNeedsGatewayRecovery(action, now) {
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load active config after service start: %w", err)
		}
		if err := gateway.RestoreTunState(cfg); err != nil {
			return fmt.Errorf("restore gateway runtime after service start: %w", err)
		}
	}
	return nil
}

func mainServiceActionNeedsGatewayRecovery(action string, now bool) bool {
	return action == "start" || (action == "enable" && now)
}

var serviceInstallCmd = &cobra.Command{Use: "install", Short: "Write managed systemd unit files without enabling or starting them", RunE: func(cmd *cobra.Command, args []string) error { return serviceInstall() }}
var serviceUninstallCmd = &cobra.Command{Use: "uninstall", Short: "Remove stopped managed systemd unit files without disabling them", RunE: func(cmd *cobra.Command, args []string) error { return serviceUninstall() }}

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
