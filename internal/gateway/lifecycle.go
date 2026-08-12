package gateway

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"xray-proxya/internal/config"
	proxyaSELinux "xray-proxya/internal/selinux"
	"xray-proxya/internal/xray"
)

const tunWaitTimeout = 5 * time.Second

func init() {
	// Xray recreates its TUN devices during every process restart. Register the
	// gateway-owned state repair with the common restart path so service
	// restarts, crash recovery, and ordinary apply operations all converge on
	// the same kernel state.
	xray.RegisterRestartHook(func() error {
		cfg, err := config.LoadConfig()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		return RestoreTunStateLocked(cfg)
	})
}

// WantsTunnel reports whether the desired gateway configuration needs an Xray
// TUN inbound. Forward-only and disabled states deliberately run without one.
func WantsTunnel(cfg *config.UserConfig) bool {
	state := ""
	if cfg != nil {
		state = cfg.Gateway.State
	}
	if state == "" {
		state = "proxy"
	}
	return cfg != nil &&
		cfg.Role == config.RoleGateway &&
		cfg.Gateway.Mode == "tun" &&
		state == "proxy" &&
		(cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled)
}

func waitForTun(present bool) error {
	return waitForInterface(tunName, present)
}

func waitForInterface(name string, present bool) error {
	deadline := time.Now().Add(tunWaitTimeout)
	for time.Now().Before(deadline) {
		_, err := net.InterfaceByName(name)
		if (err == nil) == present {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if present {
		return fmt.Errorf("tun interface %s was not created in time", name)
	}
	return fmt.Errorf("tun interface %s still exists after Xray restart", name)
}

func restartWithTunDisabled(disabled bool) error {
	if err := config.SetGatewayTunDisabled(disabled); err != nil {
		return fmt.Errorf("set gateway runtime state: %w", err)
	}
	if err := xray.RestartXrayServiceWithoutHook(); err != nil {
		return fmt.Errorf("restart Xray service: %w", err)
	}
	return waitForTun(!disabled)
}

// RestoreTunState reapplies all kernel state that is intentionally outside
// Xray's config: interface addresses, forwarding/rp_filter sysctls, policy
// routing, and nftables. It is a no-op when the active gateway is down.
func RestoreTunState(cfg *config.UserConfig) error {
	return config.WithLifecycleLock(func() error {
		return RestoreTunStateLocked(cfg)
	})
}

// RestoreTunStateLocked is the lock-aware implementation used by the Xray
// restart hook and other callers that already hold the lifecycle lock.
func RestoreTunStateLocked(cfg *config.UserConfig) error {
	if cfg == nil || !WantsTunnel(cfg) || config.GatewayTunDisabled() {
		return nil
	}
	// A gateway transition may have already repaired the freshly recreated
	// interface while the service process was waiting for this lock. Avoid a
	// second cleanup/rebuild pass, which would expose a transient window with
	// no nftables or policy rules after `gateway up` returns.
	if len(Verify(cfg)) == 0 {
		return nil
	}
	if err := waitForTun(true); err != nil {
		return err
	}
	if pathTunnelEnabled(cfg) {
		if err := waitForInterface(pathTunName, true); err != nil {
			return err
		}
	}
	if err := ApplyFirewall(cfg); err != nil {
		return fmt.Errorf("reapply gateway runtime state: %w", err)
	}
	return waitForReady(cfg)
}

func waitForReady(cfg *config.UserConfig) error {
	deadline := time.Now().Add(tunWaitTimeout)
	var problems []string
	for time.Now().Before(deadline) {
		problems = Verify(cfg)
		if len(problems) == 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("gateway runtime did not become ready: %s", strings.Join(problems, "; "))
}

// Up makes the active gateway configuration operational. Xray owns the TUN
// device; firewall and policy rules are installed only after that device exists.
func Up(cfg *config.UserConfig) error {
	delegated, err := ensureManagementDomain("system-up")
	if err != nil {
		return err
	}
	if delegated {
		return nil
	}
	return config.WithLifecycleLock(func() error {
		return upLocked(cfg)
	})
}

func upLocked(cfg *config.UserConfig) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("gateway up requires root")
	}
	if !WantsTunnel(cfg) {
		return fmt.Errorf("gateway TUN is not enabled in active config; set state=proxy and enable local or LAN first")
	}
	if err := restartWithTunDisabled(false); err != nil {
		_ = config.SetGatewayTunDisabled(true)
		return errors.Join(err, CleanupFirewall())
	}
	// Firewall and policy routing are owned by this explicit root operation,
	// rather than the long-running Xray service domain.
	if err := ApplyFirewall(cfg); err != nil {
		_ = downLocked()
		return fmt.Errorf("apply gateway firewall: %w", err)
	}
	if err := waitForReady(cfg); err != nil {
		_ = downLocked()
		return err
	}
	return nil
}

// Down first removes the traffic interception rules, then restarts the single
// Xray core with no TUN inbound. It intentionally leaves active config intact.
func Down() error {
	delegated, err := ensureManagementDomain("system-down")
	if err != nil {
		return err
	}
	if delegated {
		return nil
	}
	return config.WithLifecycleLock(func() error {
		return downLocked()
	})
}

func downLocked() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("gateway down requires root")
	}
	cleanupErr := CleanupFirewall()
	return errors.Join(cleanupErr, restartWithTunDisabled(true))
}

// SyncDesired is used by apply after committing a gateway configuration change.
func SyncDesired(cfg *config.UserConfig) error {
	delegated, err := ensureManagementDomain("system-sync")
	if err != nil {
		return err
	}
	if delegated {
		return nil
	}
	return config.WithLifecycleLock(func() error {
		return syncDesiredLocked(cfg)
	})
}

// SyncDesiredLocked synchronizes an already committed gateway config while
// the caller owns the lifecycle lock.
func SyncDesiredLocked(cfg *config.UserConfig) error {
	return syncDesiredLocked(cfg)
}

func syncDesiredLocked(cfg *config.UserConfig) error {
	if cfg == nil || cfg.Role != config.RoleGateway {
		return nil
	}
	if WantsTunnel(cfg) {
		return upLocked(cfg)
	}
	if err := CleanupFirewall(); err != nil {
		return err
	}
	if err := restartWithTunDisabled(true); err != nil {
		return err
	}
	if cfg.Gateway.State == "forward-only" {
		return ApplyFirewall(cfg)
	}
	return nil
}

// ensureManagementDomain re-executes Gateway mutations in the short-lived
// SELinux domain. On non-SELinux hosts and from the child process it is a no-op.
func ensureManagementDomain(operation string) (bool, error) {
	if !proxyaSELinux.IsEnforcing() || proxyaSELinux.InGatewayDomain() {
		return false, nil
	}
	if _, err := exec.LookPath("runcon"); err != nil {
		return false, fmt.Errorf("SELinux is enforcing but runcon is unavailable: %w", err)
	}
	bin, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("locate xray-proxya binary: %w", err)
	}
	cmd := exec.Command("runcon", "-r", "system_r", "-t", "xray_proxya_gateway_t", bin, "gateway", operation)
	// Gateway management does not accept interactive input.  Do not inherit the
	// caller's terminal or SSH pipes into the confined child: their labels are
	// deliberately outside xray_proxya_gateway_t and would otherwise make a
	// successful network operation fail on its diagnostic output path.
	cmd.Env = append(os.Environ(), proxyaSELinux.GatewayManagementEnv()+"=1")
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("run Gateway SELinux management domain: %w", err)
	}
	return true, nil
}
