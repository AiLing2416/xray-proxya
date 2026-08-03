package gateway

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
)

const tunWaitTimeout = 5 * time.Second

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
	deadline := time.Now().Add(tunWaitTimeout)
	for time.Now().Before(deadline) {
		_, err := net.InterfaceByName(tunName)
		if (err == nil) == present {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if present {
		return fmt.Errorf("tun interface %s was not created in time by Xray core", tunName)
	}
	return fmt.Errorf("tun interface %s still exists after Xray restart", tunName)
}

func restartWithTunDisabled(disabled bool) error {
	if err := config.SetGatewayTunDisabled(disabled); err != nil {
		return fmt.Errorf("set gateway runtime state: %w", err)
	}
	if err := xray.RestartXrayService(); err != nil {
		return fmt.Errorf("restart Xray service: %w", err)
	}
	return waitForTun(!disabled)
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
	if os.Geteuid() != 0 {
		return fmt.Errorf("gateway up requires root")
	}
	if !WantsTunnel(cfg) {
		return fmt.Errorf("gateway TUN is not enabled in active config; set state=proxy and enable local or LAN first")
	}
	if err := restartWithTunDisabled(false); err != nil {
		_ = config.SetGatewayTunDisabled(true)
		CleanupFirewall()
		return err
	}
	// The restarted run command owns initial firewall setup. Waiting for the
	// complete observed state prevents a second concurrent ApplyFirewall call.
	if err := waitForReady(cfg); err != nil {
		_ = Down()
		return err
	}
	return nil
}

// Down first removes the traffic interception rules, then restarts the single
// Xray core with no TUN inbound. It intentionally leaves active config intact.
func Down() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("gateway down requires root")
	}
	CleanupFirewall()
	return restartWithTunDisabled(true)
}

// SyncDesired is used by apply after committing a gateway configuration change.
func SyncDesired(cfg *config.UserConfig) error {
	if cfg == nil || cfg.Role != config.RoleGateway {
		return nil
	}
	if WantsTunnel(cfg) {
		return Up(cfg)
	}
	CleanupFirewall()
	if err := restartWithTunDisabled(true); err != nil {
		return err
	}
	if cfg.Gateway.State == "forward-only" {
		return ApplyFirewall(cfg)
	}
	return nil
}
