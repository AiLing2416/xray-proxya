package selinux

import (
	"os"
	"os/exec"
	"strings"
)

const gatewayManagementEnv = "XRAY_PROXYA_GATEWAY_SELINUX_DOMAIN"
const gatewayLifecycleLockHeldEnv = "XRAY_PROXYA_GATEWAY_LIFECYCLE_LOCK_HELD"

// IsEnforcing reports whether SELinux is enabled and currently enforcing.
// Missing SELinux tooling is treated as a non-SELinux host.
func IsEnforcing() bool {
	out, err := exec.Command("getenforce").Output()
	return err == nil && strings.TrimSpace(string(out)) == "Enforcing"
}

// InGatewayDomain reports whether this process already runs in the short-lived
// Gateway management domain.
func InGatewayDomain() bool {
	// The marker is set only on the runcon child. It prevents that child from
	// re-executing itself; its privileges still come exclusively from the
	// xray_proxya_gateway_t SELinux domain.
	if os.Getenv(gatewayManagementEnv) == "1" {
		return true
	}
	data, err := os.ReadFile("/proc/self/attr/current")
	return err == nil && strings.Contains(string(data), "xray_proxya_gateway_t")
}

// GatewayManagementEnv returns the internal re-execution marker for the
// short-lived Gateway SELinux management domain.
func GatewayManagementEnv() string { return gatewayManagementEnv }

// GatewayLifecycleLockHeldEnv marks a management child whose parent already
// owns the cross-process lifecycle lock. Such a child must not try to acquire
// the same lock while the parent waits for it to finish.
func GatewayLifecycleLockHeldEnv() string { return gatewayLifecycleLockHeldEnv }
