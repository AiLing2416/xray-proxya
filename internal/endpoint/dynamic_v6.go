package endpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

// AddressEntry tracks the state and lifecycle of an allocated IPv6 address.
type AddressEntry struct {
	Address      string    `json:"address"`
	State        string    `json:"state"` // "active", "deprecated"
	CreatedAt    time.Time `json:"created_at"`
	DeprecatedAt time.Time `json:"deprecated_at,omitempty"`
}

// RotationState records the active and deprecated address pools for an endpoint.
type RotationState struct {
	ActivePool     []AddressEntry `json:"active_pool"`
	DeprecatedPool []AddressEntry `json:"deprecated_pool"`
}

var (
	rotationMutex sync.Mutex
	probeFunc     = TestIPv6Reachability
	cmdRunner     = func(name string, arg ...string) ([]byte, error) {
		return exec.Command(name, arg...).CombinedOutput()
	}
)

// RotationStatePath returns the path to the JSON state file for the given endpoint name.
func RotationStatePath(endpointName string) string {
	return filepath.Join(config.GetConfigDir(), "endpoints", endpointName+".json")
}

// LoadRotationState reads and unmarshals the rotation state from disk.
func LoadRotationState(endpointName string) (*RotationState, error) {
	p := RotationStatePath(endpointName)
	data, err := os.ReadFile(p)
	if err != nil {
		return &RotationState{
			ActivePool:     []AddressEntry{},
			DeprecatedPool: []AddressEntry{},
		}, err
	}
	var st RotationState
	if err := json.Unmarshal(data, &st); err != nil {
		return &RotationState{
			ActivePool:     []AddressEntry{},
			DeprecatedPool: []AddressEntry{},
		}, err
	}
	if st.ActivePool == nil {
		st.ActivePool = []AddressEntry{}
	}
	if st.DeprecatedPool == nil {
		st.DeprecatedPool = []AddressEntry{}
	}
	return &st, nil
}

// SaveRotationState atomically writes the rotation state to disk.
func SaveRotationState(endpointName string, st *RotationState) error {
	p := RotationStatePath(endpointName)
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

func execCmd(name string, arg ...string) {
	_, _ = cmdRunner(name, arg...)
}

func isTunnelInterface(iface string) bool {
	lower := strings.ToLower(iface)
	return strings.Contains(lower, "sit") || strings.Contains(lower, "he-") || strings.Contains(lower, "tun")
}

// NextAddress generates a new random IPv6 address from ep.Subnet, verifies outer connectivity,
// updates the active pool, softly deprecates old addresses in compliance with RFC 4941,
// cleans expired addresses, and persists state.
func NextAddress(endpointName string, ep config.EndpointConfig) (string, error) {
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	subnet := strings.TrimSpace(ep.Subnet)
	if subnet == "" {
		return "", fmt.Errorf("dynamic-v6 endpoint '%s' has no subnet configured", endpointName)
	}

	iface := strings.TrimSpace(ep.Interface)
	if iface == "" {
		iface = "he-ipv6"
	}

	maxAddrs := ep.MaxAddresses
	if maxAddrs <= 0 {
		maxAddrs = 6
	}

	st, _ := LoadRotationState(endpointName)
	if st == nil {
		st = &RotationState{
			ActivePool:     []AddressEntry{},
			DeprecatedPool: []AddressEntry{},
		}
	}

	var newIP string
	var verified bool
	var lastProbeErr error

	for attempt := 0; attempt < 3; attempt++ {
		genIP, err := utils.GenerateRandomIPv6(subnet)
		if err != nil {
			return "", fmt.Errorf("failed to generate random IPv6: %w", err)
		}

		// Avoid collisions with current pools
		collision := false
		for _, a := range st.ActivePool {
			if a.Address == genIP {
				collision = true
				break
			}
		}
		if !collision {
			for _, a := range st.DeprecatedPool {
				if a.Address == genIP {
					collision = true
					break
				}
			}
		}
		if collision {
			continue
		}

		// Bind new IP to interface with preferred_lft 7200 valid_lft 14400
		if out, err := cmdRunner("ip", "-6", "addr", "replace", genIP+"/128", "dev", iface, "nodad", "preferred_lft", "7200", "valid_lft", "14400"); err != nil {
			lastProbeErr = fmt.Errorf("failed to bind address to %s: %w (%s)", iface, err, strings.TrimSpace(string(out)))
			continue
		}

		// Smart NDP: skip on tunnels (sit*, he-*, tun*); configure on physical interfaces if enabled
		if !isTunnelInterface(iface) && ep.EnableNDP {
			execCmd("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.proxy_ndp=1", iface))
			execCmd("ip", "-6", "neigh", "replace", "proxy", genIP, "dev", iface)
		}

		// Pre-flight reachability test
		ok, _, pErr := probeFunc(genIP, 3*time.Second)
		if ok {
			newIP = genIP
			verified = true
			break
		}

		// Rollback failed address immediately
		lastProbeErr = pErr
		execCmd("ip", "-6", "addr", "del", genIP+"/128", "dev", iface)
		if !isTunnelInterface(iface) && ep.EnableNDP {
			execCmd("ip", "-6", "neigh", "del", "proxy", genIP, "dev", iface)
		}
	}

	if !verified {
		return "", fmt.Errorf("failed to verify reachability for new IPv6 address: %v", lastProbeErr)
	}

	now := time.Now()
	// Add to ActivePool
	st.ActivePool = append(st.ActivePool, AddressEntry{
		Address:   newIP,
		State:     "active",
		CreatedAt: now,
	})

	// RFC 4941 Soft Deprecation if ActivePool exceeds MaxAddresses
	for len(st.ActivePool) > maxAddrs {
		old := st.ActivePool[0]
		st.ActivePool = st.ActivePool[1:]

		// Change preferred_lft to 0, keep valid_lft for 3600 seconds
		execCmd("ip", "-6", "addr", "change", old.Address+"/128", "dev", iface, "preferred_lft", "0", "valid_lft", "3600")

		old.State = "deprecated"
		old.DeprecatedAt = now
		st.DeprecatedPool = append(st.DeprecatedPool, old)
	}

	// Evict entries from DeprecatedPool older than 1 hour
	var remainingDeprecated []AddressEntry
	for _, dep := range st.DeprecatedPool {
		if !dep.DeprecatedAt.IsZero() && now.Sub(dep.DeprecatedAt) >= 1*time.Hour {
			execCmd("ip", "-6", "addr", "del", dep.Address+"/128", "dev", iface)
			if !isTunnelInterface(iface) && ep.EnableNDP {
				execCmd("ip", "-6", "neigh", "del", "proxy", dep.Address, "dev", iface)
			}
		} else {
			remainingDeprecated = append(remainingDeprecated, dep)
		}
	}
	st.DeprecatedPool = remainingDeprecated

	if err := SaveRotationState(endpointName, st); err != nil {
		return newIP, fmt.Errorf("address allocated (%s) but failed to save state: %w", newIP, err)
	}

	return newIP, nil
}

// ReconcileOnStartup reads the persisted pool state and aligns kernel addresses.
func ReconcileOnStartup(endpointName string, ep config.EndpointConfig) error {
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	st, err := LoadRotationState(endpointName)
	if err != nil || st == nil {
		return nil
	}

	iface := strings.TrimSpace(ep.Interface)
	if iface == "" {
		iface = "he-ipv6"
	}

	now := time.Now()
	for _, act := range st.ActivePool {
		execCmd("ip", "-6", "addr", "replace", act.Address+"/128", "dev", iface, "nodad", "preferred_lft", "7200", "valid_lft", "14400")
		if !isTunnelInterface(iface) && ep.EnableNDP {
			execCmd("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.proxy_ndp=1", iface))
			execCmd("ip", "-6", "neigh", "replace", "proxy", act.Address, "dev", iface)
		}
	}

	var remaining []AddressEntry
	for _, dep := range st.DeprecatedPool {
		if !dep.DeprecatedAt.IsZero() && now.Sub(dep.DeprecatedAt) >= 1*time.Hour {
			execCmd("ip", "-6", "addr", "del", dep.Address+"/128", "dev", iface)
			if !isTunnelInterface(iface) && ep.EnableNDP {
				execCmd("ip", "-6", "neigh", "del", "proxy", dep.Address, "dev", iface)
			}
		} else {
			execCmd("ip", "-6", "addr", "change", dep.Address+"/128", "dev", iface, "preferred_lft", "0", "valid_lft", "3600")
			remaining = append(remaining, dep)
		}
	}
	st.DeprecatedPool = remaining

	return SaveRotationState(endpointName, st)
}
