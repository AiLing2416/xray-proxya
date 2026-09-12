package endpoint

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// ConsumerState tracks active and deprecated addresses for an isolated consumer.
type ConsumerState struct {
	ActivePool     []AddressEntry `json:"active_pool"`
	DeprecatedPool []AddressEntry `json:"deprecated_pool"`
}

// RotationState records the active and deprecated address pools for an endpoint.
type RotationState struct {
	ActivePool     []AddressEntry            `json:"active_pool"`
	DeprecatedPool []AddressEntry            `json:"deprecated_pool"`
	Consumers      map[string]*ConsumerState `json:"consumers,omitempty"`
}

var (
	rotationMutex sync.Mutex
	probeFunc     = TestIPv6Reachability
	cmdRunner     = func(name string, arg ...string) ([]byte, error) {
		return exec.Command(name, arg...).CombinedOutput()
	}
	interfaceCheckFunc = func(iface string) bool {
		ifc, err := net.InterfaceByName(iface)
		if err != nil {
			return false
		}
		return (ifc.Flags & net.FlagUp) != 0
	}
	interfaceWaitTimeout  = 5 * time.Second
	interfaceWaitInterval = 500 * time.Millisecond
)

// SetTestInterfaceChecker configures a mock interface checker and wait parameters.
func SetTestInterfaceChecker(checker func(string) bool, timeout, interval time.Duration) func() {
	origChecker := interfaceCheckFunc
	origTimeout := interfaceWaitTimeout
	origInterval := interfaceWaitInterval
	if checker != nil {
		interfaceCheckFunc = checker
	}
	if timeout > 0 {
		interfaceWaitTimeout = timeout
	}
	if interval > 0 {
		interfaceWaitInterval = interval
	}
	return func() {
		interfaceCheckFunc = origChecker
		interfaceWaitTimeout = origTimeout
		interfaceWaitInterval = origInterval
	}
}

func waitForInterface(iface string, timeout, interval time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if interfaceCheckFunc(iface) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

func withFileLock(endpointName string, fn func() error) error {
	lockDir := filepath.Join(config.GetConfigDir(), "endpoints")
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return err
	}
	lockPath := filepath.Join(lockDir, endpointName+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire file lock for endpoint '%s': %w", endpointName, err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	return fn()
}

// SetTestRunners configures mock command and reachability runners for testing.
// It returns a restore function that resets the runners to defaults.
func SetTestRunners(runner func(name string, arg ...string) ([]byte, error), probe func(string, time.Duration) (bool, time.Duration, error)) func() {
	origCmd := cmdRunner
	origProbe := probeFunc
	if runner != nil {
		cmdRunner = runner
	}
	if probe != nil {
		probeFunc = probe
	}
	return func() {
		cmdRunner = origCmd
		probeFunc = origProbe
	}
}

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
	if st.Consumers == nil {
		st.Consumers = make(map[string]*ConsumerState)
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

// NormalizeProfile returns a canonical rotation profile name. Defaults to "turtle".
func NormalizeProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case config.RotationProfileProactive:
		return config.RotationProfileProactive
	case config.RotationProfileIsolated:
		return config.RotationProfileIsolated
	case config.RotationProfileTurtle:
		return config.RotationProfileTurtle
	default:
		return config.RotationProfileTurtle
	}
}

// ParseTTL parses a duration string or shorthand like "1d", "12h". Defaults to 12h.
func ParseTTL(ttlStr string) time.Duration {
	defaultTTL := 12 * time.Hour
	s := strings.ToLower(strings.TrimSpace(ttlStr))
	if s == "" {
		return defaultTTL
	}
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(numStr)
		if err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return defaultTTL
	}
	return d
}

func allocateAndVerifyAddress(subnet, iface string, enableNDP bool, isColliding func(string) bool) (string, error) {
	var newIP string
	var verified bool
	var lastProbeErr error

	for attempt := 0; attempt < 3; attempt++ {
		genIP, err := utils.GenerateRandomIPv6(subnet)
		if err != nil {
			return "", fmt.Errorf("failed to generate random IPv6: %w", err)
		}

		if isColliding != nil && isColliding(genIP) {
			continue
		}

		// Bind new IP to interface with preferred_lft 7200 valid_lft 14400
		if out, err := cmdRunner("ip", "-6", "addr", "replace", genIP+"/128", "dev", iface, "nodad", "preferred_lft", "7200", "valid_lft", "14400"); err != nil {
			lastProbeErr = fmt.Errorf("failed to bind address to %s: %w (%s)", iface, err, strings.TrimSpace(string(out)))
			continue
		}

		// Smart NDP: skip on tunnels (sit*, he-*, tun*); configure on physical interfaces if enabled
		if !isTunnelInterface(iface) && enableNDP {
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
		if !isTunnelInterface(iface) && enableNDP {
			execCmd("ip", "-6", "neigh", "del", "proxy", genIP, "dev", iface)
		}
	}

	if !verified {
		return "", fmt.Errorf("failed to verify reachability for new IPv6 address: %v", lastProbeErr)
	}
	return newIP, nil
}

func demoteAddress(iface string, old AddressEntry, now time.Time) AddressEntry {
	execCmd("ip", "-6", "addr", "change", old.Address+"/128", "dev", iface, "preferred_lft", "0", "valid_lft", "3600")
	old.State = "deprecated"
	old.DeprecatedAt = now
	return old
}

func pruneDeprecated(iface string, enableNDP bool, pool []AddressEntry, now time.Time) []AddressEntry {
	var remaining []AddressEntry
	for _, dep := range pool {
		if !dep.DeprecatedAt.IsZero() && now.Sub(dep.DeprecatedAt) >= 1*time.Hour {
			execCmd("ip", "-6", "addr", "del", dep.Address+"/128", "dev", iface)
			if !isTunnelInterface(iface) && enableNDP {
				execCmd("ip", "-6", "neigh", "del", "proxy", dep.Address, "dev", iface)
			}
		} else {
			remaining = append(remaining, dep)
		}
	}
	return remaining
}

// ResolveDynamicV6Address resolves the active address for a dynamic-v6 endpoint
// according to its configured rotation profile (turtle, proactive, or isolated).
func ResolveDynamicV6Address(endpointName string, ep config.EndpointConfig, consumer string, forSubscription bool) (string, error) {
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	var ip string
	err := withFileLock(endpointName, func() error {
		var err error
		ip, err = resolveDynamicV6Locked(endpointName, ep, consumer, forSubscription)
		return err
	})
	return ip, err
}

func resolveDynamicV6Locked(endpointName string, ep config.EndpointConfig, consumer string, forSubscription bool) (string, error) {
	subnet := strings.TrimSpace(ep.Subnet)
	if subnet == "" {
		return "", fmt.Errorf("dynamic-v6 endpoint '%s' has no subnet configured", endpointName)
	}
	iface := strings.TrimSpace(ep.Interface)
	if iface == "" {
		return "", fmt.Errorf("dynamic-v6 endpoint '%s' has no network interface configured", endpointName)
	}

	profile := NormalizeProfile(ep.Profile)
	ttl := ParseTTL(ep.TTL)

	st, _ := LoadRotationState(endpointName)
	if st == nil {
		st = &RotationState{
			ActivePool:     []AddressEntry{},
			DeprecatedPool: []AddressEntry{},
			Consumers:      make(map[string]*ConsumerState),
		}
	}
	if st.Consumers == nil {
		st.Consumers = make(map[string]*ConsumerState)
	}

	now := time.Now()

	isColliding := func(candidate string) bool {
		for _, a := range st.ActivePool {
			if a.Address == candidate {
				return true
			}
		}
		for _, a := range st.DeprecatedPool {
			if a.Address == candidate {
				return true
			}
		}
		for _, cs := range st.Consumers {
			for _, a := range cs.ActivePool {
				if a.Address == candidate {
					return true
				}
			}
			for _, a := range cs.DeprecatedPool {
				if a.Address == candidate {
					return true
				}
			}
		}
		return false
	}

	switch profile {
	case config.RotationProfileIsolated:
		cKey := strings.TrimSpace(consumer)
		if cKey == "" {
			cKey = "admin"
		}
		cs, exists := st.Consumers[cKey]
		if !exists || cs == nil {
			cs = &ConsumerState{
				ActivePool:     []AddressEntry{},
				DeprecatedPool: []AddressEntry{},
			}
			st.Consumers[cKey] = cs
		}

		if len(cs.ActivePool) == 0 {
			newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
			if err != nil {
				return "", err
			}
			cs.ActivePool = []AddressEntry{{
				Address:   newIP,
				State:     "active",
				CreatedAt: now,
			}}
			cs.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, cs.DeprecatedPool, now)
			_ = SaveRotationState(endpointName, st)
			return newIP, nil
		}

		current := cs.ActivePool[len(cs.ActivePool)-1]
		if !forSubscription {
			return current.Address, nil
		}

		// Subscription request: rotate if TTL has elapsed
		if now.Sub(current.CreatedAt) < ttl {
			return current.Address, nil
		}

		newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
		if err != nil {
			return "", err
		}

		for _, old := range cs.ActivePool {
			cs.DeprecatedPool = append(cs.DeprecatedPool, demoteAddress(iface, old, now))
		}
		cs.ActivePool = []AddressEntry{{
			Address:   newIP,
			State:     "active",
			CreatedAt: now,
		}}
		cs.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, cs.DeprecatedPool, now)
		_ = SaveRotationState(endpointName, st)
		return newIP, nil

	case config.RotationProfileProactive:
		if len(st.ActivePool) == 0 {
			newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
			if err != nil {
				return "", err
			}
			st.ActivePool = []AddressEntry{{
				Address:   newIP,
				State:     "active",
				CreatedAt: now,
			}}
			st.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, st.DeprecatedPool, now)
			_ = SaveRotationState(endpointName, st)
			return newIP, nil
		}

		current := st.ActivePool[len(st.ActivePool)-1]
		if now.Sub(current.CreatedAt) < ttl {
			return current.Address, nil
		}

		// Strict TTL expired: rotate immediately
		newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
		if err != nil {
			return "", err
		}

		for _, old := range st.ActivePool {
			st.DeprecatedPool = append(st.DeprecatedPool, demoteAddress(iface, old, now))
		}
		st.ActivePool = []AddressEntry{{
			Address:   newIP,
			State:     "active",
			CreatedAt: now,
		}}
		st.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, st.DeprecatedPool, now)
		_ = SaveRotationState(endpointName, st)
		return newIP, nil

	case config.RotationProfileTurtle:
		fallthrough
	default:
		// Turtle (default): Single active address, rotates on-demand upon subscription pull after TTL expires
		if len(st.ActivePool) == 0 {
			newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
			if err != nil {
				return "", err
			}
			st.ActivePool = []AddressEntry{{
				Address:   newIP,
				State:     "active",
				CreatedAt: now,
			}}
			st.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, st.DeprecatedPool, now)
			_ = SaveRotationState(endpointName, st)
			return newIP, nil
		}

		current := st.ActivePool[len(st.ActivePool)-1]
		if !forSubscription {
			return current.Address, nil
		}

		if now.Sub(current.CreatedAt) < ttl {
			return current.Address, nil
		}

		// TTL expired AND subscription requested: rotate on-demand
		newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
		if err != nil {
			return "", err
		}

		for _, old := range st.ActivePool {
			st.DeprecatedPool = append(st.DeprecatedPool, demoteAddress(iface, old, now))
		}
		st.ActivePool = []AddressEntry{{
			Address:   newIP,
			State:     "active",
			CreatedAt: now,
		}}
		st.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, st.DeprecatedPool, now)
		_ = SaveRotationState(endpointName, st)
		return newIP, nil
	}
}

// NextAddress generates a new random IPv6 address from ep.Subnet, verifies outer connectivity,
// updates the active pool, softly deprecates old addresses in compliance with RFC 4941,
// cleans expired addresses, and persists state.
func NextAddress(endpointName string, ep config.EndpointConfig) (string, error) {
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	var ip string
	err := withFileLock(endpointName, func() error {
		var err error
		ip, err = nextAddressLocked(endpointName, ep)
		return err
	})
	return ip, err
}

func nextAddressLocked(endpointName string, ep config.EndpointConfig) (string, error) {
	subnet := strings.TrimSpace(ep.Subnet)
	if subnet == "" {
		return "", fmt.Errorf("dynamic-v6 endpoint '%s' has no subnet configured", endpointName)
	}

	iface := strings.TrimSpace(ep.Interface)
	if iface == "" {
		return "", fmt.Errorf("dynamic-v6 endpoint '%s' has no network interface configured", endpointName)
	}

	maxAddrs := ep.MaxAddresses
	if maxAddrs <= 0 {
		maxAddrs = 1
	}

	st, _ := LoadRotationState(endpointName)
	if st == nil {
		st = &RotationState{
			ActivePool:     []AddressEntry{},
			DeprecatedPool: []AddressEntry{},
		}
	}

	isColliding := func(candidate string) bool {
		for _, a := range st.ActivePool {
			if a.Address == candidate {
				return true
			}
		}
		for _, a := range st.DeprecatedPool {
			if a.Address == candidate {
				return true
			}
		}
		return false
	}

	newIP, err := allocateAndVerifyAddress(subnet, iface, ep.EnableNDP, isColliding)
	if err != nil {
		return "", err
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
		st.DeprecatedPool = append(st.DeprecatedPool, demoteAddress(iface, old, now))
	}

	st.DeprecatedPool = pruneDeprecated(iface, ep.EnableNDP, st.DeprecatedPool, now)

	if err := SaveRotationState(endpointName, st); err != nil {
		return newIP, fmt.Errorf("address allocated (%s) but failed to save state: %w", newIP, err)
	}

	return newIP, nil
}

// ReconcileOnStartup reads the persisted pool state and aligns kernel addresses.
// It waits up to 5 seconds for the interface to become UP, performs time-aware
// deprecation pruning, replays active addresses, and prewarms empty pools.
func ReconcileOnStartup(endpointName string, ep config.EndpointConfig) error {
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	return withFileLock(endpointName, func() error {
		return reconcileOnStartupLocked(endpointName, ep)
	})
}

func reconcileOnStartupLocked(endpointName string, ep config.EndpointConfig) error {
	iface := strings.TrimSpace(ep.Interface)
	if iface == "" {
		return fmt.Errorf("dynamic-v6 endpoint '%s' has no network interface configured", endpointName)
	}

	// 1. Polling check for interface readiness (up to 5s)
	if !waitForInterface(iface, interfaceWaitTimeout, interfaceWaitInterval) {
		fmt.Fprintf(os.Stderr, "⚠️  Interface '%s' not ready or DOWN after %v; skipping dynamic-v6 reconciliation for '%s'\n", iface, interfaceWaitTimeout, endpointName)
		return nil
	}

	st, err := LoadRotationState(endpointName)
	if err != nil || st == nil {
		st = &RotationState{
			ActivePool:     []AddressEntry{},
			DeprecatedPool: []AddressEntry{},
			Consumers:      make(map[string]*ConsumerState),
		}
	}
	if st.Consumers == nil {
		st.Consumers = make(map[string]*ConsumerState)
	}

	now := time.Now()

	// 2. Prewarm empty active pool
	if len(st.ActivePool) == 0 {
		_, err := nextAddressLocked(endpointName, ep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Cold-start prewarm failed for dynamic-v6 endpoint '%s': %v\n", endpointName, err)
		}
		return err
	}

	// 3. Replay active pool into kernel
	for _, act := range st.ActivePool {
		execCmd("ip", "-6", "addr", "replace", act.Address+"/128", "dev", iface, "nodad", "preferred_lft", "7200", "valid_lft", "14400")
		if !isTunnelInterface(iface) && ep.EnableNDP {
			execCmd("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.proxy_ndp=1", iface))
			execCmd("ip", "-6", "neigh", "replace", "proxy", act.Address, "dev", iface)
		}
	}
	for _, cs := range st.Consumers {
		for _, act := range cs.ActivePool {
			execCmd("ip", "-6", "addr", "replace", act.Address+"/128", "dev", iface, "nodad", "preferred_lft", "7200", "valid_lft", "14400")
			if !isTunnelInterface(iface) && ep.EnableNDP {
				execCmd("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.proxy_ndp=1", iface))
				execCmd("ip", "-6", "neigh", "replace", "proxy", act.Address, "dev", iface)
			}
		}
	}

	// 4. DeprecatedPool precise clock pruning
	var remaining []AddressEntry
	for _, dep := range st.DeprecatedPool {
		elapsed := now.Sub(dep.DeprecatedAt)
		if !dep.DeprecatedAt.IsZero() && elapsed >= 1*time.Hour {
			continue
		}

		rem := int((1*time.Hour - elapsed).Seconds())
		if rem <= 0 {
			continue
		}
		execCmd("ip", "-6", "addr", "replace", dep.Address+"/128", "dev", iface, "nodad", "preferred_lft", "0", "valid_lft", strconv.Itoa(rem))
		remaining = append(remaining, dep)
	}
	st.DeprecatedPool = remaining

	for _, cs := range st.Consumers {
		var csRem []AddressEntry
		for _, dep := range cs.DeprecatedPool {
			elapsed := now.Sub(dep.DeprecatedAt)
			if !dep.DeprecatedAt.IsZero() && elapsed >= 1*time.Hour {
				continue
			}
			rem := int((1*time.Hour - elapsed).Seconds())
			if rem <= 0 {
				continue
			}
			execCmd("ip", "-6", "addr", "replace", dep.Address+"/128", "dev", iface, "nodad", "preferred_lft", "0", "valid_lft", strconv.Itoa(rem))
			csRem = append(csRem, dep)
		}
		cs.DeprecatedPool = csRem
	}

	return SaveRotationState(endpointName, st)
}
