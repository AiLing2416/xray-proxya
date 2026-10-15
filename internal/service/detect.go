package service

import (
	"os"
	"os/exec"
	"sync"
)

var (
	currentProvider Provider
	providerMu      sync.RWMutex
)

// DetectInitSystem detects the active init/supervisor system on the host.
func DetectInitSystem() InitType {
	// 1. systemd is active when /run/systemd/system directory exists.
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return InitSystemd
	}

	// 2. OpenWrt procd is active when procd binary or OpenWrt release file exists.
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return InitProcd
	}
	if _, err := os.Stat("/sbin/procd"); err == nil {
		return InitProcd
	}

	// 3. OpenRC is active when /run/openrc exists or rc-service is in PATH.
	if fi, err := os.Stat("/run/openrc"); err == nil && fi.IsDir() {
		return InitOpenRC
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return InitOpenRC
	}

	// 4. Fallback: if systemctl is present (e.g. non-booted chroot or minimal container).
	if _, err := exec.LookPath("systemctl"); err == nil {
		return InitSystemd
	}

	return InitUnknown
}

// GetProvider returns the appropriate Provider for the specified InitType.
func GetProvider(t InitType) Provider {
	switch t {
	case InitSystemd:
		return NewSystemdProvider()
	case InitOpenRC:
		return NewOpenRCProvider()
	case InitProcd:
		return NewProcdProvider()
	default:
		return NewSystemdProvider()
	}
}

// CurrentProvider returns the globally active init Provider.
func CurrentProvider() Provider {
	providerMu.RLock()
	p := currentProvider
	providerMu.RUnlock()
	if p != nil {
		return p
	}

	providerMu.Lock()
	defer providerMu.Unlock()
	if currentProvider == nil {
		currentProvider = GetProvider(DetectInitSystem())
	}
	return currentProvider
}

// SetCurrentProviderForTest overrides the active provider during unit tests.
// Returns a cleanup function that restores the previous provider.
func SetCurrentProviderForTest(p Provider) func() {
	providerMu.Lock()
	prev := currentProvider
	currentProvider = p
	providerMu.Unlock()

	return func() {
		providerMu.Lock()
		currentProvider = prev
		providerMu.Unlock()
	}
}
