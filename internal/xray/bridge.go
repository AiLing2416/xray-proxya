package xray

import "sync"

// ServiceBridge provides callbacks into the active init system provider.
type ServiceBridge struct {
	IsUnitActive       func(unit string) bool
	RestartMainService func() error
	StopMainService    func() error
}

var (
	bridgeMu      sync.RWMutex
	serviceBridge *ServiceBridge
)

// RegisterServiceBridge registers lifecycle hooks provided by the service package.
func RegisterServiceBridge(bridge *ServiceBridge) {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	serviceBridge = bridge
}

func getServiceBridge() *ServiceBridge {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	return serviceBridge
}
