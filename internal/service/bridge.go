package service

import "xray-proxya/internal/xray"

func init() {
	xray.RegisterServiceBridge(&xray.ServiceBridge{
		IsUnitActive: func(unit string) bool {
			return CurrentProvider().IsActive(unit)
		},
		RestartMainService: func() error {
			return CurrentProvider().Restart(MainUnit)
		},
		StopMainService: func() error {
			return CurrentProvider().Stop(MainUnit)
		},
	})
}
