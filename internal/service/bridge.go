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
		GetInitType: func() string {
			return string(CurrentProvider().Type())
		},
		GetServiceInfo: func() xray.ServiceInfo {
			p := CurrentProvider()
			st, _ := p.GetStatus(MainUnit)
			return xray.ServiceInfo{
				InitType:  string(p.Type()),
				UnitPath:  p.UnitPath(MainUnit),
				Installed: p.IsInstalled(MainUnit),
				Active:    st.Active,
				PID:       st.PID,
			}
		},
	})
}
