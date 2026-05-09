package main

import (
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/quota"
	"xray-proxya/internal/xray"
)

func checkGuestQuotaState(cfg *config.UserConfig, monitor *quota.Monitor, now time.Time) (quota.UpdateResult, error) {
	if cfg == nil {
		return quota.UpdateResult{}, nil
	}
	allStats, err := xray.GetXrayStats(cfg.APIInbound)
	if err != nil {
		return quota.UpdateResult{}, err
	}
	update := monitor.UpdateGuests(cfg, allStats, now)
	if err := monitor.Save(); err != nil {
		return update, err
	}
	if update.Changed {
		if err := cfg.Save(); err != nil {
			return update, err
		}
	}
	return update, nil
}
