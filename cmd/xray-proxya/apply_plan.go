package main

import (
	"xray-proxya/internal/applyops"
	"xray-proxya/internal/config"
)

type applyImpact = applyops.Impact

func buildApplyImpact(activeCfg, stagingCfg *config.UserConfig) applyImpact {
	return applyops.BuildImpact(activeCfg, stagingCfg)
}

func hasSubServiceInstalled() bool {
	return applyops.HasSubServiceInstalled()
}

func restartSubServiceIfInstalled() error {
	return applyops.RestartSubServiceIfInstalled()
}
