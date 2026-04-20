package presets

import (
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

// RegenerateMarkedModes refreshes secrets or paths for any preset with RegenFlag set.
// It mutates cfg in place and clears RegenFlag after regeneration succeeds.
func RegenerateMarkedModes(cfg *config.UserConfig) error {
	for i := range cfg.ActiveModes {
		if !cfg.ActiveModes[i].RegenFlag {
			continue
		}
		mode := &cfg.ActiveModes[i]

		switch mode.Mode {
		case config.ModeVLESSVision:
			pk, pub, err := xray.GenerateX25519()
			if err != nil {
				return err
			}
			mode.Settings.PrivateKey = pk
			mode.Settings.PublicKey = pub
			mode.Settings.ShortID = xray.GetRandomShortID()
			mode.SNI = config.GetRandomRealityDomain()

		case config.ModeVLESSReality:
			pk, pub, err := xray.GenerateX25519()
			if err != nil {
				return err
			}
			mode.Path = xray.GetRandomPath()
			mode.Settings.PrivateKey = pk
			mode.Settings.PublicKey = pub
			mode.Settings.ShortID = xray.GetRandomShortID()
			mode.SNI = config.GetRandomRealityDomain()

		case config.ModeVLESSXHTTP:
			enc, dec, err := xray.GenerateMLKEM()
			if err != nil {
				return err
			}
			mode.Path = xray.GetRandomPath()
			mode.Settings.Password = enc
			mode.Settings.PrivateKey = dec

		case config.ModeVMessWS:
			mode.Path = xray.GetRandomPath()

		case config.ModeShadowsocksTCP:
			mode.Settings.Password = utils.GenerateRandomString(16)
		}

		mode.RegenFlag = false
	}
	return nil
}
