package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"xray-proxya/internal/config"
)

func GenerateLinks(cfg *config.UserConfig, ip string) []string {
	return generateAllLinks(cfg, ip, cfg.UUID, "")
}

func GenerateRelayLinks(cfg *config.UserConfig, ip string, relay config.CustomOutbound) []string {
	return generateAllLinks(cfg, ip, relay.UserUUID, "Relay-"+relay.Alias)
}

func generateAllLinks(cfg *config.UserConfig, ip string, userUUID string, suffix string) []string {
	var links []string
	parsedIP := net.ParseIP(ip)
	formattedIP := ip
	if parsedIP != nil && parsedIP.To4() == nil {
		formattedIP = "[" + ip + "]"
	}

	// Priority Order for v0.1.3
	order := []config.PresetMode{
		config.ModeVLESSVision,
		config.ModeVLESSReality,
		config.ModeVLESSXHTTP,
		config.ModeVMessWS,
		config.ModeShadowsocksTCP,
	}

	for _, targetMode := range order {
		var mode *config.ModeInfo
		for _, m := range cfg.ActiveModes {
			if m.Mode == targetMode {
				mode = &m
				break
			}
		}
		if mode == nil || !mode.Enabled {
			continue
		}

		var link string
		psSuffix := ""
		if suffix != "" {
			psSuffix = "-" + suffix
		}

		switch mode.Mode {
		case config.ModeVLESSReality:
			ps := fmt.Sprintf("VLess-XHTTP-Reality-%d%s", mode.Port, psSuffix)
			link = fmt.Sprintf("vless://%s@%s:%d?security=reality&encryption=none&pbk=%s&fp=chrome&type=xhttp&serviceName=&path=%s&sni=%s&sid=%s&spx=%%2F#%s",
				userUUID, formattedIP, mode.Port, mode.Settings.PublicKey, mode.Path, mode.SNI, mode.Settings.ShortID, ps)

		case config.ModeVLESSVision:
			ps := fmt.Sprintf("VLess-Vision-Reality-%d%s", mode.Port, psSuffix)
			link = fmt.Sprintf("vless://%s@%s:%d?security=reality&encryption=none&pbk=%s&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=%s&sid=%s#%s",
				userUUID, formattedIP, mode.Port, mode.Settings.PublicKey, mode.SNI, mode.Settings.ShortID, ps)

		case config.ModeVLESSXHTTP:
			ps := fmt.Sprintf("VLess-XHTTP-KEM768-%d%s", mode.Port, psSuffix)
			link = fmt.Sprintf("vless://%s@%s:%d?security=none&encryption=%s&type=xhttp&path=%s#%s",
				userUUID, formattedIP, mode.Port, mode.Settings.Password, mode.Path, ps)

		case config.ModeVMessWS:
			ps := fmt.Sprintf("VMess-WS%s", psSuffix)
			vmessObj := map[string]interface{}{
				"v": "2", "ps": ps, "add": ip, "port": mode.Port, "id": userUUID,
				"aid": 0, "scy": "chacha20-poly1305", "net": "ws", "type": "none", "path": mode.Path,
			}
			data, _ := json.Marshal(vmessObj)
			link = "vmess://" + base64.StdEncoding.EncodeToString(data)

		case config.ModeShadowsocksTCP:
			if suffix == "" {
				ps := fmt.Sprintf("SS-TCP-%d", mode.Port)
				auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", mode.Settings.Cipher, mode.Settings.Password)))
				link = fmt.Sprintf("ss://%s@%s:%d#%s", auth, formattedIP, mode.Port, ps)
			}
		}
		if link != "" {
			links = append(links, link)
		}
	}
	return links
}
