package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"xray-proxya/internal/config"
)

func splitAddresses(raw string) []string {
	var addrs []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			addrs = append(addrs, part)
		}
	}
	return addrs
}

func GenerateLinks(cfg *config.UserConfig, ip string) []string {
	addrs := splitAddresses(ip)
	if len(addrs) == 0 {
		return nil
	}
	var all []string
	for _, addr := range addrs {
		all = append(all, generateAllLinks(cfg, addr, cfg.UUID, "")...)
	}
	return all
}

func GenerateRelayLinks(cfg *config.UserConfig, ip string, relay config.CustomOutbound) []string {
	addrs := splitAddresses(ip)
	if len(addrs) == 0 {
		return nil
	}
	var all []string
	for _, addr := range addrs {
		all = append(all, generateAllLinks(cfg, addr, relay.UserUUID, "Relay-"+relay.Alias)...)
	}
	return all
}

func GenerateGuestLinks(cfg *config.UserConfig, ip string, guestUUID string, alias string) []string {
	addrs := splitAddresses(ip)
	if len(addrs) == 0 {
		return nil
	}
	var all []string
	for _, addr := range addrs {
		all = append(all, generateAllLinks(cfg, addr, guestUUID, "Guest-"+alias)...)
	}
	return all
}

func WithPrimaryRemark(links []string, remark string) []string {
	if len(links) == 0 || strings.TrimSpace(remark) == "" {
		return links
	}
	out := append([]string(nil), links...)
	if updated, ok := rewritePrimaryRemark(out[0], remark); ok {
		out[0] = updated
	}
	return out
}

func generateAllLinks(cfg *config.UserConfig, ip string, userUUID string, suffix string) []string {
	var links []string
	parsedIP := net.ParseIP(ip)
	formattedIP := ip
	if parsedIP != nil && parsedIP.To4() == nil {
		formattedIP = "[" + ip + "]"
	}

	order := config.PresetOrder

	for _, targetMode := range order {
		var mode *config.ModeInfo
		for _, m := range cfg.Presets {
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
			fp := mode.Fingerprint
			if fp == "" {
				fp = "chrome"
			}
			ps := fmt.Sprintf("VLess-XHTTP-Reality-%d%s", mode.Port, psSuffix)
			link = fmt.Sprintf("vless://%s@%s:%d?security=reality&encryption=none&pbk=%s&fp=%s&type=xhttp&serviceName=&path=%s&sni=%s&sid=%s&spx=%%2F#%s",
				userUUID, formattedIP, mode.Port, mode.Settings.PublicKey, url.QueryEscape(fp), url.QueryEscape(mode.Path), url.QueryEscape(mode.SNI), mode.Settings.ShortID, url.PathEscape(ps))

		case config.ModeVLESSVision:
			fp := mode.Fingerprint
			if fp == "" {
				fp = "chrome"
			}
			ps := fmt.Sprintf("VLess-Vision-Reality-%d%s", mode.Port, psSuffix)
			link = fmt.Sprintf("vless://%s@%s:%d?security=reality&encryption=none&pbk=%s&fp=%s&type=tcp&flow=xtls-rprx-vision&sni=%s&sid=%s#%s",
				userUUID, formattedIP, mode.Port, mode.Settings.PublicKey, url.QueryEscape(fp), url.QueryEscape(mode.SNI), mode.Settings.ShortID, url.PathEscape(ps))

		case config.ModeVLESSXHTTP:
			ps := fmt.Sprintf("VLess-XHTTP-KEM768-%d%s", mode.Port, psSuffix)
			link = fmt.Sprintf("vless://%s@%s:%d?security=none&encryption=%s&type=xhttp&path=%s#%s",
				userUUID, formattedIP, mode.Port, url.QueryEscape(mode.Settings.Password), url.QueryEscape(mode.Path), url.PathEscape(ps))

		case config.ModeVMessWS:
			ps := fmt.Sprintf("VMess-WS%s", psSuffix)
			vmessObj := map[string]interface{}{
				"v": "2", "ps": ps, "add": ip, "port": mode.Port, "id": userUUID,
				"aid": 0, "scy": "chacha20-poly1305", "net": "ws", "type": "none", "path": mode.Path,
			}
			data, _ := json.Marshal(vmessObj)
			link = "vmess://" + base64.StdEncoding.EncodeToString(data)

		case config.ModeShadowsocksTCP:
			// Shadowsocks usually doesn't support the same user-UUID routing in this context
			if suffix == "" {
				ps := fmt.Sprintf("SS-TCP-%d", mode.Port)
				auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", mode.Settings.Cipher, mode.Settings.Password)))
				link = fmt.Sprintf("ss://%s@%s:%d#%s", auth, formattedIP, mode.Port, url.PathEscape(ps))
			}
		}
		if link != "" {
			links = append(links, link)
		}
	}
	return links
}

func rewritePrimaryRemark(link string, remark string) (string, bool) {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		return rewriteVMessRemark(link, remark)
	case strings.HasPrefix(link, "vless://"), strings.HasPrefix(link, "ss://"):
		return rewriteFragmentRemark(link, remark), true
	default:
		return link, false
	}
}

func rewriteVMessRemark(link string, remark string) (string, bool) {
	raw := strings.TrimPrefix(link, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return link, false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return link, false
	}
	payload["ps"] = remark
	updated, err := json.Marshal(payload)
	if err != nil {
		return link, false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(updated), true
}

func rewriteFragmentRemark(link string, remark string) string {
	escaped := url.PathEscape(remark)
	if idx := strings.Index(link, "#"); idx >= 0 {
		return link[:idx+1] + escaped
	}
	return link + "#" + escaped
}
