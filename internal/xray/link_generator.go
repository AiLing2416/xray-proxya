package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/sharelink"
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

// TargetNode represents an address paired with an endpoint alias for link generation.
type TargetNode struct {
	Address string
	Alias   string
}

func GenerateLinksWithTargets(cfg *config.UserConfig, targets []TargetNode) []string {
	if len(targets) == 0 {
		return nil
	}
	var all []string
	for _, t := range targets {
		suffix := ""
		if t.Alias != "" {
			suffix = t.Alias
		}
		all = append(all, generateAllLinks(cfg, t.Address, cfg.UUID, suffix)...)
	}
	return all
}

func GenerateRelayLinksWithTargets(cfg *config.UserConfig, targets []TargetNode, relay config.CustomOutbound) []string {
	if len(targets) == 0 {
		return nil
	}
	var all []string
	for _, t := range targets {
		suffix := "Relay-" + relay.Alias
		if t.Alias != "" {
			suffix = "Relay-" + relay.Alias + "-" + t.Alias
		}
		all = append(all, generateAllLinks(cfg, t.Address, relay.UserUUID, suffix)...)
	}
	return all
}

func GenerateGuestLinksWithTargets(cfg *config.UserConfig, targets []TargetNode, guestUUID string, alias string) []string {
	if len(targets) == 0 {
		return nil
	}
	var all []string
	for _, t := range targets {
		suffix := "Guest-" + alias
		if t.Alias != "" {
			suffix = "Guest-" + alias + "-" + t.Alias
		}
		all = append(all, generateAllLinks(cfg, t.Address, guestUUID, suffix)...)
	}
	return all
}

func GenerateLinks(cfg *config.UserConfig, ip string) []string {
	addrs := splitAddresses(ip)
	if len(addrs) == 0 {
		return nil
	}
	var targets []TargetNode
	for _, addr := range addrs {
		targets = append(targets, TargetNode{Address: addr})
	}
	return GenerateLinksWithTargets(cfg, targets)
}

func GenerateRelayLinks(cfg *config.UserConfig, ip string, relay config.CustomOutbound) []string {
	addrs := splitAddresses(ip)
	if len(addrs) == 0 {
		return nil
	}
	var targets []TargetNode
	for _, addr := range addrs {
		targets = append(targets, TargetNode{Address: addr})
	}
	return GenerateRelayLinksWithTargets(cfg, targets, relay)
}

func GenerateGuestLinks(cfg *config.UserConfig, ip string, guestUUID string, alias string) []string {
	addrs := splitAddresses(ip)
	if len(addrs) == 0 {
		return nil
	}
	var targets []TargetNode
	for _, addr := range addrs {
		targets = append(targets, TargetNode{Address: addr})
	}
	return GenerateGuestLinksWithTargets(cfg, targets, guestUUID, alias)
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
			if !strings.HasPrefix(suffix, "Guest-") && !strings.HasPrefix(suffix, "Relay-") {
				ps := fmt.Sprintf("SS-TCP-%d%s", mode.Port, psSuffix)
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
	if strings.HasPrefix(link, "vmess://") || strings.HasPrefix(link, "vless://") || strings.HasPrefix(link, "ss://") {
		return sharelink.RewriteRemark(link, remark), true
	}
	return link, false
}
