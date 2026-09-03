package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// flexInt handles JSON ports that can be either string or int
type flexInt int

func (fi *flexInt) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			*fi = 0
			return nil
		}
		i, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		*fi = flexInt(i)
		return nil
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	*fi = flexInt(i)
	return nil
}

func ParseProxyLink(link string) (map[string]interface{}, error) {
	out, _, err := ParseProxyLinkWithRemark(link)
	return out, err
}

func ParseProxyLinkWithRemark(link string) (map[string]interface{}, string, error) {
	// Sanity check for shell truncation
	if strings.Contains(link, "?") && !strings.Contains(link, "&") {
		// Most complex links (VLESS/VMess) should have multiple params
		if strings.HasPrefix(link, "vless://") || strings.HasPrefix(link, "vmess://") {
			fmt.Println("⚠️  Warning: This link looks truncated. Did you forget to wrap it in 'single quotes'?")
		}
	}

	if strings.HasPrefix(link, "vmess://") {
		return parseVMess(link)
	} else if strings.HasPrefix(link, "vless://") {
		return parseVLESS(link)
	} else if strings.HasPrefix(link, "ss://") {
		return parseSS(link)
	} else if strings.HasPrefix(link, "socks://") || strings.HasPrefix(link, "socks5://") {
		return parseSocks(link)
	} else if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return parseHTTP(link)
	}
	return nil, "", fmt.Errorf("unsupported or malformed proxy link")
}

func parseVLESS(link string) (map[string]interface{}, string, error) {
	// Standard: vless://uuid@host:port?params#tag
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}

	raw := strings.TrimPrefix(link, "vless://")
	atIdx := strings.Index(raw, "@")
	if atIdx == -1 {
		return nil, "", fmt.Errorf("invalid vless link: missing @")
	}
	uuid := raw[:atIdx]
	rest := raw[atIdx+1:]

	qIdx := strings.Index(rest, "?")
	var hostPortStr string
	if qIdx == -1 {
		hostPortStr = rest
		if hashIdx := strings.Index(hostPortStr, "#"); hashIdx != -1 {
			hostPortStr = hostPortStr[:hashIdx]
		}
	} else {
		hostPortStr = rest[:qIdx]
	}

	host, portStr, err := net.SplitHostPort(hostPortStr)
	if err != nil {
		host = hostPortStr
		portStr = "443"
	}
	port, _ := strconv.Atoi(portStr)

	remark := u.Fragment
	if remark == "" {
		if hashIdx := strings.Index(link, "#"); hashIdx != -1 {
			remark = link[hashIdx+1:]
		}
	}
	if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
		remark = unescaped
	}

	query := u.Query()
	security := query.Get("security")
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}
	path := query.Get("path")
	encryptionStr := query.Get("encryption")
	if encryptionStr == "" {
		encryptionStr = "none"
	}

	userObj := map[string]interface{}{
		"id":         uuid,
		"encryption": "none",
	}
	if flow := query.Get("flow"); flow != "" {
		userObj["flow"] = flow
	}

	vlessSettings := map[string]interface{}{
		"vnext": []interface{}{
			map[string]interface{}{
				"address": host,
				"port":    port,
				"users":   []interface{}{userObj},
			},
		},
	}
	if encryptionStr != "" && encryptionStr != "none" {
		vlessSettings["decryption"] = encryptionStr
	}

	out := map[string]interface{}{
		"protocol": "vless",
		"settings": vlessSettings,
		"streamSettings": map[string]interface{}{
			"network": network,
		},
	}

	if security != "" {
		out["streamSettings"].(map[string]interface{})["security"] = security
	}

	if security == "reality" {
		pbk := query.Get("pbk")
		if pbk == "" {
			return nil, "", fmt.Errorf("invalid reality link: missing 'pbk' parameter")
		}
		realitySettings := map[string]interface{}{
			"serverName":  query.Get("sni"),
			"publicKey":   pbk,
			"shortId":     query.Get("sid"),
			"fingerprint": query.Get("fp"),
		}
		if spx := query.Get("spx"); spx != "" {
			realitySettings["spiderX"] = spx
		}
		out["streamSettings"].(map[string]interface{})["realitySettings"] = realitySettings
	} else if security == "tls" || security == "xtls" {
		tlsSettings := map[string]interface{}{
			"serverName": query.Get("sni"),
		}
		if alpn := query.Get("alpn"); alpn != "" {
			tlsSettings["alpn"] = strings.Split(alpn, ",")
		}
		out["streamSettings"].(map[string]interface{})[security+"Settings"] = tlsSettings
	}

	// Network specific settings
	switch network {
	case "ws":
		wsSettings := map[string]interface{}{
			"path": path,
		}
		if host := query.Get("host"); host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
		out["streamSettings"].(map[string]interface{})["wsSettings"] = wsSettings
	case "grpc":
		grpcSettings := map[string]interface{}{
			"serviceName": query.Get("serviceName"),
		}
		if mode := query.Get("mode"); mode != "" {
			grpcSettings["multiMode"] = (mode == "multi")
		}
		out["streamSettings"].(map[string]interface{})["grpcSettings"] = grpcSettings
	case "xhttp":
		xhttpSettings := map[string]interface{}{
			"path": path,
			"mode": query.Get("mode"),
		}
		if host := query.Get("host"); host != "" {
			xhttpSettings["host"] = host
		}
		out["streamSettings"].(map[string]interface{})["xhttpSettings"] = xhttpSettings
	case "http", "h2":
		httpSettings := map[string]interface{}{
			"path": path,
		}
		if host := query.Get("host"); host != "" {
			httpSettings["host"] = strings.Split(host, ",")
		}
		out["streamSettings"].(map[string]interface{})["httpSettings"] = httpSettings
	}

	return out, remark, nil
}

func parseSS(link string) (map[string]interface{}, string, error) {
	raw := strings.TrimPrefix(link, "ss://")
	var remark string
	if hashIdx := strings.Index(raw, "#"); hashIdx != -1 {
		remark = raw[hashIdx+1:]
		raw = raw[:hashIdx]
		if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
			remark = unescaped
		}
	}

	parts := strings.Split(raw, "@")
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("invalid shadowsocks link format")
	}

	auth := parts[0]
	hostPortPart := parts[1]

	decoded, err := decodeBase64Flexible(auth)
	if err != nil {
		if strings.Contains(auth, ":") {
			decoded = []byte(auth)
		} else {
			return nil, "", fmt.Errorf("failed to decode ss auth: %v", err)
		}
	}

	authParts := strings.SplitN(string(decoded), ":", 2)
	if len(authParts) < 2 {
		return nil, "", fmt.Errorf("invalid ss auth info")
	}

	var host string
	var port int
	if h, pStr, err := net.SplitHostPort(hostPortPart); err == nil {
		host = h
		port, _ = strconv.Atoi(pStr)
	} else {
		host = hostPortPart
		port = 8388
	}
	if port == 0 {
		port = 8388
	}

	return map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"address":  host,
					"port":     port,
					"method":   authParts[0],
					"password": authParts[1],
				},
			},
		},
	}, remark, nil
}

func parseVMess(link string) (map[string]interface{}, string, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	var remark string
	if hashIdx := strings.Index(raw, "#"); hashIdx != -1 {
		remark = raw[hashIdx+1:]
		raw = raw[:hashIdx]
		if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
			remark = unescaped
		}
	}

	decoded, err := decodeBase64Flexible(raw)
	if err != nil {
		return nil, "", err
	}
	var vcfg struct {
		Add  string  `json:"add"`
		Port flexInt `json:"port"`
		ID   string  `json:"id"`
		Net  string  `json:"net"`
		Path string  `json:"path"`
		TLS  string  `json:"tls"`
		Ps   string  `json:"ps"`
	}
	if err := json.Unmarshal(decoded, &vcfg); err != nil {
		return nil, "", err
	}
	if remark == "" && vcfg.Ps != "" {
		remark = vcfg.Ps
	}

	out := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": vcfg.Add,
					"port":    int(vcfg.Port),
					"users": []interface{}{
						map[string]interface{}{"id": vcfg.ID},
					},
				},
			},
		},
	}
	if vcfg.Net == "ws" {
		out["streamSettings"] = map[string]interface{}{
			"network": "ws",
			"wsSettings": map[string]interface{}{
				"path": vcfg.Path,
			},
		}
	}
	return out, remark, nil
}

func parseSocks(link string) (map[string]interface{}, string, error) {
	raw := strings.TrimPrefix(link, "socks://")
	raw = strings.TrimPrefix(raw, "socks5://")
	var remark string
	if hashIdx := strings.Index(raw, "#"); hashIdx != -1 {
		remark = raw[hashIdx+1:]
		raw = raw[:hashIdx]
		if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
			remark = unescaped
		}
	}

	parts := strings.Split(raw, "@")
	var user, pass, hostPort string

	if len(parts) == 2 {
		auth := parts[0]
		hostPort = parts[1]
		// Try Base64 decode
		decoded, err := decodeBase64Flexible(auth)
		if err == nil && strings.Contains(string(decoded), ":") {
			authParts := strings.SplitN(string(decoded), ":", 2)
			user, pass = authParts[0], authParts[1]
		} else if strings.Contains(auth, ":") {
			// Plain user:pass
			authParts := strings.SplitN(auth, ":", 2)
			user, pass = authParts[0], authParts[1]
		} else {
			user = auth
		}
	} else {
		hostPort = parts[0]
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		portStr = "1080"
	}
	port, _ := strconv.Atoi(portStr)

	srv := map[string]interface{}{
		"address": host,
		"port":    port,
	}
	if user != "" {
		srv["users"] = []interface{}{map[string]interface{}{"user": user, "pass": pass}}
	}

	return map[string]interface{}{
		"protocol": "socks",
		"settings": map[string]interface{}{
			"servers": []interface{}{srv},
			"udp":     true,
		},
	}, remark, nil
}

func parseHTTP(link string) (map[string]interface{}, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	remark := u.Fragment
	if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
		remark = unescaped
	}
	pass, _ := u.User.Password()
	port, _ := strconv.Atoi(u.Port())
	srv := map[string]interface{}{
		"address": u.Hostname(),
		"port":    port,
	}
	if u.User.Username() != "" {
		srv["users"] = []interface{}{map[string]interface{}{"user": u.User.Username(), "pass": pass}}
	}
	return map[string]interface{}{
		"protocol": "http",
		"settings": map[string]interface{}{
			"servers": []interface{}{srv},
		},
	}, remark, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Try standard
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try URL
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try raw URL
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try raw Std
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Pad with == and try again
	padLen := (4 - len(s)%4) % 4
	if padLen > 0 {
		padded := s + strings.Repeat("=", padLen)
		if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return b, nil
		}
		if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("failed to decode base64")
}

func ParseInterfaceBind(iface string, bindAddr string) (map[string]interface{}, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	out := map[string]interface{}{
		"protocol": "freedom",
		"settings": map[string]interface{}{
			"domainStrategy": "UseIP",
		},
		"streamSettings": map[string]interface{}{
			"sockopt": map[string]interface{}{
				"interface": iface,
			},
		},
	}

	if bindAddr != "" {
		out["sendThrough"] = bindAddr
	}

	return out, nil
}
