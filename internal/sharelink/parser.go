package sharelink

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// flexInt handles JSON ports that can be either string or int in VMess payloads.
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

// Parse parses a share link (vless://, vmess://, ss://, socks://, http://) into a typed NodeSpec.
func Parse(link string) (*NodeSpec, error) {
	trimmed := strings.TrimSpace(link)
	if strings.Contains(trimmed, "?") && !strings.Contains(trimmed, "&") {
		if strings.HasPrefix(trimmed, "vless://") || strings.HasPrefix(trimmed, "vmess://") {
			fmt.Println("⚠️  Warning: This link looks truncated. Did you forget to wrap it in 'single quotes'?")
		}
	}

	switch {
	case strings.HasPrefix(trimmed, "vless://"):
		return parseVLESS(trimmed)
	case strings.HasPrefix(trimmed, "vmess://"):
		return parseVMess(trimmed)
	case strings.HasPrefix(trimmed, "ss://"):
		return parseSS(trimmed)
	case strings.HasPrefix(trimmed, "socks://"), strings.HasPrefix(trimmed, "socks5://"):
		return parseSocks(trimmed)
	case strings.HasPrefix(trimmed, "http://"), strings.HasPrefix(trimmed, "https://"):
		return parseHTTP(trimmed)
	default:
		return nil, fmt.Errorf("unsupported or malformed proxy link")
	}
}

func parseVLESS(link string) (*NodeSpec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	raw := strings.TrimPrefix(link, "vless://")
	atIdx := strings.Index(raw, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid vless link: missing @")
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
	serviceName := query.Get("serviceName")
	if path == "" && serviceName != "" {
		path = serviceName
	}
	encryptionStr := query.Get("encryption")
	if encryptionStr == "" {
		encryptionStr = "none"
	}

	spec := &NodeSpec{
		Protocol:    ProtoVLESS,
		Address:     host,
		Port:        port,
		UUID:        uuid,
		Password:    encryptionStr,
		Security:    security,
		Transport:   network,
		Path:        path,
		ServiceName: serviceName,
		Mode:        query.Get("mode"),
		ALPN:        query.Get("alpn"),
		Flow:        query.Get("flow"),
		Remark:      remark,
		RawLink:     link,
	}

	if security == "reality" {
		pbk := query.Get("pbk")
		if pbk == "" {
			return nil, fmt.Errorf("invalid reality link: missing 'pbk' parameter")
		}
		spec.PublicKey = pbk
		spec.SNI = query.Get("sni")
		spec.ShortID = query.Get("sid")
		spec.Fingerprint = query.Get("fp")
		spec.SpiderX = query.Get("spx")
	} else if security == "tls" || security == "xtls" {
		spec.SNI = query.Get("sni")
	}

	if h := query.Get("host"); h != "" {
		spec.Host = h
	}

	return spec, nil
}

func parseSS(link string) (*NodeSpec, error) {
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
		return nil, fmt.Errorf("invalid shadowsocks link format")
	}

	auth := parts[0]
	hostPortPart := parts[1]

	decoded, err := DecodeBase64Flexible(auth)
	if err != nil {
		if strings.Contains(auth, ":") {
			decoded = []byte(auth)
		} else {
			return nil, fmt.Errorf("failed to decode ss auth: %v", err)
		}
	}

	authParts := strings.SplitN(string(decoded), ":", 2)
	if len(authParts) < 2 {
		return nil, fmt.Errorf("invalid ss auth info")
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

	return &NodeSpec{
		Protocol:  ProtoShadowsocks,
		Address:   host,
		Port:      port,
		Method:    authParts[0],
		Password:  authParts[1],
		Transport: "tcp",
		Remark:    remark,
		RawLink:   link,
	}, nil
}

func parseVMess(link string) (*NodeSpec, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	var remark string
	if hashIdx := strings.Index(raw, "#"); hashIdx != -1 {
		remark = raw[hashIdx+1:]
		raw = raw[:hashIdx]
		if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
			remark = unescaped
		}
	}

	decoded, err := DecodeBase64Flexible(raw)
	if err != nil {
		return nil, err
	}

	var vcfg struct {
		Add  string  `json:"add"`
		Port flexInt `json:"port"`
		ID   string  `json:"id"`
		Net  string  `json:"net"`
		Path string  `json:"path"`
		TLS  string  `json:"tls"`
		Ps   string  `json:"ps"`
		Host string  `json:"host"`
		SNI  string  `json:"sni"`
	}
	if err := json.Unmarshal(decoded, &vcfg); err != nil {
		return nil, err
	}

	if remark == "" && vcfg.Ps != "" {
		remark = vcfg.Ps
	}

	sec := "none"
	if vcfg.TLS != "" && vcfg.TLS != "none" {
		sec = vcfg.TLS
	}

	transport := vcfg.Net
	if transport == "" {
		transport = "tcp"
	}

	sni := vcfg.SNI
	if sni == "" && vcfg.Host != "" {
		sni = vcfg.Host
	}

	return &NodeSpec{
		Protocol:  ProtoVMess,
		Address:   vcfg.Add,
		Port:      int(vcfg.Port),
		UUID:      vcfg.ID,
		Transport: transport,
		Path:      vcfg.Path,
		Security:  sec,
		SNI:       sni,
		Host:      vcfg.Host,
		Remark:    remark,
		RawLink:   link,
	}, nil
}

func parseSocks(link string) (*NodeSpec, error) {
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
		decoded, err := DecodeBase64Flexible(auth)
		if err == nil && strings.Contains(string(decoded), ":") {
			authParts := strings.SplitN(string(decoded), ":", 2)
			user, pass = authParts[0], authParts[1]
		} else if strings.Contains(auth, ":") {
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

	return &NodeSpec{
		Protocol:  ProtoSocks,
		Address:   host,
		Port:      port,
		User:      user,
		Password:  pass,
		Transport: "tcp",
		Remark:    remark,
		RawLink:   link,
	}, nil
}

func parseHTTP(link string) (*NodeSpec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	remark := u.Fragment
	if unescaped, err := url.QueryUnescape(remark); err == nil && unescaped != "" {
		remark = unescaped
	}
	pass, _ := u.User.Password()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	sec := "none"
	if u.Scheme == "https" {
		sec = "tls"
	}

	return &NodeSpec{
		Protocol:  ProtoHTTP,
		Address:   u.Hostname(),
		Port:      port,
		User:      u.User.Username(),
		Password:  pass,
		Security:  sec,
		Transport: "tcp",
		Remark:    remark,
		RawLink:   link,
	}, nil
}
