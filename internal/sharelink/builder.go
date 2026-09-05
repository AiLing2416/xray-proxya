package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ToOutbound transforms the NodeSpec into a complete Xray outbound configuration dictionary.
func (n *NodeSpec) ToOutbound() map[string]interface{} {
	if n == nil {
		return nil
	}

	switch n.Protocol {
	case ProtoVLESS:
		userObj := map[string]interface{}{
			"id":         n.UUID,
			"encryption": "none",
		}
		if n.Flow != "" {
			userObj["flow"] = n.Flow
		}

		vlessSettings := map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": n.Address,
					"port":    n.Port,
					"users":   []interface{}{userObj},
				},
			},
		}
		if n.Password != "" && n.Password != "none" {
			vlessSettings["decryption"] = n.Password
		}

		transport := n.Transport
		if transport == "" {
			transport = "tcp"
		}

		out := map[string]interface{}{
			"protocol": "vless",
			"settings": vlessSettings,
			"streamSettings": map[string]interface{}{
				"network": transport,
			},
		}

		stream := out["streamSettings"].(map[string]interface{})
		if n.Security != "" {
			stream["security"] = n.Security
		}

		if n.Security == "reality" {
			realitySettings := map[string]interface{}{
				"serverName":  n.SNI,
				"publicKey":   n.PublicKey,
				"shortId":     n.ShortID,
				"fingerprint": n.Fingerprint,
			}
			if n.SpiderX != "" {
				realitySettings["spiderX"] = n.SpiderX
			}
			stream["realitySettings"] = realitySettings
		} else if n.Security == "tls" || n.Security == "xtls" {
			tlsSettings := map[string]interface{}{
				"serverName": n.SNI,
			}
			if n.ALPN != "" {
				tlsSettings["alpn"] = strings.Split(n.ALPN, ",")
			}
			stream[n.Security+"Settings"] = tlsSettings
		}

		switch transport {
		case "ws":
			wsSettings := map[string]interface{}{
				"path": n.Path,
			}
			if n.Host != "" {
				wsSettings["headers"] = map[string]interface{}{
					"Host": n.Host,
				}
			}
			stream["wsSettings"] = wsSettings
		case "xhttp":
			xhttpSettings := map[string]interface{}{
				"path": n.Path,
			}
			if n.Mode != "" {
				xhttpSettings["mode"] = n.Mode
			}
			if n.Host != "" {
				xhttpSettings["host"] = n.Host
			}
			stream["xhttpSettings"] = xhttpSettings
		case "grpc":
			serviceName := n.ServiceName
			if serviceName == "" {
				serviceName = n.Path
			}
			grpcSettings := map[string]interface{}{
				"serviceName": serviceName,
			}
			if n.Mode == "multi" {
				grpcSettings["multiMode"] = true
			}
			stream["grpcSettings"] = grpcSettings
		case "http", "h2":
			httpSettings := map[string]interface{}{
				"path": n.Path,
			}
			if n.Host != "" {
				httpSettings["host"] = strings.Split(n.Host, ",")
			}
			stream["httpSettings"] = httpSettings
		}
		return out

	case ProtoVMess:
		out := map[string]interface{}{
			"protocol": "vmess",
			"settings": map[string]interface{}{
				"vnext": []interface{}{
					map[string]interface{}{
						"address": n.Address,
						"port":    n.Port,
						"users": []interface{}{
							map[string]interface{}{"id": n.UUID},
						},
					},
				},
			},
		}
		if n.Transport == "ws" {
			out["streamSettings"] = map[string]interface{}{
				"network": "ws",
				"wsSettings": map[string]interface{}{
					"path": n.Path,
				},
			}
		}
		return out

	case ProtoShadowsocks:
		return map[string]interface{}{
			"protocol": "shadowsocks",
			"settings": map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{
						"address":  n.Address,
						"port":     n.Port,
						"method":   n.Method,
						"password": n.Password,
					},
				},
			},
		}

	case ProtoSocks:
		srv := map[string]interface{}{
			"address": n.Address,
			"port":    n.Port,
		}
		if n.User != "" {
			srv["users"] = []interface{}{map[string]interface{}{"user": n.User, "pass": n.Password}}
		}
		return map[string]interface{}{
			"protocol": "socks",
			"settings": map[string]interface{}{
				"servers": []interface{}{srv},
				"udp":     true,
			},
		}

	case ProtoHTTP:
		srv := map[string]interface{}{
			"address": n.Address,
			"port":    n.Port,
		}
		if n.User != "" {
			srv["users"] = []interface{}{map[string]interface{}{"user": n.User, "pass": n.Password}}
		}
		return map[string]interface{}{
			"protocol": "http",
			"settings": map[string]interface{}{
				"servers": []interface{}{srv},
			},
		}

	case ProtoFreedom:
		out := map[string]interface{}{
			"protocol": "freedom",
			"settings": map[string]interface{}{
				"domainStrategy": "UseIP",
			},
			"streamSettings": map[string]interface{}{
				"sockopt": map[string]interface{}{
					"interface": n.Address,
				},
			},
		}
		if n.Host != "" {
			out["sendThrough"] = n.Host
		}
		return out

	default:
		return nil
	}
}

// ParseInterfaceBind creates a freedom outbound configuration bound to a local network interface.
func ParseInterfaceBind(iface string, bindAddr string) (map[string]interface{}, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface name is required")
	}
	spec := &NodeSpec{
		Protocol: ProtoFreedom,
		Address:  iface,
		Host:     bindAddr,
	}
	return spec.ToOutbound(), nil
}

// RewriteRemark updates the node remark/tag in a share link.
func RewriteRemark(link string, remark string) string {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		return rewriteVMessRemark(link, remark)
	case strings.HasPrefix(link, "vless://"), strings.HasPrefix(link, "ss://"), strings.HasPrefix(link, "socks://"), strings.HasPrefix(link, "http://"):
		return rewriteFragmentRemark(link, remark)
	default:
		return link
	}
}

func rewriteVMessRemark(link string, remark string) string {
	raw := strings.TrimPrefix(link, "vmess://")
	data, err := DecodeBase64Flexible(raw)
	if err != nil {
		return link
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return link
	}
	payload["ps"] = remark
	updated, err := json.Marshal(payload)
	if err != nil {
		return link
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(updated)
}

func rewriteFragmentRemark(link string, remark string) string {
	escaped := url.PathEscape(remark)
	if idx := strings.Index(link, "#"); idx >= 0 {
		return link[:idx+1] + escaped
	}
	return link + "#" + escaped
}
