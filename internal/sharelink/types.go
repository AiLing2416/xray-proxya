package sharelink

import (
	"fmt"
	"strings"
)

// Supported protocol identifiers.
const (
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
	ProtoShadowsocks = "shadowsocks"
	ProtoSocks       = "socks"
	ProtoHTTP        = "http"
	ProtoFreedom     = "freedom"
)

// NodeSpec represents a strongly-typed proxy node specification
// extracted from a share link or an Xray outbound configuration.
type NodeSpec struct {
	Protocol    string `json:"protocol"`     // "vless", "vmess", "shadowsocks", "socks", "http", "freedom"
	Address     string `json:"address"`      // Hostname, IPv4, IPv6, or interface name
	Port        int    `json:"port"`         // Remote port
	UUID        string `json:"uuid"`         // User UUID (vless/vmess)
	Password    string `json:"password"`     // Password for shadowsocks/socks/http, or encryption key
	Security    string `json:"security"`     // "none", "tls", "reality", "xtls"
	Transport   string `json:"transport"`    // "tcp", "ws", "xhttp", "grpc", "h2"
	Path        string `json:"path"`         // Request path (ws, xhttp, h2)
	SNI         string `json:"sni"`          // ServerName for TLS/Reality
	Fingerprint string `json:"fingerprint"`  // Client fingerprint (e.g. "chrome")
	PublicKey   string `json:"public_key"`   // Reality public key (pbk)
	ShortID     string `json:"short_id"`     // Reality short ID (sid)
	SpiderX     string `json:"spider_x"`     // Reality spiderX (spx)
	Flow        string `json:"flow"`         // Flow control (e.g. "xtls-rprx-vision")
	Method      string `json:"method"`       // Shadowsocks cipher method (e.g. "chacha20-poly1305")
	User        string `json:"user"`         // SOCKS / HTTP auth username
	Host        string `json:"host"`         // Host header override
	Remark      string `json:"remark"`       // Node name / remark / ps / fragment
	RawLink     string `json:"raw_link"`     // Original raw link
}

// ServerSpec returns a friendly "host:port" or interface identifier.
func (n *NodeSpec) ServerSpec() string {
	if n == nil {
		return ""
	}
	if n.Protocol == ProtoFreedom {
		if n.Address != "" {
			return n.Address
		}
		return "direct"
	}
	if n.Address == "" {
		return ""
	}
	if n.Port > 0 {
		return fmt.Sprintf("%s:%d", n.Address, n.Port)
	}
	return n.Address
}

// DisplayProtocol returns a normalized protocol name for UI and tables.
func (n *NodeSpec) DisplayProtocol() string {
	if n == nil || n.Protocol == "" {
		return "unknown"
	}
	return n.Protocol
}

// DisplayPort returns the port formatted as a string or "--" if not configured.
func (n *NodeSpec) DisplayPort() string {
	if n == nil || n.Port <= 0 {
		return "--"
	}
	return fmt.Sprintf("%d", n.Port)
}

// TransportSummary produces a short string summary of transport and security parameters (e.g. "xhttp reality sni=...").
func (n *NodeSpec) TransportSummary() string {
	if n == nil {
		return "-"
	}
	var parts []string
	transport := n.Transport
	if transport == "" {
		switch n.Protocol {
		case ProtoShadowsocks, ProtoSocks, ProtoHTTP, ProtoFreedom:
			transport = "tcp"
		}
	}
	if transport != "" {
		parts = append(parts, transport)
	}
	if n.Security != "" && n.Security != "none" {
		parts = append(parts, n.Security)
	}
	if n.SNI != "" {
		parts = append(parts, "sni="+n.SNI)
	}
	if n.Host != "" && n.Host != n.SNI {
		parts = append(parts, "host="+n.Host)
	}
	if n.Path != "" {
		parts = append(parts, "path="+n.Path)
	}
	if n.Fingerprint != "" {
		parts = append(parts, "fp="+n.Fingerprint)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}
