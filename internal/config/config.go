package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/pathd"
)

type AppRole string

const (
	RoleServer  AppRole = "server"
	RoleGateway AppRole = "gateway"
)

const (
	DefaultTProxyPort = 12345
)

type PresetMode string

const (
	ModeVLESSReality   PresetMode = "vless-reality-xhttp"
	ModeVLESSVision    PresetMode = "vless-vision-reality-tcp"
	ModeVLESSXHTTP     PresetMode = "vless-xhttp-kem768"
	ModeVMessWS        PresetMode = "vmess-ws"
	ModeShadowsocksTCP PresetMode = "shadowsocks-tcp"
	ModeHysteria2      PresetMode = "hysteria2"
)

const (
	MinRealityClientVersion = "26.10.21"
)

var AllowedRealityFingerprints = []string{
	"chrome",
	"firefox",
	"safari",
	"ios",
	"edge",
}

// DefaultRealityFingerprints contains browser fingerprints with optimal TLS 1.3/REALITY compatibility.
var DefaultRealityFingerprints = []string{
	"chrome",
	"firefox",
	"safari",
}

// GetRandomRealityFingerprint picks a random browser fingerprint from DefaultRealityFingerprints using crypto/rand.
func GetRandomRealityFingerprint() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(DefaultRealityFingerprints))))
	if err != nil {
		return "", fmt.Errorf("failed to generate random reality fingerprint: %w", err)
	}
	return DefaultRealityFingerprints[n.Int64()], nil
}

// IsAllowedRealityFingerprint checks whether a fingerprint is within the allowed browser fingerprint list.
func IsAllowedRealityFingerprint(fp string) bool {
	for _, allowed := range AllowedRealityFingerprints {
		if fp == allowed {
			return true
		}
	}
	return false
}

// NormalizeMinClientVersion normalizes and validates a minimum client version string.
// It accepts formats like "26.10.17", "26.10", "0", "0.0.0", or "v26.10.17" and strips leading 'v'/'V'.
// A single "0" or "0.0.0" is normalized to "0.0.0".
func NormalizeMinClientVersion(ver string) (string, error) {
	ver = strings.TrimSpace(ver)
	ver = strings.TrimPrefix(ver, "v")
	ver = strings.TrimPrefix(ver, "V")
	if ver == "" {
		return "", errors.New("minimum client version cannot be empty")
	}
	if ver == "0" || ver == "0.0.0" {
		return "0.0.0", nil
	}
	parts := strings.Split(ver, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return "", fmt.Errorf("invalid version format %q, expected x.y.z or 0.0.0", ver)
	}
	for _, part := range parts {
		if part == "" {
			return "", fmt.Errorf("invalid version format %q", ver)
		}
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 {
			return "", fmt.Errorf("invalid version component %q in %q", part, ver)
		}
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return strings.Join(parts, "."), nil
}

// ResolveMinClientVersion returns the effective minimum client version for a preset mode.
func ResolveMinClientVersion(m *ModeInfo) string {
	if m == nil {
		return MinRealityClientVersion
	}
	if m.MinClientVer != "" {
		return m.MinClientVer
	}
	return MinRealityClientVersion
}

var PresetOrder = []PresetMode{
	ModeVLESSVision,
	ModeVLESSReality,
	ModeVLESSXHTTP,
	ModeVMessWS,
	ModeShadowsocksTCP,
	ModeHysteria2,
}

type EndpointType string

const (
	EndpointTypeStatic    EndpointType = "static"     // 静态域名或单/多 IP
	EndpointTypeAuto      EndpointType = "auto"       // 自动探测宿主机公网出口
	EndpointTypeDynamicV6 EndpointType = "dynamic-v6" // 动态 IPv6 轮换池 (预留)
)

const (
	RotationProfileTurtle    = "turtle"    // Single-IP lazy on-demand TTL (default)
	RotationProfileProactive = "proactive" // Single-IP strict scheduled TTL
	RotationProfileIsolated  = "isolated"  // Per-consumer dedicated pool (1 IP per user, 3600s retirement)
)

type EndpointConfig struct {
	Type         EndpointType `json:"type"`                     // static, auto, dynamic-v6
	Host         string       `json:"host,omitempty"`            // 域名或 IP (用于 static)
	Family       string       `json:"family,omitempty"`          // v4 或 v6 (用于 auto)
	Interface    string       `json:"interface,omitempty"`       // 网卡名称 (预留给 dynamic-v6)
	Subnet       string       `json:"subnet,omitempty"`          // IPv6 前缀 CIDR (预留给 dynamic-v6)
	MaxAddresses int          `json:"max_addresses,omitempty"`   // 最大活跃数 (预留给 dynamic-v6)
	EnableNDP    bool         `json:"enable_ndp,omitempty"`       // 是否开启 NDP 代理 (预留给 dynamic-v6)
	Profile      string       `json:"profile,omitempty"`          // 轮换策略包: turtle, proactive, isolated
	TTL          string       `json:"ttl,omitempty"`              // 轮换周期/冷却时间: 如 12h, 6h, 1d (默认 12h)
}

type UserConfig struct {
	Role            AppRole          `json:"role"`
	UUID            string           `json:"uuid"`
	APIInbound      int              `json:"api_inbound"`
	TestInbound     int              `json:"test_inbound"`
	Presets         []ModeInfo       `json:"presets"`
	CustomOutbounds []CustomOutbound `json:"custom_outbounds"`
	RelaySubs       map[string]string `json:"relay_subs,omitempty"`
	Guests          []GuestConfig    `json:"guests"`
	Gateway         GatewayConfig    `json:"-"`
	// legacyGateway is set when the file still carried the pre-gateway.conf
	// (v0.5.x) inline "gateway" object; see migrateLegacyGateway.
	legacyGateway bool
	// Path is the local Pathd daemon endpoint. It is meaningful only on a
	// Server. Gateway-side PathLink credentials live on the relay that uses
	// them (CustomOutbound.Path).
	Path     PathConfig     `json:"path,omitempty"`
	AdminSub AdminSubConfig `json:"admin_sub,omitempty"`
	// SubscriptionInstances contains named multi-instance subscription configurations.
	SubscriptionInstances map[string]AdminSubConfig `json:"subscription_instances,omitempty"`
	// IPv6Rotation contains the privileged address allocator used by
	// subscription services.
	IPv6Rotation IPv6Config `json:"ipv6_rotation,omitempty"`
	// IPv6Rotations is preserved for backwards compatibility with multi-instance schema.
	IPv6Rotations map[string]IPv6Config `json:"ipv6_rotations,omitempty"`
	Subscriptions []Subscription        `json:"subscriptions"`
	SubPort       int                   `json:"sub_port"`
	GuestSubPort    int                   `json:"guest_sub_port,omitempty"`
	GuestSubBind    string                `json:"guest_sub_bind,omitempty"`
	GuestSubAddress string                `json:"guest_sub_address,omitempty"`
	AddressSub      string                `json:"address_sub,omitempty"`
	AddressNode     string                `json:"address_node,omitempty"`
	GateURL         string                `json:"gate_url,omitempty"`
	Endpoints       map[string]EndpointConfig `json:"endpoints,omitempty"`
	IPv6Pool        IPv6Config            `json:"ipv6_pool"`
	Certs         []ManagedCert         `json:"certs,omitempty"`
	SkinPort      int                   `json:"skin_port,omitempty"`

	// legacyPath* are populated only while decoding the pre-relay PathLink
	// schema. They are intentionally not persisted.
	legacyPathEnabled *bool
	legacyPathSeen    bool
}

// PathConfig configures one loopback-only Pathd endpoint.  On a Server it is
// the local daemon configuration; on a Gateway it is attached to a relay.
// Service enablement deliberately belongs to systemd, not this config.
type PathConfig struct {
	Listen      string `json:"listen,omitempty"`
	Token       string `json:"token,omitempty"`
	IdleSeconds int    `json:"idle_seconds,omitempty"`
	// LegacyEnabled is retained only for an enabled legacy Gateway config whose
	// selected relay no longer exists. It is cleared as soon as migration can
	// attach the credential; new code never reads it for enablement.
	LegacyEnabled bool `json:"enabled,omitempty"`
}

func (cfg *UserConfig) UnmarshalJSON(data []byte) error {
	type Alias UserConfig
	aux := &struct {
		ActiveModes   []ModeInfo      `json:"active_modes"`
		Path          json.RawMessage `json:"path"`
		LegacyGateway *GatewayConfig  `json:"gateway,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(cfg),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.LegacyGateway != nil {
		// v0.5.x stored the Gateway settings inline in config.json. They are
		// now owned by gateway.conf; the inline copy is read only so that
		// LoadConfigEx can migrate it, and is never written back.
		cfg.Gateway = *aux.LegacyGateway
		cfg.legacyGateway = true
	}
	if len(aux.ActiveModes) > 0 && len(cfg.Presets) == 0 {
		cfg.Presets = aux.ActiveModes
	}
	if len(aux.Path) > 0 && string(aux.Path) != "null" {
		if err := json.Unmarshal(aux.Path, &cfg.Path); err != nil {
			return err
		}
		var legacy struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.Unmarshal(aux.Path, &legacy); err != nil {
			return err
		}
		cfg.legacyPathEnabled = legacy.Enabled
		cfg.legacyPathSeen = legacy.Enabled != nil
		if legacy.Enabled != nil && *legacy.Enabled {
			cfg.Path.LegacyEnabled = true
		}
	}
	return nil
}

type AdminSubConfig struct {
	Listen       string `json:"listen,omitempty"`
	Token        string `json:"token,omitempty"`
	Address      string `json:"address,omitempty"`
	AddressSub   string `json:"address_sub,omitempty"`
	AddressNode  string `json:"address_node,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	Port         int    `json:"port,omitempty"`
	TargetType   string `json:"target_type,omitempty"`
	TargetAlias  string `json:"target_alias,omitempty"`
	IPv6Rotation string `json:"ipv6_rotation,omitempty"`

	legacyEnabled    *bool
	legacyMode       string
	legacyIPv6Rotate IPv6Config
}

// SubscriptionServiceConfig is the private runtime configuration consumed by
// xray-proxya-sub.service.
type SubscriptionServiceConfig struct {
	Listen    string         `json:"listen"`
	Port      int            `json:"port"`
	GuestBind string         `json:"guest_bind,omitempty"`
	GuestPort int            `json:"guest_port,omitempty"`
	AdminSub  AdminSubConfig `json:"admin_sub"`
}

type IPv6Config struct {
	Subnet       string `json:"subnet"`        // e.g., 2001:db8::/64
	Interface    string `json:"interface"`     // e.g., eth0
	MaxAddresses int    `json:"max_addresses"` // Max addresses to keep active (rotation limit)
	EnableNDP    bool   `json:"enable_ndp"`    // Whether to auto-configure NDP

	legacyEnabled *bool
}

// UnmarshalJSON accepts the pre-service schema but intentionally never
// serializes its enablement/mode switches again.
func (a *AdminSubConfig) UnmarshalJSON(data []byte) error {
	type wire struct {
		Listen       string     `json:"listen"`
		Token        string     `json:"token"`
		Address      string     `json:"address"`
		AddressSub   string     `json:"address_sub"`
		AddressNode  string     `json:"address_node"`
		Endpoint     string     `json:"endpoint"`
		Port         int        `json:"port"`
		TargetType   string     `json:"target_type"`
		TargetAlias  string     `json:"target_alias"`
		IPv6Rotation string     `json:"ipv6_rotation"`
		Enabled      *bool      `json:"enabled"`
		Mode         string     `json:"mode"`
		IPv6Rotate   IPv6Config `json:"ipv6_rotate"`
	}
	var v wire
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*a = AdminSubConfig{
		Listen:           v.Listen,
		Token:            v.Token,
		Address:          v.Address,
		AddressSub:       v.AddressSub,
		AddressNode:      v.AddressNode,
		Endpoint:         v.Endpoint,
		Port:             v.Port,
		TargetType:       v.TargetType,
		TargetAlias:      v.TargetAlias,
		IPv6Rotation:     v.IPv6Rotation,
		legacyEnabled:    v.Enabled,
		legacyMode:       v.Mode,
		legacyIPv6Rotate: v.IPv6Rotate,
	}
	return nil
}

func (v *IPv6Config) UnmarshalJSON(data []byte) error {
	type wire struct {
		Subnet       string `json:"subnet"`
		Interface    string `json:"interface"`
		MaxAddresses int    `json:"max_addresses"`
		EnableNDP    bool   `json:"enable_ndp"`
		Enabled      *bool  `json:"enabled"`
	}
	var raw wire
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = IPv6Config{Subnet: raw.Subnet, Interface: raw.Interface, MaxAddresses: raw.MaxAddresses, EnableNDP: raw.EnableNDP, legacyEnabled: raw.Enabled}
	return nil
}

type Subscription struct {
	Alias       string `json:"alias"`        // "" for the default direct outbound
	TargetType  string `json:"target_type"`  // "direct", "outbound", "guest"
	TargetAlias string `json:"target_alias"` // specific alias for outbound/guest
	Address     string `json:"address"`      // custom address or hostname
	Token       string `json:"token"`        // random URL path token
}

type GuestDisabledReason string

const (
	GuestDisabledNone         GuestDisabledReason = ""
	GuestDisabledManual       GuestDisabledReason = "manual"
	GuestDisabledQuotaReached GuestDisabledReason = "quota_reached"
	GuestDisabledQuotaZero    GuestDisabledReason = "quota_zero"
)

type GuestNotifyMode string

const (
	GuestNotifyOff    GuestNotifyMode = "off"
	GuestNotifyHeader GuestNotifyMode = "header"
	GuestNotifyRemark GuestNotifyMode = "remark"
	GuestNotifyAll    GuestNotifyMode = "all"
)

type GuestConfig struct {
	Alias          string                 `json:"alias"`
	UUID           string                 `json:"uuid"`
	Enabled        bool                   `json:"enabled"`
	DisabledReason GuestDisabledReason    `json:"disabled_reason,omitempty"`
	QuotaGB         float64                `json:"quota_gb"` // -1 for unlimited, 0 for paused
	LimitBytes      int64                  `json:"limit_bytes,omitempty"`
	UsedBytes       int64                  `json:"used_bytes"`
	ResetDay        int                    `json:"reset_day"`               // 1-31
	LastResetYM     string                 `json:"last_reset_ym,omitempty"` // YYYY-MM of the last quota reset
	SubToken        string                 `json:"sub_token,omitempty"`
	Endpoint        string                 `json:"endpoint,omitempty"`
	OutboundLink    string                 `json:"outbound_link,omitempty"` // For custom routing
	OutboundConf    map[string]interface{} `json:"outbound_conf,omitempty"` // Parsed version
	Notify          GuestNotifyMode        `json:"notify,omitempty"`
	NotifyWebhook   string                 `json:"notify_webhook,omitempty"`
	NotifyTrigger   []string               `json:"notify_trigger,omitempty"`
	AlertedTriggers []string               `json:"alerted_triggers,omitempty"`
	AlertedYM       string                 `json:"alerted_ym,omitempty"`
}

func (g GuestConfig) EffectiveLimitBytes() int64 {
	if g.LimitBytes > 0 {
		return g.LimitBytes
	}
	if g.QuotaGB > 0 {
		return int64(math.Round(g.QuotaGB * float64(GigaByte)))
	}
	if g.QuotaGB == 0 || (g.LimitBytes == 0 && g.DisabledReason == GuestDisabledQuotaZero) {
		return 0
	}
	return -1
}

func (g GuestConfig) NormalizedNotifyMode() GuestNotifyMode {
	switch g.Notify {
	case GuestNotifyHeader, GuestNotifyRemark, GuestNotifyAll:
		return g.Notify
	default:
		return GuestNotifyOff
	}
}

func (g GuestConfig) DaysUntilReset(now time.Time) int {
	resetDay := g.ResetDay
	if resetDay < 1 {
		resetDay = 1
	}
	location := now.Location()
	year, month, day := now.Date()
	targetYear, targetMonth := year, month
	targetDay := ClampResetDay(resetDay, targetYear, targetMonth, location)
	if day > targetDay {
		nextMonth := now.AddDate(0, 1, 0)
		targetYear, targetMonth, _ = nextMonth.Date()
		targetDay = ClampResetDay(resetDay, targetYear, targetMonth, location)
	}
	start := time.Date(year, month, day, 0, 0, 0, 0, location)
	target := time.Date(targetYear, targetMonth, targetDay, 0, 0, 0, 0, location)
	return int(target.Sub(start).Hours() / 24)
}

func (g GuestConfig) NextResetTimestamp(now time.Time) int64 {
	resetDay := g.ResetDay
	if resetDay < 1 {
		resetDay = 1
	}
	location := now.Location()
	year, month, day := now.Date()
	targetYear, targetMonth := year, month
	targetDay := ClampResetDay(resetDay, targetYear, targetMonth, location)
	if day >= targetDay {
		nextMonth := now.AddDate(0, 1, 0)
		targetYear, targetMonth, _ = nextMonth.Date()
		targetDay = ClampResetDay(resetDay, targetYear, targetMonth, location)
	}
	return time.Date(targetYear, targetMonth, targetDay, 0, 0, 0, 0, location).Unix()
}

func ClampResetDay(resetDay int, year int, month time.Month, location *time.Location) int {
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, location).Day()
	if resetDay > lastDay {
		return lastDay
	}
	return resetDay
}

// SanitizeGuestAlias normalizes a guest alias to lowercase alphanumeric and hyphens.
// This matches the transformation applied when generating Xray configuration tags and emails.
func SanitizeGuestAlias(alias string) string {
	var b strings.Builder
	for _, r := range alias {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	return out
}

// CleanGuestAlias validates and cleans a guest alias input:
// - Trims leading/trailing whitespace
// - Normalizes to lowercase
// - Enforces length between 3 and 20 characters
// - Enforces allowed character set: lowercase alphanumeric, underscore, and hyphen.
func CleanGuestAlias(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 3 || len(trimmed) > 20 {
		return "", fmt.Errorf("guest alias must be between 3 and 20 characters")
	}
	alias := strings.ToLower(trimmed)
	for _, r := range alias {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return "", fmt.Errorf("invalid guest alias %q: only alphanumeric, underscore, and hyphen allowed", raw)
		}
	}
	return alias, nil
}

type GatewayRule struct {
	MAC       string `json:"mac,omitempty"`       // normalized lowercase MAC e.g. "52:54:00:83:00:11"
	IP        string `json:"ip,omitempty"`        // normalized IP or CIDR e.g. "192.168.1.95" or "10.0.0.0/24"
	Interface string `json:"interface,omitempty"` // LAN interface e.g. "eth1"
	Target    string `json:"target"`              // "direct", "block", or relay alias
}

type GatewayConfig struct {
	LocalEnabled    bool                `json:"local_enabled"`
	LANEnabled      bool                `json:"lan_enabled"`
	Mode            string              `json:"mode,omitempty"`        // legacy mode field, superseded by TProxy as default
	TUNEnabled      bool                `json:"tun_enabled,omitempty"` // standalone pure TUN adapter (proxya-tun) without nftables rules
	RelayAlias      string              `json:"relay_alias"`
	LANInterface    string              `json:"lan_interface"`
	LANInterfaces   []string            `json:"lan_interfaces,omitempty"`
	WANInterface    string              `json:"wan_interface,omitempty"`
	NATDisabled     bool                `json:"nat_disabled,omitempty"`
	Rules           []GatewayRule       `json:"rules,omitempty"`
	TProxyPort      int                 `json:"tproxy_port,omitempty"`
	BypassDNS       []string            `json:"bypass_dns,omitempty"`
	State           string              `json:"state,omitempty"` // "disabled", "forward-only", "proxy"
	BypassCountries []string            `json:"bypass_countries,omitempty"`
	DNSListen       string              `json:"dns_listen,omitempty"`
	DNSStrategy     string              `json:"dns_strategy,omitempty"`
	DNSServers      []string            `json:"dns_servers,omitempty"`
	DNSRecords      map[string][]string `json:"dns_records,omitempty"`
	PortForwards    []PortForwardRule   `json:"port_forwards,omitempty"`
	IsolatedInterfaces []string         `json:"isolated_interfaces,omitempty"`
}

type PortForwardRule struct {
	WANPort    int    `json:"wan_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Proto      string `json:"proto,omitempty"` // "tcp", "udp", or "tcp,udp" (default)
}

func NormalizePortForwardProto(proto string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "" || p == "tcp,udp" || p == "udp,tcp" || p == "all" {
		return "tcp,udp", nil
	}
	if p == "tcp" || p == "udp" {
		return p, nil
	}
	return "", fmt.Errorf("invalid proto %q: must be tcp, udp, or tcp,udp", proto)
}

func PortForwardProtoOverlap(p1, p2 string) bool {
	norm1, _ := NormalizePortForwardProto(p1)
	norm2, _ := NormalizePortForwardProto(p2)
	if norm1 == "tcp,udp" || norm2 == "tcp,udp" {
		return true
	}
	return norm1 == norm2
}

func ValidatePortForwardRule(pf PortForwardRule) error {
	if pf.WANPort < 1 || pf.WANPort > 65535 {
		return fmt.Errorf("invalid wan port %d: must be between 1 and 65535", pf.WANPort)
	}
	if pf.TargetPort < 1 || pf.TargetPort > 65535 {
		return fmt.Errorf("invalid target port %d: must be between 1 and 65535", pf.TargetPort)
	}
	ipStr := strings.TrimSpace(pf.TargetIP)
	if ipStr == "" {
		return fmt.Errorf("target ip cannot be empty")
	}
	if net.ParseIP(ipStr) == nil {
		return fmt.Errorf("invalid target ip %q: must be a valid IPv4 or IPv6 address", pf.TargetIP)
	}
	if _, err := NormalizePortForwardProto(pf.Proto); err != nil {
		return err
	}
	return nil
}

var allowedDNSServerSchemes = map[string]bool{
	"https":       true,
	"https+local": true,
	"h2c":         true,
	"tcp":         true,
	"tcp+local":   true,
	"tls":         true,
	"quic":        true,
	"quic+local":  true,
}

// ParseDNSListen parses and normalizes a DNS listen address.
// Accepts: "127.0.0.1:5353", "[::1]:5353", ":53", "0.0.0.0:53", "[::]:53", or a bare port like "5353".
// Bare port normalizes to "127.0.0.1:<port>".
// Wildcard hosts ("", "0.0.0.0", "::", "[::]") normalize to ":<port>" with Xray listen host "::".
// Specific IP hosts must be valid IPv4/IPv6 addresses (net.ParseIP), port must be 1..65535.
func ParseDNSListen(raw string) (host string, port int, normalized string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", 0, "", fmt.Errorf("empty dns listen address")
	}

	// 1. Bare port: "5353" -> "127.0.0.1:5353"
	if p, convErr := strconv.Atoi(trimmed); convErr == nil {
		if p < 1 || p > 65535 {
			return "", 0, "", fmt.Errorf("invalid port %d: must be between 1 and 65535", p)
		}
		return "127.0.0.1", p, fmt.Sprintf("127.0.0.1:%d", p), nil
	}

	// 2. Colon port: ":53" -> wildcard host "::", normalized ":53"
	if strings.HasPrefix(trimmed, ":") && !strings.HasPrefix(trimmed, "::") {
		pStr := strings.TrimPrefix(trimmed, ":")
		p, convErr := strconv.Atoi(pStr)
		if convErr != nil || p < 1 || p > 65535 {
			return "", 0, "", fmt.Errorf("invalid port %q: must be between 1 and 65535", pStr)
		}
		return "::", p, fmt.Sprintf(":%d", p), nil
	}

	// 3. host:port
	h, portStr, splitErr := net.SplitHostPort(trimmed)
	if splitErr != nil {
		return "", 0, "", fmt.Errorf("invalid dns listen address %q: %w", raw, splitErr)
	}

	p, convErr := strconv.Atoi(portStr)
	if convErr != nil || p < 1 || p > 65535 {
		return "", 0, "", fmt.Errorf("invalid port %q: must be between 1 and 65535", portStr)
	}

	hTrim := strings.Trim(h, "[]")
	if hTrim == "" || hTrim == "0.0.0.0" || hTrim == "::" {
		return "::", p, fmt.Sprintf(":%d", p), nil
	}

	ip := net.ParseIP(hTrim)
	if ip == nil {
		return "", 0, "", fmt.Errorf("invalid host IP %q in dns listen address", h)
	}

	if ip.To4() != nil {
		return ip.String(), p, fmt.Sprintf("%s:%d", ip.String(), p), nil
	}
	return ip.String(), p, fmt.Sprintf("[%s]:%d", ip.String(), p), nil
}

// ValidateDNSServerEntry validates and normalizes an upstream DNS server entry.
// Accepts plain IPv4/IPv6, ip:port, "localhost", or URI with supported schemes:
// https://, https+local://, h2c://, tcp://, tcp+local://, tls://, quic://, quic+local://.
func ValidateDNSServerEntry(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty dns server entry")
	}

	if strings.EqualFold(trimmed, "localhost") {
		return "localhost", nil
	}

	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String(), nil
	}

	if host, portStr, err := net.SplitHostPort(trimmed); err == nil {
		if p, pErr := strconv.Atoi(portStr); pErr == nil && p >= 1 && p <= 65535 {
			hTrim := strings.Trim(host, "[]")
			if ip := net.ParseIP(hTrim); ip != nil {
				if ip.To4() != nil {
					return fmt.Sprintf("%s:%d", ip.String(), p), nil
				}
				return fmt.Sprintf("[%s]:%d", ip.String(), p), nil
			}
		}
	}

	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("invalid dns server URI %q: %w", raw, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if !allowedDNSServerSchemes[scheme] {
			return "", fmt.Errorf("unsupported dns server scheme %q in %q", u.Scheme, raw)
		}
		if u.Host == "" {
			return "", fmt.Errorf("missing host in dns server URI %q", raw)
		}
		return trimmed, nil
	}

	return "", fmt.Errorf("invalid dns server entry %q: must be IP, IP:port, localhost, or URI with supported scheme", raw)
}

// NormalizeDNSRecordDomain trims, validates, and lowercases a DNS record domain.
// Allows standard domains like "router.lan" as well as Xray "domain:", "full:", "regexp:" prefixes.
func NormalizeDNSRecordDomain(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}
	if strings.ContainsAny(trimmed, " \t\r\n/") {
		return "", fmt.Errorf("invalid domain %q: contains whitespace or slashes", raw)
	}
	return trimmed, nil
}

// ValidateDNSRecordIPs validates, normalizes, and deduplicates IPv4/IPv6 addresses while preserving order.
func ValidateDNSRecordIPs(ips []string) ([]string, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("at least one IP address must be provided")
	}
	seen := make(map[string]bool, len(ips))
	var result []string
	for _, ipStr := range ips {
		for _, part := range strings.Split(ipStr, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			parsed := net.ParseIP(trimmed)
			if parsed == nil {
				return nil, fmt.Errorf("invalid IP address %q", trimmed)
			}
			norm := parsed.String()
			if !seen[norm] {
				seen[norm] = true
				result = append(result, norm)
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("at least one valid IP address must be provided")
	}
	return result, nil
}

// NormalizeDNSQueryStrategy validates and normalizes DNS query strategy names.
func NormalizeDNSQueryStrategy(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "useip":
		return "UseIP", true
	case "useipv4":
		return "UseIPv4", true
	case "useipv6":
		return "UseIPv6", true
	default:
		return "", false
	}
}

func (g GatewayConfig) EffectiveMode() string {
	return "tproxy"
}

func (g GatewayConfig) EffectiveTUNEnabled() bool {
	if g.TUNEnabled {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(g.Mode), "tun")
}

func (g GatewayConfig) EffectiveTProxyPort() int {
	if g.TProxyPort > 0 {
		return g.TProxyPort
	}
	return DefaultTProxyPort
}

// EffectiveLANInterfaces parses, trims, and deduplicates interfaces from both
// g.LANInterfaces and comma-separated g.LANInterface (preserving order).
func (g GatewayConfig) EffectiveLANInterfaces() []string {
	var result []string
	seen := make(map[string]bool)

	add := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}

	for _, item := range g.LANInterfaces {
		for _, part := range strings.Split(item, ",") {
			add(part)
		}
	}
	for _, part := range strings.Split(g.LANInterface, ",") {
		add(part)
	}
	return result
}

// EffectiveIsolatedInterfaces parses, trims, deduplicates, and sorts interfaces in g.IsolatedInterfaces.
func (g GatewayConfig) EffectiveIsolatedInterfaces() []string {
	var result []string
	seen := make(map[string]bool)

	for _, item := range g.IsolatedInterfaces {
		for _, part := range strings.Split(item, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			if !seen[trimmed] {
				seen[trimmed] = true
				result = append(result, trimmed)
			}
		}
	}
	sort.Strings(result)
	return result
}

// NormalizeMAC parses a MAC address using net.ParseMAC, requires a 6-byte EUI-48 hardware address,
// and returns the lowercase normalized format "xx:xx:xx:xx:xx:xx".
func NormalizeMAC(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("empty MAC address")
	}
	hw, err := net.ParseMAC(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid MAC address %q: %w", raw, err)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC address %q: expected 6-byte EUI-48 address, got %d bytes", raw, len(hw))
	}
	return strings.ToLower(hw.String()), nil
}

// NormalizeIPOrCIDR parses and normalizes an IP address or CIDR notation.
// Single IPv4/IPv6 addresses are returned in standard canonical form.
// CIDR prefixes are returned in canonical masked prefix form (e.g. "192.168.1.5/24" -> "192.168.1.0/24").
func NormalizeIPOrCIDR(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("IP or CIDR cannot be empty")
	}
	if strings.Contains(trimmed, "/") {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		if prefix.Addr().Is4In6() {
			unmapped := prefix.Addr().Unmap()
			bits := prefix.Bits() - 96
			if bits >= 0 && bits <= 32 {
				prefix = netip.PrefixFrom(unmapped, bits)
			}
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q: %w", raw, err)
	}
	return addr.Unmap().String(), nil
}

// ValidateGatewayRule validates and normalizes a GatewayRule.
// It requires at least one of MAC, IP, or Interface to be non-empty,
// normalizes MAC and IP if set, trims Interface, and normalizes Target.
func ValidateGatewayRule(rule GatewayRule) (GatewayRule, error) {
	norm := GatewayRule{
		Interface: strings.TrimSpace(rule.Interface),
	}
	if strings.TrimSpace(rule.MAC) != "" {
		mac, err := NormalizeMAC(rule.MAC)
		if err != nil {
			return rule, err
		}
		norm.MAC = mac
	}
	if strings.TrimSpace(rule.IP) != "" {
		ipNorm, err := NormalizeIPOrCIDR(rule.IP)
		if err != nil {
			return rule, err
		}
		norm.IP = ipNorm
	}
	if norm.MAC == "" && norm.IP == "" && norm.Interface == "" {
		return rule, errors.New("gateway rule must specify at least one of MAC, IP, or Interface")
	}
	if norm.Interface != "" {
		if err := ValidateInterfaceName(norm.Interface); err != nil {
			return rule, err
		}
	}

	target := strings.TrimSpace(rule.Target)
	if target == "" {
		return rule, errors.New("gateway rule target cannot be empty")
	}
	if strings.EqualFold(target, "direct") {
		norm.Target = "direct"
	} else if strings.EqualFold(target, "block") {
		norm.Target = "block"
	} else {
		norm.Target = target
	}
	return norm, nil
}

// ValidateInterfaceName checks that name is a safe Linux network interface
// name: 1-15 characters from [A-Za-z0-9._-], and not "." or "..". Names are
// embedded in nftables scripts, so anything else is rejected.
func ValidateInterfaceName(name string) error {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return fmt.Errorf("invalid interface name %q: must be 1-15 characters and not '.' or '..'", name)
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return fmt.Errorf("invalid interface name %q: only letters, digits, '.', '-' and '_' are allowed", name)
		}
	}
	return nil
}

// ValidateGatewayRulesForMode verifies that gateway rules are compatible with the gateway configuration.
// TProxy is the primary gateway interception mechanism supporting multi-relay rules.
// Standalone pure TUN operates as a supplementary adapter for direct routing without restricting rules.
func ValidateGatewayRulesForMode(userCfg *UserConfig) error {
	return nil
}

// ValidateGatewayMode verifies that Gateway.Mode is either empty, "tproxy", or "tun".
func ValidateGatewayMode(userCfg *UserConfig) error {
	if userCfg == nil || userCfg.Role != RoleGateway {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(userCfg.Gateway.Mode))
	if mode != "" && mode != "tproxy" && mode != "tun" {
		return fmt.Errorf("invalid gateway mode %q; valid options are 'tproxy' and 'tun'", userCfg.Gateway.Mode)
	}
	return ValidateGatewayRulesForMode(userCfg)
}

// ValidateGatewayInterfaces validates every interface name referenced by the
// gateway configuration (LAN, WAN and per-rule interfaces).
func ValidateGatewayInterfaces(userCfg *UserConfig) error {
	if userCfg == nil {
		return nil
	}
	lanIfaces := userCfg.Gateway.EffectiveLANInterfaces()
	for _, name := range lanIfaces {
		if err := ValidateInterfaceName(name); err != nil {
			return fmt.Errorf("gateway LAN interface: %w", err)
		}
	}
	isoIfaces := userCfg.Gateway.EffectiveIsolatedInterfaces()
	for _, name := range isoIfaces {
		if err := ValidateInterfaceName(name); err != nil {
			return fmt.Errorf("gateway isolated interface: %w", err)
		}
	}
	if wan := strings.TrimSpace(userCfg.Gateway.WANInterface); wan != "" && !strings.EqualFold(wan, "auto") {
		if err := ValidateInterfaceName(wan); err != nil {
			return fmt.Errorf("gateway WAN interface: %w", err)
		}
		for _, lan := range lanIfaces {
			if wan == lan {
				return fmt.Errorf("WAN interface %q cannot also be configured as a LAN interface", wan)
			}
		}
		for _, iso := range isoIfaces {
			if wan == iso {
				return fmt.Errorf("WAN interface %q cannot be configured as an isolated interface", wan)
			}
		}
	}
	for _, rule := range userCfg.Gateway.Rules {
		if rule.Interface != "" {
			if err := ValidateInterfaceName(rule.Interface); err != nil {
				return fmt.Errorf("gateway rule interface: %w", err)
			}
		}
	}
	return nil
}

// ValidateGatewayPorts verifies that the TProxy listener ports (the base port
// plus one per extra relay target) are valid and do not collide with each
// other or with any other port configured by Xray-Proxya.
func ValidateGatewayPorts(userCfg *UserConfig) error {
	if userCfg == nil || userCfg.Role != RoleGateway {
		return nil
	}
	owners := map[int]string{}
	var conflict error
	// Ports of other components are only recorded (they may legitimately
	// coexist among themselves); the TProxy ports are checked against them.
	claim := func(port int, owner string) {
		if port > 0 {
			if _, ok := owners[port]; !ok {
				owners[port] = owner
			}
		}
	}
	tproxyOwners := map[int]string{}
	claimTProxy := func(port int, owner string) {
		if conflict != nil {
			return
		}
		if port <= 0 || port > 65535 {
			conflict = fmt.Errorf("%s port %d is out of range", owner, port)
			return
		}
		if prev, ok := owners[port]; ok {
			conflict = fmt.Errorf("port %d is used by both %s and %s", port, prev, owner)
			return
		}
		if prev, ok := tproxyOwners[port]; ok && prev != owner {
			conflict = fmt.Errorf("port %d is used by both %s and %s", port, prev, owner)
			return
		}
		tproxyOwners[port] = owner
	}
	// Ports owned by other components are claimed first.
	claim(userCfg.APIInbound, "api inbound")
	claim(userCfg.TestInbound, "test inbound")
	claim(userCfg.SubPort, "subscription")
	claim(userCfg.GuestSubPort, "guest subscription")
	claim(userCfg.SkinPort, "skin")
	if userCfg.Gateway.DNSListen != "" {
		if _, dnsPort, _, err := ParseDNSListen(userCfg.Gateway.DNSListen); err == nil {
			claim(dnsPort, "gateway dns listener")
		}
	}
	for _, m := range userCfg.Presets {
		if m.Enabled {
			claim(m.Port, fmt.Sprintf("preset %s", m.Mode))
		}
	}
	for i := range userCfg.CustomOutbounds {
		co := &userCfg.CustomOutbounds[i]
		claim(co.InternalProxyPort, "relay "+co.Alias+" proxy")
		claim(co.InternalHttpPort, "relay "+co.Alias+" http")
	}
	if userCfg.Gateway.EffectiveMode() != "tun" {
		var aliases []string
		for alias := range GatewayTProxyPorts(userCfg) {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		ports := GatewayTProxyPorts(userCfg)
		// The base port is shared with the relay that owns it; claim it explicitly
		// only when no relay does (e.g. a gateway with no relay yet).
		baseOwned := false
		for _, p := range ports {
			if p == userCfg.Gateway.EffectiveTProxyPort() {
				baseOwned = true
			}
		}
		if !baseOwned {
			claimTProxy(userCfg.Gateway.EffectiveTProxyPort(), "tproxy base port")
		}
		for _, alias := range aliases {
			claimTProxy(ports[alias], "tproxy relay "+alias)
		}
	}
	for i, pf := range userCfg.Gateway.PortForwards {
		if conflict != nil {
			break
		}
		if pf.WANPort <= 0 || pf.WANPort > 65535 {
			conflict = fmt.Errorf("port forward wan port %d is out of range", pf.WANPort)
			break
		}
		owner := fmt.Sprintf("port forward wan:%d", pf.WANPort)
		if prev, ok := owners[pf.WANPort]; ok {
			conflict = fmt.Errorf("port %d is used by both %s and %s", pf.WANPort, prev, owner)
			break
		}
		if prev, ok := tproxyOwners[pf.WANPort]; ok {
			conflict = fmt.Errorf("port %d is used by both %s and %s", pf.WANPort, prev, owner)
			break
		}
		for j := 0; j < i; j++ {
			prev := userCfg.Gateway.PortForwards[j]
			if prev.WANPort == pf.WANPort && PortForwardProtoOverlap(prev.Proto, pf.Proto) {
				conflict = fmt.Errorf("port %d is used by both %s and %s", pf.WANPort, fmt.Sprintf("port forward (proto %s)", prev.Proto), owner)
				break
			}
		}
	}
	return conflict
}

// ValidateGatewayRuleTargets verifies that every relay target referenced by a
// gateway rule still names an existing, enabled custom outbound. It protects
// against rules becoming dangling after a relay is deleted or disabled.
func ValidateGatewayRuleTargets(userCfg *UserConfig) error {
	if userCfg == nil {
		return nil
	}
	for _, rule := range userCfg.Gateway.Rules {
		target := strings.TrimSpace(rule.Target)
		if target == "" || strings.EqualFold(target, "direct") || strings.EqualFold(target, "block") {
			continue
		}
		if !GatewayRelayActive(userCfg, target) {
			return fmt.Errorf("gateway rule (MAC=%q, IP=%q, Interface=%q) targets relay %q which does not exist or is disabled; delete or update the rule first", rule.MAC, rule.IP, rule.Interface, target)
		}
	}
	return nil
}

// GatewayRelayActive reports whether alias names an enabled custom outbound.
func GatewayRelayActive(userCfg *UserConfig, alias string) bool {
	if userCfg == nil {
		return false
	}
	for i := range userCfg.CustomOutbounds {
		if userCfg.CustomOutbounds[i].Alias == alias {
			return userCfg.CustomOutbounds[i].Enabled
		}
	}
	return false
}

// GatewayTProxyPorts returns a map of relay aliases to their allocated TProxy ports.
// The default relay alias (if set and not direct/block) uses basePort (default 12345).
// Additional relay targets specified in Gateway.Rules receive basePort + len(ports).
func GatewayTProxyPorts(userCfg *UserConfig) map[string]int {
	ports := make(map[string]int)
	if userCfg == nil {
		return ports
	}
	basePort := userCfg.Gateway.EffectiveTProxyPort()
	defaultRelay := strings.TrimSpace(userCfg.Gateway.RelayAlias)
	if defaultRelay != "" && !strings.EqualFold(defaultRelay, "direct") && !strings.EqualFold(defaultRelay, "block") {
		ports[defaultRelay] = basePort
	}
	for _, rule := range userCfg.Gateway.Rules {
		target := strings.TrimSpace(rule.Target)
		if target == "" || strings.EqualFold(target, "direct") || strings.EqualFold(target, "block") {
			continue
		}
		if _, exists := ports[target]; !exists {
			if len(ports) == 0 && defaultRelay == "" {
				ports[target] = basePort
			} else {
				ports[target] = basePort + len(ports)
			}
		}
	}
	return ports
}

func NewDefaultConfig() *UserConfig {
	cfg := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Mode:       "tproxy",
			TProxyPort: DefaultTProxyPort,
		},
	}
	cfg.BackfillDefaults()
	return cfg
}

type CustomOutbound struct {
	Alias    string `json:"alias"`
	Enabled  bool   `json:"enabled"`
	UserUUID string `json:"user_uuid"`
	// AllowPrivateTargets permits the relay identity generated for this
	// outbound to forward RFC1918 and loopback destinations to its next hop.
	// It is false by default so relay users cannot reach a next-hop private
	// network unless an operator explicitly opts in.
	AllowPrivateTargets bool     `json:"allow_private_targets"`
	DNSStrategy         string   `json:"dns_strategy,omitempty"`
	DNSServers          []string `json:"dns_servers,omitempty"`
	InternalProxyPort   int      `json:"internal_proxy_port,omitempty"`
	InternalHttpPort    int      `json:"internal_http_port,omitempty"`
	InternalListenAddr  string   `json:"internal_listen_addr,omitempty"`
	// Path holds the remote loopback Pathd credentials used when this outbound
	// is selected as the Gateway relay. It is not rendered into share links.
	Path   *PathConfig            `json:"path,omitempty"`
	Config map[string]interface{} `json:"config"`
}

const (
	SkinNextcloud   = "nextcloud"
	SkinFilebrowser = "filebrowser"
	SkinSeafile     = "seafile"
)

var SupportedSkins = []string{SkinNextcloud, SkinFilebrowser, SkinSeafile}

func IsValidSkin(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SkinNextcloud, SkinFilebrowser, SkinSeafile:
		return true
	default:
		return false
	}
}

type ManagedCert struct {
	Domain    string    `json:"domain"`
	CertPath  string    `json:"cert_path"`
	KeyPath   string    `json:"key_path"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Issuer    string    `json:"issuer,omitempty"`
	AutoRenew bool      `json:"auto_renew"`
}

type ModeInfo struct {
	Mode         PresetMode `json:"mode"`
	Enabled      bool       `json:"enabled"`
	Port         int        `json:"port"`
	SNI          string     `json:"sni,omitempty"`
	Dest         string     `json:"dest,omitempty"`
	Path         string     `json:"path,omitempty"`
	Fingerprint  string     `json:"fingerprint,omitempty"`
	MinClientVer string     `json:"min_client_ver,omitempty"`
	Settings     Settings   `json:"settings"`
	Skin         string     `json:"skin,omitempty"`
	SkinDomain   string     `json:"skin_domain,omitempty"`
	RegenFlag    bool       `json:"regen_flag,omitempty"`
}

func (m *ModeInfo) UnmarshalJSON(data []byte) error {
	type Alias ModeInfo
	aux := &struct {
		Skin json.RawMessage `json:"skin"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(aux.Skin) > 0 {
		var s string
		if err := json.Unmarshal(aux.Skin, &s); err == nil {
			m.Skin = s
		} else {
			// legacy bool: ignore
			m.Skin = ""
		}
	}
	return nil
}

type Settings struct {
	PrivateKey string `json:"privateKey,omitempty"`
	PublicKey  string `json:"publicKey,omitempty"`
	CertPEM    string `json:"certPem,omitempty"`
	ShortID    string `json:"shortId,omitempty"`
	Password   string `json:"password,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
}

// GenerateSelfSignedCert generates an ECDSA P-256 self-signed certificate and private key for domain,
// along with the lowercase 64-character SHA-256 hex digest of the raw DER certificate.
func GenerateSelfSignedCert(domain string) (certPEM string, keyPEM string, sha256Hex string, err error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		domain = "www.bing.com"
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		domain = "www.bing.com"
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate ecdsa key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}
	if serialNumber.Sign() <= 0 {
		serialNumber = big.NewInt(1)
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Xray Inc"},
			CommonName:   domain,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	sum := sha256.Sum256(derBytes)
	sha256Hex = hex.EncodeToString(sum[:])

	certPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}))

	ecDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal ec private key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	}))

	return certPEM, keyPEM, sha256Hex, nil
}

func (cfg *UserConfig) FindCert(domain string) *ManagedCert {
	d := strings.ToLower(strings.TrimSpace(domain))
	for i := range cfg.Certs {
		if strings.ToLower(cfg.Certs[i].Domain) == d {
			return &cfg.Certs[i]
		}
	}
	return nil
}

func (cfg *UserConfig) AddCert(cert ManagedCert) {
	d := strings.ToLower(strings.TrimSpace(cert.Domain))
	cert.Domain = d
	for i := range cfg.Certs {
		if strings.ToLower(cfg.Certs[i].Domain) == d {
			cfg.Certs[i] = cert
			return
		}
	}
	cfg.Certs = append(cfg.Certs, cert)
}

func (cfg *UserConfig) RemoveCert(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	idx := -1
	for i := range cfg.Certs {
		if strings.ToLower(cfg.Certs[i].Domain) == d {
			idx = i
			break
		}
	}
	if idx >= 0 {
		cfg.Certs = append(cfg.Certs[:idx], cfg.Certs[idx+1:]...)
		return true
	}
	return false
}

func (cfg *UserConfig) GetCertDir() string {
	return filepath.Join(GetConfigDir(), "certs")
}

// AllocateRandomSkinPort attempts to find an available local TCP port for the Web camouflage server.
// It tries random ports in the range 10000-59999 first, falling back to ephemeral allocation.
func AllocateRandomSkinPort() int {
	for i := 0; i < 50; i++ {
		p, err := rand.Int(rand.Reader, big.NewInt(50000))
		if err != nil {
			break
		}
		port := int(p.Int64()) + 10000
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = ln.Close()
			return port
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		defer ln.Close()
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			return tcpAddr.Port
		}
	}
	return 9443
}

// GetSkinPort returns the configured Web camouflage skin port.
// If SkinPort is not configured, it returns 0.
func (cfg *UserConfig) GetSkinPort() int {
	if cfg == nil {
		return 0
	}
	return cfg.SkinPort
}

// EnsureSkinPort ensures that a valid local port is assigned to SkinPort.
// If SkinPort is already configured (> 0 and < 65536), it is returned.
// Otherwise, an available random port is allocated and stored in SkinPort.
func (cfg *UserConfig) EnsureSkinPort() int {
	if cfg == nil {
		return 0
	}
	if cfg.SkinPort > 0 && cfg.SkinPort < 65536 {
		return cfg.SkinPort
	}
	cfg.SkinPort = AllocateRandomSkinPort()
	return cfg.SkinPort
}

func (cfg *UserConfig) Normalize() {
	if cfg.Role != RoleServer {
		return
	}
	newModes := make([]ModeInfo, 0, len(PresetOrder))
	for _, target := range PresetOrder {
		found := false
		for _, m := range cfg.Presets {
			if m.Mode == target {
				newModes = append(newModes, m)
				found = true
				break
			}
		}
		if !found {
			if target == ModeHysteria2 {
				newModes = append(newModes, ModeInfo{Mode: target, Enabled: false, Port: 443})
			} else {
				newModes = append(newModes, ModeInfo{Mode: target, Enabled: false})
			}
		}
	}
	cfg.Presets = newModes
}

func randomHexString(length int) string {
	if length <= 0 {
		return ""
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(buf)[:length]
}

func normalizeStringSlice(values []string) ([]string, bool) {
	if values == nil {
		return nil, false
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	changed := false
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != value {
			changed = true
		}
		if trimmed == "" {
			changed = true
			continue
		}
		if _, ok := seen[trimmed]; ok {
			changed = true
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) != len(values) {
		changed = true
	}
	return out, changed
}

func normalizeDNSStrategyValue(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", strings.TrimSpace(value) != ""
	case "useip":
		return "UseIP", value != "UseIP"
	case "useipv4":
		return "UseIPv4", value != "UseIPv4"
	case "useipv6":
		return "UseIPv6", value != "UseIPv6"
	default:
		return value, false
	}
}

func (cfg *UserConfig) BackfillDefaults() []string {
	if cfg == nil {
		return nil
	}
	changes := []string{}

	if cfg.Role == "" {
		cfg.Role = RoleServer
		changes = append(changes, "set missing role=server")
	}
	changes = append(changes, cfg.migrateLegacyPath()...)
	if cfg.Role == RoleServer && cfg.Path.Token != "" {
		if cfg.Path.Listen == "" {
			cfg.Path.Listen = pathd.DefaultListenAddress
			changes = append(changes, "set missing pathd.listen="+pathd.DefaultListenAddress)
		}
		if cfg.Path.IdleSeconds <= 0 {
			cfg.Path.IdleSeconds = 20
			changes = append(changes, "set missing pathd.idle_seconds=20")
		}
	}
	if cfg.UUID == "" {
		cfg.UUID = randomHexString(32)
		changes = append(changes, "generated missing service UUID")
	}
	if cfg.Presets == nil {
		cfg.Presets = []ModeInfo{}
		changes = append(changes, "initialized presets")
	}
	if cfg.CustomOutbounds == nil {
		cfg.CustomOutbounds = []CustomOutbound{}
		changes = append(changes, "initialized custom_outbounds")
	}
	if cfg.Guests == nil {
		cfg.Guests = []GuestConfig{}
		changes = append(changes, "initialized guests")
	}
	if cfg.Subscriptions == nil {
		cfg.Subscriptions = []Subscription{}
		changes = append(changes, "initialized subscriptions")
	}
	if cfg.IPv6Rotations == nil {
		cfg.IPv6Rotations = map[string]IPv6Config{}
	}
	if cfg.Endpoints == nil {
		cfg.Endpoints = map[string]EndpointConfig{}
	}
	if len(cfg.Endpoints) == 0 {
		if strings.TrimSpace(cfg.AddressNode) != "" {
			cfg.Endpoints["default"] = EndpointConfig{
				Type: EndpointTypeStatic,
				Host: strings.TrimSpace(cfg.AddressNode),
			}
			changes = append(changes, "injected default endpoint from address_node")
		} else {
			cfg.Endpoints["default"] = EndpointConfig{
				Type:   EndpointTypeAuto,
				Family: "v4",
			}
			changes = append(changes, "injected default auto(v4) endpoint")
		}
	}
	if cfg.GateURL == "" && strings.TrimSpace(cfg.AddressSub) != "" {
		cfg.GateURL = strings.TrimSpace(cfg.AddressSub)
		changes = append(changes, "migrated address_sub to gate_url")
	}
	if cfg.Role == RoleGateway {
		if cfg.Gateway.Mode == "" {
			cfg.Gateway.Mode = "tproxy"
			changes = append(changes, "set missing gateway.mode=tproxy")
		}
		if cfg.Gateway.TProxyPort <= 0 {
			cfg.Gateway.TProxyPort = DefaultTProxyPort
			changes = append(changes, "set default gateway.tproxy_port")
		}
		if cfg.Gateway.State == "" {
			if cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled {
				cfg.Gateway.State = "proxy"
				changes = append(changes, "initialized gateway.state to proxy")
			} else {
				cfg.Gateway.State = "disabled"
				changes = append(changes, "initialized gateway.state to disabled")
			}
		} else {
			state := strings.ToLower(strings.TrimSpace(cfg.Gateway.State))
			switch state {
			case "disabled", "forward-only", "proxy":
				if state != cfg.Gateway.State {
					cfg.Gateway.State = state
					changes = append(changes, "normalized gateway.state")
				}
			default:
				cfg.Gateway.State = "disabled"
				changes = append(changes, "reset invalid gateway.state to disabled")
			}
		}
		effectiveLANs := cfg.Gateway.EffectiveLANInterfaces()
		if !reflect.DeepEqual(cfg.Gateway.LANInterfaces, effectiveLANs) {
			cfg.Gateway.LANInterfaces = effectiveLANs
			changes = append(changes, "synchronized gateway.lan_interfaces")
		}
		expectedLANInterface := strings.Join(effectiveLANs, ",")
		if cfg.Gateway.LANInterface != expectedLANInterface {
			cfg.Gateway.LANInterface = expectedLANInterface
			changes = append(changes, "synchronized gateway.lan_interface")
		}
		effectiveIsolated := cfg.Gateway.EffectiveIsolatedInterfaces()
		if !reflect.DeepEqual(cfg.Gateway.IsolatedInterfaces, effectiveIsolated) {
			cfg.Gateway.IsolatedInterfaces = effectiveIsolated
			changes = append(changes, "synchronized gateway.isolated_interfaces")
		}
		if cfg.Gateway.WANInterface != strings.TrimSpace(cfg.Gateway.WANInterface) {
			cfg.Gateway.WANInterface = strings.TrimSpace(cfg.Gateway.WANInterface)
			changes = append(changes, "normalized gateway.wan_interface")
		}
		if len(cfg.Gateway.Rules) > 0 {
			var normRules []GatewayRule
			changedRules := false
			for _, r := range cfg.Gateway.Rules {
				normRule, err := ValidateGatewayRule(r)
				if err != nil {
					changedRules = true
					continue
				}
				if normRule != r {
					changedRules = true
				}
				normRules = append(normRules, normRule)
			}
			if changedRules || len(normRules) != len(cfg.Gateway.Rules) {
				cfg.Gateway.Rules = normRules
				changes = append(changes, "normalized gateway.rules")
			}
		}
	}
	if cfg.Gateway.BypassDNS != nil {
		normalized, changed := normalizeStringSlice(cfg.Gateway.BypassDNS)
		if changed {
			cfg.Gateway.BypassDNS = normalized
			changes = append(changes, "normalized gateway.bypass_dns")
		}
	}
	if cfg.Gateway.BypassCountries != nil {
		normalized, changed := normalizeStringSlice(cfg.Gateway.BypassCountries)
		if changed {
			cfg.Gateway.BypassCountries = normalized
			changes = append(changes, "normalized gateway.bypass_countries")
		}
	}
	if cfg.Gateway.DNSStrategy != "" {
		if norm, ok := NormalizeDNSQueryStrategy(cfg.Gateway.DNSStrategy); ok {
			if norm != cfg.Gateway.DNSStrategy {
				cfg.Gateway.DNSStrategy = norm
				changes = append(changes, "normalized gateway.dns_strategy")
			}
		} else {
			cfg.Gateway.DNSStrategy = ""
			changes = append(changes, "reset invalid gateway.dns_strategy")
		}
	}
	if cfg.Gateway.DNSServers != nil {
		normalized, changed := normalizeStringSlice(cfg.Gateway.DNSServers)
		if changed {
			cfg.Gateway.DNSServers = normalized
			changes = append(changes, "normalized gateway.dns_servers")
		}
	}
	if cfg.Gateway.DNSListen != "" {
		if _, _, normListen, err := ParseDNSListen(cfg.Gateway.DNSListen); err == nil {
			if normListen != cfg.Gateway.DNSListen {
				cfg.Gateway.DNSListen = normListen
				changes = append(changes, "normalized gateway.dns_listen")
			}
		}
	}
	if cfg.Gateway.DNSRecords != nil {
		normRecords := make(map[string][]string, len(cfg.Gateway.DNSRecords))
		changed := false
		for dom, ips := range cfg.Gateway.DNSRecords {
			normDom, domErr := NormalizeDNSRecordDomain(dom)
			normIPs, ipErr := ValidateDNSRecordIPs(ips)
			if domErr != nil || ipErr != nil {
				changed = true
				continue
			}
			if normDom != dom || !reflect.DeepEqual(normIPs, ips) {
				changed = true
			}
			normRecords[normDom] = normIPs
		}
		if changed {
			cfg.Gateway.DNSRecords = normRecords
			changes = append(changes, "normalized gateway.dns_records")
		}
	}
	if strings.TrimSpace(cfg.GuestSubBind) == "" {
		cfg.GuestSubBind = "127.0.0.1"
		changes = append(changes, "set missing guest_sub_bind=127.0.0.1")
	}

	legacyAdminIdx := -1
	for i := range cfg.Subscriptions {
		if cfg.Subscriptions[i].Alias == "admin" {
			legacyAdminIdx = i
			break
		}
	}
	if legacyAdminIdx >= 0 {
		legacyAdmin := cfg.Subscriptions[legacyAdminIdx]
		if cfg.AdminSub.Token == "" {
			cfg.AdminSub.Token = legacyAdmin.Token
			changes = append(changes, "migrated legacy admin subscription token")
		}
		if cfg.AdminSub.Address == "" {
			cfg.AdminSub.Address = legacyAdmin.Address
			changes = append(changes, "migrated legacy admin subscription address")
		}
		if cfg.AdminSub.TargetType == "direct" && legacyAdmin.TargetType != "" {
			cfg.AdminSub.TargetType = legacyAdmin.TargetType
			cfg.AdminSub.TargetAlias = legacyAdmin.TargetAlias
			changes = append(changes, "migrated legacy admin subscription target")
		}
	}
	if cfg.AdminSub.Port == 0 && cfg.SubPort > 0 {
		cfg.AdminSub.Port = cfg.SubPort
		changes = append(changes, "migrated legacy sub_port to admin_sub.port")
	}
	// In the new schema an endpoint exists when it has a token; systemd owns
	// whether it serves requests. A deliberately disabled legacy endpoint is
	// therefore removed rather than accidentally exposed after migration.
	if cfg.AdminSub.legacyEnabled != nil && !*cfg.AdminSub.legacyEnabled {
		cfg.AdminSub = AdminSubConfig{}
		changes = append(changes, "removed disabled legacy admin subscription")
	}
	if cfg.AdminSub.Token != "" && cfg.AdminSub.TargetType == "" {
		cfg.AdminSub.TargetType = "direct"
		changes = append(changes, "set missing admin_sub.target_type=direct")
	}
	if cfg.AdminSub.Token != "" && cfg.AdminSub.Port == 0 && cfg.SubPort > 0 {
		cfg.AdminSub.Port = cfg.SubPort
	}
	legacyRotate := cfg.AdminSub.legacyMode == "ipv6-rotate" ||
		(cfg.AdminSub.legacyIPv6Rotate.legacyEnabled != nil && *cfg.AdminSub.legacyIPv6Rotate.legacyEnabled) ||
		(cfg.IPv6Pool.legacyEnabled != nil && *cfg.IPv6Pool.legacyEnabled)
	if legacyRotate && cfg.AdminSub.Token != "" && cfg.AdminSub.IPv6Rotation == "" {
		rotation := cfg.AdminSub.legacyIPv6Rotate
		if rotation.Subnet == "" {
			rotation.Subnet = cfg.IPv6Pool.Subnet
		}
		if rotation.Interface == "" {
			rotation.Interface = cfg.IPv6Pool.Interface
		}
		if rotation.MaxAddresses == 0 {
			rotation.MaxAddresses = cfg.IPv6Pool.MaxAddresses
		}
		if !rotation.EnableNDP {
			rotation.EnableNDP = cfg.IPv6Pool.EnableNDP
		}
		cfg.IPv6Rotation = IPv6Config{Subnet: rotation.Subnet, Interface: rotation.Interface, MaxAddresses: rotation.MaxAddresses, EnableNDP: rotation.EnableNDP}
		cfg.IPv6Rotations["default"] = cfg.IPv6Rotation
		cfg.AdminSub.IPv6Rotation = "default"
		changes = append(changes, "migrated legacy IPv6 rotation to ipv6_rotation")
	}
	if cfg.IPv6Rotation.Subnet == "" && cfg.IPv6Rotations != nil && cfg.IPv6Rotations["default"].Subnet != "" {
		cfg.IPv6Rotation = cfg.IPv6Rotations["default"]
	}
	if cfg.IPv6Rotation.Subnet != "" {
		if cfg.IPv6Rotations == nil {
			cfg.IPv6Rotations = make(map[string]IPv6Config)
		}
		cfg.IPv6Rotations["default"] = cfg.IPv6Rotation
	}
	if cfg.SubscriptionInstances == nil {
		cfg.SubscriptionInstances = make(map[string]AdminSubConfig)
	}
	if cfg.AdminSub.Token != "" {
		cfg.SubscriptionInstances["default"] = cfg.AdminSub
	} else if defaultSub, ok := cfg.SubscriptionInstances["default"]; ok && defaultSub.Token != "" {
		cfg.AdminSub = defaultSub
	}
	if cfg.AdminSub.Port > 0 && cfg.SubPort != cfg.AdminSub.Port {
		cfg.SubPort = cfg.AdminSub.Port
		changes = append(changes, "synced legacy sub_port from admin_sub.port")
	}
	if cfg.IPv6Pool.Subnet != "" || cfg.IPv6Pool.Interface != "" || cfg.IPv6Pool.MaxAddresses != 0 || cfg.IPv6Pool.EnableNDP {
		cfg.IPv6Pool = IPv6Config{}
		changes = append(changes, "removed migrated legacy ipv6_pool")
	}
	if legacyAdminIdx >= 0 {
		newSubs := make([]Subscription, 0, len(cfg.Subscriptions)-1)
		for _, sub := range cfg.Subscriptions {
			if sub.Alias == "admin" {
				continue
			}
			newSubs = append(newSubs, sub)
		}
		cfg.Subscriptions = newSubs
		changes = append(changes, "removed managed admin alias from legacy subscriptions")
	}

	for i := range cfg.CustomOutbounds {
		co := &cfg.CustomOutbounds[i]
		if co.UserUUID == "" {
			co.UserUUID = randomHexString(32)
			changes = append(changes, "generated missing user_uuid for outbound "+co.Alias)
		}
		if co.Config == nil {
			co.Config = map[string]interface{}{}
			changes = append(changes, "initialized config for outbound "+co.Alias)
		}
		if normalizedStrategy, changed := normalizeDNSStrategyValue(co.DNSStrategy); changed {
			co.DNSStrategy = normalizedStrategy
			changes = append(changes, "normalized dns_strategy for outbound "+co.Alias)
		}
		if normalizedServers, changed := normalizeStringSlice(co.DNSServers); changed {
			co.DNSServers = normalizedServers
			changes = append(changes, "normalized dns_servers for outbound "+co.Alias)
		}
	}

	for i := range cfg.Guests {
		guest := &cfg.Guests[i]
		cleanAlias := strings.ToLower(strings.TrimSpace(guest.Alias))
		if cleanAlias != "" && cleanAlias != guest.Alias {
			changes = append(changes, fmt.Sprintf("normalized guest alias %q to lowercase %q", guest.Alias, cleanAlias))
			guest.Alias = cleanAlias
		}
		if guest.UUID == "" {
			guest.UUID = randomHexString(32)
			changes = append(changes, "generated missing UUID for guest "+guest.Alias)
		}
		if guest.UsedBytes < 0 && guest.UsedBytes != -1 {
			guest.UsedBytes = 0
			changes = append(changes, "normalized negative used_bytes for guest "+guest.Alias)
		}
		switch guest.DisabledReason {
		case GuestDisabledQuotaZero, GuestDisabledQuotaReached, GuestDisabledManual, GuestDisabledNone:
		default:
			guest.DisabledReason = GuestDisabledNone
			changes = append(changes, "cleared invalid disabled_reason for guest "+guest.Alias)
		}
		if guest.Enabled && guest.DisabledReason != GuestDisabledNone {
			guest.DisabledReason = GuestDisabledNone
			changes = append(changes, "cleared stale disabled_reason for enabled guest "+guest.Alias)
		}
		if !guest.Enabled && guest.DisabledReason == GuestDisabledNone {
			if guest.QuotaGB == 0 {
				guest.DisabledReason = GuestDisabledQuotaZero
				changes = append(changes, "backfilled disabled_reason=quota_zero for guest "+guest.Alias)
			} else {
				guest.DisabledReason = GuestDisabledManual
				changes = append(changes, "backfilled disabled_reason=manual for guest "+guest.Alias)
			}
		}
		if guest.ResetDay < 1 || guest.ResetDay > 31 {
			guest.ResetDay = 1
			changes = append(changes, "normalized invalid reset_day for guest "+guest.Alias)
		}
	}

	for i := range cfg.Presets {
		m := &cfg.Presets[i]
		if m.Skin != "" && !IsValidSkin(m.Skin) {
			m.Skin = ""
			m.SkinDomain = ""
			changes = append(changes, "cleared invalid skin for preset "+string(m.Mode))
		}
		if m.Mode == ModeHysteria2 && m.Skin != "" && m.SkinDomain == "" {
			if m.SNI != "" {
				m.SkinDomain = m.SNI
			} else {
				m.SkinDomain = "www.bing.com"
			}
		}
		if m.Skin != "" && m.SkinDomain == "" {
			// If skin is set but domain is missing, skin cannot be active
			m.Skin = ""
			changes = append(changes, "cleared skin without domain for preset "+string(m.Mode))
		}
		if m.Skin != "" && m.Mode != ModeVLESSVision && m.Mode != ModeVLESSReality && m.Mode != ModeHysteria2 {
			m.Skin = ""
			m.SkinDomain = ""
			changes = append(changes, "cleared unsupported skin for preset "+string(m.Mode))
		}
		if m.Skin != "" {
			if cfg.SkinPort <= 0 || cfg.SkinPort >= 65536 {
				customPort := 0
				if strings.HasPrefix(m.Dest, "127.0.0.1:") {
					if p, err := strconv.Atoi(strings.TrimPrefix(m.Dest, "127.0.0.1:")); err == nil && p != 8443 && p != 9443 {
						customPort = p
					}
				}
				if customPort > 0 {
					cfg.SkinPort = customPort
					changes = append(changes, fmt.Sprintf("adopted existing skin dest port %d as skin_port", cfg.SkinPort))
				} else {
					cfg.EnsureSkinPort()
					changes = append(changes, fmt.Sprintf("allocated random skin_port %d", cfg.SkinPort))
				}
			}
		}
		if m.Mode == ModeVLESSVision || m.Mode == ModeVLESSReality {
			if m.Fingerprint == "" || !IsAllowedRealityFingerprint(m.Fingerprint) {
				fp, err := GetRandomRealityFingerprint()
				if err != nil {
					fp = "chrome"
				}
				m.Fingerprint = fp
				changes = append(changes, "backfilled reality fingerprint for preset "+string(m.Mode))
			}
			if m.SNI != "" {
				normSNI := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m.SNI)), ".")
				if normSNI != m.SNI {
					m.SNI = normSNI
					changes = append(changes, "normalized SNI for preset "+string(m.Mode))
				}
				if m.Dest == "" {
					if m.Skin != "" {
						skinPort := cfg.EnsureSkinPort()
						m.Dest = fmt.Sprintf("127.0.0.1:%d", skinPort)
						changes = append(changes, fmt.Sprintf("set skin dest to 127.0.0.1:%d for preset %s", skinPort, m.Mode))
					} else {
						m.Dest = net.JoinHostPort(normSNI, "443")
						changes = append(changes, "backfilled default dest for preset "+string(m.Mode))
					}
				} else {
					// If Dest is local fallback for skin, preserve it
					isLocalDest := strings.HasPrefix(m.Dest, "127.0.0.1:") || strings.HasPrefix(m.Dest, "localhost:")
					if m.Skin != "" && isLocalDest {
						skinDest := fmt.Sprintf("127.0.0.1:%d", cfg.SkinPort)
						if m.Dest != skinDest {
							m.Dest = skinDest
							changes = append(changes, fmt.Sprintf("migrated skin dest port to %d for preset %s", cfg.SkinPort, m.Mode))
						}
					} else if m.Skin != "" {
						skinDest := fmt.Sprintf("127.0.0.1:%d", cfg.SkinPort)
						m.Dest = skinDest
						changes = append(changes, fmt.Sprintf("set skin dest to %s for preset %s", skinDest, m.Mode))
					} else {
						destHost, _, normDest, err := NormalizeRealityTarget(m.Dest)
						if err != nil || destHost != normSNI {
							m.Dest = net.JoinHostPort(normSNI, "443")
							changes = append(changes, "aligned mismatched dest with SNI for preset "+string(m.Mode))
						} else if normDest != m.Dest {
							m.Dest = normDest
							changes = append(changes, "normalized dest for preset "+string(m.Mode))
						}
					}
				}
			}
		}
		if m.Mode == ModeHysteria2 {
			changes = append(changes, cfg.backfillHysteria2(m)...)
		}
	}

	beforeModes := len(cfg.Presets)
	cfg.Normalize()
	if cfg.Role == RoleServer && len(cfg.Presets) != beforeModes {
		changes = append(changes, "completed presets to current preset set")
	}
	for i := range cfg.Presets {
		if cfg.Presets[i].Mode == ModeHysteria2 {
			changes = append(changes, cfg.backfillHysteria2(&cfg.Presets[i])...)
		}
	}

	return changes
}

func (cfg *UserConfig) backfillHysteria2(m *ModeInfo) []string {
	var changes []string
	if m.Port <= 0 {
		if os.Geteuid() != 0 {
			m.Port = 10443
		} else {
			m.Port = 443
		}
		changes = append(changes, fmt.Sprintf("backfilled port %d for preset %s", m.Port, m.Mode))
	}
	if strings.TrimSpace(m.SNI) == "" {
		var visionSNI string
		for _, p := range cfg.Presets {
			if p.Mode == ModeVLESSVision && strings.TrimSpace(p.SNI) != "" {
				visionSNI = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p.SNI)), ".")
				break
			}
		}
		if visionSNI != "" {
			m.SNI = visionSNI
		} else {
			m.SNI = "www.bing.com"
		}
		changes = append(changes, "backfilled default SNI for preset "+string(m.Mode))
	} else {
		normSNI := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m.SNI)), ".")
		if normSNI == "" {
			normSNI = "www.bing.com"
		}
		if normSNI != m.SNI {
			m.SNI = normSNI
			changes = append(changes, "normalized SNI for preset "+string(m.Mode))
		}
	}
	if m.Skin != "" {
		cfg.EnsureSkinPort()
		skinDest := fmt.Sprintf("127.0.0.1:%d", cfg.SkinPort)
		if m.Dest != skinDest {
			m.Dest = skinDest
			changes = append(changes, fmt.Sprintf("set skin dest to 127.0.0.1:%d for preset %s", cfg.SkinPort, m.Mode))
		}
	} else if m.Dest == "" {
		m.Dest = net.JoinHostPort(m.SNI, "443")
		changes = append(changes, "backfilled default dest for preset "+string(m.Mode))
	}
	if m.Settings.Password == "" {
		m.Settings.Password = randomHexString(16)
		changes = append(changes, "backfilled password for preset "+string(m.Mode))
	}
	if m.Settings.CertPEM == "" || m.Settings.PrivateKey == "" || m.Settings.PublicKey == "" {
		certPEM, keyPEM, sha256Hex, err := GenerateSelfSignedCert(m.SNI)
		if err == nil {
			m.Settings.CertPEM = certPEM
			m.Settings.PrivateKey = keyPEM
			m.Settings.PublicKey = sha256Hex
			changes = append(changes, "generated self-signed cert for preset "+string(m.Mode))
		}
	}
	return changes
}

// migrateLegacyPath moves the former global, enabled Gateway PathLink
// credentials onto the relay selected by that configuration. Server Pathd
// configuration stays top-level because it describes the local daemon.
// The migration is idempotent and is persisted on the next normal config save.
func (cfg *UserConfig) migrateLegacyPath() []string {
	if cfg == nil || !cfg.legacyPathSeen {
		return nil
	}
	changes := []string{}
	legacyEnabled := cfg.legacyPathEnabled != nil && *cfg.legacyPathEnabled
	if cfg.Role == RoleServer {
		cfg.Path.LegacyEnabled = false
		cfg.legacyPathSeen = false
		return append(changes, "migrated legacy Server path configuration")
	}
	if cfg.Role != RoleGateway {
		return nil
	}
	if legacyEnabled && cfg.Path.Token != "" && cfg.Gateway.RelayAlias != "" {
		for i := range cfg.CustomOutbounds {
			outbound := &cfg.CustomOutbounds[i]
			if outbound.Alias != cfg.Gateway.RelayAlias {
				continue
			}
			if outbound.Path == nil || outbound.Path.Token == "" {
				endpoint := cfg.Path
				endpoint.LegacyEnabled = false
				if endpoint.Listen == "" {
					endpoint.Listen = pathd.DefaultListenAddress
				}
				if endpoint.IdleSeconds <= 0 {
					endpoint.IdleSeconds = 20
				}
				outbound.Path = &endpoint
				changes = append(changes, "migrated legacy enabled path credentials to relay "+outbound.Alias)
			} else {
				changes = append(changes, "kept existing relay path credentials for "+outbound.Alias)
			}
			cfg.Path = PathConfig{}
			cfg.legacyPathSeen = false
			return changes
		}
	}
	if !legacyEnabled {
		cfg.Path = PathConfig{}
		cfg.legacyPathSeen = false
		return append(changes, "removed disabled legacy gateway path configuration")
	}
	// Keep an enabled legacy value in memory until its selected relay exists;
	// LegacyEnabled causes it to remain durable until a later config operation
	// supplies that relay, avoiding silent credential loss during an upgrade.
	return changes
}

func GetHomeDir() string {
	if os.Geteuid() == 0 {
		return "/root"
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/root"
	}
	return home
}

func GetConfigDir() string {
	// System services must never inherit a caller-controlled configuration
	// directory. In particular, sudo preserves enough environment state on some
	// systems to otherwise make a root service consume an unprivileged tree.
	if os.Geteuid() == 0 {
		const rootConfigDir = "/root/.config/xray-proxya"
		_ = os.MkdirAll(rootConfigDir, 0700)
		return rootConfigDir
	}
	if envDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR"); envDir != "" {
		os.MkdirAll(envDir, 0700)
		return envDir
	}
	dir := filepath.Join(GetHomeDir(), ".config", "xray-proxya")
	os.MkdirAll(dir, 0700)
	return dir
}

func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.json")
}

func GetConfigPathEx(staging bool) string {
	path := GetConfigPath()
	if staging {
		path += ".staging"
	}
	return path
}

func GetGatewayConfPath() string {
	return filepath.Join(GetConfigDir(), "gateway.conf")
}

func GatewayConfExists() bool {
	info, err := os.Stat(GetGatewayConfPath())
	return err == nil && !info.IsDir()
}

func GetGatewayActiveConfPath() string {
	return filepath.Join(GetConfigDir(), "gateway.active.conf")
}

func GatewayActiveConfExists() bool {
	info, err := os.Stat(GetGatewayActiveConfPath())
	return err == nil && !info.IsDir()
}

func CommitGatewayConf() error {
	src := GetGatewayConfPath()
	dst := GetGatewayActiveConfPath()
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, data, 0600)
}

// writeFileAtomic writes data to a temporary sibling file and renames it over
// path, so readers never observe a partially written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// GatewayConfigGenerator is an optional hook (set by gatewayconf) that renders
// the gateway.conf text for a UserConfig. It is used to migrate v0.5.x configs.
var GatewayConfigGenerator func(cfg *UserConfig) string

// migrateLegacyGateway upgrades a v0.5.x config, whose Gateway settings lived
// inline in config.json, to the declarative gateway.conf layout. Only upgrades
// from v0.5.x are supported: gateway.conf did not exist in any release before
// this layout. It is a no-op once either gateway file exists, so it runs at
// most once, and the inline copy disappears on the next config.json save.
func migrateLegacyGateway(cfg *UserConfig) error {
	if cfg == nil || !cfg.legacyGateway || cfg.Role != RoleGateway || GatewayConfigGenerator == nil {
		return nil
	}
	if GatewayConfExists() || GatewayActiveConfExists() {
		return nil
	}
	content := []byte(GatewayConfigGenerator(cfg))
	if err := os.MkdirAll(GetConfigDir(), 0700); err != nil {
		return fmt.Errorf("migrate legacy gateway config: %w", err)
	}
	// Active first: a crash in between leaves a valid active file and the
	// staging file is simply recreated from it on the next load.
	if err := writeFileAtomic(GetGatewayActiveConfPath(), content, 0600); err != nil {
		return fmt.Errorf("migrate legacy gateway config: %w", err)
	}
	if err := writeFileAtomic(GetGatewayConfPath(), content, 0600); err != nil {
		return fmt.Errorf("migrate legacy gateway config: %w", err)
	}
	return nil
}

func RollbackGatewayConf() error {
	active := GetGatewayActiveConfPath()
	stg := GetGatewayConfPath()
	if _, err := os.Stat(active); os.IsNotExist(err) {
		if err := os.Remove(stg); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := os.ReadFile(active)
	if err != nil {
		return err
	}
	return writeFileAtomic(stg, data, 0600)
}

// GatewayTunDisabledPath is a runtime-only marker. It lets a gateway be
// brought down without mutating the active, staged configuration; the next
// gateway up removes it before restarting Xray with its TUN inbound enabled.
func GatewayTunDisabledPath() string {
	return filepath.Join(GetConfigDir(), "gateway.tun.disabled")
}

func GatewayTunDisabled() bool {
	_, err := os.Stat(GatewayTunDisabledPath())
	return err == nil
}

func SetGatewayTunDisabled(disabled bool) error {
	path := GatewayTunDisabledPath()
	if disabled {
		return os.WriteFile(path, []byte("disabled\n"), 0600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// PathTunDisabledPath records that the optional PathLink TUN could not be
// created for the current service runtime.  It is deliberately separate from
// the desired configuration: a PathLink failure must not prevent the main
// transparent gateway from coming up.
func PathTunDisabledPath() string {
	return filepath.Join(GetConfigDir(), "gateway.path-tun.disabled")
}

func PathTunDisabled() bool {
	_, err := os.Stat(PathTunDisabledPath())
	return err == nil
}

func SetPathTunDisabled(disabled bool) error {
	path := PathTunDisabledPath()
	if disabled {
		return os.WriteFile(path, []byte("disabled\n"), 0600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func GatewayConfStaged() bool {
	stgPath := GetGatewayConfPath()
	actPath := GetGatewayActiveConfPath()
	stgBytes, err1 := os.ReadFile(stgPath)
	if err1 != nil {
		return false
	}
	actBytes, err2 := os.ReadFile(actPath)
	if err2 != nil {
		return len(stgBytes) > 0
	}
	return !bytes.Equal(stgBytes, actBytes)
}

func StagingExists() bool {
	if _, err := os.Stat(GetConfigPathEx(true)); err == nil {
		return true
	}
	return GatewayConfStaged()
}

func LoadConfig() (*UserConfig, error) {
	// If a staging config exists, we should generally be aware of it to avoid split-brain.
	// However, for 'run' and 'status', we want the active one.
	cfg, err := LoadConfigEx(false)
	if err == nil {
		cfg.Normalize()
	}
	return cfg, err
}

// GatewayConfigLoader is an optional hook (set by gatewayconf) that compiles GatewayConfig
// from gateway.conf (if staging) or gateway.active.conf (if active).
var GatewayConfigLoader func(staging bool, userCfg *UserConfig) (*GatewayConfig, error)

// GatewayConfigSaver is an optional hook (set by gatewayconf) that saves GatewayConfig
// to gateway.conf (if staging) or gateway.active.conf (if active).
var GatewayConfigSaver func(gw *GatewayConfig, staging bool) error

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func defaultGatewayConfLoader(staging bool, userCfg *UserConfig) (*GatewayConfig, error) {
	// Minimal fallback used only when the gatewayconf package is not linked in;
	// the full parser lives there (config cannot import it without a cycle).
	var confPath string
	if staging {
		confPath = GetGatewayConfPath()
		if !GatewayConfExists() && GatewayActiveConfExists() {
			confPath = GetGatewayActiveConfPath()
		}
	} else {
		if !GatewayActiveConfExists() {
			return &GatewayConfig{Mode: "tproxy"}, nil
		}
		confPath = GetGatewayActiveConfPath()
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read gateway configuration: %w", err)
	}
	gw := &GatewayConfig{Mode: "tproxy"}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "set") {
			k := strings.ToLower(fields[1])
			idx := strings.Index(trimmed, fields[1])
			v := strings.TrimSpace(trimmed[idx+len(fields[1]):])
			switch k {
			case "state":
				gw.State = strings.ToLower(v)
			case "mode":
				gw.Mode = strings.ToLower(v)
				if gw.Mode == "tun" {
					gw.TUNEnabled = true
				}
			case "tun", "tun_enabled":
				vLow := strings.ToLower(v)
				gw.TUNEnabled = (vLow == "true" || vLow == "1" || vLow == "yes" || vLow == "on")
			case "nat":
				vLow := strings.ToLower(v)
				gw.NATDisabled = !(vLow == "true" || vLow == "1" || vLow == "yes" || vLow == "on")
			case "wan":
				gw.WANInterface = v
			case "tproxy_port", "tproxy":
				if p, err := strconv.Atoi(v); err == nil {
					gw.TProxyPort = p
				}
			case "relay":
				gw.RelayAlias = v
			case "local", "local_enabled":
				vLow := strings.ToLower(v)
				gw.LocalEnabled = (vLow == "true" || vLow == "1" || vLow == "yes" || vLow == "on")
			case "lan", "lan_enabled":
				vLow := strings.ToLower(v)
				gw.LANEnabled = (vLow == "true" || vLow == "1" || vLow == "yes" || vLow == "on")
			case "lan_interfaces", "lan_interface":
				parts := strings.Split(v, ",")
				for _, p := range parts {
					pTrim := strings.TrimSpace(p)
					if pTrim != "" {
						gw.LANInterfaces = append(gw.LANInterfaces, pTrim)
					}
				}
				if len(gw.LANInterfaces) > 0 {
					gw.LANInterface = gw.LANInterfaces[0]
				}
			case "bypass_countries":
				gw.BypassCountries = splitCSV(v)
			case "bypass_dns":
				gw.BypassDNS = splitCSV(v)
			case "dns_listen":
				gw.DNSListen = v
			case "dns_strategy":
				gw.DNSStrategy = v
			case "dns_servers":
				for _, s := range strings.Split(v, ",") {
					sTrim := strings.TrimSpace(s)
					if sTrim != "" {
						gw.DNSServers = append(gw.DNSServers, sTrim)
					}
				}
			}
		}
	}
	return gw, nil
}

func LoadConfigEx(staging bool) (*UserConfig, error) {
	path := GetConfigPathEx(staging)
	if staging {
		// If requesting staging but config.staging.json doesn't exist, fallback to official config.json for base settings
		if _, err := os.Stat(path); os.IsNotExist(err) {
			path = GetConfigPathEx(false)
		}
	}
	cfg, err := LoadConfigFile(path, true)
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.Role == RoleGateway {
		if err := migrateLegacyGateway(cfg); err != nil {
			return nil, err
		}
		loader := GatewayConfigLoader
		if loader == nil {
			loader = defaultGatewayConfLoader
		}
		if gw, gwErr := loader(staging, cfg); gwErr != nil {
			return nil, gwErr
		} else if gw != nil {
			cfg.Gateway = *gw
		}
	}
	return cfg, nil
}

func LoadConfigFile(path string, backfill bool) (*UserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg *UserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if backfill {
		cfg.BackfillDefaults()
	}
	return cfg, nil
}

func (cfg *UserConfig) Save() error {
	// Safety check: if we are saving to official but a staging file exists,
	// we might be overwriting a pending change with stale data.
	// For background tasks like quota, we should ideally merge, but for now
	// we'll just ensure we save to the right place.
	return cfg.SaveEx(false)
}

// saveJSON atomically writes only the JSON config, leaving gateway.conf alone.
func (cfg *UserConfig) saveJSON(staging bool) error {
	path := GetConfigPathEx(staging)
	os.MkdirAll(filepath.Dir(path), 0700)
	cfg.BackfillDefaults()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0600)
}

func (cfg *UserConfig) SaveEx(staging bool) error {
	if err := cfg.saveJSON(staging); err != nil {
		return err
	}
	if GatewayConfigSaver != nil && (cfg.Role == RoleGateway || cfg.Gateway.Mode != "") {
		if err := GatewayConfigSaver(&cfg.Gateway, staging); err != nil {
			return err
		}
	}
	return nil
}

// CommitStaging promotes the staged JSON and gateway.conf to active. The two
// files are committed as a unit: if the JSON commit fails, the previous active
// gateway.conf is restored so the pair never ends up mismatched.
func CommitStaging() error {
	prevGW, prevErr := os.ReadFile(GetGatewayActiveConfPath())
	if err := CommitGatewayConf(); err != nil {
		return fmt.Errorf("commit gateway configuration: %w", err)
	}
	if err := commitStagingJSON(); err != nil {
		if prevErr == nil {
			_ = writeFileAtomic(GetGatewayActiveConfPath(), prevGW, 0600)
		} else if os.IsNotExist(prevErr) {
			_ = os.Remove(GetGatewayActiveConfPath())
		}
		return err
	}
	return nil
}

func commitStagingJSON() error {
	src := GetConfigPath() + ".staging"
	dst := GetConfigPath()
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	}

	stagingCfg, err := LoadConfigFile(src, false)
	if err != nil {
		return err
	}

	// Try to load the active config to merge background runtime updates
	if activeCfg, err := LoadConfigFile(dst, false); err == nil {
		// Merge background-mutable fields of guests
		for i := range stagingCfg.Guests {
			sg := &stagingCfg.Guests[i]
			// Find corresponding guest in active config
			var activeG *GuestConfig
			for j := range activeCfg.Guests {
				if activeCfg.Guests[j].Alias == sg.Alias {
					activeG = &activeCfg.Guests[j]
					break
				}
			}
			if activeG == nil {
				if sg.UsedBytes < 0 {
					sg.UsedBytes = 0
				}
				continue
			}

			// 1. Merge UsedBytes and LastResetYM (unless explicitly reset to -1 by admin)
			if sg.UsedBytes < 0 {
				sg.UsedBytes = 0
				sg.AlertedYM = ""
				sg.AlertedTriggers = nil
			} else {
				sg.UsedBytes = activeG.UsedBytes
				sg.LastResetYM = activeG.LastResetYM
				if sg.NotifyWebhook == activeG.NotifyWebhook {
					sg.AlertedYM = activeG.AlertedYM
					sg.AlertedTriggers = activeG.AlertedTriggers
				}
			}

			// 2. Merge Enabled and DisabledReason (unless explicitly changed by admin)
			adminChangedEnablement := false
			if sg.UsedBytes == 0 && activeG.UsedBytes > 0 && activeG.DisabledReason == GuestDisabledQuotaReached {
				// Admin reset the usage via -1 which we just set to 0 above
				adminChangedEnablement = true
			} else if sg.QuotaGB != activeG.QuotaGB {
				adminChangedEnablement = true
			} else if sg.DisabledReason == GuestDisabledManual && activeG.DisabledReason != GuestDisabledManual {
				// Admin manually paused
				adminChangedEnablement = true
			} else if sg.DisabledReason == GuestDisabledNone && activeG.DisabledReason == GuestDisabledManual {
				// Admin manually resumed
				adminChangedEnablement = true
			}

			if !adminChangedEnablement {
				sg.Enabled = activeG.Enabled
				sg.DisabledReason = activeG.DisabledReason
			}
		}
	}

	// Normalize any remaining -1 values before saving to config.json
	for i := range stagingCfg.Guests {
		if stagingCfg.Guests[i].UsedBytes < 0 {
			stagingCfg.Guests[i].UsedBytes = 0
		}
	}

	// Save the merged configuration directly to active config path. Only the
	// JSON is written: stagingCfg was loaded without its gateway section, and
	// gateway.conf has already been committed above.
	if err := stagingCfg.saveJSON(false); err != nil {
		return err
	}

	return os.Remove(src)
}

// ClearStaging discards staged changes. Each step is idempotent, so a failure
// part-way can simply be retried.
func ClearStaging() error {
	if err := RollbackGatewayConf(); err != nil {
		return fmt.Errorf("rollback gateway configuration: %w", err)
	}
	path := GetConfigPath() + ".staging"
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}
