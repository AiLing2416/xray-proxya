package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	// DefaultWarpAlias is the standard relay alias name for the Cloudflare WARP node.
	DefaultWarpAlias = "CF_WARP"

	// DefaultWarpEndpoint is the default WireGuard peer endpoint for Cloudflare WARP.
	DefaultWarpEndpoint = "engage.cloudflareclient.com:2408"

	// DefaultCloudflarePeerKey is the standard Cloudflare WireGuard public key.
	DefaultCloudflarePeerKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

	defaultRegURL = "https://api.cloudflareclient.com/v0a2158/reg"
)

var currentRegURL = defaultRegURL

// SetRegistrationURLForTest overrides the registration API URL during automated tests.
func SetRegistrationURLForTest(u string) func() {
	prev := currentRegURL
	currentRegURL = u
	return func() {
		currentRegURL = prev
	}
}

// AccountInfo holds the registration results and WireGuard parameters for Cloudflare WARP.
type AccountInfo struct {
	ID         string    `json:"id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	IPv4       string    `json:"ipv4"`
	IPv6       string    `json:"ipv6"`
	ClientID   string    `json:"client_id,omitempty"`
	Reserved   []int     `json:"reserved,omitempty"`
	Endpoint   string    `json:"endpoint"`
	PeerKey    string    `json:"peer_key"`
	CreatedAt  time.Time `json:"created_at"`
}

// GenerateKeypair generates a WireGuard Curve25519 keypair encoded in standard Base64.
func GenerateKeypair() (privBase64, pubBase64 string, err error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Standard WireGuard Curve25519 clamp
	privKey[0] &= 248
	privKey[31] = (privKey[31] & 127) | 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	return base64.StdEncoding.EncodeToString(privKey[:]), base64.StdEncoding.EncodeToString(pubKey[:]), nil
}

func genInstallID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// RegisterFreeAccount registers a new free Cloudflare WARP account via Cloudflare client API.
func RegisterFreeAccount(ctx context.Context, customEndpoint string) (*AccountInfo, error) {
	return RegisterFreeAccountWithURL(ctx, currentRegURL, customEndpoint)
}

// RegisterFreeAccountWithURL registers a free WARP account against a specific API endpoint.
func RegisterFreeAccountWithURL(ctx context.Context, regURL string, customEndpoint string) (*AccountInfo, error) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	installID := genInstallID()
	tos := time.Now().UTC().Format(time.RFC3339Nano)

	reqPayload := map[string]interface{}{
		"key":          pub,
		"install_id":   installID,
		"fcm_token":    "",
		"warp_enabled": true,
		"tos":          tos,
		"type":         "Android",
		"locale":       "en_US",
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read cloudflare response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		ID     string `json:"id"`
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}

	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to decode cloudflare response: %w", err)
	}

	endpoint := strings.TrimSpace(customEndpoint)
	if endpoint == "" {
		if len(parsed.Config.Peers) > 0 && parsed.Config.Peers[0].Endpoint.Host != "" {
			endpoint = parsed.Config.Peers[0].Endpoint.Host
		} else {
			endpoint = DefaultWarpEndpoint
		}
	}

	peerKey := DefaultCloudflarePeerKey
	if len(parsed.Config.Peers) > 0 && parsed.Config.Peers[0].PublicKey != "" {
		peerKey = parsed.Config.Peers[0].PublicKey
	}

	var reserved []int
	if parsed.Config.ClientID != "" {
		if decoded, err := base64.StdEncoding.DecodeString(parsed.Config.ClientID); err == nil && len(decoded) == 3 {
			reserved = []int{int(decoded[0]), int(decoded[1]), int(decoded[2])}
		}
	}

	return &AccountInfo{
		ID:         parsed.ID,
		PrivateKey: priv,
		PublicKey:  pub,
		IPv4:       parsed.Config.Interface.Addresses.V4,
		IPv6:       parsed.Config.Interface.Addresses.V6,
		ClientID:   parsed.Config.ClientID,
		Reserved:   reserved,
		Endpoint:   endpoint,
		PeerKey:    peerKey,
		CreatedAt:  time.Now(),
	}, nil
}

// BuildOutboundConfig constructs the Xray WireGuard outbound configuration map.
func BuildOutboundConfig(info *AccountInfo) map[string]interface{} {
	peerKey := info.PeerKey
	if peerKey == "" {
		peerKey = DefaultCloudflarePeerKey
	}

	addresses := []string{}
	if info.IPv4 != "" {
		addr := info.IPv4
		if !strings.Contains(addr, "/") {
			addr += "/32"
		}
		addresses = append(addresses, addr)
	}
	if info.IPv6 != "" {
		addr := info.IPv6
		if !strings.Contains(addr, "/") {
			addr += "/128"
		}
		addresses = append(addresses, addr)
	}

	peer := map[string]interface{}{
		"publicKey": peerKey,
		"endpoint":  info.Endpoint,
	}

	settings := map[string]interface{}{
		"secretKey": info.PrivateKey,
		"address":   addresses,
		"peers":     []interface{}{peer},
		"mtu":       1280,
	}

	if len(info.Reserved) == 3 {
		settings["reserved"] = info.Reserved
	}

	return map[string]interface{}{
		"protocol": "wireguard",
		"settings": settings,
	}
}
