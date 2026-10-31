package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(privBytes) != 32 {
		t.Fatalf("invalid private key bytes: %v, len=%d", err, len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("invalid public key bytes: %v, len=%d", err, len(pubBytes))
	}

	// Verify Curve25519 relationship
	var expectedPub [32]byte
	var privArr [32]byte
	copy(privArr[:], privBytes)
	curve25519.ScalarBaseMult(&expectedPub, &privArr)

	if base64.StdEncoding.EncodeToString(expectedPub[:]) != pub {
		t.Fatalf("public key does not match curve25519 computation")
	}
}

func TestBuildOutboundConfig(t *testing.T) {
	info := &AccountInfo{
		ID:         "test-id-123",
		PrivateKey: "privKeyBase64=",
		PublicKey:  "pubKeyBase64=",
		IPv4:       "172.16.0.2",
		IPv6:       "2606:4700::1",
		ClientID:   "rUgi",
		Reserved:   []int{173, 72, 34},
		Endpoint:   "162.159.192.1:2408",
		PeerKey:    DefaultCloudflarePeerKey,
	}

	cfg := BuildOutboundConfig(info)
	if cfg["protocol"] != "wireguard" {
		t.Fatalf("protocol = %v, want wireguard", cfg["protocol"])
	}

	settings, ok := cfg["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("settings is not map: %v", cfg["settings"])
	}

	if settings["secretKey"] != "privKeyBase64=" {
		t.Fatalf("secretKey = %v", settings["secretKey"])
	}

	addresses, ok := settings["address"].([]string)
	if !ok || len(addresses) != 2 {
		t.Fatalf("address invalid: %v", settings["address"])
	}
	if addresses[0] != "172.16.0.2/32" || addresses[1] != "2606:4700::1/128" {
		t.Fatalf("unexpected addresses: %v", addresses)
	}

	peers, ok := settings["peers"].([]interface{})
	if !ok || len(peers) != 1 {
		t.Fatalf("peers invalid: %v", settings["peers"])
	}
	peer := peers[0].(map[string]interface{})
	if peer["endpoint"] != "162.159.192.1:2408" {
		t.Fatalf("peer endpoint = %v", peer["endpoint"])
	}
	if peer["publicKey"] != DefaultCloudflarePeerKey {
		t.Fatalf("peer publicKey = %v", peer["publicKey"])
	}

	reserved, ok := settings["reserved"].([]int)
	if !ok || len(reserved) != 3 || reserved[0] != 173 || reserved[1] != 72 || reserved[2] != 34 {
		t.Fatalf("reserved invalid: %v", settings["reserved"])
	}
}

func TestRegisterFreeAccountWithURL_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("User-Agent") != "okhttp/3.12.1" {
			http.Error(w, "bad user-agent", http.StatusBadRequest)
			return
		}

		resp := map[string]interface{}{
			"id": "mock-warp-uuid",
			"config": map[string]interface{}{
				"client_id": "rUgi",
				"peers": []map[string]interface{}{
					{
						"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
						"endpoint": map[string]interface{}{
							"host": "engage.cloudflareclient.com:2408",
						},
					},
				},
				"interface": map[string]interface{}{
					"addresses": map[string]interface{}{
						"v4": "172.16.0.2",
						"v6": "2606:4700:110:8996:fd65:3885:4a6e:c2c4",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	// Case 1: default endpoint
	info, err := RegisterFreeAccountWithURL(context.Background(), ts.URL, "")
	if err != nil {
		t.Fatalf("RegisterFreeAccountWithURL failed: %v", err)
	}
	if info.ID != "mock-warp-uuid" {
		t.Errorf("ID = %s", info.ID)
	}
	if info.IPv4 != "172.16.0.2" {
		t.Errorf("IPv4 = %s", info.IPv4)
	}
	if info.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("Endpoint = %s", info.Endpoint)
	}
	if len(info.Reserved) != 3 || info.Reserved[0] != 173 || info.Reserved[1] != 72 || info.Reserved[2] != 34 {
		t.Errorf("Reserved = %v", info.Reserved)
	}

	// Case 2: custom endpoint override
	infoCustom, err := RegisterFreeAccountWithURL(context.Background(), ts.URL, "198.51.100.1:2408")
	if err != nil {
		t.Fatalf("RegisterFreeAccountWithURL with custom endpoint failed: %v", err)
	}
	if infoCustom.Endpoint != "198.51.100.1:2408" {
		t.Errorf("custom endpoint not applied: %s", infoCustom.Endpoint)
	}
}
