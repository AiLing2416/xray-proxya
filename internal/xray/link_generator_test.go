package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestWithPrimaryRemarkUpdatesVLESSFragment(t *testing.T) {
	links := []string{"vless://uuid@example.com:443?type=tcp#Old-Name", "vless://uuid@example.com:8443?type=tcp#Second"}
	updated := WithPrimaryRemark(links, "1GB/5GB/10d")
	if !strings.Contains(updated[0], "#1GB%2F5GB%2F10d") {
		t.Fatalf("expected first vless link fragment to be updated, got %q", updated[0])
	}
	if updated[1] != links[1] {
		t.Fatalf("expected only first link to change")
	}
}

func TestWithPrimaryRemarkUpdatesVMessPS(t *testing.T) {
	payload := map[string]interface{}{"v": "2", "ps": "old", "add": "example.com"}
	data, _ := json.Marshal(payload)
	links := []string{"vmess://" + base64.StdEncoding.EncodeToString(data)}
	updated := WithPrimaryRemark(links, "2GB/10GB/3d")
	raw := strings.TrimPrefix(updated[0], "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode vmess: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(decoded, &obj); err != nil {
		t.Fatalf("unmarshal vmess: %v", err)
	}
	if got := obj["ps"]; got != "2GB/10GB/3d" {
		t.Fatalf("ps = %#v, want %q", got, "2GB/10GB/3d")
	}
}

func TestGenerateAllLinksURLEscapesVLESSXHTTPPassword(t *testing.T) {
	cfg := &config.UserConfig{
		UUID: "12345678-1234-1234-1234-123456789012",
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSXHTTP,
				Enabled: true,
				Port:    443,
				Path:    "/xhttp",
				Settings: config.Settings{
					Password: "ML-KEM-768:key+with/slash=and+plus",
				},
			},
		},
	}

	links := GenerateLinks(cfg, "1.2.3.4")
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	wantEnc := "encryption=ML-KEM-768%3Akey%2Bwith%2Fslash%3Dand%2Bplus"
	if !strings.Contains(links[0], wantEnc) {
		t.Fatalf("expected link to contain escaped encryption query parameter %q, got %q", wantEnc, links[0])
	}
}

func TestGenerateLinksOutputsConfiguredFingerprintAndStable(t *testing.T) {
	cfg := &config.UserConfig{
		UUID: "12345678-1234-1234-1234-123456789012",
		Presets: []config.ModeInfo{
			{
				Mode:        config.ModeVLESSVision,
				Enabled:     true,
				Port:        443,
				SNI:         "vision.domain.com",
				Dest:        "vision.domain.com:443",
				Fingerprint: "firefox",
				Settings: config.Settings{
					PublicKey: "pubkey-vision",
					ShortID:   "sid1",
				},
			},
			{
				Mode:        config.ModeVLESSReality,
				Enabled:     true,
				Port:        8443,
				SNI:         "reality.domain.com",
				Dest:        "reality.domain.com:443",
				Path:        "/xhttp-path",
				Fingerprint: "safari",
				Settings: config.Settings{
					PublicKey: "pubkey-reality",
					ShortID:   "sid2",
				},
			},
		},
	}

	links1 := GenerateLinks(cfg, "1.2.3.4")
	if len(links1) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links1))
	}

	// Vision link (links1[0]) should have fp=firefox
	if !strings.Contains(links1[0], "fp=firefox") {
		t.Errorf("Vision link %q does not contain fp=firefox", links1[0])
	}
	if strings.Contains(links1[0], "fp=chrome") {
		t.Errorf("Vision link %q unexpectedly contains fp=chrome", links1[0])
	}

	// Reality link (links1[1]) should have fp=safari
	if !strings.Contains(links1[1], "fp=safari") {
		t.Errorf("Reality link %q does not contain fp=safari", links1[1])
	}

	// Multiple calls produce identical results (no jitter/randomization on each show)
	links2 := GenerateLinks(cfg, "1.2.3.4")
	for i := range links1 {
		if links1[i] != links2[i] {
			t.Errorf("link %d mutated on second call: %q != %q", i, links1[i], links2[i])
		}
	}
}

func TestGenerateLinksMultiAddressGrouping(t *testing.T) {
	cfg := &config.UserConfig{
		UUID: "12345678-1234-1234-1234-123456789012",
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "example.com",
				Settings: config.Settings{
					PublicKey: "pub",
					ShortID:   "abcd",
				},
			},
		},
	}

	links := GenerateLinks(cfg, "1.1.2.2, 2006:9999::8844, proxy.example.com")
	if len(links) != 3 {
		t.Fatalf("expected 3 links for 3 addresses, got %d", len(links))
	}
	if !strings.Contains(links[0], "@1.1.2.2:443") {
		t.Errorf("expected 1.1.2.2 in first link, got %q", links[0])
	}
	if !strings.Contains(links[1], "@[2006:9999::8844]:443") {
		t.Errorf("expected [2006:9999::8844] in second link, got %q", links[1])
	}
	if !strings.Contains(links[2], "@proxy.example.com:443") {
		t.Errorf("expected proxy.example.com in third link, got %q", links[2])
	}
}

func TestGenerateLinksWithTargets_Remarks(t *testing.T) {
	cfg := &config.UserConfig{
		UUID: "12345678-1234-1234-1234-123456789012",
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSReality,
				Enabled: true,
				Port:    443,
				SNI:     "reality.domain.com",
				Settings: config.Settings{
					PublicKey: "pubkey-reality",
					ShortID:   "sid",
				},
			},
		},
	}

	targets := []TargetNode{
		{Address: "1.2.3.4", Alias: "default"},
		{Address: "2600::1", Alias: "he-pool"},
	}

	// 1. Admin links with targets
	adminLinks := GenerateLinksWithTargets(cfg, targets)
	if len(adminLinks) != 2 {
		t.Fatalf("expected 2 admin links, got %d", len(adminLinks))
	}
	if !strings.Contains(adminLinks[0], "#VLess-XHTTP-Reality-443-default") {
		t.Errorf("expected admin link 0 to end with #VLess-XHTTP-Reality-443-default, got %q", adminLinks[0])
	}
	if !strings.Contains(adminLinks[1], "#VLess-XHTTP-Reality-443-he-pool") {
		t.Errorf("expected admin link 1 to end with #VLess-XHTTP-Reality-443-he-pool, got %q", adminLinks[1])
	}

	// 2. Guest links with targets
	guestLinks := GenerateGuestLinksWithTargets(cfg, targets, "guest-uuid-1", "SPYS")
	if len(guestLinks) != 2 {
		t.Fatalf("expected 2 guest links, got %d", len(guestLinks))
	}
	if !strings.Contains(guestLinks[0], "#VLess-XHTTP-Reality-443-Guest-SPYS-default") {
		t.Errorf("expected guest link 0 to end with #VLess-XHTTP-Reality-443-Guest-SPYS-default, got %q", guestLinks[0])
	}
	if !strings.Contains(guestLinks[1], "#VLess-XHTTP-Reality-443-Guest-SPYS-he-pool") {
		t.Errorf("expected guest link 1 to end with #VLess-XHTTP-Reality-443-Guest-SPYS-he-pool, got %q", guestLinks[1])
	}
}

func TestGenerateHysteria2Links(t *testing.T) {
	pinHex := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cfg := &config.UserConfig{
		UUID: "11111111-2222-3333-4444-555555555555",
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeHysteria2,
				Enabled: true,
				Port:    8443,
				SNI:     "hy2.example.com",
				Settings: config.Settings{
					PublicKey: pinHex,
					Password:  "salamander-secret",
				},
			},
		},
	}

	// 1. GenerateLinks
	links := GenerateLinks(cfg, "203.0.113.1")
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	link := links[0]
	if !strings.HasPrefix(link, "hysteria2://") {
		t.Fatalf("expected hysteria2:// prefix, got %q", link)
	}
	if !strings.Contains(link, "hy2.example.com") {
		t.Errorf("missing SNI: %q", link)
	}
	if !strings.Contains(link, "alpn=h3") {
		t.Errorf("missing alpn=h3: %q", link)
	}
	if !strings.Contains(link, "obfs=salamander") || !strings.Contains(link, "obfs-password=salamander-secret") {
		t.Errorf("missing obfs parameters: %q", link)
	}
	if !strings.Contains(link, "pinSHA256="+pinHex) {
		t.Errorf("missing pinSHA256: %q", link)
	}
	if !strings.Contains(link, "insecure=0") {
		t.Errorf("missing insecure=0: %q", link)
	}
	if !strings.Contains(link, "#Hysteria2-8443") {
		t.Errorf("missing #Hysteria2-8443: %q", link)
	}

	// 2. GenerateGuestLinks
	guestLinks := GenerateGuestLinks(cfg, "203.0.113.1", "22222222-2222-2222-2222-222222222222", "guestA")
	if len(guestLinks) != 1 {
		t.Fatalf("expected 1 guest link, got %d", len(guestLinks))
	}
	if !strings.Contains(guestLinks[0], "22222222-2222-2222-2222-222222222222@") {
		t.Errorf("guest link should use guest UUID: %q", guestLinks[0])
	}
	if !strings.Contains(guestLinks[0], "#Hysteria2-8443-Guest-guestA") {
		t.Errorf("guest link remark mismatch: %q", guestLinks[0])
	}

	// 3. GenerateRelayLinks
	relay := config.CustomOutbound{
		Alias:    "relay-hk",
		UserUUID: "33333333-3333-3333-3333-333333333333",
	}
	relayLinks := GenerateRelayLinks(cfg, "203.0.113.1", relay)
	if len(relayLinks) != 1 {
		t.Fatalf("expected 1 relay link, got %d", len(relayLinks))
	}
	if !strings.Contains(relayLinks[0], "33333333-3333-3333-3333-333333333333@") {
		t.Errorf("relay link should use relay UserUUID: %q", relayLinks[0])
	}
	if !strings.Contains(relayLinks[0], "#Hysteria2-8443-Relay-relay-hk") {
		t.Errorf("relay link remark mismatch: %q", relayLinks[0])
	}

	// 4. GenerateLinksWithTargets
	targets := []TargetNode{
		{Address: "198.51.100.1", Alias: "target-1"},
	}
	targetLinks := GenerateLinksWithTargets(cfg, targets)
	if len(targetLinks) != 1 || !strings.Contains(targetLinks[0], "#Hysteria2-8443-target-1") {
		t.Errorf("target link remark mismatch: %v", targetLinks)
	}

	// 5. WithPrimaryRemark
	renamed := WithPrimaryRemark(links, "RenamedHysteria2")
	if !strings.Contains(renamed[0], "#RenamedHysteria2") {
		t.Errorf("WithPrimaryRemark failed: %q", renamed[0])
	}
}

