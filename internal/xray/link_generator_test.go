package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
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
