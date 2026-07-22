package xray

import (
	"testing"
)

func TestParseVLESSWithMLKEMEncryption(t *testing.T) {
	link := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@203.88.112.207:34035?security=none&encryption=mlkem768x25519plus.native.0rtt.SOME_KEY&type=xhttp&path=%2Fc085425d9bc32c05#VLess-XHTTP-KEM768-34035"
	out, err := ParseProxyLink(link)
	if err != nil {
		t.Fatalf("ParseProxyLink failed: %v", err)
	}

	if out["protocol"] != "vless" {
		t.Fatalf("expected protocol vless, got %v", out["protocol"])
	}

	settings, ok := out["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected settings map")
	}

	vnext, ok := settings["vnext"].([]interface{})
	if !ok || len(vnext) == 0 {
		t.Fatalf("expected vnext list")
	}

	node := vnext[0].(map[string]interface{})
	users := node["users"].([]interface{})
	user := users[0].(map[string]interface{})

	if user["encryption"] != "none" {
		t.Fatalf("user encryption must be 'none', got %v", user["encryption"])
	}

	decryption, ok := settings["decryption"].(string)
	if !ok || decryption != "mlkem768x25519plus.native.0rtt.SOME_KEY" {
		t.Fatalf("expected settings.decryption to be mlkem768x25519plus.native.0rtt.SOME_KEY, got %v", settings["decryption"])
	}
}
