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

func TestParseProxyLinkWithRemark(t *testing.T) {
	// VLESS with URL-encoded remark
	vlessLink := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@203.88.112.207:34035?security=none#%E9%A6%99%E6%B8%AF-01"
	out, remark, err := ParseProxyLinkWithRemark(vlessLink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["protocol"] != "vless" {
		t.Fatalf("expected vless, got %v", out["protocol"])
	}
	if remark != "香港-01" {
		t.Fatalf("expected remark '香港-01', got %q", remark)
	}

	// VMess with ps field
	// {"add":"1.2.3.4","port":443,"id":"c8abfd6a-bba7-4db9-b43e-82c2beb76049","net":"ws","ps":"Tokyo-01"}
	// eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6ImM4YWJmZDZhLWJiYTctNGRiOS1iNDNlLTgyYzJiZWI3NjA0OSIsIm5ldCI6IndzIiwicHMiOiJUb2t5by0wMSJ9
	vmessLink := "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6ImM4YWJmZDZhLWJiYTctNGRiOS1iNDNlLTgyYzJiZWI3NjA0OSIsIm5ldCI6IndzIiwicHMiOiJUb2t5by0wMSJ9"
	outVmess, remarkVmess, err := ParseProxyLinkWithRemark(vmessLink)
	if err != nil {
		t.Fatalf("unexpected vmess error: %v", err)
	}
	if outVmess["protocol"] != "vmess" {
		t.Fatalf("expected vmess, got %v", outVmess["protocol"])
	}
	if remarkVmess != "Tokyo-01" {
		t.Fatalf("expected remark 'Tokyo-01', got %q", remarkVmess)
	}

	// SS with remark
	// ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#US-West
	ssLink := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#US-West"
	outSS, remarkSS, err := ParseProxyLinkWithRemark(ssLink)
	if err != nil {
		t.Fatalf("unexpected ss error: %v", err)
	}
	if outSS["protocol"] != "shadowsocks" {
		t.Fatalf("expected shadowsocks, got %v", outSS["protocol"])
	}
	if remarkSS != "US-West" {
		t.Fatalf("expected remark 'US-West', got %q", remarkSS)
	}
}
