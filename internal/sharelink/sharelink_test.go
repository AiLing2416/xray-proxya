package sharelink

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@203.0.113.207:34035?security=reality&encryption=none&pbk=SOME_PBK&fp=chrome&type=xhttp&path=%2Fcustom&sni=example.com&sid=abcdef12&spx=%2F#HK-Reality"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if spec.Protocol != ProtoVLESS {
		t.Errorf("Protocol = %s, want vless", spec.Protocol)
	}
	if spec.Address != "203.0.113.207" || spec.Port != 34035 {
		t.Errorf("Address:Port = %s:%d, want 203.0.113.207:34035", spec.Address, spec.Port)
	}
	if spec.UUID != "c8abfd6a-bba7-4db9-b43e-82c2beb76049" {
		t.Errorf("UUID = %s", spec.UUID)
	}
	if spec.Security != "reality" || spec.PublicKey != "SOME_PBK" {
		t.Errorf("Security/PublicKey = %s / %s", spec.Security, spec.PublicKey)
	}
	if spec.Transport != "xhttp" || spec.Path != "/custom" {
		t.Errorf("Transport/Path = %s / %s", spec.Transport, spec.Path)
	}
	if spec.Remark != "HK-Reality" {
		t.Errorf("Remark = %s, want HK-Reality", spec.Remark)
	}

	// Test ToOutbound and round-trip extraction via FromOutbound
	out := spec.ToOutbound()
	if out == nil {
		t.Fatal("ToOutbound returned nil")
	}

	extracted := FromOutbound(out)
	if extracted.Protocol != ProtoVLESS || extracted.Address != "203.0.113.207" || extracted.Port != 34035 {
		t.Errorf("Extracted = %+v", extracted)
	}
	if extracted.Security != "reality" || extracted.PublicKey != "SOME_PBK" || extracted.SNI != "example.com" {
		t.Errorf("Extracted security fields = %+v", extracted)
	}
	if extracted.ServerSpec() != "203.0.113.207:34035" {
		t.Errorf("ServerSpec = %s", extracted.ServerSpec())
	}
	summary := extracted.TransportSummary()
	if !strings.Contains(summary, "xhttp") || !strings.Contains(summary, "reality") || !strings.Contains(summary, "sni=example.com") {
		t.Errorf("TransportSummary = %s", summary)
	}
}

func TestParseShadowsocks(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("chacha20-poly1305:secretpassword"))
	link := "ss://" + auth + "@198.51.100.1:8388#MySSNode"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse SS failed: %v", err)
	}
	if spec.Protocol != ProtoShadowsocks || spec.Address != "198.51.100.1" || spec.Port != 8388 {
		t.Fatalf("SS Spec = %+v", spec)
	}
	if spec.Method != "chacha20-poly1305" || spec.Password != "secretpassword" {
		t.Fatalf("SS Auth = %s / %s", spec.Method, spec.Password)
	}
	if spec.Remark != "MySSNode" {
		t.Errorf("SS Remark = %s", spec.Remark)
	}

	out := spec.ToOutbound()
	extracted := FromOutbound(out)
	if extracted.Protocol != ProtoShadowsocks || extracted.Port != 8388 || extracted.Method != "chacha20-poly1305" {
		t.Fatalf("SS Extracted = %+v", extracted)
	}
}

func TestParseVMessWS(t *testing.T) {
	payload := `{"v":"2","ps":"HK-VMess","add":"1.2.3.4","port":10086,"id":"uuid-123","net":"ws","path":"/vmessws","tls":"tls"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	link := "vmess://" + encoded

	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse VMess failed: %v", err)
	}
	if spec.Protocol != ProtoVMess || spec.Address != "1.2.3.4" || spec.Port != 10086 {
		t.Fatalf("VMess Spec = %+v", spec)
	}
	if spec.Transport != "ws" || spec.Path != "/vmessws" || spec.Remark != "HK-VMess" {
		t.Fatalf("VMess details = %+v", spec)
	}

	// Test remark rewrite
	rewritten := RewriteRemark(link, "NewRemark")
	newSpec, err := Parse(rewritten)
	if err != nil {
		t.Fatalf("Parse rewritten VMess failed: %v", err)
	}
	if newSpec.Remark != "NewRemark" {
		t.Errorf("NewRemark = %s, want NewRemark", newSpec.Remark)
	}
}

func TestInterfaceBind(t *testing.T) {
	out, err := ParseInterfaceBind("eth0", "10.0.0.2")
	if err != nil {
		t.Fatalf("ParseInterfaceBind failed: %v", err)
	}
	spec := FromOutbound(out)
	if spec.Protocol != ProtoFreedom || spec.Address != "eth0" || spec.Host != "10.0.0.2" {
		t.Fatalf("Freedom Spec = %+v", spec)
	}
	if spec.ServerSpec() != "eth0" {
		t.Errorf("ServerSpec = %s, want eth0", spec.ServerSpec())
	}
}

func TestDecodePayload(t *testing.T) {
	plain := "vless://u1@h1:443#N1\n# Comment\nvless://u2@h2:443#N2\n"
	lines, err := DecodePayload([]byte(plain))
	if err != nil || len(lines) != 2 {
		t.Fatalf("DecodePayload plain: len=%d, err=%v", len(lines), err)
	}

	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	lines2, err := DecodePayload([]byte(b64))
	if err != nil || len(lines2) != 2 {
		t.Fatalf("DecodePayload b64: len=%d, err=%v", len(lines2), err)
	}
}

func TestParseVLESSGRPC(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=grpc&serviceName=my-grpc-service&mode=multi&security=tls&sni=example.com&alpn=h2#GRPC-Node"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse gRPC link failed: %v", err)
	}
	if spec.Transport != "grpc" || spec.ServiceName != "my-grpc-service" || spec.Mode != "multi" {
		t.Fatalf("spec mismatch: Transport=%s, ServiceName=%s, Mode=%s", spec.Transport, spec.ServiceName, spec.Mode)
	}
	if spec.ALPN != "h2" {
		t.Fatalf("spec ALPN=%s, want h2", spec.ALPN)
	}

	out := spec.ToOutbound()
	stream := out["streamSettings"].(map[string]interface{})
	grpcSettings := stream["grpcSettings"].(map[string]interface{})
	if grpcSettings["serviceName"] != "my-grpc-service" {
		t.Errorf("grpcSettings.serviceName = %v", grpcSettings["serviceName"])
	}
	if grpcSettings["multiMode"] != true {
		t.Errorf("grpcSettings.multiMode = %v", grpcSettings["multiMode"])
	}
	tlsSettings := stream["tlsSettings"].(map[string]interface{})
	alpnSlice, ok := tlsSettings["alpn"].([]string)
	if !ok || len(alpnSlice) != 1 || alpnSlice[0] != "h2" {
		t.Errorf("tlsSettings.alpn = %v", tlsSettings["alpn"])
	}

	extracted := FromOutbound(out)
	if extracted.ServiceName != "my-grpc-service" || extracted.Mode != "multi" || extracted.ALPN != "h2" {
		t.Errorf("FromOutbound extracted: %+v", extracted)
	}
}

func TestParseVLESSXHTTPMode(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=xhttp&path=%2Fcustom&mode=packet-up&host=cdn.example.com#XHTTP-Node"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse xhttp failed: %v", err)
	}
	if spec.Mode != "packet-up" || spec.Host != "cdn.example.com" {
		t.Fatalf("spec mismatch: Mode=%s, Host=%s", spec.Mode, spec.Host)
	}

	out := spec.ToOutbound()
	stream := out["streamSettings"].(map[string]interface{})
	xhttpSettings := stream["xhttpSettings"].(map[string]interface{})
	if xhttpSettings["mode"] != "packet-up" || xhttpSettings["host"] != "cdn.example.com" {
		t.Errorf("xhttpSettings mismatch: %+v", xhttpSettings)
	}

	extracted := FromOutbound(out)
	if extracted.Mode != "packet-up" || extracted.Host != "cdn.example.com" {
		t.Errorf("FromOutbound extracted xhttp mismatch: %+v", extracted)
	}
}

func TestParseVMessTLS(t *testing.T) {
	payload := `{"v":"2","ps":"TLS-VMess","add":"1.2.3.4","port":443,"id":"uuid-123","net":"ws","path":"/ws","tls":"tls","host":"ws.example.com","sni":"ws.example.com"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	link := "vmess://" + encoded

	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse VMess TLS failed: %v", err)
	}
	if spec.Security != "tls" || spec.SNI != "ws.example.com" || spec.Host != "ws.example.com" {
		t.Fatalf("spec mismatch: Security=%s, SNI=%s, Host=%s", spec.Security, spec.SNI, spec.Host)
	}

	out := spec.ToOutbound()
	stream, ok := out["streamSettings"].(map[string]interface{})
	if !ok || stream["security"] != "tls" {
		t.Fatalf("streamSettings missing security=tls: %+v", stream)
	}
	tlsSettings, ok := stream["tlsSettings"].(map[string]interface{})
	if !ok || tlsSettings["serverName"] != "ws.example.com" {
		t.Fatalf("tlsSettings missing serverName: %+v", tlsSettings)
	}
	wsSettings, ok := stream["wsSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("wsSettings missing: %+v", stream)
	}
	headers, ok := wsSettings["headers"].(map[string]interface{})
	if !ok || headers["Host"] != "ws.example.com" {
		t.Fatalf("wsSettings missing Host header: %+v", wsSettings)
	}

	extracted := FromOutbound(out)
	if extracted.Security != "tls" || extracted.SNI != "ws.example.com" || extracted.Host != "ws.example.com" {
		t.Fatalf("FromOutbound extracted VMess mismatch: %+v", extracted)
	}
}

func TestNormalizeCertHashHex(t *testing.T) {
	rawHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	colonHex := "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef"
	if got := NormalizeCertHashHex(colonHex); got != rawHex {
		t.Errorf("NormalizeCertHashHex colon = %q, want %q", got, rawHex)
	}

	b64 := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	gotB64 := NormalizeCertHashHex(b64)
	if len(gotB64) != 64 {
		t.Errorf("NormalizeCertHashHex b64 len = %d, want 64", len(gotB64))
	}

	if got := NormalizeCertHashHex(""); got != "" {
		t.Errorf("NormalizeCertHashHex empty = %q, want empty", got)
	}
}

func TestParseHysteria2(t *testing.T) {
	pinHex := "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
	colonPin := "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
	link := "hysteria2://myauth@198.51.100.2:8443?sni=example.com&obfs=salamander&obfs-password=secretpass&pinSHA256=" + colonPin + "#HK-Hy2"

	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse Hysteria2 failed: %v", err)
	}
	if spec.Protocol != ProtoHysteria2 {
		t.Errorf("Protocol = %s, want hysteria2", spec.Protocol)
	}
	if spec.Address != "198.51.100.2" || spec.Port != 8443 {
		t.Errorf("Address:Port = %s:%d, want 198.51.100.2:8443", spec.Address, spec.Port)
	}
	if spec.Password != "myauth" {
		t.Errorf("Password = %s, want myauth", spec.Password)
	}
	if spec.SNI != "example.com" {
		t.Errorf("SNI = %s, want example.com", spec.SNI)
	}
	if spec.ALPN != "h3" {
		t.Errorf("ALPN = %s, want h3", spec.ALPN)
	}
	if spec.ObfsType != "salamander" || spec.ObfsPassword != "secretpass" {
		t.Errorf("Obfs = %s / %s", spec.ObfsType, spec.ObfsPassword)
	}
	if spec.PinnedPeerCertSha256 != pinHex {
		t.Errorf("PinnedPeerCertSha256 = %s, want %s", spec.PinnedPeerCertSha256, pinHex)
	}
	if spec.VerifyPeerCertByName != "example.com" {
		t.Errorf("VerifyPeerCertByName = %s, want example.com", spec.VerifyPeerCertByName)
	}
	if spec.Remark != "HK-Hy2" {
		t.Errorf("Remark = %s, want HK-Hy2", spec.Remark)
	}

	summary := spec.TransportSummary()
	if !strings.Contains(summary, "hysteria") && !strings.Contains(summary, "udp") {
		t.Errorf("TransportSummary = %s, want hysteria or udp", summary)
	}
	if !strings.Contains(summary, "obfs=salamander") || !strings.Contains(summary, "pin=sha256") {
		t.Errorf("TransportSummary = %s, missing obfs or pin", summary)
	}

	// Test ToOutbound
	out := spec.ToOutbound()
	if out["protocol"] != "hysteria" {
		t.Fatalf("ToOutbound protocol = %v, want hysteria", out["protocol"])
	}
	settings, ok := out["settings"].(map[string]interface{})
	if !ok || settings["address"] != "198.51.100.2" || settings["port"] != 8443 {
		t.Fatalf("settings mismatch: %+v", settings)
	}
	stream, ok := out["streamSettings"].(map[string]interface{})
	if !ok || stream["network"] != "hysteria" || stream["security"] != "tls" {
		t.Fatalf("streamSettings mismatch: %+v", stream)
	}
	tlsSettings, ok := stream["tlsSettings"].(map[string]interface{})
	if !ok || tlsSettings["serverName"] != "example.com" || tlsSettings["pinnedPeerCertSha256"] != pinHex || tlsSettings["verifyPeerCertByName"] != "example.com" {
		t.Fatalf("tlsSettings mismatch: %+v", tlsSettings)
	}
	hySettings, ok := stream["hysteriaSettings"].(map[string]interface{})
	if !ok || hySettings["auth"] != "myauth" || hySettings["version"] != 2 {
		t.Fatalf("hysteriaSettings mismatch: %+v", hySettings)
	}
	fm, ok := stream["finalmask"].(map[string]interface{})
	if !ok {
		t.Fatalf("finalmask missing: %+v", stream)
	}
	udpSlice, ok := fm["udp"].([]interface{})
	if !ok || len(udpSlice) == 0 {
		t.Fatalf("finalmask udp missing: %+v", fm)
	}

	// Test FromOutbound round-trip
	extracted := FromOutbound(out)
	if extracted.Protocol != ProtoHysteria2 || extracted.Address != "198.51.100.2" || extracted.Port != 8443 {
		t.Fatalf("FromOutbound mismatch: %+v", extracted)
	}
	if extracted.Password != "myauth" || extracted.SNI != "example.com" || extracted.PinnedPeerCertSha256 != pinHex || extracted.VerifyPeerCertByName != "example.com" {
		t.Fatalf("FromOutbound fields mismatch: %+v", extracted)
	}
	if extracted.ObfsType != "salamander" || extracted.ObfsPassword != "secretpass" {
		t.Fatalf("FromOutbound obfs mismatch: %+v", extracted)
	}

	// Test Remark rewrite
	rewritten := RewriteRemark(link, "NewHy2Tag")
	reSpec, err := Parse(rewritten)
	if err != nil {
		t.Fatalf("Parse rewritten failed: %v", err)
	}
	if reSpec.Remark != "NewHy2Tag" {
		t.Errorf("Rewritten remark = %s, want NewHy2Tag", reSpec.Remark)
	}
}

func TestParseHy2_IPv6_Insecure(t *testing.T) {
	link := "hy2://secretpass@[::1]?peer=test.org&insecure=1#LocalHy2"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse hy2 failed: %v", err)
	}
	if spec.Protocol != ProtoHysteria2 || spec.Address != "::1" || spec.Port != 443 {
		t.Errorf("Spec = %+v", spec)
	}
	if spec.SNI != "test.org" || !spec.Insecure {
		t.Errorf("SNI/Insecure = %s / %v", spec.SNI, spec.Insecure)
	}

	out := spec.ToOutbound()
	stream := out["streamSettings"].(map[string]interface{})
	tlsSettings := stream["tlsSettings"].(map[string]interface{})
	if tlsSettings["allowInsecure"] != true {
		t.Errorf("tlsSettings allowInsecure = %v, want true", tlsSettings["allowInsecure"])
	}

	extracted := FromOutbound(out)
	if !extracted.Insecure || extracted.SNI != "test.org" {
		t.Errorf("extracted Insecure/SNI = %v / %s", extracted.Insecure, extracted.SNI)
	}
}

func TestParseVLESS_CertPinning(t *testing.T) {
	rawPin := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&sni=tls.example.com&pcs=" + rawPin + "&vcn=custom.domain.com#VLESS-PIN"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse VLESS pin failed: %v", err)
	}
	if spec.PinnedPeerCertSha256 != rawPin || spec.VerifyPeerCertByName != "custom.domain.com" {
		t.Errorf("spec pin = %s / %s", spec.PinnedPeerCertSha256, spec.VerifyPeerCertByName)
	}

	out := spec.ToOutbound()
	stream := out["streamSettings"].(map[string]interface{})
	tlsSettings := stream["tlsSettings"].(map[string]interface{})
	if tlsSettings["pinnedPeerCertSha256"] != rawPin || tlsSettings["verifyPeerCertByName"] != "custom.domain.com" {
		t.Errorf("tlsSettings pin = %v / %v", tlsSettings["pinnedPeerCertSha256"], tlsSettings["verifyPeerCertByName"])
	}

	extracted := FromOutbound(out)
	if extracted.PinnedPeerCertSha256 != rawPin || extracted.VerifyPeerCertByName != "custom.domain.com" {
		t.Errorf("extracted pin = %s / %s", extracted.PinnedPeerCertSha256, extracted.VerifyPeerCertByName)
	}
}

func TestFromOutbound_WireGuard(t *testing.T) {
	outbound := map[string]interface{}{
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"secretKey": "testSecretKey=",
			"address":   []string{"172.16.0.2/32", "2606:4700::1/128"},
			"peers": []interface{}{
				map[string]interface{}{
					"publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint":  "engage.cloudflareclient.com:2408",
				},
			},
			"reserved": []int{1, 2, 3},
			"mtu":      1280,
		},
	}

	spec := FromOutbound(outbound)
	if spec.Protocol != ProtoWireGuard {
		t.Fatalf("Protocol = %s, want %s", spec.Protocol, ProtoWireGuard)
	}
	if spec.Address != "engage.cloudflareclient.com" || spec.Port != 2408 {
		t.Fatalf("Address:Port = %s:%d, want engage.cloudflareclient.com:2408", spec.Address, spec.Port)
	}
	if spec.ServerSpec() != "engage.cloudflareclient.com:2408" {
		t.Fatalf("ServerSpec = %s, want engage.cloudflareclient.com:2408", spec.ServerSpec())
	}
	if spec.TransportSummary() != "udp" {
		t.Fatalf("TransportSummary = %s, want udp", spec.TransportSummary())
	}
}



