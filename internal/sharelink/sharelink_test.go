package sharelink

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@203.88.112.207:34035?security=reality&encryption=none&pbk=SOME_PBK&fp=chrome&type=xhttp&path=%2Fcustom&sni=example.com&sid=abcdef12&spx=%2F#HK-Reality"
	spec, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if spec.Protocol != ProtoVLESS {
		t.Errorf("Protocol = %s, want vless", spec.Protocol)
	}
	if spec.Address != "203.88.112.207" || spec.Port != 34035 {
		t.Errorf("Address:Port = %s:%d, want 203.88.112.207:34035", spec.Address, spec.Port)
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
	if extracted.Protocol != ProtoVLESS || extracted.Address != "203.88.112.207" || extracted.Port != 34035 {
		t.Errorf("Extracted = %+v", extracted)
	}
	if extracted.Security != "reality" || extracted.PublicKey != "SOME_PBK" || extracted.SNI != "example.com" {
		t.Errorf("Extracted security fields = %+v", extracted)
	}
	if extracted.ServerSpec() != "203.88.112.207:34035" {
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


