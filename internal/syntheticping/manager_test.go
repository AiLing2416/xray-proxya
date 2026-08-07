package syntheticping

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseAndReplyEchoRequest(t *testing.T) {
	gatewayMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	clientMAC := net.HardwareAddr{6, 7, 8, 9, 10, 11}
	frame := make([]byte, 14+20+8)
	copy(frame[0:6], gatewayMAC)
	copy(frame[6:12], clientMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(ip[2:4], 28)
	copy(ip[12:16], net.ParseIP("10.49.0.203").To4())
	copy(ip[16:20], net.ParseIP("13.193.197.192").To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	icmp := frame[34:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:8], 0x0042)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	request, ok := parseEchoRequest(frame, gatewayMAC)
	if !ok {
		t.Fatal("parseEchoRequest() = false")
	}
	reply := buildEchoReply(request, gatewayMAC)
	if len(reply) != len(frame) || reply[34] != 0 {
		t.Fatalf("invalid echo reply: %x", reply)
	}
	if got := net.IP(reply[26:30]).String(); got != "13.193.197.192" {
		t.Fatalf("reply source = %s", got)
	}
	if got := net.IP(reply[30:34]).String(); got != "10.49.0.203" {
		t.Fatalf("reply destination = %s", got)
	}
	if checksum(reply[14:34]) != 0 || checksum(reply[34:]) != 0 {
		t.Fatal("reply checksum is invalid")
	}
}

func TestIsPublicIPv4(t *testing.T) {
	if !isPublicIPv4(net.ParseIP("13.193.197.192")) {
		t.Fatal("expected public target")
	}
	for _, value := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "224.0.0.1"} {
		if isPublicIPv4(net.ParseIP(value)) {
			t.Fatalf("%s must not be treated as public", value)
		}
	}
}

func TestParseAndReplyIPv6EchoRequest(t *testing.T) {
	gatewayMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	clientMAC := net.HardwareAddr{6, 7, 8, 9, 10, 11}
	frame := make([]byte, 14+40+8)
	copy(frame[0:6], gatewayMAC)
	copy(frame[6:12], clientMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:54]
	ip[0], ip[6], ip[7] = 0x60, 58, 64
	binary.BigEndian.PutUint16(ip[4:6], 8)
	copy(ip[8:24], net.ParseIP("2001:db8:1::203").To16())
	copy(ip[24:40], net.ParseIP("2606:4700:4700::1111").To16())
	icmp := frame[54:]
	icmp[0] = 128
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:8], 0x0042)
	binary.BigEndian.PutUint16(icmp[2:4], checksumIPv6(ip[8:24], ip[24:40], icmp))

	request, ok := parseEchoRequest(frame, gatewayMAC)
	if !ok {
		t.Fatal("parse IPv6 echo request = false")
	}
	reply := buildEchoReply(request, gatewayMAC)
	if len(reply) != len(frame) || reply[54] != 129 {
		t.Fatalf("invalid IPv6 reply: %x", reply)
	}
	if got := net.IP(reply[22:38]).String(); got != "2606:4700:4700::1111" {
		t.Fatalf("reply source = %s", got)
	}
	if got := net.IP(reply[38:54]).String(); got != "2001:db8:1::203" {
		t.Fatalf("reply destination = %s", got)
	}
	if checksumIPv6(reply[22:38], reply[38:54], reply[54:]) != 0 {
		t.Fatal("IPv6 ICMP checksum is invalid")
	}
}

func TestVerifyEndpointSSHBanner(t *testing.T) {
	probe, endpoint := net.Pipe()
	defer probe.Close()
	go func() {
		_, _ = endpoint.Write([]byte("SSH-2.0-test\r\n"))
		_ = endpoint.Close()
	}()
	if !verifyEndpoint(probe, 22) {
		t.Fatal("SSH banner endpoint verification failed")
	}
}
