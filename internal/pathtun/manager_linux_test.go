//go:build linux

package pathtun

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
	"xray-proxya/internal/pathd"
)

func TestIPv4EchoRoundTripKeepsClientPayload(t *testing.T) {
	icmp := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'a', 't', 'h'}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packet := make([]byte, 20+len(icmp))
	packet[0], packet[8], packet[9] = 0x45, 55, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.ParseIP("192.0.2.10").To4())
	copy(packet[16:20], net.ParseIP("8.8.8.8").To4())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	copy(packet[20:], icmp)
	req, ok := parseRequest(packet)
	if !ok {
		t.Fatal("parseRequest rejected a public echo request")
	}
	if string(req.echoData) != "path" {
		t.Fatalf("echo payload = %q", req.echoData)
	}
	reply := req.echoReply()
	if reply[9] != unix.IPPROTO_ICMP || reply[20] != 0 {
		t.Fatalf("not an IPv4 echo reply: %v", reply[:21])
	}
	if got := net.IP(reply[12:16]).String(); got != "8.8.8.8" {
		t.Fatalf("reply source = %s", got)
	}
	if got := net.IP(reply[16:20]).String(); got != "192.0.2.10" {
		t.Fatalf("reply destination = %s", got)
	}
	if string(reply[28:]) != "path" {
		t.Fatalf("reply payload = %q", reply[28:])
	}
}

func TestIPv4TimeExceededQuotesOriginalRequest(t *testing.T) {
	packet := make([]byte, 28)
	packet[0], packet[8], packet[9], packet[20] = 0x45, 1, unix.IPPROTO_ICMP, 8
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.ParseIP("192.0.2.10").To4())
	copy(packet[16:20], net.ParseIP("8.8.8.8").To4())
	req, ok := parseRequest(packet)
	if !ok {
		t.Fatal("parseRequest rejected trace request")
	}
	reply := req.diagnostic(pathd.ProbeResult{ICMPType: 11, ICMPCode: 0, Responder: net.ParseIP("203.0.113.1")})
	if reply[20] != 11 || reply[21] != 0 {
		t.Fatalf("not time exceeded: %v", reply[20:22])
	}
	if got := net.IP(reply[12:16]).String(); got != "203.0.113.1" {
		t.Fatalf("responder = %s", got)
	}
	if reply[28] != 0x45 || reply[36] != 1 {
		t.Fatal("diagnostic does not quote original IPv4 header")
	}
}

func TestIPv4RequestPreservesDontFragment(t *testing.T) {
	packet := make([]byte, 28)
	packet[0], packet[8], packet[9], packet[20] = 0x45, 64, unix.IPPROTO_ICMP, 8
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	copy(packet[12:16], net.ParseIP("192.0.2.10").To4())
	copy(packet[16:20], net.ParseIP("8.8.8.8").To4())
	req, ok := parseRequest(packet)
	if !ok || !req.dontFragment {
		t.Fatalf("DF request parsed as ok=%t df=%t", ok, req.dontFragment)
	}
}
