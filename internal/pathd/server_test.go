package pathd

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestHandleProbeRejectsOversizedPayload(t *testing.T) {
	s := &Server{}
	result := s.handleProbe(frame{
		Type:        "icmp_echo",
		Target:      "8.8.8.8",
		Timeout:     1000,
		TTL:         64,
		PayloadSize: maxPayloadSize + 1,
	})
	if result.Error != "invalid ICMP payload size" {
		t.Fatalf("oversized payload error = %q", result.Error)
	}
}

func TestServerLimitsAreFinite(t *testing.T) {
	if maxGlobalInFlight <= maxInFlight || maxConnections <= 0 || maxPayloadSize != 1024 {
		t.Fatalf("unexpected limits: global=%d per-connection=%d connections=%d payload=%d", maxGlobalInFlight, maxInFlight, maxConnections, maxPayloadSize)
	}
}

func TestPendingPingRequiresMatchingEchoSource(t *testing.T) {
	p := &pinger{proto: 1}
	pending := pendingPing{target: net.ParseIP("8.8.8.8")}
	message := &icmp.Message{Type: ipv4.ICMPTypeEchoReply}

	if p.pendingMatches(pending, &net.IPAddr{IP: net.ParseIP("1.1.1.1")}, false, message) {
		t.Fatal("echo reply from an unexpected source was accepted")
	}
	if !p.pendingMatches(pending, &net.IPAddr{IP: net.ParseIP("8.8.8.8")}, false, message) {
		t.Fatal("echo reply from the target was rejected")
	}
}

func TestPendingPingRequiresMatchingDiagnosticQuoteTarget(t *testing.T) {
	quote := make([]byte, 28)
	quote[0] = 0x45
	binary.BigEndian.PutUint16(quote[2:4], uint16(len(quote)))
	copy(quote[16:20], net.ParseIP("8.8.8.8").To4())
	message := &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: quote}}
	p := &pinger{proto: 1}

	if !p.pendingMatches(pendingPing{target: net.ParseIP("8.8.8.8")}, nil, true, message) {
		t.Fatal("diagnostic quoting the target was rejected")
	}
	if p.pendingMatches(pendingPing{target: net.ParseIP("1.1.1.1")}, nil, true, message) {
		t.Fatal("diagnostic quoting another target was accepted")
	}
}

func TestMatchMessageFindsICMPv6AfterHopByHopHeader(t *testing.T) {
	quote := make([]byte, 40+8+8)
	quote[0], quote[6] = 0x60, 0
	binary.BigEndian.PutUint16(quote[4:6], 64)
	copy(quote[24:40], net.ParseIP("2606:4700:4700::1111").To16())
	quote[40], quote[41] = 58, 0
	quote[48] = 128
	binary.BigEndian.PutUint16(quote[52:54], 0x5054)
	binary.BigEndian.PutUint16(quote[54:56], 7)

	p := &pinger{proto: 58, reply: ipv6.ICMPTypeEchoReply}
	key, cookieMatch, diagnostic, ok := p.matchMessage(&icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: quote}})
	if !ok || !diagnostic || cookieMatch || key.id != 0x5054 || key.seq != 7 {
		t.Fatalf("matchMessage() = %#v, %t, %t, %t", key, cookieMatch, diagnostic, ok)
	}
	if !p.pendingMatches(pendingPing{target: net.ParseIP("2606:4700:4700::1111")}, nil, true, &icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: quote}}) {
		t.Fatal("IPv6 diagnostic with an extension header did not match its target")
	}
}
