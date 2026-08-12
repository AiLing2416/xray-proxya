package pathd

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

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
