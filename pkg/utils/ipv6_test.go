package utils

import (
	"encoding/binary"
	"testing"
)

func TestIPv6PayloadOffsetSkipsHopByHopHeader(t *testing.T) {
	packet := make([]byte, 40+8+8)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	packet[6] = ipv6NextHopByHop
	packet[40], packet[41] = ipv6NextICMP, 0
	packet[48] = 128

	offset, end, ok := IPv6PayloadOffset(packet, ipv6NextICMP)
	if !ok || offset != 48 || end != len(packet) {
		t.Fatalf("IPv6PayloadOffset() = (%d, %d, %t), want (48, %d, true)", offset, end, ok, len(packet))
	}
}

func TestIPv6PayloadOffsetRejectsNonAtomicFragment(t *testing.T) {
	packet := make([]byte, 40+8+8)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	packet[6] = ipv6NextFragment
	packet[40] = ipv6NextICMP
	binary.BigEndian.PutUint16(packet[42:44], 1)

	if _, _, ok := IPv6PayloadOffset(packet, ipv6NextICMP); ok {
		t.Fatal("non-atomic IPv6 fragment was accepted")
	}
}

func TestIPv6QuotePayloadOffsetAcceptsTruncatedQuote(t *testing.T) {
	packet := make([]byte, 40+8+8)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 64)
	packet[6] = ipv6NextHopByHop
	packet[40], packet[41] = ipv6NextICMP, 0
	packet[48] = 128

	offset, end, ok := IPv6QuotePayloadOffset(packet, ipv6NextICMP)
	if !ok || offset != 48 || end != len(packet) {
		t.Fatalf("IPv6QuotePayloadOffset() = (%d, %d, %t), want (48, %d, true)", offset, end, ok, len(packet))
	}
}
