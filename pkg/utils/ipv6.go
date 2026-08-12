package utils

import "encoding/binary"

const (
	ipv6NextHopByHop    = 0
	ipv6NextRouting     = 43
	ipv6NextFragment    = 44
	ipv6NextAH          = 51
	ipv6NextICMP        = 58
	ipv6NextNoNext      = 59
	ipv6NextDestination = 60
)

// IPv6PayloadOffset locates a transport payload after common IPv6 extension
// headers. It returns the payload offset and the end of the IPv6 packet.
// Fragmented packets are rejected unless they use an atomic fragment header,
// because an incomplete Echo Request cannot be safely reconstructed here.
func IPv6PayloadOffset(packet []byte, protocol byte) (offset, end int, ok bool) {
	return ipv6PayloadOffset(packet, protocol, false)
}

// IPv6QuotePayloadOffset is like IPv6PayloadOffset but accepts an ICMP
// diagnostic quote that may end before the original packet's declared end.
func IPv6QuotePayloadOffset(packet []byte, protocol byte) (offset, end int, ok bool) {
	return ipv6PayloadOffset(packet, protocol, true)
}

func ipv6PayloadOffset(packet []byte, protocol byte, allowTruncated bool) (offset, end int, ok bool) {
	if len(packet) < 40 || packet[0]>>4 != 6 {
		return 0, 0, false
	}
	end = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	if end < 40 {
		return 0, 0, false
	}
	if end > len(packet) {
		if !allowTruncated {
			return 0, 0, false
		}
		end = len(packet)
	}
	if end < 40 {
		return 0, 0, false
	}
	next := packet[6]
	offset = 40
	for depth := 0; depth < 16; depth++ {
		if next == protocol {
			return offset, end, true
		}
		if next == ipv6NextNoNext {
			return 0, 0, false
		}
		var headerLen int
		switch next {
		case ipv6NextHopByHop, ipv6NextRouting, ipv6NextDestination:
			if offset+2 > end {
				return 0, 0, false
			}
			headerLen = (int(packet[offset+1]) + 1) * 8
		case ipv6NextFragment:
			if offset+8 > end {
				return 0, 0, false
			}
			fragment := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			if fragment&0xfff9 != 0 {
				return 0, 0, false
			}
			headerLen = 8
		case ipv6NextAH:
			if offset+2 > end {
				return 0, 0, false
			}
			headerLen = (int(packet[offset+1]) + 2) * 4
		default:
			return 0, 0, false
		}
		if headerLen < 8 || offset+headerLen > end {
			return 0, 0, false
		}
		next = packet[offset]
		offset += headerLen
	}
	return 0, 0, false
}
