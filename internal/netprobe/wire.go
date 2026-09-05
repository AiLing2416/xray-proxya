package netprobe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// --- STUN (RFC 5389) Wire Protocol ---

// BuildSTUNBindingRequest constructs a 20-byte STUN Binding Request packet.
func BuildSTUNBindingRequest() []byte {
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)     // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0x0000)     // Message Length: 0
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442) // Magic Cookie
	_, _ = rand.Read(req[8:20])                      // Transaction ID (12 bytes)
	return req
}

// ValidateSTUNBindingResponse validates that a received payload is an RFC 5389 Binding Success Response.
func ValidateSTUNBindingResponse(resp []byte) error {
	if len(resp) < 20 {
		return fmt.Errorf("truncated STUN packet: length %d < 20", len(resp))
	}
	msgType := binary.BigEndian.Uint16(resp[0:2])
	cookie := binary.BigEndian.Uint32(resp[4:8])
	// 0x0101 = RFC 5389 Binding Success Response; 0x0111 = RFC 3489 Binding Response
	if (msgType == 0x0101 || msgType == 0x0111) && cookie == 0x2112A442 {
		return nil
	}
	return fmt.Errorf("invalid STUN response type 0x%04x (cookie 0x%08x)", msgType, cookie)
}

// --- NTP / SNTP (RFC 4330 / 5905) Wire Protocol ---

// BuildNTPRequest constructs a standard 48-byte NTP client request packet.
// Setting req[0] = 0x23 corresponds to LI=0, VN=4, Mode=3 (Client).
func BuildNTPRequest() []byte {
	req := make([]byte, 48)
	req[0] = 0x23
	return req
}

// ParseSNTPResponse parses a 48-byte SNTP response packet and calculates clock offset and RTT.
func ParseSNTPResponse(resp []byte, t0, t3 time.Time) (offset, rtt time.Duration, err error) {
	if len(resp) < 48 {
		return 0, 0, fmt.Errorf("truncated NTP packet (%d bytes)", len(resp))
	}

	// Transmit Timestamp (T2) located at bytes 40..47
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])

	if secs == 0 {
		return 0, 0, fmt.Errorf("invalid zero timestamp in NTP response")
	}

	// NTP Epoch is 1900-01-01; Unix Epoch is 1970-01-01 (70 years = 2208988800 seconds)
	const ntpEpochOffset = 2208988800
	unixSecs := int64(secs) - ntpEpochOffset
	nanosecs := (int64(frac) * 1e9) >> 32
	serverTime := time.Unix(unixSecs, nanosecs)

	// Round-trip time and clock offset calculation: Offset = (T2 - T0) - RTT/2
	rtt = t3.Sub(t0)
	offset = serverTime.Sub(t0.Add(rtt / 2))

	return offset, rtt, nil
}

// --- QUIC (RFC 9000) Initial Packet ---

// BuildQUICInitialPacket constructs an RFC 9000 QUIC Initial handshake packet padded to 1200 bytes.
func BuildQUICInitialPacket() []byte {
	packet := make([]byte, 1200)
	// Long Header: Header Form(1) | Fixed Bit(1) | Long Packet Type(00 Initial) -> 0xC0
	packet[0] = 0xC0
	// Version 1 (RFC 9000): 0x00000001
	binary.BigEndian.PutUint32(packet[1:5], 0x00000001)
	// DCID Length: 8
	packet[5] = 0x08
	_, _ = rand.Read(packet[6:14])
	// SCID Length: 8
	packet[14] = 0x08
	_, _ = rand.Read(packet[15:23])
	// Token Length: 0
	packet[23] = 0x00
	// Length (varint): 2-byte varint indicator 0x4490
	packet[24] = 0x44
	packet[25] = 0x90
	// Packet Number: 1
	packet[26] = 0x01
	return packet
}

// ValidateQUICResponse checks whether a received datagram is a valid QUIC response (Long/Short Header).
func ValidateQUICResponse(resp []byte) bool {
	return len(resp) > 0 && (resp[0]&0x80 != 0 || resp[0]&0x40 != 0)
}

// --- DNS Wire Query and Response (RFC 1035) ---

const (
	DNSTypeA    uint16 = 1
	DNSTypeAAAA uint16 = 28
)

// BuildDNSWireQuery serializes a standard DNS question packet into wire format.
func BuildDNSWireQuery(domain string, qtype uint16) ([]byte, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], 0x1234) // Transaction ID
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // Standard query with RD (Recursion Desired)
	binary.BigEndian.PutUint16(packet[4:6], 1)      // QDCOUNT = 1

	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid domain label %q", label)
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00) // Root null terminator

	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], qtype)
	binary.BigEndian.PutUint16(qtail[2:4], 1) // Class IN
	packet = append(packet, qtail...)
	return packet, nil
}

// ValidateDNSResponse checks if a received packet looks like a valid DNS response.
func ValidateDNSResponse(resp []byte) error {
	if len(resp) < 12 {
		return fmt.Errorf("dns response too short (%d bytes)", len(resp))
	}
	qr := (resp[2] & 0x80) != 0
	if !qr {
		return fmt.Errorf("not a dns response (QR bit not set)")
	}
	return nil
}

// ParseDNSAnswers parses answers from a DNS response packet for a specific query type.
func ParseDNSAnswers(packet []byte, qtype uint16) ([]string, error) {
	if err := ValidateDNSResponse(packet); err != nil {
		return nil, err
	}
	qdcount := int(binary.BigEndian.Uint16(packet[4:6]))
	ancount := int(binary.BigEndian.Uint16(packet[6:8]))
	offset := 12

	for i := 0; i < qdcount; i++ {
		var err error
		offset, err = skipDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		if offset+4 > len(packet) {
			return nil, fmt.Errorf("truncated dns question")
		}
		offset += 4
	}

	answers := make([]string, 0, ancount)
	for i := 0; i < ancount; i++ {
		var err error
		offset, err = skipDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		if offset+10 > len(packet) {
			return nil, fmt.Errorf("truncated dns answer")
		}

		recordType := binary.BigEndian.Uint16(packet[offset : offset+2])
		recordClass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		rdlength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if offset+rdlength > len(packet) {
			return nil, fmt.Errorf("truncated dns rdata")
		}

		if recordClass == 1 && recordType == qtype {
			switch qtype {
			case DNSTypeA:
				if rdlength == net.IPv4len {
					answers = append(answers, net.IP(packet[offset:offset+rdlength]).String())
				}
			case DNSTypeAAAA:
				if rdlength == net.IPv6len {
					answers = append(answers, net.IP(packet[offset:offset+rdlength]).String())
				}
			}
		}
		offset += rdlength
	}

	return answers, nil
}

func skipDNSName(packet []byte, offset int) (int, error) {
	for {
		if offset >= len(packet) {
			return 0, fmt.Errorf("truncated dns name")
		}
		length := int(packet[offset])
		if length == 0 {
			return offset + 1, nil
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(packet) {
				return 0, fmt.Errorf("truncated dns pointer")
			}
			return offset + 2, nil
		}
		offset++
		if offset+length > len(packet) {
			return 0, fmt.Errorf("truncated dns label")
		}
		offset += length
	}
}
