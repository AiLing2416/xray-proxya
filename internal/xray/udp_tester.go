package xray

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	DNSTypeA    uint16 = 1
	DNSTypeAAAA uint16 = 28
)

// TestUDP sends a DNS query (8.8.8.8:53) via SOCKS5 UDP Associate to test UDP support.
func TestUDP(socksAddr string, user, pass string) (time.Duration, error) {
	// 1. Establish TCP connection to SOCKS5 server
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// 2. SOCKS5 Handshake (Method selection)
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return 0, err
	}
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil {
		return 0, err
	}

	method := buf[1]
	if method == 0x02 {
		// 3. User/Pass Auth
		authPayload := append([]byte{0x01, byte(len(user))}, []byte(user)...)
		authPayload = append(authPayload, byte(len(pass)))
		authPayload = append(authPayload, []byte(pass)...)
		if _, err := conn.Write(authPayload); err != nil {
			return 0, err
		}
		if _, err := conn.Read(buf); err != nil || buf[1] != 0x00 {
			return 0, fmt.Errorf("socks5 auth failed")
		}
	} else if method != 0x00 {
		return 0, fmt.Errorf("socks5 handshake failed: unsupported method %d", method)
	}

	// 4. UDP ASSOCIATE Request
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return 0, err
	}
	n, err := conn.Read(buf)
	if err != nil || n < 10 || buf[1] != 0x00 {
		return 0, fmt.Errorf("udp associate failed")
	}

	// Parse Relay Address correctly based on ATYP
	var relayIP string
	var relayPort int
	atyp := buf[3]
	pos := 4

	switch atyp {
	case 0x01: // IPv4
		relayIP = net.IP(buf[pos : pos+4]).String()
		pos += 4
	case 0x03: // Domain
		l := int(buf[pos])
		relayIP = string(buf[pos+1 : pos+1+l])
		pos += 1 + l
	case 0x04: // IPv6
		relayIP = "[" + net.IP(buf[pos:pos+16]).String() + "]"
		pos += 16
	default:
		return 0, fmt.Errorf("unknown ATYP: %d", atyp)
	}
	relayPort = int(buf[pos])<<8 | int(buf[pos+1])
	relayAddr := fmt.Sprintf("%s:%d", relayIP, relayPort)

	// If relay IP is all zeros, use the SOCKS server's IP
	if strings.Contains(relayIP, "0.0.0.0") || strings.Contains(relayIP, "::") {
		host, _, _ := net.SplitHostPort(socksAddr)
		relayAddr = fmt.Sprintf("%s:%d", host, relayPort)
	}

	// 5. Send UDP Data to Relay
	udpConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		return 0, err
	}
	defer udpConn.Close()

	// SOCKS5 UDP Header + DNS Query (Standard 8.8.8.8:53 query for google.com)
	header := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0, 53}
	dnsQuery := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	payload := append(header, dnsQuery...)

	start := time.Now()
	if _, err := udpConn.Write(payload); err != nil {
		return 0, err
	}

	udpConn.SetReadDeadline(time.Now().Add(4 * time.Second))
	rn, err := udpConn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("read error: %v (relay: %s)", err, relayAddr)
	}
	if rn < 10 {
		return 0, fmt.Errorf("truncated response")
	}

	return time.Since(start), nil
}

func ResolveDNS(serverAddr string, domain string, qtype uint16) ([]string, time.Duration, error) {
	conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	query, err := buildDNSQuery(domain, qtype)
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, 1500)
	if err := conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return nil, 0, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}

	answers, err := parseDNSAnswers(buf[:n], qtype)
	if err != nil {
		return nil, 0, err
	}
	return answers, time.Since(start), nil
}

func ResolveDNSTCP(serverAddr string, domain string, qtype uint16) ([]string, time.Duration, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	query, err := buildDNSQuery(domain, qtype)
	if err != nil {
		return nil, 0, err
	}

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	start := time.Now()
	if _, err := conn.Write(frame); err != nil {
		return nil, 0, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return nil, 0, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, 0, err
	}
	respLen := int(binary.BigEndian.Uint16(header))
	if respLen <= 0 {
		return nil, 0, fmt.Errorf("empty dns tcp response")
	}
	packet := make([]byte, respLen)
	if _, err := io.ReadFull(conn, packet); err != nil {
		return nil, 0, err
	}

	answers, err := parseDNSAnswers(packet, qtype)
	if err != nil {
		return nil, 0, err
	}
	return answers, time.Since(start), nil
}

func buildDNSQuery(domain string, qtype uint16) ([]byte, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], 0x1234)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)

	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid domain label %q", label)
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00)

	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], qtype)
	binary.BigEndian.PutUint16(qtail[2:4], 1)
	packet = append(packet, qtail...)
	return packet, nil
}

func parseDNSAnswers(packet []byte, qtype uint16) ([]string, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("truncated dns response")
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
