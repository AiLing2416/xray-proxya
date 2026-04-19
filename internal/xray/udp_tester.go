package xray

import (
	"fmt"
	"net"
	"strings"
	"time"
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
