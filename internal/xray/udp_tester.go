package xray

import (
	"fmt"
	"net"
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
	// Support both NO AUTH (0x00) and USER/PASS (0x02)
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return 0, err
	}
	buf := make([]byte, 256)
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
	// [VER, CMD, RSV, ATYP, ADDR, PORT] -> [0x05, 0x03, 0x00, 0x01, 0,0,0,0, 0,0]
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return 0, err
	}
	if _, err := conn.Read(buf); err != nil || buf[1] != 0x00 {
		return 0, fmt.Errorf("udp associate failed")
	}

	// Parse Relay Address (usually the same as socksAddr but with different port)
	relayIP := net.IP(buf[4:8])
	relayPort := int(buf[8])<<8 | int(buf[9])
	relayAddr := fmt.Sprintf("%s:%d", relayIP.String(), relayPort)
	if relayIP.IsUnspecified() || relayIP.String() == "::" {
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
	// Header: [RSV, RSV, FRAG, ATYP, ADDR, PORT] -> [0,0,0, 0x01, 8,8,8,8, 0,53]
	header := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0, 53}
	dnsQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer RRs, Authority RRs, Additional RRs
		0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // google.com
		0x00, 0x01, 0x00, 0x01, // Type A, Class IN
	}
	payload := append(header, dnsQuery...)

	start := time.Now()
	if _, err := udpConn.Write(payload); err != nil {
		return 0, err
	}

	udpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := udpConn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 10 {
		return 0, fmt.Errorf("truncated udp response")
	}

	return time.Since(start), nil
}
