package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// SOCKS5UDPConn manages a SOCKS5 UDP Associate session over a control TCP connection.
type SOCKS5UDPConn struct {
	tcpConn   net.Conn
	udpConn   net.Conn
	relayAddr string
}

// DialSOCKS5UDP establishes a SOCKS5 control connection, requests a UDP Associate,
// and returns a SOCKS5UDPConn ready to send and receive UDP datagrams.
func DialSOCKS5UDP(socksAddr string, timeout time.Duration) (*SOCKS5UDPConn, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// 1. Establish TCP connection to SOCKS5 server
	tcpConn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("socks5 tcp dial: %w", err)
	}

	if err := tcpConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		tcpConn.Close()
		return nil, err
	}

	// 2. SOCKS5 Handshake (Method negotiation: No Auth / User-Pass supported)
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth write: %w", err)
	}

	authBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authBuf); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth read: %w", err)
	}
	if authBuf[0] != 0x05 || authBuf[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %v", authBuf)
	}

	// 3. UDP ASSOCIATE Request
	if _, err := tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("udp associate request: %w", err)
	}

	respBuf := make([]byte, 256)
	n, err := tcpConn.Read(respBuf)
	if err != nil || n < 10 || respBuf[0] != 0x05 || respBuf[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("udp associate failed (n=%d, err=%v)", n, err)
	}

	// 4. Parse Relay BND.ADDR and BND.PORT
	var relayIP string
	var relayPort int
	atyp := respBuf[3]
	pos := 4

	switch atyp {
	case 0x01: // IPv4
		if n < pos+4+2 {
			tcpConn.Close()
			return nil, fmt.Errorf("truncated ipv4 udp associate reply")
		}
		relayIP = net.IP(respBuf[pos : pos+4]).String()
		pos += 4
	case 0x03: // Domain
		l := int(respBuf[pos])
		pos++
		if n < pos+l+2 {
			tcpConn.Close()
			return nil, fmt.Errorf("truncated domain udp associate reply")
		}
		relayIP = string(respBuf[pos : pos+l])
		pos += l
	case 0x04: // IPv6
		if n < pos+16+2 {
			tcpConn.Close()
			return nil, fmt.Errorf("truncated ipv6 udp associate reply")
		}
		relayIP = net.IP(respBuf[pos : pos+16]).String()
		pos += 16
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("unsupported atyp in udp associate reply: %d", atyp)
	}

	relayPort = int(binary.BigEndian.Uint16(respBuf[pos : pos+2]))
	relayAddr := net.JoinHostPort(relayIP, strconv.Itoa(relayPort))

	// If relay IP is all zeroes (0.0.0.0 or ::), use the SOCKS server's host IP
	if strings.Contains(relayIP, "0.0.0.0") || strings.Contains(relayIP, "::") || relayIP == "" {
		host, _, err := net.SplitHostPort(socksAddr)
		if err == nil && host != "" {
			relayAddr = net.JoinHostPort(host, strconv.Itoa(relayPort))
		}
	}

	// 5. Connect UDP to the SOCKS5 UDP relay address
	udpConn, err := net.DialTimeout("udp", relayAddr, timeout)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("udp dial to relay %s: %w", relayAddr, err)
	}

	// Remove TCP deadline so association remains alive
	_ = tcpConn.SetDeadline(time.Time{})

	return &SOCKS5UDPConn{
		tcpConn:   tcpConn,
		udpConn:   udpConn,
		relayAddr: relayAddr,
	}, nil
}

// BuildSOCKS5UDPHeader builds a RFC 1928 SOCKS5 UDP header for the target destination.
func BuildSOCKS5UDPHeader(targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	header := []byte{0x00, 0x00, 0x00} // RSV (2) + FRAG (1)
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		header = append(header, 0x01)
		header = append(header, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		header = append(header, 0x04)
		header = append(header, ip.To16()...)
	default:
		if len(host) > 255 {
			return nil, fmt.Errorf("target hostname too long")
		}
		header = append(header, 0x03, byte(len(host)))
		header = append(header, host...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	header = append(header, portBytes...)
	return header, nil
}

// StripSOCKS5UDPHeader strips the RFC 1928 SOCKS5 UDP header from received datagram.
func StripSOCKS5UDPHeader(packet []byte) ([]byte, error) {
	if len(packet) < 10 {
		return nil, fmt.Errorf("packet too short for socks5 udp header: %d bytes", len(packet))
	}
	atyp := packet[3]
	headerLen := 0
	switch atyp {
	case 0x01: // IPv4: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + PORT(2) = 10
		headerLen = 10
	case 0x04: // IPv6: RSV(2) + FRAG(1) + ATYP(1) + IP(16) + PORT(2) = 22
		headerLen = 22
	case 0x03: // Domain: RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + DOMAIN(L) + PORT(2) = 7 + L
		domainLen := int(packet[4])
		headerLen = 7 + domainLen
	default:
		return nil, fmt.Errorf("unknown atyp %d in received socks5 udp datagram", atyp)
	}

	if len(packet) < headerLen {
		return nil, fmt.Errorf("packet truncated: len=%d < headerLen=%d", len(packet), headerLen)
	}
	return packet[headerLen:], nil
}

// SendAndReceive sends a UDP payload to the target destination through the SOCKS5 UDP relay,
// waits for a response, and returns the response payload along with the round-trip duration.
func (c *SOCKS5UDPConn) SendAndReceive(targetAddr string, payload []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	if c == nil || c.udpConn == nil {
		return nil, 0, fmt.Errorf("nil socks5 udp connection")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	header, err := BuildSOCKS5UDPHeader(targetAddr)
	if err != nil {
		return nil, 0, err
	}

	frame := append(header, payload...)

	if err := c.udpConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, err
	}

	start := time.Now()
	if _, err := c.udpConn.Write(frame); err != nil {
		return nil, 0, fmt.Errorf("udp write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := c.udpConn.Read(buf)
	duration := time.Since(start)
	if err != nil {
		return nil, duration, fmt.Errorf("udp read: %w", err)
	}

	data, err := StripSOCKS5UDPHeader(buf[:n])
	if err != nil {
		return nil, duration, err
	}
	return data, duration, nil
}

// Close closes both the UDP socket and the underlying SOCKS5 control TCP connection.
func (c *SOCKS5UDPConn) Close() error {
	var err1, err2 error
	if c.udpConn != nil {
		err1 = c.udpConn.Close()
	}
	if c.tcpConn != nil {
		err2 = c.tcpConn.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}
