package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type SOCKS5Dialer struct {
	address string
	timeout time.Duration
}

func NewSOCKS5Dialer(address string) (*SOCKS5Dialer, error) {
	if address == "" {
		return nil, fmt.Errorf("empty SOCKS5 address")
	}
	return &SOCKS5Dialer{address: address, timeout: 10 * time.Second}, nil
}

func (d *SOCKS5Dialer) Dial(network, address string) (net.Conn, error) {
	if d == nil {
		return nil, fmt.Errorf("nil SOCKS5 dialer")
	}
	if network != "tcp" {
		return nil, fmt.Errorf("SOCKS5 dialer only supports tcp, got %s", network)
	}

	conn, err := net.DialTimeout("tcp", d.address, d.timeout)
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake rejected: %v", reply)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	default:
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect rejected: %d", head[1])
	}

	addrLen := 0
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(conn, size); err != nil {
			conn.Close()
			return nil, err
		}
		addrLen = int(size[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS5 address type %d", head[3])
	}

	if addrLen > 0 {
		discard := make([]byte, addrLen+2)
		if _, err := io.ReadFull(conn, discard); err != nil {
			conn.Close()
			return nil, err
		}
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
