// Package syntheticping answers LAN ICMP echo requests after verifying that
// the requested public IP is reachable through the gateway's SOCKS relay.
package syntheticping

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
	"xray-proxya/pkg/utils"
)

var defaultPorts = []int{443, 80, 22, 8443, 8080, 51820, 25565}

type Manager struct {
	fd     int
	iface  *net.Interface
	dialer *utils.SOCKS5Dialer
	stop   chan struct{}
}

func Start(interfaceName, socksAddress string) (*Manager, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find LAN interface: %w", err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("LAN interface %s has no ethernet address", interfaceName)
	}
	// A failed port must not hold a ping request for the normal SOCKS timeout.
	// The common ports are tried in order, with HTTPS and HTTP first.
	dialer, err := utils.NewSOCKS5DialerWithTimeout(socksAddress, 2*time.Second)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return nil, fmt.Errorf("open packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind packet socket: %w", err)
	}

	m := &Manager{fd: fd, iface: iface, dialer: dialer, stop: make(chan struct{})}
	go m.serve()
	return m, nil
}

func (m *Manager) Close() error {
	select {
	case <-m.stop:
		return nil
	default:
		close(m.stop)
		return unix.Close(m.fd)
	}
}

func (m *Manager) serve() {
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(m.fd, buf, 0)
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
				continue
			}
		}
		packet, ok := parseEchoRequest(buf[:n], m.iface.HardwareAddr)
		if !ok {
			continue
		}
		go m.handle(packet)
	}
}

func (m *Manager) handle(request echoRequest) {
	if !tcpReachable(m.dialer, request.destination) {
		return
	}
	reply := buildEchoReply(request, m.iface.HardwareAddr)
	if len(reply) == 0 {
		return
	}
	addr := &unix.SockaddrLinklayer{Ifindex: m.iface.Index, Halen: 6}
	copy(addr.Addr[:], request.sourceMAC)
	_ = unix.Sendto(m.fd, reply, 0, addr)
}

func tcpReachable(dialer *utils.SOCKS5Dialer, destination net.IP) bool {
	for _, port := range defaultPorts {
		conn, err := dialer.Dial("tcp", net.JoinHostPort(destination.String(), fmt.Sprintf("%d", port)))
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

type echoRequest struct {
	sourceMAC   net.HardwareAddr
	destination net.IP
	source      net.IP
	ttl         byte
	icmp        []byte
}

func parseEchoRequest(frame []byte, gatewayMAC net.HardwareAddr) (echoRequest, bool) {
	if len(frame) < 14+20+8 || binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
		return echoRequest{}, false
	}
	if !equalMAC(frame[0:6], gatewayMAC) {
		return echoRequest{}, false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+8 || ip[9] != unix.IPPROTO_ICMP {
		return echoRequest{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl+8 || len(ip) < totalLen {
		return echoRequest{}, false
	}
	icmp := append([]byte(nil), ip[ihl:totalLen]...)
	if icmp[0] != 8 || icmp[1] != 0 {
		return echoRequest{}, false
	}
	destination := net.IPv4(ip[16], ip[17], ip[18], ip[19])
	if !isPublicIPv4(destination) {
		return echoRequest{}, false
	}
	return echoRequest{
		sourceMAC:   append(net.HardwareAddr(nil), frame[6:12]...),
		destination: destination,
		source:      net.IPv4(ip[12], ip[13], ip[14], ip[15]),
		ttl:         ip[8],
		icmp:        icmp,
	}, true
}

func buildEchoReply(request echoRequest, gatewayMAC net.HardwareAddr) []byte {
	if len(request.sourceMAC) != 6 || len(gatewayMAC) != 6 || len(request.icmp) < 8 {
		return nil
	}
	frame := make([]byte, 14+20+len(request.icmp))
	copy(frame[0:6], request.sourceMAC)
	copy(frame[6:12], gatewayMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, request.ttl, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(request.icmp)))
	copy(ip[12:16], request.destination.To4())
	copy(ip[16:20], request.source.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	icmp := frame[34:]
	copy(icmp, request.icmp)
	icmp[0], icmp[1], icmp[2], icmp[3] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return frame
}

func isPublicIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || v4[0] == 0 || v4[0] >= 224 || v4[0] == 10 || v4[0] == 127 {
		return false
	}
	if v4[0] == 100 && v4[1]&0xc0 == 0x40 {
		return false
	}
	if v4[0] == 169 && v4[1] == 254 {
		return false
	}
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return false
	}
	return !(v4[0] == 192 && v4[1] == 168)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func equalMAC(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }
