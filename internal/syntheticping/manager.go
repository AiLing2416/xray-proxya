// Package syntheticping answers LAN ICMP echo requests after verifying that
// the requested public IP is reachable through the gateway's SOCKS relay.
package syntheticping

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/sys/unix"
	"xray-proxya/internal/pathd"
	"xray-proxya/pkg/utils"
)

var defaultPorts = []int{443, 80, 22, 8443, 8080, 51820, 25565}

type Manager struct {
	fd    int
	iface *net.Interface
	probe func(net.IP, int) pathd.ProbeResult
	stop  chan struct{}
}

func Start(interfaceName, socksAddress string) (*Manager, error) {
	dialer, err := utils.NewSOCKS5DialerWithTimeout(socksAddress, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return StartWithProbe(interfaceName, func(destination net.IP, _ int) pathd.ProbeResult {
		return pathd.ProbeResult{Echo: tcpReachable(dialer, destination)}
	})
}

// StartWithProbe lets PathLink provide a real remote ICMP result while keeping
// all Ethernet interception and echo-reply construction in this package.
func StartWithProbe(interfaceName string, probe func(net.IP, int) pathd.ProbeResult) (*Manager, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find LAN interface: %w", err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("LAN interface %s has no ethernet address", interfaceName)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("open packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind packet socket: %w", err)
	}

	m := &Manager{fd: fd, iface: iface, probe: probe, stop: make(chan struct{})}
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
	result := m.probe(request.destination, int(request.ttl))
	var reply []byte
	if result.Echo {
		reply = buildEchoReply(request, m.iface.HardwareAddr)
	} else if result.ICMPType != 0 {
		reply = buildICMPError(request, m.iface.HardwareAddr, result)
	}
	if len(reply) == 0 {
		return
	}
	addr := &unix.SockaddrLinklayer{Ifindex: m.iface.Index, Halen: 6}
	copy(addr.Addr[:], request.sourceMAC)
	_ = unix.Sendto(m.fd, reply, 0, addr)
}

func buildICMPError(request echoRequest, gatewayMAC net.HardwareAddr, result pathd.ProbeResult) []byte {
	if request.destination.To4() == nil {
		return buildIPv6ICMPError(request, gatewayMAC, result)
	}
	if result.ICMPType != 3 && result.ICMPType != 11 && result.ICMPType != 12 {
		return nil
	}
	responder := result.Responder.To4()
	if responder == nil {
		responder = request.destination.To4()
	}
	inner := make([]byte, 20+8)
	inner[0], inner[8], inner[9] = 0x45, request.ttl, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	copy(inner[12:16], request.source.To4())
	copy(inner[16:20], request.destination.To4())
	binary.BigEndian.PutUint16(inner[10:12], checksum(inner))
	copy(inner[20:], request.icmp[:8])
	frame := make([]byte, 14+20+8+len(inner))
	copy(frame[0:6], request.sourceMAC)
	copy(frame[6:12], gatewayMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, request.ttl, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(inner)))
	copy(ip[12:16], responder)
	copy(ip[16:20], request.source.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	icmp := frame[34:]
	icmp[0], icmp[1] = result.ICMPType, result.ICMPCode
	if result.ICMPType == 3 && result.ICMPCode == 4 && result.MTU > 0 {
		binary.BigEndian.PutUint16(icmp[6:8], uint16(result.MTU))
	}
	copy(icmp[8:], inner)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return frame
}

func buildIPv6ICMPError(request echoRequest, gatewayMAC net.HardwareAddr, result pathd.ProbeResult) []byte {
	if result.ICMPType < 1 || result.ICMPType > 4 {
		return nil
	}
	responder := result.Responder.To16()
	if responder == nil {
		responder = request.destination.To16()
	}
	inner := make([]byte, 40+8)
	inner[0], inner[6], inner[7] = 0x60, unix.IPPROTO_ICMPV6, request.ttl
	binary.BigEndian.PutUint16(inner[4:6], 8)
	copy(inner[8:24], request.source.To16())
	copy(inner[24:40], request.destination.To16())
	copy(inner[40:], request.icmp[:8])
	frame := make([]byte, 14+40+8+len(inner))
	copy(frame[0:6], request.sourceMAC)
	copy(frame[6:12], gatewayMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IPV6)
	ip := frame[14:54]
	ip[0], ip[6], ip[7] = 0x60, unix.IPPROTO_ICMPV6, request.ttl
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(inner)))
	copy(ip[8:24], responder)
	copy(ip[24:40], request.source.To16())
	icmp := frame[54:]
	icmp[0], icmp[1] = result.ICMPType, result.ICMPCode
	if result.ICMPType == 2 && result.MTU > 0 {
		binary.BigEndian.PutUint32(icmp[4:8], uint32(result.MTU))
	}
	copy(icmp[8:], inner)
	binary.BigEndian.PutUint16(icmp[2:4], checksumIPv6(ip[8:24], ip[24:40], icmp))
	return frame
}

func tcpReachable(dialer *utils.SOCKS5Dialer, destination net.IP) bool {
	for _, port := range defaultPorts {
		conn, err := dialer.Dial("tcp", net.JoinHostPort(destination.String(), fmt.Sprintf("%d", port)))
		if err != nil {
			continue
		}
		if verifyEndpoint(conn, port) {
			return true
		}
	}
	return false
}

// verifyEndpoint requires traffic from the target, not merely a successful
// SOCKS CONNECT response. Some proxy transports acknowledge CONNECT after the
// upstream relay accepts it, before that relay has opened the destination.
func verifyEndpoint(conn net.Conn, port int) bool {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return false
	}

	switch port {
	case 443, 8443:
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // The IP is the probe target, not an identity check.
		return tlsConn.Handshake() == nil
	case 80, 8080:
		if _, err := io.WriteString(conn, "HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n"); err != nil {
			return false
		}
	case 22:
		// SSH servers send their identification string immediately.
	case 25565:
		// Legacy Minecraft server-list ping; modern servers still answer it.
		if _, err := conn.Write([]byte{0xfe, 0x01}); err != nil {
			return false
		}
	default:
		// A TCP probe cannot establish reachability of a UDP service such as
		// WireGuard. Keep it as a TCP fallback only when it sends a banner.
	}

	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	return err == nil
}

type echoRequest struct {
	sourceMAC   net.HardwareAddr
	destination net.IP
	source      net.IP
	ttl         byte
	icmp        []byte
}

func parseEchoRequest(frame []byte, gatewayMAC net.HardwareAddr) (echoRequest, bool) {
	if len(frame) < 14+8 || !equalMAC(frame[0:6], gatewayMAC) {
		return echoRequest{}, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IPV6 {
		return parseIPv6EchoRequest(frame, gatewayMAC)
	}
	if binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP || len(frame) < 14+20+8 {
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
	if !pathd.IsPublicTarget(destination) {
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

func parseIPv6EchoRequest(frame []byte, gatewayMAC net.HardwareAddr) (echoRequest, bool) {
	ip := frame[14:]
	if len(ip) < 48 || ip[0]>>4 != 6 || ip[6] != unix.IPPROTO_ICMPV6 {
		return echoRequest{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if payloadLen < 8 || len(ip) < 40+payloadLen {
		return echoRequest{}, false
	}
	icmp := append([]byte(nil), ip[40:40+payloadLen]...)
	if icmp[0] != 128 || icmp[1] != 0 {
		return echoRequest{}, false
	}
	destination := append(net.IP(nil), ip[24:40]...)
	if !pathd.IsPublicTarget(destination) {
		return echoRequest{}, false
	}
	return echoRequest{sourceMAC: append(net.HardwareAddr(nil), frame[6:12]...), destination: destination, source: append(net.IP(nil), ip[8:24]...), ttl: ip[7], icmp: icmp}, true
}

func buildEchoReply(request echoRequest, gatewayMAC net.HardwareAddr) []byte {
	if len(request.sourceMAC) != 6 || len(gatewayMAC) != 6 || len(request.icmp) < 8 {
		return nil
	}
	if request.destination.To4() == nil {
		return buildIPv6EchoReply(request, gatewayMAC)
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

func buildIPv6EchoReply(request echoRequest, gatewayMAC net.HardwareAddr) []byte {
	if request.source.To16() == nil || request.destination.To16() == nil {
		return nil
	}
	frame := make([]byte, 14+40+len(request.icmp))
	copy(frame[0:6], request.sourceMAC)
	copy(frame[6:12], gatewayMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IPV6)
	ip := frame[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(request.icmp)))
	ip[6] = unix.IPPROTO_ICMPV6
	ip[7] = request.ttl
	copy(ip[8:24], request.destination.To16())
	copy(ip[24:40], request.source.To16())
	icmp := frame[54:]
	copy(icmp, request.icmp)
	icmp[0], icmp[1], icmp[2], icmp[3] = 129, 0, 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], checksumIPv6(ip[8:24], ip[24:40], icmp))
	return frame
}

func isPublicIPv4(ip net.IP) bool {
	return pathd.IsPublicTarget(ip)
}

func isPublicIPv6(ip net.IP) bool {
	return pathd.IsPublicTarget(ip)
}

func checksumIPv6(source, destination, data []byte) uint16 {
	pseudo := make([]byte, 40+len(data))
	copy(pseudo, source)
	copy(pseudo[16:], destination)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(data)))
	pseudo[39] = unix.IPPROTO_ICMPV6
	copy(pseudo[40:], data)
	return checksum(pseudo)
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
