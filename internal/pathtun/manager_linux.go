//go:build linux

// Package pathtun owns the Gateway's ICMP-only TUN device. It deliberately
// accepts only public ICMP echo requests; all TCP and UDP stay with Xray's
// proxya-tun.
package pathtun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"xray-proxya/internal/pathd"
	"xray-proxya/pkg/utils"
)

const (
	Name                  = "path-tun"
	maxConcurrentRequests = 32
)

type Manager struct {
	file  *os.File
	relay func(net.IP, int, []byte, bool) pathd.ProbeResult
	close sync.Once
}

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

func Start(relay func(net.IP, int, []byte, bool) pathd.ProbeResult) (*Manager, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open path TUN: %w", err)
	}
	var req ifreq
	copy(req.Name[:], Name)
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create %s: %w", Name, errno)
	}
	m := &Manager{file: os.NewFile(uintptr(fd), Name), relay: relay}
	go m.serve()
	return m, nil
}

func (m *Manager) Close() error {
	var err error
	m.close.Do(func() { err = m.file.Close() })
	return err
}

func (m *Manager) serve() {
	buf := make([]byte, 9216)
	requestSem := make(chan struct{}, maxConcurrentRequests)
	for {
		n, err := m.file.Read(buf)
		if err != nil {
			return
		}
		req, ok := parseRequest(buf[:n])
		if !ok {
			continue
		}
		select {
		case requestSem <- struct{}{}:
		default:
			continue
		}
		go func(request request) {
			defer func() { <-requestSem }()
			result := m.relay(request.destination, int(request.ttl), request.echoData, request.dontFragment)
			var response []byte
			if result.Echo {
				response = request.echoReply()
			} else if result.ICMPType != 0 {
				response = request.diagnostic(result)
			}
			if len(response) > 0 {
				_, _ = m.file.Write(response)
			}
		}(req)
	}
}

type request struct {
	v6                  bool
	source, destination net.IP
	ttl                 byte
	icmpOffset          int
	icmp                []byte
	original            []byte
	echoData            []byte
	dontFragment        bool
}

func parseRequest(packet []byte) (request, bool) {
	if len(packet) < 28 {
		return request{}, false
	}
	if packet[0]>>4 == 4 {
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl+8 || packet[9] != unix.IPPROTO_ICMP || packet[ihl] != 8 || packet[ihl+1] != 0 {
			return request{}, false
		}
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if total < ihl+8 || total > len(packet) {
			return request{}, false
		}
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if fragment&0x2000 != 0 || fragment&0x1fff != 0 {
			return request{}, false
		}
		destination := net.IPv4(packet[16], packet[17], packet[18], packet[19])
		if !pathd.IsPublicTarget(destination) {
			return request{}, false
		}
		icmp := append([]byte(nil), packet[ihl:total]...)
		df := binary.BigEndian.Uint16(packet[6:8])&0x4000 != 0
		return request{source: net.IPv4(packet[12], packet[13], packet[14], packet[15]), destination: destination, ttl: packet[8], icmp: icmp, original: append([]byte(nil), packet[:total]...), echoData: append([]byte(nil), icmp[8:]...), dontFragment: df}, true
	}
	if packet[0]>>4 != 6 {
		return request{}, false
	}
	icmpOffset, total, ok := utils.IPv6PayloadOffset(packet, unix.IPPROTO_ICMPV6)
	if !ok || total < icmpOffset+8 || packet[icmpOffset] != 128 || packet[icmpOffset+1] != 0 {
		return request{}, false
	}
	destination := append(net.IP(nil), packet[24:40]...)
	if !pathd.IsPublicTarget(destination) {
		return request{}, false
	}
	icmp := append([]byte(nil), packet[icmpOffset:total]...)
	return request{v6: true, source: append(net.IP(nil), packet[8:24]...), destination: destination, ttl: packet[7], icmpOffset: icmpOffset, icmp: icmp, original: append([]byte(nil), packet[:total]...), echoData: append([]byte(nil), icmp[8:]...)}, true
}

func (r request) echoReply() []byte {
	icmp := append([]byte(nil), r.icmp...)
	if r.v6 {
		icmp[0], icmp[1], icmp[2], icmp[3] = 129, 0, 0, 0
		packet := make([]byte, 40+len(icmp))
		packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_ICMPV6, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(icmp)))
		copy(packet[8:24], r.destination.To16())
		copy(packet[24:40], r.source.To16())
		binary.BigEndian.PutUint16(icmp[2:4], checksumIPv6(packet[8:24], packet[24:40], icmp))
		copy(packet[40:], icmp)
		return packet
	}
	icmp[0], icmp[1], icmp[2], icmp[3] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packet := make([]byte, 20+len(icmp))
	packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], r.destination.To4())
	copy(packet[16:20], r.source.To4())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	copy(packet[20:], icmp)
	return packet
}

func (r request) diagnostic(result pathd.ProbeResult) []byte {
	if r.v6 {
		if result.ICMPType < 1 || result.ICMPType > 4 {
			return nil
		}
		quote := r.original
		quoteLimit := 48
		if r.icmpOffset > 0 && r.icmpOffset+8 > quoteLimit {
			quoteLimit = r.icmpOffset + 8
		}
		if len(quote) > quoteLimit {
			quote = quote[:quoteLimit]
		}
		icmp := make([]byte, 8+len(quote))
		icmp[0], icmp[1] = result.ICMPType, result.ICMPCode
		if result.ICMPType == 2 && result.MTU > 0 {
			binary.BigEndian.PutUint32(icmp[4:8], uint32(result.MTU))
		}
		copy(icmp[8:], quote)
		responder := result.Responder.To16()
		if responder == nil {
			responder = r.destination.To16()
		}
		packet := make([]byte, 40+len(icmp))
		packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_ICMPV6, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(icmp)))
		copy(packet[8:24], responder)
		copy(packet[24:40], r.source.To16())
		binary.BigEndian.PutUint16(icmp[2:4], checksumIPv6(packet[8:24], packet[24:40], icmp))
		copy(packet[40:], icmp)
		return packet
	}
	if result.ICMPType != 3 && result.ICMPType != 11 && result.ICMPType != 12 {
		return nil
	}
	quote := r.original
	ihl := int(quote[0]&0x0f) * 4
	if len(quote) > ihl+8 {
		quote = quote[:ihl+8]
	}
	icmp := make([]byte, 8+len(quote))
	icmp[0], icmp[1] = result.ICMPType, result.ICMPCode
	if result.ICMPType == 3 && result.ICMPCode == 4 && result.MTU > 0 {
		binary.BigEndian.PutUint16(icmp[6:8], uint16(result.MTU))
	}
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	responder := result.Responder.To4()
	if responder == nil {
		responder = r.destination.To4()
	}
	packet := make([]byte, 20+len(icmp))
	packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], responder)
	copy(packet[16:20], r.source.To4())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	copy(packet[20:], icmp)
	return packet
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
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
func checksumIPv6(source, destination, data []byte) uint16 {
	pseudo := make([]byte, 40+len(data))
	copy(pseudo, source)
	copy(pseudo[16:], destination)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(data)))
	pseudo[39] = unix.IPPROTO_ICMPV6
	copy(pseudo[40:], data)
	return checksum(pseudo)
}
