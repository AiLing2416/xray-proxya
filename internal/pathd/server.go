package pathd

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// Server listens only on a local address. It has no HTTP or public listener.
type Server struct {
	listener  net.Listener
	token     string
	idle      time.Duration
	pinger4   *pinger
	pinger6   *pinger
	closed    chan struct{}
	closeOnce sync.Once
}

func Listen(address, token string, idle time.Duration) (*Server, error) {
	if token == "" {
		return nil, fmt.Errorf("pathd token is empty")
	}
	if err := ValidateListenAddress(address); err != nil {
		return nil, err
	}
	if idle <= 0 {
		idle = 20 * time.Second
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	p4, err := newPinger("ip4:icmp", "0.0.0.0", 1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply)
	if err != nil {
		listener.Close()
		return nil, err
	}
	p6, err := newPinger("ip6:ipv6-icmp", "::", 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply)
	if err != nil {
		listener.Close()
		_ = p4.Close()
		return nil, fmt.Errorf("open raw IPv6 ICMP socket: %w", err)
	}
	return &Server{listener: listener, token: token, idle: idle, pinger4: p4, pinger6: p6, closed: make(chan struct{})}, nil
}

// ValidateListenAddress guarantees that pathd cannot accidentally become a
// public service. PathLink is reached only after the proxy relay terminates.
func ValidateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid pathd listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("pathd must listen on a numeric loopback address, got %q", host)
	}
	return nil
}

func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
				return err
			}
		}
		go s.serveConn(conn)
	}
}

func (s *Server) Addr() net.Addr { return s.listener.Addr() }

func (s *Server) Close() error {
	s.closeOnce.Do(func() { close(s.closed); _ = s.listener.Close(); _ = s.pinger4.Close(); _ = s.pinger6.Close() })
	return nil
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	var writeMu sync.Mutex
	sem := make(chan struct{}, maxInFlight)
	_ = conn.SetDeadline(time.Now().Add(s.idle))
	hello, err := readFrame(conn)
	if err != nil || hello.Type != "hello" || !tokenEqual(s.token, hello.Token) {
		_ = writeFrame(conn, frame{Type: "denied", Error: "authentication failed"})
		return
	}
	if err := writeFrame(conn, frame{Type: "ready"}); err != nil {
		return
	}
	for {
		_ = conn.SetDeadline(time.Now().Add(s.idle))
		request, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return
			}
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			writeMu.Lock()
			_ = writeFrame(conn, frame{Type: "result", ID: request.ID, Error: "PathLink is busy"})
			writeMu.Unlock()
			continue
		}
		go func(request frame) {
			defer func() { <-sem }()
			result := s.handleProbe(request)
			writeMu.Lock()
			_ = writeFrame(conn, result)
			writeMu.Unlock()
		}(request)
	}
}

func (s *Server) handleProbe(request frame) frame {
	ip := net.ParseIP(request.Target)
	if request.Type != "icmp_echo" || ValidateProbeTarget(ip) != nil {
		return frame{Type: "result", ID: request.ID, Error: "invalid request"}
	}
	if request.Timeout < 100 || request.Timeout > 15000 {
		request.Timeout = 3000
	}
	pinger := s.pinger6
	if ip.To4() != nil {
		pinger = s.pinger4
	}
	if request.TTL == 0 {
		request.TTL = 64
	}
	if request.TTL < 1 || request.TTL > 255 {
		return frame{Type: "result", ID: request.ID, Error: "invalid ICMP TTL"}
	}
	payloadSize := request.PayloadSize
	if payloadSize == 0 {
		payloadSize = 8
	}
	if payloadSize < 8 || payloadSize > 65507 {
		return frame{Type: "result", ID: request.ID, Error: "invalid ICMP payload size"}
	}
	var probe ProbeResult
	var err error
	if request.Relay {
		if len(request.EchoData) > 8192 {
			return frame{Type: "result", ID: request.ID, Error: "ICMP echo payload is too large"}
		}
		echoData := request.EchoData
		if echoData == nil {
			echoData = []byte{}
		}
		probe, err = pinger.RelayEcho(ip, time.Duration(request.Timeout)*time.Millisecond, request.TTL, echoData)
	} else {
		probe, err = pinger.ProbeWithOptions(ip, time.Duration(request.Timeout)*time.Millisecond, ProbeOptions{TTL: request.TTL, PayloadSize: payloadSize, DontFragment: request.DontFragment})
	}
	result := frame{Type: "result", ID: request.ID, RTT: probe.RTT.Nanoseconds(), Echo: probe.Echo, ICMPType: probe.ICMPType, ICMPCode: probe.ICMPCode, MTU: probe.MTU}
	if probe.Responder != nil {
		result.Responder = probe.Responder.String()
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

type pingKey struct {
	id, seq uint16
	cookie  uint64
}
type pingResult struct {
	probe ProbeResult
	err   error
}
type pendingPing struct {
	result      chan pingResult
	started     time.Time
	matchCookie bool
}
type pinger struct {
	conn      *icmp.PacketConn
	proto     int
	echo      icmp.Type
	reply     icmp.Type
	mu        sync.Mutex
	sendMu    sync.Mutex
	next      uint16
	pending   map[pingKey]pendingPing
	done      chan struct{}
	closeOnce sync.Once
	dfFD      int
}

func newPinger(network, listen string, proto int, echo, reply icmp.Type) (*pinger, error) {
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return nil, fmt.Errorf("open raw ICMP socket (need root or CAP_NET_RAW): %w", err)
	}
	p := &pinger{conn: conn, proto: proto, echo: echo, reply: reply, pending: make(map[pingKey]pendingPing), done: make(chan struct{}), dfFD: -1}
	if proto == 1 {
		fd, fdErr := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
		if fdErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("open IPv4 DF ICMP socket: %w", fdErr)
		}
		p.dfFD = fd
	}
	go p.readLoop()
	return p, nil
}

func (p *pinger) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		_ = p.conn.Close()
		if p.dfFD >= 0 {
			_ = unix.Close(p.dfFD)
		}
	})
	return nil
}

func (p *pinger) Probe(ip net.IP, timeout time.Duration, ttl int) (ProbeResult, error) {
	return p.ProbeWithOptions(ip, timeout, ProbeOptions{TTL: ttl, PayloadSize: 8})
}

func (p *pinger) ProbeWithOptions(ip net.IP, timeout time.Duration, options ProbeOptions) (ProbeResult, error) {
	return p.probe(ip, timeout, options, nil)
}

// RelayEcho preserves a caller's echo data while using a pathd-owned ID/Seq
// pair, which makes independent LAN clients safe to multiplex at remote NAT.
func (p *pinger) RelayEcho(ip net.IP, timeout time.Duration, ttl int, data []byte) (ProbeResult, error) {
	return p.probe(ip, timeout, ProbeOptions{TTL: ttl}, data)
}

func (p *pinger) probe(ip net.IP, timeout time.Duration, options ProbeOptions, relayData []byte) (ProbeResult, error) {
	ttl := options.TTL
	if relayData == nil && (options.PayloadSize < 8 || options.PayloadSize > 65507) {
		return ProbeResult{}, fmt.Errorf("invalid ICMP payload size")
	}
	if p.proto == 1 {
		ip = ip.To4()
		if ip == nil {
			return ProbeResult{}, fmt.Errorf("invalid IPv4 target")
		}
	} else if ip = ip.To16(); ip == nil {
		return ProbeResult{}, fmt.Errorf("invalid IPv6 target")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ProbeResult{}, err
	}
	cookie := binary.BigEndian.Uint64(random[:])
	p.mu.Lock()
	p.next++
	key := pingKey{id: 0x5054, seq: p.next, cookie: cookie}
	result := make(chan pingResult, 1)
	p.pending[key] = pendingPing{result: result, started: time.Now(), matchCookie: relayData == nil}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, key); p.mu.Unlock() }()
	payload := relayData
	if payload == nil {
		payload = make([]byte, options.PayloadSize)
		copy(payload, random[:])
	}
	message := icmp.Message{Type: p.echo, Code: 0, Body: &icmp.Echo{ID: int(key.id), Seq: int(key.seq), Data: payload}}
	b, err := message.Marshal(nil)
	if err != nil {
		return ProbeResult{}, err
	}
	p.sendMu.Lock()
	var sendErr error
	if p.proto == 1 && options.DontFragment {
		sendErr = p.sendIPv4DontFragment(b, ip, ttl)
	} else if p.proto == 1 {
		sendErr = p.conn.IPv4PacketConn().SetTTL(ttl)
	} else {
		sendErr = p.conn.IPv6PacketConn().SetHopLimit(ttl)
	}
	if sendErr == nil && !(p.proto == 1 && options.DontFragment) {
		_, sendErr = p.conn.WriteTo(b, &net.IPAddr{IP: ip})
	}
	if p.proto == 1 {
		_ = p.conn.IPv4PacketConn().SetTTL(64)
	} else {
		_ = p.conn.IPv6PacketConn().SetHopLimit(64)
	}
	p.sendMu.Unlock()
	if sendErr != nil {
		return ProbeResult{}, sendErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case reply := <-result:
		if reply.err != nil {
			return ProbeResult{}, reply.err
		}
		return reply.probe, nil
	case <-ctx.Done():
		return ProbeResult{}, fmt.Errorf("ICMP timeout after %s", timeout)
	case <-p.done:
		return ProbeResult{}, fmt.Errorf("pathd is stopping")
	}
}

func (p *pinger) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, source, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		message, err := icmp.ParseMessage(p.proto, buf[:n])
		if err != nil {
			continue
		}
		key, cookieMatch, diagnostic, ok := p.matchMessage(message)
		if !ok {
			continue
		}
		p.mu.Lock()
		pending, ok := p.pending[key]
		if !ok {
			for candidate, value := range p.pending {
				if candidate.id == key.id && candidate.seq == key.seq {
					key, pending, ok = candidate, value, true
					break
				}
			}
		}
		p.mu.Unlock()
		if ok && (diagnostic || cookieMatch || !pending.matchCookie) {
			select {
			case pending.result <- pingResult{probe: p.probeFromMessage(message, source, pending.started, diagnostic, buf[:n])}:
			default:
			}
		}
	}
}

func (p *pinger) matchMessage(message *icmp.Message) (pingKey, bool, bool, bool) {
	if message.Type == p.reply {
		echo, ok := message.Body.(*icmp.Echo)
		if !ok {
			return pingKey{}, false, false, false
		}
		key := pingKey{id: uint16(echo.ID), seq: uint16(echo.Seq)}
		if len(echo.Data) >= 8 {
			key.cookie = binary.BigEndian.Uint64(echo.Data)
			return key, true, false, true
		}
		return key, false, false, true
	}
	if !p.isDiagnostic(message.Type) {
		return pingKey{}, false, false, false
	}
	data := quotedData(message.Body)
	if len(data) == 0 {
		return pingKey{}, false, false, false
	}
	if p.proto == 1 {
		if len(data) < 28 || data[0]>>4 != 4 {
			return pingKey{}, false, false, false
		}
		offset := int(data[0]&0x0f) * 4
		if offset < 20 || len(data) < offset+8 {
			return pingKey{}, false, false, false
		}
		return pingKey{id: binary.BigEndian.Uint16(data[offset+4:]), seq: binary.BigEndian.Uint16(data[offset+6:])}, false, true, true
	}
	if len(data) < 48 || data[0]>>4 != 6 {
		return pingKey{}, false, false, false
	}
	return pingKey{id: binary.BigEndian.Uint16(data[44:]), seq: binary.BigEndian.Uint16(data[46:])}, false, true, true
}

func (p *pinger) sendIPv4DontFragment(packet []byte, ip net.IP, ttl int) error {
	if p.dfFD < 0 {
		return fmt.Errorf("IPv4 DF probes are unavailable")
	}
	if err := unix.SetsockoptInt(p.dfFD, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(p.dfFD, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
		return err
	}
	var address [4]byte
	copy(address[:], ip.To4())
	return unix.Sendto(p.dfFD, packet, 0, &unix.SockaddrInet4{Addr: address})
}

func (p *pinger) isDiagnostic(typ icmp.Type) bool {
	if p.proto == 1 {
		return typ == ipv4.ICMPTypeDestinationUnreachable || typ == ipv4.ICMPTypeTimeExceeded || typ == ipv4.ICMPTypeParameterProblem
	}
	return typ == ipv6.ICMPTypeDestinationUnreachable || typ == ipv6.ICMPTypeTimeExceeded || typ == ipv6.ICMPTypePacketTooBig || typ == ipv6.ICMPTypeParameterProblem
}

func quotedData(body icmp.MessageBody) []byte {
	switch value := body.(type) {
	case *icmp.DstUnreach:
		return value.Data
	case *icmp.TimeExceeded:
		return value.Data
	case *icmp.PacketTooBig:
		return value.Data
	default:
		return nil
	}
}

func (p *pinger) probeFromMessage(message *icmp.Message, source net.Addr, started time.Time, diagnostic bool, raw []byte) ProbeResult {
	result := ProbeResult{RTT: time.Since(started), Echo: !diagnostic, ICMPType: p.typeNumber(message.Type), ICMPCode: uint8(message.Code)}
	if address, ok := source.(*net.IPAddr); ok {
		result.Responder = address.IP
	}
	if tooBig, ok := message.Body.(*icmp.PacketTooBig); ok {
		result.MTU = tooBig.MTU
	}
	if p.proto == 1 && result.ICMPType == uint8(ipv4.ICMPTypeDestinationUnreachable) && result.ICMPCode == 4 && len(raw) >= 8 {
		result.MTU = int(binary.BigEndian.Uint16(raw[6:8]))
	}
	return result
}

func (p *pinger) typeNumber(typ icmp.Type) uint8 {
	if p.proto == 1 {
		return uint8(typ.(ipv4.ICMPType))
	}
	return uint8(typ.(ipv6.ICMPType))
}
