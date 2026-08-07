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
	if request.Type != "icmp_echo" || net.ParseIP(request.Target) == nil {
		return frame{Type: "result", ID: request.ID, Error: "invalid request"}
	}
	if request.Timeout < 100 || request.Timeout > 15000 {
		request.Timeout = 3000
	}
	ip := net.ParseIP(request.Target)
	pinger := s.pinger6
	if ip.To4() != nil {
		pinger = s.pinger4
	}
	rtt, err := pinger.Ping(ip, time.Duration(request.Timeout)*time.Millisecond)
	result := frame{Type: "result", ID: request.ID, RTT: rtt.Nanoseconds()}
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
	rtt time.Duration
	err error
}
type pendingPing struct {
	result  chan pingResult
	started time.Time
}
type pinger struct {
	conn      *icmp.PacketConn
	proto     int
	echo      icmp.Type
	reply     icmp.Type
	mu        sync.Mutex
	next      uint16
	pending   map[pingKey]pendingPing
	done      chan struct{}
	closeOnce sync.Once
}

func newPinger(network, listen string, proto int, echo, reply icmp.Type) (*pinger, error) {
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return nil, fmt.Errorf("open raw ICMP socket (need root or CAP_NET_RAW): %w", err)
	}
	p := &pinger{conn: conn, proto: proto, echo: echo, reply: reply, pending: make(map[pingKey]pendingPing), done: make(chan struct{})}
	go p.readLoop()
	return p, nil
}

func (p *pinger) Close() error {
	p.closeOnce.Do(func() { close(p.done); _ = p.conn.Close() })
	return nil
}

func (p *pinger) Ping(ip net.IP, timeout time.Duration) (time.Duration, error) {
	if p.proto == 1 {
		ip = ip.To4()
		if ip == nil {
			return 0, fmt.Errorf("invalid IPv4 target")
		}
	} else if ip = ip.To16(); ip == nil {
		return 0, fmt.Errorf("invalid IPv6 target")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 0, err
	}
	cookie := binary.BigEndian.Uint64(random[:])
	p.mu.Lock()
	p.next++
	key := pingKey{id: 0x5054, seq: p.next, cookie: cookie}
	result := make(chan pingResult, 1)
	p.pending[key] = pendingPing{result: result, started: time.Now()}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, key); p.mu.Unlock() }()
	message := icmp.Message{Type: p.echo, Code: 0, Body: &icmp.Echo{ID: int(key.id), Seq: int(key.seq), Data: random[:]}}
	b, err := message.Marshal(nil)
	if err != nil {
		return 0, err
	}
	if _, err := p.conn.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case reply := <-result:
		if reply.err != nil {
			return 0, reply.err
		}
		return reply.rtt, nil
	case <-ctx.Done():
		return 0, fmt.Errorf("ICMP timeout after %s", timeout)
	case <-p.done:
		return 0, fmt.Errorf("pathd is stopping")
	}
}

func (p *pinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		message, err := icmp.ParseMessage(p.proto, buf[:n])
		if err != nil || message.Type != p.reply {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if !ok || len(echo.Data) != 8 {
			continue
		}
		key := pingKey{id: uint16(echo.ID), seq: uint16(echo.Seq), cookie: binary.BigEndian.Uint64(echo.Data)}
		p.mu.Lock()
		pending, ok := p.pending[key]
		p.mu.Unlock()
		if ok {
			select {
			case pending.result <- pingResult{rtt: time.Since(pending.started)}:
			default:
			}
		}
	}
}
