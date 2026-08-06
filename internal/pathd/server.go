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
)

// Server listens only on a local address. It has no HTTP or public listener.
type Server struct {
	listener  net.Listener
	token     string
	idle      time.Duration
	pinger    *pinger
	closed    chan struct{}
	closeOnce sync.Once
}

func Listen(address, token string, idle time.Duration) (*Server, error) {
	if token == "" {
		return nil, fmt.Errorf("pathd token is empty")
	}
	if idle <= 0 {
		idle = 20 * time.Second
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	p, err := newPinger()
	if err != nil {
		listener.Close()
		return nil, err
	}
	return &Server{listener: listener, token: token, idle: idle, pinger: p, closed: make(chan struct{})}, nil
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
	s.closeOnce.Do(func() { close(s.closed); _ = s.listener.Close(); _ = s.pinger.Close() })
	return nil
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
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
		if request.Type != "icmp_echo" || net.ParseIP(request.Target) == nil {
			_ = writeFrame(conn, frame{Type: "result", ID: request.ID, Error: "invalid request"})
			continue
		}
		if request.Timeout < 100 || request.Timeout > 15000 {
			request.Timeout = 3000
		}
		rtt, err := s.pinger.Ping(request.Target, time.Duration(request.Timeout)*time.Millisecond)
		result := frame{Type: "result", ID: request.ID, RTT: rtt.Nanoseconds()}
		if err != nil {
			result.Error = err.Error()
		}
		if err := writeFrame(conn, result); err != nil {
			return
		}
	}
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
	mu        sync.Mutex
	next      uint16
	pending   map[pingKey]pendingPing
	done      chan struct{}
	closeOnce sync.Once
}

func newPinger() (*pinger, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open raw ICMP socket (need root or CAP_NET_RAW): %w", err)
	}
	p := &pinger{conn: conn, pending: make(map[pingKey]pendingPing), done: make(chan struct{})}
	go p.readLoop()
	return p, nil
}

func (p *pinger) Close() error {
	p.closeOnce.Do(func() { close(p.done); _ = p.conn.Close() })
	return nil
}

func (p *pinger) Ping(target string, timeout time.Duration) (time.Duration, error) {
	ip := net.ParseIP(target).To4()
	if ip == nil {
		return 0, fmt.Errorf("only IPv4 ICMP is currently supported")
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
	message := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: int(key.id), Seq: int(key.seq), Data: random[:]}}
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
		message, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || message.Type != ipv4.ICMPTypeEchoReply {
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
