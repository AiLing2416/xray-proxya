package netprobe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// DirectTransport executes network probes directly using the local host operating system network stack.
type DirectTransport struct{}

func (d *DirectTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 4 * time.Second}
	return dialer.DialContext(ctx, network, addr)
}

func (d *DirectTransport) NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func (d *DirectTransport) NewHTTP2Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

func (d *DirectTransport) SendAndReceiveUDP(ctx context.Context, targetAddr string, payload []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	t0 := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	duration := time.Since(t0)
	if err != nil {
		return nil, duration, err
	}
	return buf[:n], duration, nil
}
