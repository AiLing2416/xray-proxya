package netprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
	"xray-proxya/pkg/utils"
)

// ProxyTransport routes network probes through an upstream proxy session (e.g. SOCKS5 relay).
type ProxyTransport struct {
	dialer     *utils.SOCKS5Dialer
	httpClient *http.Client
	socksAddr  string
}

// NewProxyTransport creates a ProxyTransport given SOCKS5 dialer, HTTP client, and SOCKS5 UDP address.
func NewProxyTransport(dialer *utils.SOCKS5Dialer, httpClient *http.Client, socksAddr string) *ProxyTransport {
	return &ProxyTransport{
		dialer:     dialer,
		httpClient: httpClient,
		socksAddr:  socksAddr,
	}
}

func (p *ProxyTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.dialer != nil {
		return p.dialer.Dial(network, addr)
	}
	return nil, fmt.Errorf("no dialer configured in ProxyTransport")
}

func (p *ProxyTransport) NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if p.httpClient != nil {
		c := *p.httpClient
		c.Timeout = timeout
		return &c
	}
	if p.dialer != nil {
		return &http.Client{
			Transport: &http.Transport{
				Dial: p.dialer.Dial,
			},
			Timeout: timeout,
		}
	}
	return &http.Client{Timeout: timeout}
}

func (p *ProxyTransport) NewHTTP2Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialFn := func(network, addr string) (net.Conn, error) {
		if p.dialer != nil {
			return p.dialer.Dial(network, addr)
		}
		return nil, fmt.Errorf("no dialer configured in ProxyTransport")
	}
	tr := &http.Transport{
		Dial: dialFn,
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

func (p *ProxyTransport) SendAndReceiveUDP(ctx context.Context, targetAddr string, payload []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if p.socksAddr == "" {
		return nil, 0, fmt.Errorf("socks address not set in ProxyTransport")
	}

	udpClient, err := utils.DialSOCKS5UDP(p.socksAddr, timeout)
	if err != nil {
		return nil, 0, fmt.Errorf("socks5 udp associate: %w", err)
	}
	defer udpClient.Close()

	return udpClient.SendAndReceive(targetAddr, payload, timeout)
}
