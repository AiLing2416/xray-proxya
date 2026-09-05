package netprobe

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Transport abstracts active network diagnostic transmissions.
// Implementations include DirectTransport (host network) and ProxyTransport (SOCKS5/HTTP proxy session).
type Transport interface {
	// DialContext connects to the address on the named network using a stream transport.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	// NewHTTPClient creates an HTTP client configured with this transport.
	NewHTTPClient(timeout time.Duration) *http.Client
	// NewHTTP2Client creates an HTTP client configured to negotiate HTTP/2 ALPN.
	NewHTTP2Client(timeout time.Duration) *http.Client
	// SendAndReceiveUDP sends a UDP payload to targetAddr and returns the response datagram and round-trip duration.
	SendAndReceiveUDP(ctx context.Context, targetAddr string, payload []byte, timeout time.Duration) ([]byte, time.Duration, error)
}
