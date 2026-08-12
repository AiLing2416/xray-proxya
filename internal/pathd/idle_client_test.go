package pathd

import (
	"net"
	"testing"
	"time"
)

func TestIdleClientResetTimerWithoutConnection(t *testing.T) {
	client := NewIdleClient("127.0.0.1:1", "127.0.0.1:2", "token", time.Millisecond)
	client.mu.Lock()
	client.resetIdleTimerLocked()
	client.mu.Unlock()
	if client.timer != nil {
		t.Fatal("an idle timer must not be created without a PathLink connection")
	}
}

func TestIdleTimerDoesNotCloseInFlightClient(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	defer peerConn.Close()
	idle := NewIdleClient("127.0.0.1:1", "127.0.0.1:2", "token", 20*time.Millisecond)
	idle.mu.Lock()
	idle.client = &Client{conn: clientConn, done: make(chan struct{}), pending: make(map[uint64]chan clientResult)}
	idle.last = time.Now()
	idle.inFlight = 1
	idle.resetIdleTimerLocked()
	idle.mu.Unlock()

	time.Sleep(3 * idle.idle)
	idle.mu.Lock()
	if idle.client == nil {
		idle.mu.Unlock()
		t.Fatal("idle timer closed a client with an in-flight request")
	}
	idle.inFlight = 0
	idle.last = time.Now().Add(-idle.idle)
	idle.resetIdleTimerLocked()
	idle.mu.Unlock()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		idle.mu.Lock()
		closed := idle.client == nil
		idle.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = idle.Close()
	t.Fatal("idle timer did not close an idle client")
}
