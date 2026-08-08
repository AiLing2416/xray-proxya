package pathd

import (
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
