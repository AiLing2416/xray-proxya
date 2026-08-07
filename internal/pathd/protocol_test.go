package pathd

import (
	"net"
	"sync"
	"testing"
)

func TestClientMultiplexesOutOfOrderResponses(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		hello, _ := readFrame(serverConn)
		if hello.Type != "hello" {
			return
		}
		_ = writeFrame(serverConn, frame{Type: "ready"})
		first, err := readFrame(serverConn)
		if err != nil {
			return
		}
		second, err := readFrame(serverConn)
		if err != nil {
			return
		}
		_ = writeFrame(serverConn, frame{Type: "result", ID: second.ID, RTT: 22})
		_ = writeFrame(serverConn, frame{Type: "result", ID: first.ID, RTT: 11})
	}()
	client, err := NewClient(clientConn, "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	results := make(chan int64, 2)
	var wg sync.WaitGroup
	for _, target := range []string{"1.1.1.1", "8.8.8.8"} {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			rtt, err := client.Ping(target, 1000)
			if err != nil {
				t.Errorf("Ping: %v", err)
				return
			}
			results <- rtt
		}(target)
	}
	wg.Wait()
	close(results)
	seen := map[int64]bool{}
	for result := range results {
		seen[result] = true
	}
	if !seen[11] || !seen[22] {
		t.Fatalf("results = %#v", seen)
	}
}
