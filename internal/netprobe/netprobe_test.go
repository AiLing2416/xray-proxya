package netprobe

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSTUNWire(t *testing.T) {
	req := BuildSTUNBindingRequest()
	if len(req) != 20 {
		t.Fatalf("expected 20 bytes STUN request, got %d", len(req))
	}
	msgType := binary.BigEndian.Uint16(req[0:2])
	if msgType != 0x0001 {
		t.Fatalf("expected msgType 0x0001, got 0x%04x", msgType)
	}
	cookie := binary.BigEndian.Uint32(req[4:8])
	if cookie != 0x2112A442 {
		t.Fatalf("expected magic cookie 0x2112A442, got 0x%08x", cookie)
	}

	// Valid response
	validResp := make([]byte, 20)
	binary.BigEndian.PutUint16(validResp[0:2], 0x0101)
	binary.BigEndian.PutUint32(validResp[4:8], 0x2112A442)
	if err := ValidateSTUNBindingResponse(validResp); err != nil {
		t.Fatalf("expected valid STUN response, got err: %v", err)
	}

	// Invalid response cookie
	invalidResp := make([]byte, 20)
	binary.BigEndian.PutUint16(invalidResp[0:2], 0x0101)
	binary.BigEndian.PutUint32(invalidResp[4:8], 0x12345678)
	if err := ValidateSTUNBindingResponse(invalidResp); err == nil {
		t.Fatal("expected error on invalid cookie, got nil")
	}

	// Truncated response
	if err := ValidateSTUNBindingResponse(validResp[:10]); err == nil {
		t.Fatal("expected error on truncated response, got nil")
	}
}

func TestNTPWire(t *testing.T) {
	req := BuildNTPRequest()
	if len(req) != 48 {
		t.Fatalf("expected 48 bytes NTP request, got %d", len(req))
	}
	if req[0] != 0x23 {
		t.Fatalf("expected req[0] == 0x23, got 0x%02x", req[0])
	}

	// Mock valid response
	resp := make([]byte, 48)
	// Put a timestamp in 40..44 (seconds)
	now := time.Now()
	const ntpEpochOffset = 2208988800
	binary.BigEndian.PutUint32(resp[40:44], uint32(now.Unix()+ntpEpochOffset))

	t0 := now.Add(-50 * time.Millisecond)
	t3 := now.Add(50 * time.Millisecond)
	offset, rtt, err := ParseSNTPResponse(resp, t0, t3)
	if err != nil {
		t.Fatalf("unexpected error parsing SNTP response: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("expected positive RTT, got %v", rtt)
	}
	_ = offset
}

func TestQUICWire(t *testing.T) {
	pkt := BuildQUICInitialPacket()
	if len(pkt) != 1200 {
		t.Fatalf("expected 1200 bytes, got %d", len(pkt))
	}
	if pkt[0] != 0xC0 {
		t.Fatalf("expected long header flag 0xC0, got 0x%02x", pkt[0])
	}
	version := binary.BigEndian.Uint32(pkt[1:5])
	if version != 0x00000001 {
		t.Fatalf("expected version 1, got 0x%08x", version)
	}

	if !ValidateQUICResponse([]byte{0x80}) {
		t.Fatal("expected true for 0x80 header")
	}
	if !ValidateQUICResponse([]byte{0x40}) {
		t.Fatal("expected true for 0x40 header")
	}
	if ValidateQUICResponse([]byte{0x00}) {
		t.Fatal("expected false for 0x00 header")
	}
}

func TestDNSWire(t *testing.T) {
	query, err := BuildDNSWireQuery("example.com", DNSTypeA)
	if err != nil {
		t.Fatalf("failed to build dns query: %v", err)
	}
	if len(query) < 12 {
		t.Fatalf("query too short: %d", len(query))
	}
	id := binary.BigEndian.Uint16(query[0:2])
	if id != 0x1234 {
		t.Fatalf("expected ID 0x1234, got 0x%04x", id)
	}

	// Empty domain should fail
	if _, err := BuildDNSWireQuery("", DNSTypeA); err == nil {
		t.Fatal("expected error on empty domain, got nil")
	}

	// Mock valid response
	mockResp := make([]byte, len(query)+16)
	copy(mockResp, query)
	mockResp[2] |= 0x80 // Set QR bit
	binary.BigEndian.PutUint16(mockResp[6:8], 1) // ANCOUNT = 1

	// Append answer: Name pointer (2), Type (2), Class (2), TTL (4), RDLENGTH (2), IP (4)
	offset := len(query)
	mockResp[offset] = 0xC0
	mockResp[offset+1] = 0x0C // pointer to offset 12
	binary.BigEndian.PutUint16(mockResp[offset+2:offset+4], DNSTypeA)
	binary.BigEndian.PutUint16(mockResp[offset+4:offset+6], 1) // Class IN
	binary.BigEndian.PutUint32(mockResp[offset+6:offset+10], 300) // TTL
	binary.BigEndian.PutUint16(mockResp[offset+10:offset+12], 4) // RDLENGTH = 4
	copy(mockResp[offset+12:offset+16], []byte{93, 184, 216, 34})

	if err := ValidateDNSResponse(mockResp); err != nil {
		t.Fatalf("expected valid DNS response, got: %v", err)
	}

	answers, err := ParseDNSAnswers(mockResp, DNSTypeA)
	if err != nil {
		t.Fatalf("failed to parse DNS answers: %v", err)
	}
	if len(answers) != 1 || answers[0] != "93.184.216.34" {
		t.Fatalf("expected answer 93.184.216.34, got %v", answers)
	}
}

func TestDirectTransportHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	dt := &DirectTransport{}
	client := dt.NewHTTPClient(2 * time.Second)
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("direct transport get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestUDPMock(t *testing.T) {
	// Start a local UDP echo server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Echo back
		_, _ = pc.WriteTo(buf[:n], addr)
	}()

	dt := &DirectTransport{}
	payload := []byte("hello netprobe")
	resp, rtt, err := dt.SendAndReceiveUDP(context.Background(), pc.LocalAddr().String(), payload, 2*time.Second)
	if err != nil {
		t.Fatalf("SendAndReceiveUDP failed: %v", err)
	}
	if string(resp) != string(payload) {
		t.Fatalf("expected echo %q, got %q", payload, resp)
	}
	if rtt <= 0 {
		t.Fatalf("expected positive rtt, got %v", rtt)
	}
}
