package utils

import (
	"bytes"
	"testing"
)

func TestBuildAndStripSOCKS5UDPHeaderIPv4(t *testing.T) {
	target := "8.8.8.8:53"
	header, err := BuildSOCKS5UDPHeader(target)
	if err != nil {
		t.Fatalf("BuildSOCKS5UDPHeader error: %v", err)
	}

	expectedHeader := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 53}
	if !bytes.Equal(header, expectedHeader) {
		t.Fatalf("header = %x, want %x", header, expectedHeader)
	}

	payload := []byte("hello-dns-payload")
	frame := append(header, payload...)

	stripped, err := StripSOCKS5UDPHeader(frame)
	if err != nil {
		t.Fatalf("StripSOCKS5UDPHeader error: %v", err)
	}
	if !bytes.Equal(stripped, payload) {
		t.Fatalf("stripped = %s, want %s", string(stripped), string(payload))
	}
}

func TestBuildAndStripSOCKS5UDPHeaderIPv6(t *testing.T) {
	target := "[2001:4860:4860::8888]:53"
	header, err := BuildSOCKS5UDPHeader(target)
	if err != nil {
		t.Fatalf("BuildSOCKS5UDPHeader error: %v", err)
	}

	if header[3] != 0x04 {
		t.Fatalf("expected ATYP=0x04 for IPv6, got 0x%02x", header[3])
	}

	payload := []byte("ipv6-payload")
	frame := append(header, payload...)

	stripped, err := StripSOCKS5UDPHeader(frame)
	if err != nil {
		t.Fatalf("StripSOCKS5UDPHeader error: %v", err)
	}
	if !bytes.Equal(stripped, payload) {
		t.Fatalf("stripped = %s, want %s", string(stripped), string(payload))
	}
}

func TestBuildAndStripSOCKS5UDPHeaderDomain(t *testing.T) {
	target := "dns.google:53"
	header, err := BuildSOCKS5UDPHeader(target)
	if err != nil {
		t.Fatalf("BuildSOCKS5UDPHeader error: %v", err)
	}

	if header[3] != 0x03 {
		t.Fatalf("expected ATYP=0x03 for domain, got 0x%02x", header[3])
	}

	payload := []byte("domain-payload")
	frame := append(header, payload...)

	stripped, err := StripSOCKS5UDPHeader(frame)
	if err != nil {
		t.Fatalf("StripSOCKS5UDPHeader error: %v", err)
	}
	if !bytes.Equal(stripped, payload) {
		t.Fatalf("stripped = %s, want %s", string(stripped), string(payload))
	}
}
