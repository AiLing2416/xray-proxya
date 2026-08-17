package utils

import "testing"

func TestIsWildcardIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"", true},
		{"0.0.0.0", true},
		{"::", true},
		{"[::]", true},
		{"*", true},
		{"127.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"::1", false},
	}
	for _, tc := range tests {
		got := IsWildcardIP(tc.ip)
		if got != tc.want {
			t.Errorf("IsWildcardIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestListenAddressesOverlap(t *testing.T) {
	tests := []struct {
		addr1 string
		addr2 string
		want  bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"0.0.0.0", "127.0.0.1", true},
		{"127.0.0.1", "0.0.0.0", true},
		{"::", "192.168.1.100", true},
		{"", "192.168.1.100", true},
		{"192.168.1.100", "192.168.1.100", true},
		{"192.168.1.100", "192.168.1.101", false},
		{"127.0.0.1", "192.168.1.100", false},
		{"10.0.0.1", "10.0.0.2", false},
	}
	for _, tc := range tests {
		got := ListenAddressesOverlap(tc.addr1, tc.addr2)
		if got != tc.want {
			t.Errorf("ListenAddressesOverlap(%q, %q) = %v, want %v", tc.addr1, tc.addr2, got, tc.want)
		}
	}
}
