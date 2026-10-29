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

func TestParseARPTable(t *testing.T) {
	sampleARP := `IP address       HW type     Flags       HW address            Mask     Device
10.0.82.21       0x1         0x2         52:54:00:82:00:21     *        virbr82
10.0.82.99       0x1         0x0         00:00:00:00:00:00     *        virbr82
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
`
	mac, err := ParseARPTable(sampleARP, "10.0.82.21")
	if err != nil || mac != "52:54:00:82:00:21" {
		t.Errorf("ParseARPTable(10.0.82.21) = %q, %v, want 52:54:00:82:00:21", mac, err)
	}

	// Incomplete entry with 00:00:00:00:00:00 should not match
	_, err = ParseARPTable(sampleARP, "10.0.82.99")
	if err == nil {
		t.Errorf("expected error for incomplete ARP entry, got nil")
	}

	// Non-existent IP
	_, err = ParseARPTable(sampleARP, "10.0.82.100")
	if err == nil {
		t.Errorf("expected error for nonexistent IP, got nil")
	}
}

func TestParseNeighOutput(t *testing.T) {
	sampleNeigh := `10.0.82.21 dev virbr82 lladdr 52:54:00:82:00:21 REACHABLE
fd00:82::21 dev virbr82 lladdr 52:54:00:82:00:21 STALE
`
	mac, err := ParseNeighOutput(sampleNeigh)
	if err != nil || mac != "52:54:00:82:00:21" {
		t.Errorf("ParseNeighOutput = %q, %v, want 52:54:00:82:00:21", mac, err)
	}

	_, err = ParseNeighOutput("10.0.82.99 dev virbr82 FAILED\n")
	if err == nil {
		t.Errorf("expected error for output without lladdr, got nil")
	}
}

func TestGetInterfaceByIP(t *testing.T) {
	// 127.0.0.1 should match loopback interface (typically "lo")
	iface, err := GetInterfaceByIP("127.0.0.1")
	if err != nil || iface == "" {
		t.Errorf("GetInterfaceByIP(127.0.0.1) = %q, %v", iface, err)
	}

	// Invalid IP
	_, err = GetInterfaceByIP("invalid-ip")
	if err == nil {
		t.Errorf("expected error for invalid IP")
	}
}
