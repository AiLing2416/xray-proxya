package gateway

import "testing"

func TestParseDefaultInterface(t *testing.T) {
	iface, err := ParseDefaultInterface("default via 192.168.1.1 dev ens18 proto dhcp src 192.168.1.10 metric 100\n")
	if err != nil {
		t.Fatalf("ParseDefaultInterface() error = %v", err)
	}
	if iface != "ens18" {
		t.Fatalf("interface = %q, want ens18", iface)
	}
}

func TestParseDefaultInterfaceNoDefault(t *testing.T) {
	if _, err := ParseDefaultInterface("192.168.1.0/24 dev ens18 proto kernel\n"); err == nil {
		t.Fatal("ParseDefaultInterface() error = nil, want error")
	}
}
