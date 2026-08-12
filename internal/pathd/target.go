package pathd

import (
	"fmt"
	"net"
)

var nonPublicIPv4 = mustCIDRs([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
})

var nonPublicIPv6 = mustCIDRs([]string{
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
	"100:0:0:1::/64", "2001::/32", "2001:10::/28", "2001:db8::/32",
	"3fff::/20", "fc00::/7", "fe80::/10",
})

func mustCIDRs(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		result = append(result, network)
	}
	return result
}

// ValidateProbeTarget permits only globally routable addresses. It is checked
// on both ends of PathLink so a compromised gateway cannot probe remote-local
// networks, metadata endpoints, or reserved address space.
func ValidateProbeTarget(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid IP target")
	}
	if v4 := ip.To4(); v4 != nil {
		if !isPublicIPv4(v4) {
			return fmt.Errorf("target %s is not a public IPv4 address", v4)
		}
		return nil
	}
	v6 := ip.To16()
	if v6 == nil || !isPublicIPv6(v6) {
		return fmt.Errorf("target %s is not a public IPv6 address", ip)
	}
	return nil
}

func IsPublicTarget(ip net.IP) bool { return ValidateProbeTarget(ip) == nil }

func isPublicIPv4(ip net.IP) bool {
	v := ip.To4()
	if v == nil {
		return false
	}
	// IANA assigns 192.0.0.9/32 and 192.0.0.10/32 as globally reachable
	// exceptions inside the otherwise non-public 192.0.0.0/24 block.
	if v[0] == 192 && v[1] == 0 && v[2] == 0 && (v[3] == 9 || v[3] == 10) {
		return true
	}
	for _, network := range nonPublicIPv4 {
		if network.Contains(v) {
			return false
		}
	}
	return true
}

func isPublicIPv6(ip net.IP) bool {
	v := ip.To16()
	if v == nil || ip.To4() != nil || v[0]&0xe0 != 0x20 {
		return false
	}
	for _, network := range nonPublicIPv6 {
		if network.Contains(v) {
			return false
		}
	}
	return true
}
