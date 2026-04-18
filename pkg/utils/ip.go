package utils

import (
	"net"
)

// GetSmartIP implements logic: Local Public > API Public > Local Private > Loopback
func GetSmartIP(isIPv6 bool) string {
	// 1. Try Local Interfaces First
	localIPs := getLocalIPs(isIPv6)
	for _, ip := range localIPs {
		if isPublicIP(ip) {
			return ip.String()
		}
	}

	// 2. Fallback to Local Private immediately if no public found on interfaces
	// This avoids waiting for HTTP timeout in internal environments
	if len(localIPs) > 0 {
		return localIPs[0].String()
	}

	// 3. Optional: Try External API only if really needed (skipped for now to ensure stability)
	/*
	url := "https://api.ip.sb/ip"
	...
	*/

	// 4. Ultimate Fallback
	if isIPv6 { return "::1" }
	return "127.0.0.1"
}

// GetLocalIP returns the first non-loopback private IP.
func GetLocalIP() string {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet: ip = v.IP
			case *net.IPAddr: ip = v.IP
			}
			if ip == nil || ip.IsLoopback() { continue }
			if !isPublicIP(ip) && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

func getLocalIPs(isIPv6 bool) []net.IP {
	var ips []net.IP
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet: ip = v.IP
			case *net.IPAddr: ip = v.IP
			}
			if ip == nil || ip.IsLoopback() { continue }
			if isIPv6 && ip.To4() == nil {
				ips = append(ips, ip)
			} else if !isIPv6 && ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10: return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31: return false
		case ip4[0] == 192 && ip4[1] == 168: return false
		default: return true
		}
	}
	// For IPv6, simple check: global unicast range 2000::/3
	return (ip[0] & 0xe0) == 0x20
}

func GetLocalPrivateIPs() []string {
	var ips []string
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet: ip = v.IP
			case *net.IPAddr: ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				// isPublicIP returns true for non-RFC1918 IPs
				if !isPublicIP(ip) {
					ips = append(ips, ip.String())
				}
			}
		}
	}
	// Always include localhost
	foundLocal := false
	for _, s := range ips { if s == "127.0.0.1" { foundLocal = true; break } }
	if !foundLocal { ips = append(ips, "127.0.0.1") }
	return ips
}
