package utils

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetSmartIP implements logic: Local Public > API Public > Local Private > Loopback
func GetSmartIP(isIPv6 bool) string {
	// 1. Try Local Interfaces
	localIPs := getLocalIPs(isIPv6)
	for _, ip := range localIPs {
		if isPublicIP(ip) {
			return ip.String()
		}
	}

	// 2. Try External API
	url := "https://api.ip.sb/ip"
	if isIPv6 { url = "https://api6.ip.sb/ip" }
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		ipStr := strings.TrimSpace(string(b))
		if net.ParseIP(ipStr) != nil {
			return ipStr
		}
	}

	// 3. Fallback to Local Private
	if len(localIPs) > 0 {
		return localIPs[0].String()
	}

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
