package relaytest

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"xray-proxya/internal/netprobe"
	"xray-proxya/pkg/utils"
)

type dnsTarget struct {
	name   string
	proto  string // "tcp" or "udp"
	family string // "v4" or "v6"
	addr   string
	domain string
}

func defaultDNSTargets(customServers []string) []dnsTarget {
	targets := []dnsTarget{
		{name: "google_v4_tcp", proto: "tcp", family: "v4", addr: "8.8.8.8:53", domain: "google.com"},
		{name: "google_v4_udp", proto: "udp", family: "v4", addr: "8.8.8.8:53", domain: "google.com"},
		{name: "cloudflare_v4_tcp", proto: "tcp", family: "v4", addr: "1.1.1.1:53", domain: "cloudflare.com"},
		{name: "cloudflare_v4_udp", proto: "udp", family: "v4", addr: "1.1.1.1:53", domain: "cloudflare.com"},
		{name: "google_v6_tcp", proto: "tcp", family: "v6", addr: "[2001:4860:4860::8888]:53", domain: "google.com"},
		{name: "google_v6_udp", proto: "udp", family: "v6", addr: "[2001:4860:4860::8888]:53", domain: "google.com"},
		{name: "cloudflare_v6_tcp", proto: "tcp", family: "v6", addr: "[2606:4700:4700::1111]:53", domain: "cloudflare.com"},
		{name: "cloudflare_v6_udp", proto: "udp", family: "v6", addr: "[2606:4700:4700::1111]:53", domain: "cloudflare.com"},
	}

	for i, s := range customServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host := s
		if strings.Contains(s, "://") {
			if u, err := url.Parse(s); err == nil {
				host = u.Hostname()
			}
		} else if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if host != "" {
			targetAddr := net.JoinHostPort(host, "53")
			fam := "v4"
			if strings.Contains(host, ":") {
				fam = "v6"
			}
			targets = append(targets,
				dnsTarget{name: fmt.Sprintf("custom_%d_tcp", i+1), proto: "tcp", family: fam, addr: targetAddr, domain: "google.com"},
				dnsTarget{name: fmt.Sprintf("custom_%d_udp", i+1), proto: "udp", family: fam, addr: targetAddr, domain: "google.com"},
			)
		}
	}
	return targets
}

func probeDNS53(ctx context.Context, session *TestSession, customServers []string) TransportResult {
	targets := defaultDNSTargets(customServers)
	rawItems := make(map[string]ItemResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(tgt dnsTarget) {
			defer wg.Done()
			var r ItemResult
			if tgt.proto == "tcp" {
				rtt, err := probeTCPDNS(ctx, session.Dialer, tgt.addr, tgt.domain)
				if err != nil {
					r = ItemResult{Status: StatusFail, Error: err.Error()}
				} else {
					r = ItemResult{Status: StatusPass, RTTMs: rtt.Milliseconds()}
				}
			} else {
				rtt, err := probeUDPDNS(ctx, session.SOCKSAddr, tgt.addr, tgt.domain)
				if err != nil {
					r = ItemResult{Status: StatusFail, Error: err.Error()}
				} else {
					r = ItemResult{Status: StatusPass, RTTMs: rtt.Milliseconds()}
				}
			}
			mu.Lock()
			rawItems[tgt.name] = r
			mu.Unlock()
		}(t)
	}

	wg.Wait()

	var maxTCPRTT int64 = 0
	tcpPassCount := 0
	var maxUDPRTT int64 = 0
	udpPassCount := 0

	for _, t := range targets {
		r := rawItems[t.name]
		if t.proto == "tcp" {
			if r.Status == StatusPass {
				tcpPassCount++
				if r.RTTMs > maxTCPRTT {
					maxTCPRTT = r.RTTMs
				}
			}
		} else {
			if r.Status == StatusPass {
				udpPassCount++
				if r.RTTMs > maxUDPRTT {
					maxUDPRTT = r.RTTMs
				}
			}
		}
	}

	res := TransportResult{
		TCPStatus: StatusFail,
		UDPStatus: StatusFail,
		RawItems:  rawItems,
	}

	if tcpPassCount > 0 {
		res.TCPStatus = StatusPass
		res.TCPRTTMs = maxTCPRTT
	}
	if udpPassCount > 0 {
		res.UDPStatus = StatusPass
		res.UDPRTTMs = maxUDPRTT
	}

	return res
}

func probeTCPDNS(ctx context.Context, dialer *utils.SOCKS5Dialer, targetAddr, domain string) (time.Duration, error) {
	pt := netprobe.NewProxyTransport(dialer, nil, "")
	return netprobe.ProbeTCPDNS(ctx, pt, targetAddr, domain)
}

func probeUDPDNS(ctx context.Context, socksAddr, targetAddr, domain string) (time.Duration, error) {
	pt := netprobe.NewProxyTransport(nil, nil, socksAddr)
	return netprobe.ProbeUDPDNS(ctx, pt, targetAddr, domain)
}

func buildDNSWireQuery(domain string, qtype uint16) ([]byte, error) {
	return netprobe.BuildDNSWireQuery(domain, qtype)
}
