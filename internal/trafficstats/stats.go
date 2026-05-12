package trafficstats

import "strings"

type Summary struct {
	Direct       int64
	Relay        int64
	ServiceStats map[string]int64
	RelayStats   map[string]int64
	GuestStats   map[string]int64
	InboundStats map[string]int64
}

func Summarize(allStats map[string]int64) Summary {
	summary := Summary{
		ServiceStats: make(map[string]int64),
		RelayStats:   make(map[string]int64),
		GuestStats:   make(map[string]int64),
		InboundStats: make(map[string]int64),
	}

	for name, val := range allStats {
		switch {
		case strings.HasPrefix(name, "outbound>>>direct>>>"):
			summary.Direct += val
		case strings.HasPrefix(name, "outbound>>>outbound-") && !strings.Contains(name, ">>>blocked>>>"):
			summary.Relay += val
		case strings.HasPrefix(name, "user>>>"):
			parts := strings.Split(name, ">>>")
			if len(parts) < 2 {
				continue
			}
			email := parts[1]
			switch {
			case email == "service-user":
				summary.ServiceStats["service-user"] += val
			case strings.HasPrefix(email, "relay-"):
				summary.RelayStats[strings.TrimPrefix(email, "relay-")] += val
			case strings.HasPrefix(email, "guest-"):
				summary.GuestStats[strings.TrimPrefix(email, "guest-")] += val
			default:
				summary.ServiceStats[email] += val
			}
		case strings.HasPrefix(name, "inbound>>>") && !strings.Contains(name, ">>>api>>>"):
			parts := strings.Split(name, ">>>")
			if len(parts) >= 2 {
				summary.InboundStats[parts[1]] += val
			}
		}
	}

	return summary
}
