package tune

type Setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Profile struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Settings    []Setting `json:"settings"`
}

var profiles = []Profile{
	{
		Name:        "gateway",
		Description: "Transparent gateway / TUN / LAN egress profile",
		Settings: []Setting{
			{Key: "net.core.default_qdisc", Value: "fq"},
			{Key: "net.ipv4.tcp_congestion_control", Value: "bbr"},
			{Key: "net.ipv4.ip_forward", Value: "1"},
			{Key: "net.ipv6.conf.all.forwarding", Value: "1"},
			{Key: "net.core.somaxconn", Value: "4096"},
			{Key: "net.core.netdev_max_backlog", Value: "16384"},
			{Key: "net.ipv4.tcp_max_syn_backlog", Value: "8192"},
			{Key: "net.netfilter.nf_conntrack_max", Value: "262144"},
		},
	},
	{
		Name:        "relay-latency",
		Description: "Relay / transit profile for high fan-in and fan-out forwarding (Latency/Concurrency optimized)",
		Settings: []Setting{
			{Key: "net.core.default_qdisc", Value: "fq"},
			{Key: "net.ipv4.tcp_congestion_control", Value: "bbr"},
			{Key: "net.core.somaxconn", Value: "8192"},
			{Key: "net.core.netdev_max_backlog", Value: "32768"},
			{Key: "net.ipv4.tcp_max_syn_backlog", Value: "16384"},
			{Key: "net.netfilter.nf_conntrack_max", Value: "524288"},
			{Key: "net.ipv4.ip_local_port_range", Value: "10240 65535"},
			{Key: "net.core.rmem_max", Value: "33554432"},
			{Key: "net.core.wmem_max", Value: "33554432"},
			{Key: "net.ipv4.tcp_tw_reuse", Value: "1"},
			{Key: "net.ipv4.tcp_fin_timeout", Value: "15"},
			{Key: "net.ipv4.tcp_max_tw_buckets", Value: "2000000"},
			{Key: "net.ipv4.tcp_slow_start_after_idle", Value: "0"},
			{Key: "net.ipv4.tcp_notsent_lowat", Value: "16384"},
			{Key: "net.ipv4.tcp_mtu_probing", Value: "0"},
			{Key: "net.ipv4.tcp_keepalive_time", Value: "600"},
		},
	},
	{
		Name:        "relay-throughput",
		Description: "Relay / transit profile for high fan-in and fan-out forwarding (Throughput optimized)",
		Settings: []Setting{
			{Key: "net.core.default_qdisc", Value: "fq"},
			{Key: "net.ipv4.tcp_congestion_control", Value: "bbr"},
			{Key: "net.core.somaxconn", Value: "8192"},
			{Key: "net.core.netdev_max_backlog", Value: "32768"},
			{Key: "net.ipv4.tcp_max_syn_backlog", Value: "16384"},
			{Key: "net.netfilter.nf_conntrack_max", Value: "524288"},
			{Key: "net.ipv4.ip_local_port_range", Value: "10240 65535"},
			{Key: "net.core.rmem_max", Value: "33554432"},
			{Key: "net.core.wmem_max", Value: "33554432"},
			{Key: "net.ipv4.tcp_tw_reuse", Value: "1"},
			{Key: "net.ipv4.tcp_fin_timeout", Value: "15"},
			{Key: "net.ipv4.tcp_max_tw_buckets", Value: "2000000"},
			{Key: "net.ipv4.tcp_slow_start_after_idle", Value: "1"},
			// tcp_notsent_lowat = UINT32_MAX: intentionally disables the notsent limit so the
			// kernel never throttles the send buffer fill level. This trades latency for raw
			// throughput and is only appropriate for bulk-transfer / high-bandwidth scenarios.
			{Key: "net.ipv4.tcp_notsent_lowat", Value: "4294967295"},
			{Key: "net.ipv4.tcp_mtu_probing", Value: "0"},
			{Key: "net.ipv4.tcp_keepalive_time", Value: "600"},
		},
	},
	{
		Name:        "server-latency",
		Description: "Exit / server profile for stable TCP throughput and moderate buffering (Latency/Concurrency optimized)",
		Settings: []Setting{
			{Key: "net.core.default_qdisc", Value: "fq"},
			{Key: "net.ipv4.tcp_congestion_control", Value: "bbr"},
			{Key: "net.core.somaxconn", Value: "4096"},
			{Key: "net.core.netdev_max_backlog", Value: "16384"},
			{Key: "net.ipv4.tcp_max_syn_backlog", Value: "8192"},
			{Key: "net.netfilter.nf_conntrack_max", Value: "262144"},
			{Key: "net.core.rmem_max", Value: "16777216"},
			{Key: "net.core.wmem_max", Value: "16777216"},
			{Key: "net.ipv4.tcp_tw_reuse", Value: "1"},
			{Key: "net.ipv4.tcp_fin_timeout", Value: "15"},
			{Key: "net.ipv4.tcp_max_tw_buckets", Value: "2000000"},
			{Key: "net.ipv4.tcp_slow_start_after_idle", Value: "0"},
			{Key: "net.ipv4.tcp_notsent_lowat", Value: "16384"},
			{Key: "net.ipv4.tcp_mtu_probing", Value: "0"},
			{Key: "net.ipv4.tcp_keepalive_time", Value: "600"},
		},
	},
	{
		Name:        "server-throughput",
		Description: "Exit / server profile for stable TCP throughput and moderate buffering (Throughput optimized)",
		Settings: []Setting{
			{Key: "net.core.default_qdisc", Value: "fq"},
			{Key: "net.ipv4.tcp_congestion_control", Value: "bbr"},
			{Key: "net.core.somaxconn", Value: "4096"},
			{Key: "net.core.netdev_max_backlog", Value: "16384"},
			{Key: "net.ipv4.tcp_max_syn_backlog", Value: "8192"},
			{Key: "net.netfilter.nf_conntrack_max", Value: "262144"},
			{Key: "net.core.rmem_max", Value: "16777216"},
			{Key: "net.core.wmem_max", Value: "16777216"},
			{Key: "net.ipv4.tcp_tw_reuse", Value: "1"},
			{Key: "net.ipv4.tcp_fin_timeout", Value: "15"},
			{Key: "net.ipv4.tcp_max_tw_buckets", Value: "2000000"},
			{Key: "net.ipv4.tcp_slow_start_after_idle", Value: "1"},
			// tcp_notsent_lowat = UINT32_MAX: intentionally disables the notsent limit so the
			// kernel never throttles the send buffer fill level. This trades latency for raw
			// throughput and is only appropriate for bulk-transfer / high-bandwidth scenarios.
			{Key: "net.ipv4.tcp_notsent_lowat", Value: "4294967295"},
			{Key: "net.ipv4.tcp_mtu_probing", Value: "0"},
			{Key: "net.ipv4.tcp_keepalive_time", Value: "600"},
		},
	},
}

func Profiles() []Profile {
	out := make([]Profile, len(profiles))
	copy(out, profiles)
	return out
}

func ProfileNames() []string {
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.Name)
	}
	return out
}

func GetProfile(name string) (Profile, bool) {
	for _, profile := range profiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return Profile{}, false
}
