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
		Name:        "relay",
		Description: "Relay / transit profile for high fan-in and fan-out forwarding",
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
		},
	},
	{
		Name:        "server",
		Description: "Exit / server profile for stable TCP throughput and moderate buffering",
		Settings: []Setting{
			{Key: "net.core.default_qdisc", Value: "fq"},
			{Key: "net.ipv4.tcp_congestion_control", Value: "bbr"},
			{Key: "net.core.somaxconn", Value: "4096"},
			{Key: "net.core.netdev_max_backlog", Value: "16384"},
			{Key: "net.ipv4.tcp_max_syn_backlog", Value: "8192"},
			{Key: "net.netfilter.nf_conntrack_max", Value: "262144"},
			{Key: "net.core.rmem_max", Value: "16777216"},
			{Key: "net.core.wmem_max", Value: "16777216"},
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
