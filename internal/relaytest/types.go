package relaytest

type Mode string

const (
	ModeSimple Mode = "simple"
	ModeFull   Mode = "full"
)

type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// ItemResult records the status and latency of a single probe.
type ItemResult struct {
	Status Status `json:"status"`
	RTTMs  int64  `json:"rtt_ms,omitempty"`
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// TransportResult stores TCP & UDP dual-stack transport metrics.
type TransportResult struct {
	TCPStatus Status                `json:"tcp_status"`
	TCPRTTMs  int64                 `json:"tcp_rtt_ms,omitempty"`
	UDPStatus Status                `json:"udp_status"`
	UDPRTTMs  int64                 `json:"udp_rtt_ms,omitempty"`
	RawItems  map[string]ItemResult `json:"raw_items,omitempty"`
}

// ExitIPResult stores public exit IPv4 and IPv6 addresses.
type ExitIPResult struct {
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	IPv4Status Status `json:"ipv4_status"`
	IPv6Status Status `json:"ipv6_status"`
}

// CategoryResult aggregates multiple sub-probes (e.g. Modern Protocols or UDP Capabilities).
type CategoryResult struct {
	Status      Status                `json:"status"`
	MaxRTTMs    int64                 `json:"max_rtt_ms,omitempty"`
	FailedItems []string              `json:"failed_items,omitempty"`
	Items       map[string]ItemResult `json:"items,omitempty"`
}

// TestResult represents the complete test report for a relay node.
type TestResult struct {
	Alias           string           `json:"alias"`
	Mode            Mode             `json:"mode"`
	Status          Status           `json:"status"`
	DurationMs      int64            `json:"duration_ms"`
	Transport       TransportResult  `json:"transport"`
	ExitIP          ExitIPResult     `json:"exit_ip"`
	ModernProtocols *CategoryResult  `json:"modern_protocols,omitempty"`
	UDPCapabilities *CategoryResult  `json:"udp_capabilities,omitempty"`
	Error           string           `json:"error,omitempty"`
}
