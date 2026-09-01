package relayinfo

type Mode string

const (
	ModeSimple Mode = "simple"
	ModeFull   Mode = "full"
)

type IPFamily string

const (
	IPFamilyAuto    IPFamily = "auto"    // Default: prefers IPv4, auto-fallbacks to IPv6 if node has no IPv4
	IPFamilyIPv4    IPFamily = "ipv4"    // -4 / --ipv4: force IPv4
	IPFamilyIPv6    IPFamily = "ipv6"    // -6 / --ipv6: force IPv6
	IPFamilyNatural IPFamily = "natural" // -n / --natural: dual-stack natural DNS domain forwarding
)

type UnlockStatus string

const (
	StatusFull      UnlockStatus = "full"
	StatusYes       UnlockStatus = "yes"
	StatusOriginals UnlockStatus = "originals"
	StatusNo        UnlockStatus = "no"
	StatusError     UnlockStatus = "error"
	StatusNoIPv6    UnlockStatus = "no_ipv6"
	StatusNoIPv4    UnlockStatus = "no_ipv4"
)

type UnlockItem struct {
	Status UnlockStatus `json:"status"`
	Region string       `json:"region,omitempty"`
	Detail string       `json:"detail,omitempty"`
}

type StreamingUnlock struct {
	Netflix UnlockItem `json:"netflix"`
	Disney  UnlockItem `json:"disney"`
	TikTok  UnlockItem `json:"tiktok"`
}

type GeneralUnlock struct {
	Google UnlockItem `json:"google"`
	OpenAI UnlockItem `json:"openai"`
	Claude UnlockItem `json:"claude"`
}

type LandingProfile struct {
	IP          string `json:"ip,omitempty"`
	IPv4        string `json:"ipv4,omitempty"`
	IPv6        string `json:"ipv6,omitempty"`
	ASN         string `json:"asn,omitempty"`
	ASNType     string `json:"asn_type,omitempty"` // DataCenter / ISP
	Org         string `json:"org,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	Privacy     string `json:"privacy,omitempty"`   // Clear / Flagged / N/A
	Timezone    string `json:"timezone,omitempty"`   // populated only in ModeFull
	LocalTime   string `json:"local_time,omitempty"` // populated only in ModeFull
}

type InfoResult struct {
	Alias      string          `json:"alias"`
	Mode       Mode            `json:"mode,omitempty"`
	Family     IPFamily        `json:"family,omitempty"`
	DurationMs int64           `json:"duration_ms"`
	Profile    LandingProfile  `json:"profile"`
	Streaming  StreamingUnlock `json:"streaming"`
	General    GeneralUnlock   `json:"general"`
	Error      string          `json:"error,omitempty"`
}
