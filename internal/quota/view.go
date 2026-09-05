package quota

import (
	"fmt"
	"strings"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
)

// GuestQuotaView represents the comprehensive computed state of a guest's quota and runtime status.
type GuestQuotaView struct {
	Alias              string
	UUID               string
	StateLabel         string // "ON", "QUOTA", "PAUSED", "OFF"
	ReasonLabel        string // "manual", "quota reached", "quota=0", "-"
	QuotaFormatted     string
	UsedBytes          int64
	UsedFormatted      string
	LimitBytes         int64
	LimitFormatted     string
	RemainingBytes     int64
	RemainingFormatted string
	UsagePercent       float64 // 0~100 (or -1 if unlimited)
	ResetDay           int
	DaysUntilReset     int
	RelayLabel         string // "direct", "custom-link"
	OutboundLink       string
	SubToken           string
	NotifyWebhook      string
	NotifyTriggers     []string
	AlertedTriggers    []string
	LastResetYM        string
	AlertedYM          string
}

// GuestStateLabel returns standard state indicator for a guest ("ON", "QUOTA", "PAUSED", "OFF").
func GuestStateLabel(g config.GuestConfig) string {
	if g.Enabled {
		return "ON"
	}
	switch g.DisabledReason {
	case config.GuestDisabledQuotaReached:
		return "QUOTA"
	case config.GuestDisabledQuotaZero, config.GuestDisabledManual:
		return "PAUSED"
	default:
		return "OFF"
	}
}

// GuestReasonLabel returns a human-readable reason string when a guest is disabled.
func GuestReasonLabel(g config.GuestConfig) string {
	switch g.DisabledReason {
	case config.GuestDisabledManual:
		return "manual"
	case config.GuestDisabledQuotaReached:
		return "quota reached"
	case config.GuestDisabledQuotaZero:
		return "quota=0"
	default:
		return "-"
	}
}

// FormatQuota displays a quota value formatted as Unlimited, Paused, or formatted GB.
func FormatQuota(value float64) string {
	switch {
	case value < 0:
		return "Unlimited"
	case value == 0:
		return "Paused"
	case value >= 10:
		return fmt.Sprintf("%.1fGB", value)
	case value >= 1:
		return fmt.Sprintf("%.2fGB", value)
	default:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", value), "0"), ".") + "GB"
	}
}

// BuildGuestView computes the complete state and quota metrics for a single guest.
func BuildGuestView(g config.GuestConfig, now time.Time) GuestQuotaView {
	limitBytes := g.EffectiveLimitBytes()
	usedBytes := g.UsedBytes
	remainingBytes := int64(0)
	percent := float64(-1)

	if limitBytes > 0 {
		if usedBytes < limitBytes {
			remainingBytes = limitBytes - usedBytes
		}
		percent = float64(usedBytes) * 100.0 / float64(limitBytes)
	}

	relay := "direct"
	if g.OutboundLink != "" {
		relay = "custom-link"
	}

	return GuestQuotaView{
		Alias:              g.Alias,
		UUID:               g.UUID,
		StateLabel:         GuestStateLabel(g),
		ReasonLabel:        GuestReasonLabel(g),
		QuotaFormatted:     FormatQuota(g.QuotaGB),
		UsedBytes:          usedBytes,
		UsedFormatted:      config.FormatByteSize(usedBytes),
		LimitBytes:         limitBytes,
		LimitFormatted:     config.FormatByteSize(limitBytes),
		RemainingBytes:     remainingBytes,
		RemainingFormatted: config.FormatByteSize(remainingBytes),
		UsagePercent:       percent,
		ResetDay:           g.ResetDay,
		DaysUntilReset:     g.DaysUntilReset(now),
		RelayLabel:         relay,
		OutboundLink:       g.OutboundLink,
		SubToken:           g.SubToken,
		NotifyWebhook:      g.NotifyWebhook,
		NotifyTriggers:     g.NotifyTrigger,
		AlertedTriggers:    g.AlertedTriggers,
		LastResetYM:        g.LastResetYM,
		AlertedYM:          g.AlertedYM,
	}
}

// BuildAllGuestViews constructs GuestQuotaView for all configured guests.
func BuildAllGuestViews(guests []config.GuestConfig, now time.Time) []GuestQuotaView {
	views := make([]GuestQuotaView, len(guests))
	for i, g := range guests {
		views[i] = BuildGuestView(g, now)
	}
	return views
}

// TrafficOverview combines gRPC statistics summary with guest views.
type TrafficOverview struct {
	DirectTraffic int64
	RelayTraffic  int64
	InboundStats  map[string]int64
	ServiceStats  map[string]int64
	RelayStats    map[string]int64
	GuestStats    map[string]int64
	GuestViews    []GuestQuotaView
}

// FetchTrafficOverview queries the Xray gRPC API stats and aggregates it into a unified overview.
func FetchTrafficOverview(apiPort int, cfg *config.UserConfig, now time.Time) (*TrafficOverview, error) {
	allStats, err := xray.GetXrayStats(apiPort)
	if err != nil {
		return nil, err
	}
	summary := trafficstats.Summarize(allStats)
	var views []GuestQuotaView
	if cfg != nil {
		views = BuildAllGuestViews(cfg.Guests, now)
	}
	return &TrafficOverview{
		DirectTraffic: summary.Direct,
		RelayTraffic:  summary.Relay,
		InboundStats:  summary.InboundStats,
		ServiceStats:  summary.ServiceStats,
		RelayStats:    summary.RelayStats,
		GuestStats:    summary.GuestStats,
		GuestViews:    views,
	}, nil
}
