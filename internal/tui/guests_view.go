package tui

import (
	"fmt"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/sub"

	"github.com/charmbracelet/lipgloss"
)

func RenderGuests(active *config.UserConfig, staging *config.UserConfig, selectedIdx int, width int) string {
	if staging == nil {
		return "No configuration found."
	}
	if len(staging.Guests) == 0 {
		return lipgloss.NewStyle().Padding(2, 5).Render("No guests. Press [N] to add.")
	}

	availableWidth := width - 10
	if availableWidth < 50 {
		availableWidth = 50
	}

	wIndicator := 4
	wAlias := 14
	wState := 8
	wSub := 7
	wReason := 13
	wQuota := 20
	wReset := 7
	wOutbound := availableWidth - wIndicator - wAlias - wState - wSub - wReason - wQuota - wReset
	if wOutbound < 10 {
		wOutbound = 10
	}

	headers := []string{"  ", "ALIAS", "STATE", "SUB", "REASON", "QUOTA (USED/LIM)", "RESET", "OUTBOUND"}
	widths := []int{wIndicator, wAlias, wState, wSub, wReason, wQuota, wReset, wOutbound}

	var b strings.Builder
	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")
	for i, g := range staging.Guests {
		indicator := "   "
		if guestChanged(active, g) {
			indicator = "[*]"
		}
		used := fmt.Sprintf("%.2fGB", float64(g.UsedBytes)/(1024*1024*1024))
		row := []string{
			indicator,
			g.Alias,
			guestStateLabel(g),
			guestSubStateLabel(g),
			guestReasonLabel(g),
			used + "/" + formatGuestQuota(g.QuotaGB),
			fmt.Sprintf("%d", g.ResetDay),
			guestOutboundLabel(g),
		}
		s := renderRow(row, widths, false)
		if !g.Enabled {
			s = faintStyle.Render(s)
		}
		if i == selectedIdx {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func BuildGuestReport(guest config.GuestConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Guest: %s\n", guest.Alias))
	b.WriteString(fmt.Sprintf("UUID: %s\n", guest.UUID))
	b.WriteString(fmt.Sprintf("State: %s\n", guestStateLabel(guest)))
	b.WriteString(fmt.Sprintf("Reason: %s\n", guestReasonLabel(guest)))
	b.WriteString(fmt.Sprintf("Quota: %s\n", formatGuestQuota(guest.QuotaGB)))
	b.WriteString(fmt.Sprintf("Used: %.2fGB\n", float64(guest.UsedBytes)/(1024*1024*1024)))
	b.WriteString(fmt.Sprintf("Reset Day: %d\n", guest.ResetDay))
	if guest.LastResetYM == "" {
		b.WriteString("Last Reset Month: -\n")
	} else {
		b.WriteString(fmt.Sprintf("Last Reset Month: %s\n", guest.LastResetYM))
	}
	b.WriteString(fmt.Sprintf("Outbound: %s\n", guestOutboundLabel(guest)))
	if guest.SubToken == "" {
		b.WriteString("Guest Sub: disabled\n")
	} else {
		b.WriteString("Guest Sub: enabled\n")
		b.WriteString(fmt.Sprintf("Remark Preview: %s\n", sub.FormatGuestSubRemarkForDisplay(guest, time.Now())))
	}
	return b.String()
}

func formatGuestQuota(value float64) string {
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

func guestStateLabel(guest config.GuestConfig) string {
	if guest.Enabled {
		return "ON"
	}
	switch guest.DisabledReason {
	case config.GuestDisabledQuotaReached:
		return "QUOTA"
	case config.GuestDisabledQuotaZero, config.GuestDisabledManual:
		return "PAUSED"
	default:
		return "OFF"
	}
}

func guestReasonLabel(guest config.GuestConfig) string {
	switch guest.DisabledReason {
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

func guestOutboundLabel(guest config.GuestConfig) string {
	if guest.OutboundLink != "" {
		return "custom-link"
	}
	return "direct"
}

func guestSubStateLabel(guest config.GuestConfig) string {
	if guest.SubToken == "" {
		return "OFF"
	}
	return "ON"
}

func guestChanged(active *config.UserConfig, guest config.GuestConfig) bool {
	if active == nil {
		return true
	}
	for _, g := range active.Guests {
		if g.Alias == guest.Alias {
			return g.UUID != guest.UUID ||
				g.Enabled != guest.Enabled ||
				g.DisabledReason != guest.DisabledReason ||
				g.QuotaGB != guest.QuotaGB ||
				g.ResetDay != guest.ResetDay ||
				g.SubToken != guest.SubToken ||
				g.OutboundLink != guest.OutboundLink
		}
	}
	return true
}
