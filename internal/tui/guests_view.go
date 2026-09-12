package tui

import (
	"fmt"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/quota"
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

	headers := []string{"  ", "ALIAS", "STATE", "ENDPOINT", "SUB", "REASON", "QUOTA (USED/LIM)", "RESET", "RELAY"}
	rows := make([][]string, 0, len(staging.Guests))
	disabled := make([]bool, 0, len(staging.Guests))

	for _, g := range staging.Guests {
		indicator := "   "
		if guestChanged(active, g) {
			indicator = "[*]"
		}
		used := config.FormatByteSize(g.UsedBytes)
		limit := config.FormatByteSize(g.EffectiveLimitBytes())
		ep := g.Endpoint
		if ep == "" {
			ep = "default"
		}
		row := []string{
			indicator,
			g.Alias,
			guestStateLabel(g),
			ep,
			guestSubStateLabel(g),
			guestReasonLabel(g),
			used + "/" + limit,
			fmt.Sprintf("%d", g.ResetDay),
			guestOutboundLabel(g),
		}
		rows = append(rows, row)
		disabled = append(disabled, !g.Enabled)
	}

	widths := fitTableWidths(headers, rows, []int{3, 8, 5, 8, 3, 6, 14, 5, 7}, width)

	var b strings.Builder
	b.WriteString(renderRow(headers, widths, true))
	b.WriteString("\n")
	for i, row := range rows {
		s := renderRow(row, widths, false)
		if disabled[i] {
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
	b.WriteString(fmt.Sprintf("Limit: %s\n", config.FormatByteSize(guest.EffectiveLimitBytes())))
	b.WriteString(fmt.Sprintf("Used: %s\n", config.FormatByteSize(guest.UsedBytes)))
	b.WriteString(fmt.Sprintf("Reset Day: %d\n", guest.ResetDay))
	if guest.LastResetYM == "" {
		b.WriteString("Last Reset Month: -\n")
	} else {
		b.WriteString(fmt.Sprintf("Last Reset Month: %s\n", guest.LastResetYM))
	}
	ep := guest.Endpoint
	if ep == "" {
		ep = "default"
	}
	b.WriteString(fmt.Sprintf("Endpoint: %s\n", ep))
	b.WriteString(fmt.Sprintf("Notify: %s\n", guest.NormalizedNotifyMode()))
	if guest.NotifyWebhook == "" {
		b.WriteString("Notify Webhook: -\n")
	} else {
		b.WriteString(fmt.Sprintf("Notify Webhook: %s\n", guest.NotifyWebhook))
	}
	if len(guest.NotifyTrigger) > 0 {
		b.WriteString(fmt.Sprintf("Notify Trigger: %s\n", strings.Join(guest.NotifyTrigger, ", ")))
	} else {
		b.WriteString("Notify Trigger: -\n")
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
	return quota.FormatQuota(value)
}

func guestStateLabel(guest config.GuestConfig) string {
	return quota.GuestStateLabel(guest)
}

func guestReasonLabel(guest config.GuestConfig) string {
	return quota.GuestReasonLabel(guest)
}

func guestOutboundLabel(guest config.GuestConfig) string {
	if guest.OutboundLink == "" {
		return "direct"
	}
	if strings.Contains(guest.OutboundLink, "://") {
		return "link"
	}
	return guest.OutboundLink
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
				g.LimitBytes != guest.LimitBytes ||
				g.ResetDay != guest.ResetDay ||
				g.SubToken != guest.SubToken ||
				g.Endpoint != guest.Endpoint ||
				g.OutboundLink != guest.OutboundLink ||
				g.Notify != guest.Notify ||
				g.NotifyWebhook != guest.NotifyWebhook ||
				!sliceEqual(g.NotifyTrigger, guest.NotifyTrigger)
		}
	}
	return true
}
