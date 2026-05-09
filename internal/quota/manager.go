package quota

import (
	"fmt"
	"math"
	"strings"
	"time"
	"xray-proxya/internal/config"
)

type UpdateResult struct {
	Changed       bool
	RestartNeeded bool
	Messages      []string
}

type Monitor struct {
	lastObserved map[string]int64
}

func NewMonitor() *Monitor {
	return &Monitor{lastObserved: make(map[string]int64)}
}

func (m *Monitor) Reset() {
	if m == nil {
		return
	}
	m.lastObserved = make(map[string]int64)
}

func (m *Monitor) UpdateGuests(cfg *config.UserConfig, allStats map[string]int64, now time.Time) UpdateResult {
	if cfg == nil {
		return UpdateResult{}
	}
	if m == nil {
		m = NewMonitor()
	}

	observed := collectGuestUsage(allStats)
	result := UpdateResult{}
	monthKey := now.Format("2006-01")

	for i := range cfg.Guests {
		guest := &cfg.Guests[i]
		aliasKey := sanitizeGuestAlias(guest.Alias)
		currentObserved := observed[aliasKey]
		previousObserved := m.lastObserved[aliasKey]
		delta := currentObserved
		if currentObserved >= previousObserved {
			delta = currentObserved - previousObserved
		}
		m.lastObserved[aliasKey] = currentObserved

		if shouldResetGuest(guest, now, monthKey) {
			if guest.UsedBytes != 0 {
				guest.UsedBytes = 0
				result.Changed = true
			}
			if guest.LastResetYM != monthKey {
				guest.LastResetYM = monthKey
				result.Changed = true
			}
			if guest.QuotaGB > 0 && !guest.Enabled {
				guest.Enabled = true
				result.Changed = true
			}
			if guest.QuotaGB != 0 {
				result.RestartNeeded = true
				result.Messages = append(result.Messages, fmt.Sprintf("quota reset rolled guest %s into %s", guest.Alias, monthKey))
			}
			m.lastObserved[aliasKey] = 0
			delta = 0
		}

		if delta != 0 {
			guest.UsedBytes += delta
			result.Changed = true
		}

		switch {
		case guest.QuotaGB == 0:
			if guest.Enabled {
				guest.Enabled = false
				result.Changed = true
				result.RestartNeeded = true
				result.Messages = append(result.Messages, fmt.Sprintf("paused guest %s because quota is 0", guest.Alias))
			}
		case guest.QuotaGB > 0:
			limitBytes := int64(math.Round(guest.QuotaGB * 1024 * 1024 * 1024))
			if limitBytes > 0 && guest.UsedBytes >= limitBytes && guest.Enabled {
				guest.Enabled = false
				result.Changed = true
				result.RestartNeeded = true
				result.Messages = append(result.Messages, fmt.Sprintf("disabled guest %s after quota reached", guest.Alias))
			}
		}
	}

	return result
}

func collectGuestUsage(allStats map[string]int64) map[string]int64 {
	out := make(map[string]int64)
	for name, val := range allStats {
		if !strings.HasPrefix(name, "user>>>guest-") {
			continue
		}
		parts := strings.Split(name, ">>>")
		if len(parts) < 2 {
			continue
		}
		alias := strings.TrimPrefix(parts[1], "guest-")
		if alias == "" {
			continue
		}
		out[alias] += val
	}
	return out
}

func shouldResetGuest(guest *config.GuestConfig, now time.Time, monthKey string) bool {
	if guest == nil || guest.ResetDay < 1 || guest.QuotaGB == 0 {
		return false
	}
	if now.Day() < guest.ResetDay {
		return false
	}
	return guest.LastResetYM != monthKey
}

func sanitizeGuestAlias(alias string) string {
	var b strings.Builder
	for _, r := range alias {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	return out
}
