package quota

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/notify"
)

type UpdateResult struct {
	Changed       bool
	RestartNeeded bool
	Messages      []string
}

type Monitor struct {
	lastObserved map[string]int64
}

type persistedState struct {
	LastObserved map[string]int64 `json:"last_observed"`
}

func NewMonitor() *Monitor {
	return &Monitor{lastObserved: make(map[string]int64)}
}

func LoadMonitor() (*Monitor, error) {
	data, err := os.ReadFile(statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return NewMonitor(), nil
		}
		return nil, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.LastObserved == nil {
		state.LastObserved = make(map[string]int64)
	}
	return &Monitor{lastObserved: state.LastObserved}, nil
}

func (m *Monitor) Reset() {
	if m == nil {
		return
	}
	m.lastObserved = make(map[string]int64)
}

func (m *Monitor) Save() error {
	if m == nil {
		return nil
	}
	path := statePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	state := persistedState{LastObserved: m.lastObserved}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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
			if guest.AlertedYM != "" {
				guest.AlertedYM = ""
				result.Changed = true
			}
			if len(guest.AlertedTriggers) > 0 {
				guest.AlertedTriggers = nil
				result.Changed = true
			}
			if guest.EffectiveLimitBytes() > 0 && !guest.Enabled {
				guest.Enabled = true
				guest.DisabledReason = config.GuestDisabledNone
				result.Changed = true
			}
			if guest.EffectiveLimitBytes() != 0 {
				result.RestartNeeded = true
				result.Messages = append(result.Messages, fmt.Sprintf("quota reset rolled guest %s into %s", guest.Alias, monthKey))
			}
			m.lastObserved[aliasKey] = 0
			delta = 0

			if guest.NotifyWebhook != "" {
				days := guest.DaysUntilReset(now)
				notify.SendGuestWebhookAsync(guest.NotifyWebhook, notify.GuestWebhookPayload{
					Event:     "quota.reset",
					Timestamp: now.Unix(),
					Guest: notify.GuestInfo{
						Alias:          guest.Alias,
						UsedBytes:      0,
						UsedGB:         0,
						QuotaGB:        guest.QuotaGB,
						Percent:        0,
						ResetDay:       guest.ResetDay,
						DaysUntilReset: days,
						Status:         "enabled",
					},
					Message: fmt.Sprintf("Guest [%s] quota reset for %s (%.2fGB). Account is active.", guest.Alias, monthKey, guest.QuotaGB),
				})
			}
		}

		if delta != 0 {
			guest.UsedBytes += delta
			result.Changed = true
		}

		limitBytes := guest.EffectiveLimitBytes()
		switch {
		case limitBytes == 0:
			if guest.Enabled || guest.DisabledReason != config.GuestDisabledQuotaZero {
				guest.Enabled = false
				guest.DisabledReason = config.GuestDisabledQuotaZero
				result.Changed = true
				result.RestartNeeded = true
				result.Messages = append(result.Messages, fmt.Sprintf("paused guest %s because quota is 0", guest.Alias))
			}
		case limitBytes > 0:
			if guest.UsedBytes >= limitBytes && guest.Enabled {
				guest.Enabled = false
				guest.DisabledReason = config.GuestDisabledQuotaReached
				result.Changed = true
				result.RestartNeeded = true
				result.Messages = append(result.Messages, fmt.Sprintf("disabled guest %s after quota reached", guest.Alias))

				if guest.NotifyWebhook != "" && guest.AlertedYM != monthKey+"-exceeded" {
					guest.AlertedYM = monthKey + "-exceeded"
					result.Changed = true
					days := guest.DaysUntilReset(now)
					usedGB := float64(guest.UsedBytes) / float64(config.GigaByte)
					limitGB := float64(limitBytes) / float64(config.GigaByte)
					notify.SendGuestWebhookAsync(guest.NotifyWebhook, notify.GuestWebhookPayload{
						Event:     "quota.exceeded",
						Timestamp: now.Unix(),
						Guest: notify.GuestInfo{
							Alias:          guest.Alias,
							UsedBytes:      guest.UsedBytes,
							UsedGB:         usedGB,
							QuotaGB:        limitGB,
							Percent:        float64(guest.UsedBytes) * 100 / float64(limitBytes),
							ResetDay:       guest.ResetDay,
							DaysUntilReset: days,
							Status:         "disabled",
						},
						Message: fmt.Sprintf("Guest [%s] quota exceeded (%s / %s). Account is disabled.", guest.Alias, config.FormatByteSize(guest.UsedBytes), config.FormatByteSize(limitBytes)),
					})
				}
			} else if guest.UsedBytes < limitBytes && guest.Enabled && guest.NotifyWebhook != "" {
				remainingBytes := limitBytes - guest.UsedBytes
				remainingPercent := float64(remainingBytes) * 100.0 / float64(limitBytes)

				if len(guest.NotifyTrigger) > 0 {
					_, parsedTriggers, _ := config.ParseTriggers(strings.Join(guest.NotifyTrigger, ","), limitBytes)
					for _, tr := range parsedTriggers {
						alreadyFired := false
						for _, a := range guest.AlertedTriggers {
							if strings.EqualFold(a, tr.Raw) {
								alreadyFired = true
								break
							}
						}
						if alreadyFired {
							continue
						}

						matched := false
						if tr.Type == config.TriggerTypePercent && remainingPercent < tr.Percent {
							matched = true
						} else if tr.Type == config.TriggerTypeBytes && remainingBytes < tr.Bytes {
							matched = true
						}

						if matched {
							guest.AlertedTriggers = append(guest.AlertedTriggers, tr.Raw)
							result.Changed = true
							days := guest.DaysUntilReset(now)
							usedGB := float64(guest.UsedBytes) / float64(config.GigaByte)
							limitGB := float64(limitBytes) / float64(config.GigaByte)
							notify.SendGuestWebhookAsync(guest.NotifyWebhook, notify.GuestWebhookPayload{
								Event:     "quota.trigger",
								Timestamp: now.Unix(),
								Guest: notify.GuestInfo{
									Alias:          guest.Alias,
									UsedBytes:      guest.UsedBytes,
									UsedGB:         usedGB,
									QuotaGB:        limitGB,
									Percent:        float64(guest.UsedBytes) * 100 / float64(limitBytes),
									ResetDay:       guest.ResetDay,
									DaysUntilReset: days,
									Status:         "enabled",
								},
								Message: fmt.Sprintf("Guest [%s] remaining quota is below %s (Remaining: %s / %s, %.1f%%). %dd until reset.", guest.Alias, tr.Raw, config.FormatByteSize(remainingBytes), config.FormatByteSize(limitBytes), remainingPercent, days),
							})
						}
					}
				} else if guest.UsedBytes >= int64(0.8*float64(limitBytes)) {
					if guest.AlertedYM != monthKey+"-warning" && guest.AlertedYM != monthKey+"-exceeded" {
						guest.AlertedYM = monthKey + "-warning"
						result.Changed = true
						days := guest.DaysUntilReset(now)
						usedGB := float64(guest.UsedBytes) / float64(config.GigaByte)
						limitGB := float64(limitBytes) / float64(config.GigaByte)
						percent := float64(guest.UsedBytes) * 100 / float64(limitBytes)
						notify.SendGuestWebhookAsync(guest.NotifyWebhook, notify.GuestWebhookPayload{
							Event:     "quota.warning",
							Timestamp: now.Unix(),
							Guest: notify.GuestInfo{
								Alias:          guest.Alias,
								UsedBytes:      guest.UsedBytes,
								UsedGB:         usedGB,
								QuotaGB:        limitGB,
								Percent:        percent,
								ResetDay:       guest.ResetDay,
								DaysUntilReset: days,
								Status:         "enabled",
							},
							Message: fmt.Sprintf("Guest [%s] reached %.1f%% of quota (%s / %s). %dd until reset.", guest.Alias, percent, config.FormatByteSize(guest.UsedBytes), config.FormatByteSize(limitBytes), days),
						})
					}
				}
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
	if guest == nil || guest.ResetDay < 1 || guest.EffectiveLimitBytes() == 0 {
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

func statePath() string {
	return filepath.Join(config.GetConfigDir(), "quota-monitor.json")
}
