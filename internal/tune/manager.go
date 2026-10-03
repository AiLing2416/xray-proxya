package tune

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	readSysctlFn  = ReadSysctl
	writeSysctlFn = WriteSysctl
)

type DiffEntry struct {
	Key       string
	Current   string
	Target    string
	Status    string
	Error     string
	Supported bool
}

func DiffProfile(profile Profile) []DiffEntry {
	out := make([]DiffEntry, 0, len(profile.Settings))
	for _, setting := range profile.Settings {
		current, err := readSysctlFn(setting.Key)
		switch {
		case err == nil:
			status := "change"
			if normalizeValue(current) == normalizeValue(setting.Value) {
				status = "ok"
			}
			out = append(out, DiffEntry{
				Key:       setting.Key,
				Current:   current,
				Target:    normalizeValue(setting.Value),
				Status:    status,
				Supported: true,
			})
		case errors.Is(err, ErrUnsupported):
			out = append(out, DiffEntry{
				Key:       setting.Key,
				Target:    normalizeValue(setting.Value),
				Status:    "unsupported",
				Supported: false,
			})
		default:
			out = append(out, DiffEntry{
				Key:       setting.Key,
				Target:    normalizeValue(setting.Value),
				Status:    "failed",
				Error:     err.Error(),
				Supported: true,
			})
		}
	}
	return out
}

func ApplyProfile(profile Profile) (*RuntimeState, error) {
	existingOldValues := make(map[string]string)
	var preservedEntries []RuntimeEntry
	if existingState, err := LoadRuntimeState(); err == nil && existingState != nil {
		profileKeys := make(map[string]bool, len(profile.Settings))
		for _, s := range profile.Settings {
			profileKeys[s.Key] = true
		}
		for _, entry := range existingState.Entries {
			if entry.OldValue != "" {
				existingOldValues[entry.Key] = entry.OldValue
			}
			if !profileKeys[entry.Key] && entry.OldValue != "" {
				preservedEntries = append(preservedEntries, entry)
			}
		}
	}

	state := &RuntimeState{
		Profile:   profile.Name,
		AppliedAt: time.Now(),
		Entries:   make([]RuntimeEntry, 0, len(profile.Settings)+len(preservedEntries)),
	}
	var failures []string

	for _, setting := range profile.Settings {
		target := normalizeValue(setting.Value)
		current, err := readSysctlFn(setting.Key)
		switch {
		case errors.Is(err, ErrUnsupported):
			state.Entries = append(state.Entries, RuntimeEntry{
				Key:      setting.Key,
				NewValue: target,
				Status:   "unsupported",
			})
			continue
		case err != nil:
			state.Entries = append(state.Entries, RuntimeEntry{
				Key:      setting.Key,
				NewValue: target,
				Status:   "failed",
				Error:    err.Error(),
			})
			failures = append(failures, fmt.Sprintf("%s: %v", setting.Key, err))
			continue
		}

		oldVal := current
		if orig, ok := existingOldValues[setting.Key]; ok && orig != "" {
			oldVal = orig
		}

		entry := RuntimeEntry{
			Key:      setting.Key,
			OldValue: oldVal,
			NewValue: target,
		}
		if current == target {
			if oldVal == target {
				entry.Status = "ok"
			} else {
				entry.Status = "applied"
			}
			state.Entries = append(state.Entries, entry)
			continue
		}
		if err := writeSysctlFn(setting.Key, target); err != nil {
			if errors.Is(err, ErrUnsupported) {
				entry.Status = "unsupported"
			} else {
				entry.Status = "failed"
				entry.Error = err.Error()
				failures = append(failures, fmt.Sprintf("%s: %v", setting.Key, err))
			}
			state.Entries = append(state.Entries, entry)
			continue
		}
		entry.Status = "applied"
		state.Entries = append(state.Entries, entry)
	}

	state.Entries = append(state.Entries, preservedEntries...)

	if err := SaveRuntimeState(state); err != nil {
		return state, err
	}
	if len(failures) > 0 {
		return state, errors.New(strings.Join(failures, "; "))
	}
	return state, nil
}

func VerifyProfile(profile Profile) []DiffEntry {
	return DiffProfile(profile)
}

func RollbackRuntimeState(state *RuntimeState) ([]RuntimeEntry, error) {
	results := make([]RuntimeEntry, 0, len(state.Entries))
	var failures []string

	for _, entry := range state.Entries {
		result := RuntimeEntry{
			Key:      entry.Key,
			OldValue: entry.NewValue,
			NewValue: entry.OldValue,
		}
		switch entry.Status {
		case "unsupported":
			result.Status = "unsupported"
		case "failed":
			result.Status = "skipped"
			result.Error = "original apply failed"
		default:
			if entry.OldValue == "" {
				result.Status = "skipped"
				result.Error = "missing previous value"
				break
			}
			current, err := readSysctlFn(entry.Key)
			if err != nil {
				if errors.Is(err, ErrUnsupported) {
					result.Status = "unsupported"
				} else {
					result.Status = "failed"
					result.Error = err.Error()
					failures = append(failures, fmt.Sprintf("%s: %v", entry.Key, err))
				}
				break
			}
			if current == entry.OldValue {
				result.Status = "ok"
				break
			}
			if err := writeSysctlFn(entry.Key, entry.OldValue); err != nil {
				if errors.Is(err, ErrUnsupported) {
					result.Status = "unsupported"
				} else {
					result.Status = "failed"
					result.Error = err.Error()
					failures = append(failures, fmt.Sprintf("%s: %v", entry.Key, err))
				}
				break
			}
			result.Status = "rolled_back"
		}
		results = append(results, result)
	}

	if len(failures) == 0 {
		_ = ClearRuntimeState()
		return results, nil
	}
	return results, errors.New(strings.Join(failures, "; "))
}

type ShowData struct {
	KernelVersion string
	AvailableCC   []string
	Values        []DiffEntry
	RuntimeState  *RuntimeState
}

func ShowDataForKeys() ShowData {
	keys := []string{
		"net.core.default_qdisc",
		"net.ipv4.tcp_available_congestion_control",
		"net.ipv4.tcp_congestion_control",
		"net.ipv4.ip_forward",
		"net.ipv6.conf.all.forwarding",
		"net.netfilter.nf_conntrack_max",
		"net.core.somaxconn",
		"net.ipv4.tcp_max_syn_backlog",
		"net.ipv4.ip_local_port_range",
		"net.core.netdev_max_backlog",
		"net.core.rmem_max",
		"net.core.wmem_max",
	}
	values := make([]DiffEntry, 0, len(keys))
	for _, key := range keys {
		current, err := readSysctlFn(key)
		switch {
		case err == nil:
			values = append(values, DiffEntry{Key: key, Current: current, Status: "ok", Supported: true})
		case errors.Is(err, ErrUnsupported):
			values = append(values, DiffEntry{Key: key, Status: "unsupported"})
		default:
			values = append(values, DiffEntry{Key: key, Status: "failed", Error: err.Error()})
		}
	}
	cc, _ := AvailableCongestionControls()
	state, _ := LoadRuntimeState()
	return ShowData{
		KernelVersion: KernelVersion(),
		AvailableCC:   cc,
		Values:        values,
		RuntimeState:  state,
	}
}

func SupportsBBR() bool {
	cc, err := AvailableCongestionControls()
	if err != nil {
		return false
	}
	return slices.Contains(cc, "bbr")
}
