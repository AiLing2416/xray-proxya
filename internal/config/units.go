package config

import (
	"fmt"
	"strconv"
	"strings"
	"xray-proxya/pkg/units"
)

// Base 10 Decimal Constants
const (
	Byte     int64 = units.Byte
	KiloByte int64 = units.KiloByte
	MegaByte int64 = units.MegaByte
	GigaByte int64 = units.GigaByte
	TeraByte int64 = units.TeraByte
)

// Base 2 Binary Prefix Constants (int64)
const (
	KibiByte int64 = units.KibiByte
	MebiByte int64 = units.MebiByte
	GibiByte int64 = units.GibiByte
	TebiByte int64 = units.TebiByte
)

type TriggerType int

const (
	TriggerTypePercent TriggerType = iota
	TriggerTypeBytes
)

type ParsedTrigger struct {
	Raw     string
	Type    TriggerType
	Percent float64
	Bytes   int64
}

// ParseByteSize parses human-readable byte sizes with Base 10 (KB, MB, GB, TB)
// and Base 2 (KiB, MiB, GiB, TiB). Inputs are case-insensitive.
// Pure numbers default to GB (Base 10).
func ParseByteSize(s string) (int64, error) {
	return units.ParseBytes(s)
}

// FormatByteSize formats bytes into clean readable string, preferring Base 10
func FormatByteSize(bytes int64) string {
	return units.FormatSI(bytes)
}

// ParseTriggers parses and validates comma-separated trigger strings against limitBytes.
// Triggers cannot exceed limitBytes or 100%.
func ParseTriggers(raw string, limitBytes int64) ([]string, []ParsedTrigger, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "none") || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "clear") {
		return nil, nil, nil
	}

	parts := strings.Split(raw, ",")
	normalizedStrings := make([]string, 0, len(parts))
	parsedTriggers := make([]ParsedTrigger, 0, len(parts))
	seen := make(map[string]bool)

	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item == "" {
			continue
		}
		itemLower := strings.ToLower(item)
		if seen[itemLower] {
			continue
		}

		if strings.HasSuffix(itemLower, "p") || strings.HasSuffix(itemLower, "%") {
			numPart := strings.TrimSuffix(strings.TrimSuffix(itemLower, "p"), "%")
			pct, err := strconv.ParseFloat(numPart, 64)
			if err != nil || pct <= 0 {
				return nil, nil, fmt.Errorf("invalid trigger percentage %q: must be a positive number", item)
			}
			if pct > 100 {
				return nil, nil, fmt.Errorf("trigger percentage %.1f%% cannot exceed 100%%", pct)
			}
			norm := fmt.Sprintf("%sp", strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", pct), "0"), "."))
			normalizedStrings = append(normalizedStrings, norm)
			parsedTriggers = append(parsedTriggers, ParsedTrigger{
				Raw:     norm,
				Type:    TriggerTypePercent,
				Percent: pct,
			})
			seen[itemLower] = true
			continue
		}

		// Capacity trigger
		b, err := ParseByteSize(item)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid trigger %q: %w", item, err)
		}
		if b <= 0 {
			return nil, nil, fmt.Errorf("trigger capacity %q must be greater than 0", item)
		}
		if limitBytes > 0 && b > limitBytes {
			return nil, nil, fmt.Errorf("trigger %q (%s) cannot exceed limit of %s", item, FormatByteSize(b), FormatByteSize(limitBytes))
		}
		norm := itemLower
		normalizedStrings = append(normalizedStrings, norm)
		parsedTriggers = append(parsedTriggers, ParsedTrigger{
			Raw:   norm,
			Type:  TriggerTypeBytes,
			Bytes: b,
		})
		seen[itemLower] = true
	}

	return normalizedStrings, parsedTriggers, nil
}
