package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Base 10 Decimal Constants
const (
	Byte     int64 = 1
	KiloByte int64 = 1000
	MegaByte int64 = 1000 * KiloByte
	GigaByte int64 = 1000 * MegaByte
	TeraByte int64 = 1000 * GigaByte
)

// Base 2 Binary Prefix Constants (int64)
const (
	KibiByte int64 = 1024
	MebiByte int64 = 1024 * KibiByte
	GibiByte int64 = 1024 * MebiByte
	TebiByte int64 = 1024 * GibiByte
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
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty byte size")
	}

	lower := strings.ToLower(s)
	if lower == "-1" || lower == "unlimited" {
		return -1, nil
	}
	if lower == "0" || lower == "paused" {
		return 0, nil
	}

	var multiplier int64
	var numStr string

	switch {
	// Binary prefix (Base 2: 1024)
	case strings.HasSuffix(lower, "tib") || strings.HasSuffix(lower, "ti"):
		multiplier = TebiByte
		numStr = strings.TrimSuffix(strings.TrimSuffix(lower, "tib"), "ti")
	case strings.HasSuffix(lower, "gib") || strings.HasSuffix(lower, "gi"):
		multiplier = GibiByte
		numStr = strings.TrimSuffix(strings.TrimSuffix(lower, "gib"), "gi")
	case strings.HasSuffix(lower, "mib") || strings.HasSuffix(lower, "mi"):
		multiplier = MebiByte
		numStr = strings.TrimSuffix(strings.TrimSuffix(lower, "mib"), "mi")
	case strings.HasSuffix(lower, "kib") || strings.HasSuffix(lower, "ki"):
		multiplier = KibiByte
		numStr = strings.TrimSuffix(strings.TrimSuffix(lower, "kib"), "ki")

	// Decimal SI units (Base 10: 1000)
	case strings.HasSuffix(lower, "tb"):
		multiplier = TeraByte
		numStr = strings.TrimSuffix(lower, "tb")
	case strings.HasSuffix(lower, "t"):
		multiplier = TeraByte
		numStr = strings.TrimSuffix(lower, "t")
	case strings.HasSuffix(lower, "gb"):
		multiplier = GigaByte
		numStr = strings.TrimSuffix(lower, "gb")
	case strings.HasSuffix(lower, "g"):
		multiplier = GigaByte
		numStr = strings.TrimSuffix(lower, "g")
	case strings.HasSuffix(lower, "mb"):
		multiplier = MegaByte
		numStr = strings.TrimSuffix(lower, "mb")
	case strings.HasSuffix(lower, "m"):
		multiplier = MegaByte
		numStr = strings.TrimSuffix(lower, "m")
	case strings.HasSuffix(lower, "kb"):
		multiplier = KiloByte
		numStr = strings.TrimSuffix(lower, "kb")
	case strings.HasSuffix(lower, "k"):
		multiplier = KiloByte
		numStr = strings.TrimSuffix(lower, "k")
	case strings.HasSuffix(lower, "b"):
		multiplier = Byte
		numStr = strings.TrimSuffix(lower, "b")
	default:
		// Default to GB (Base 10) for pure numbers
		multiplier = GigaByte
		numStr = lower
	}

	numStr = strings.TrimSpace(numStr)
	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number format %q in %q: %w", numStr, s, err)
	}
	if val < 0 {
		return -1, nil
	}

	total := int64(math.Round(val * float64(multiplier)))
	return total, nil
}

// FormatByteSize formats bytes into clean readable string, preferring Base 10
func FormatByteSize(bytes int64) string {
	switch {
	case bytes < 0:
		return "Unlimited"
	case bytes == 0:
		return "0B"
	case bytes >= TeraByte:
		return fmt.Sprintf("%.2fTB", float64(bytes)/float64(TeraByte))
	case bytes >= GigaByte:
		return fmt.Sprintf("%.2fGB", float64(bytes)/float64(GigaByte))
	case bytes >= MegaByte:
		return fmt.Sprintf("%.2fMB", float64(bytes)/float64(MegaByte))
	case bytes >= KiloByte:
		return fmt.Sprintf("%.2fKB", float64(bytes)/float64(KiloByte))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
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
