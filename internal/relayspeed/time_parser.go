package relayspeed

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var timeRegex = regexp.MustCompile(`^([0-9]*\.?[0-9]+)\s*([a-zA-Z]*)$`)

var timeUnitMultipliers = map[string]float64{
	"":        1.0,
	"s":       1.0,
	"sec":     1.0,
	"secs":    1.0,
	"second":  1.0,
	"seconds": 1.0,
	"m":       60.0,
	"min":     60.0,
	"mins":    60.0,
	"minute":  60.0,
	"minutes": 60.0,
	"h":       3600.0,
	"hr":      3600.0,
	"hrs":     3600.0,
	"hour":    3600.0,
	"hours":   3600.0,
}

// ParseTime parses a natural time duration string into seconds.
// Supports pure integers (e.g. "10"), suffixes ("10s", "15sec", "1m", "1.5m", "60s"),
// and returns clear errors on invalid formats.
func ParseTime(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	m := timeRegex.FindStringSubmatch(s)
	if len(m) != 3 {
		return 0, fmt.Errorf("invalid duration format: %q", s)
	}

	val, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in duration %q: %w", s, err)
	}
	if val < 0 {
		return 0, fmt.Errorf("duration cannot be negative: %q", s)
	}

	unit := m[2]
	mult, ok := timeUnitMultipliers[unit]
	if !ok {
		return 0, fmt.Errorf("unknown time unit %q in duration %q", unit, s)
	}

	totalSeconds := int(math.Round(val * mult))
	return totalSeconds, nil
}
