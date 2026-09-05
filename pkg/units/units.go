package units

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Base 10 Decimal Constants (SI standard, 1000-based)
const (
	Byte     int64 = 1
	KiloByte int64 = 1000
	MegaByte int64 = 1000 * KiloByte
	GigaByte int64 = 1000 * MegaByte
	TeraByte int64 = 1000 * GigaByte
	PetaByte int64 = 1000 * TeraByte

	// Short aliases for SI units
	KB = KiloByte
	MB = MegaByte
	GB = GigaByte
	TB = TeraByte
	PB = PetaByte
)

// Base 2 Binary Prefix Constants (IEC standard, 1024-based with 'i')
const (
	KibiByte int64 = 1024
	MebiByte int64 = 1024 * KibiByte
	GibiByte int64 = 1024 * MebiByte
	TebiByte int64 = 1024 * GibiByte
	PebiByte int64 = 1024 * TebiByte
	ExbiByte int64 = 1024 * PebiByte

	// Short aliases for IEC units
	KiB = KibiByte
	MiB = MebiByte
	GiB = GibiByte
	TiB = TebiByte
	PiB = PebiByte
	EiB = ExbiByte
)

// FormatIEC formats bytes into binary prefix strings using Base 1024 with 'i' (KiB, MiB, GiB, TiB, PiB, EiB).
// Values below 1024 are formatted as "%d B".
func FormatIEC(b int64) string {
	if b < 0 {
		return fmt.Sprintf("%d B", b)
	}
	if b < KibiByte {
		return fmt.Sprintf("%d B", b)
	}

	div, exp := int64(KibiByte), 0
	unitsList := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	for n := b / KibiByte; n >= KibiByte && exp < len(unitsList)-1; n /= KibiByte {
		div *= KibiByte
		exp++
	}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), unitsList[exp])
}

// FormatSI formats bytes into decimal prefix strings using Base 1000 (KB, MB, GB, TB, PB).
// Negative values return "Unlimited", 0 returns "0B".
func FormatSI(bytes int64) string {
	switch {
	case bytes < 0:
		return "Unlimited"
	case bytes == 0:
		return "0B"
	case bytes >= PetaByte:
		return fmt.Sprintf("%.2fPB", float64(bytes)/float64(PetaByte))
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

// FormatBytes formats bytes using the IEC 1024-based standard with 'i' (e.g., "1.00 MiB", "0 B").
func FormatBytes(b int64) string {
	return FormatIEC(b)
}

// FormatByteSize formats bytes using the SI 1000-based standard (e.g., "1.00GB", "0B", "Unlimited").
func FormatByteSize(bytes int64) string {
	return FormatSI(bytes)
}

// ParseBytes parses human-readable byte sizes with Base 10 (KB, MB, GB, TB, PB)
// and Base 2 (KiB, MiB, GiB, TiB, PiB). Inputs are case-insensitive.
// By default, pure numbers without unit default to GB (Base 10), unless defaultUnit is specified.
func ParseBytes(s string, defaultUnit ...int64) (int64, error) {
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

	defMultiplier := GigaByte
	if len(defaultUnit) > 0 && defaultUnit[0] > 0 {
		defMultiplier = defaultUnit[0]
	}

	var multiplier int64
	var numStr string

	switch {
	// Binary prefix (Base 2: 1024, IEC standard)
	case strings.HasSuffix(lower, "pib") || strings.HasSuffix(lower, "pi"):
		multiplier = PebiByte
		numStr = strings.TrimSuffix(strings.TrimSuffix(lower, "pib"), "pi")
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
	case strings.HasSuffix(lower, "pb"):
		multiplier = PetaByte
		numStr = strings.TrimSuffix(lower, "pb")
	case strings.HasSuffix(lower, "p"):
		multiplier = PetaByte
		numStr = strings.TrimSuffix(lower, "p")
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
		multiplier = defMultiplier
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
