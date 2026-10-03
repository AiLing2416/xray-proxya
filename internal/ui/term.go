package ui

import (
	"os"
	"regexp"
	"strings"

	"github.com/mattn/go-runewidth"
	"golang.org/x/sys/unix"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// IsTerminal checks if the provided file descriptor is connected to a terminal.
func IsTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

// IsColorEnabled checks whether ANSI color escape codes are supported and enabled.
func IsColorEnabled() bool {
	return IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

// StripANSI removes all ANSI escape sequences from a string.
func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// VisualWidth calculates the visual column width of a string on a terminal,
// ignoring ANSI color escape sequences and properly accounting for wide characters.
func VisualWidth(s string) int {
	return runewidth.StringWidth(StripANSI(s))
}

// TruncateVisual shortens a string to at most maxWidth visual columns.
func TruncateVisual(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	clean := StripANSI(s)
	if runewidth.StringWidth(clean) <= maxWidth {
		return s
	}

	var sb strings.Builder
	curWidth := 0
	for _, r := range clean {
		rw := runewidth.RuneWidth(r)
		if curWidth+rw > maxWidth {
			break
		}
		sb.WriteRune(r)
		curWidth += rw
	}
	return sb.String()
}

// ANSI color escape codes
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorGray    = "\033[90m"
	ColorBoldCyan = "\033[1;36m"
)

// Glyphs
const (
	SymCheck     = "✔"
	SymCross     = "✖"
	SymBullet    = "●"
	SymHollow    = "○"
	SymArrowDown = "↓"
	SymArrowUp   = "↑"
	SymWarning   = "!"
)

// Color formatting functions
func Green(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorGreen + s + ColorReset
}

func Red(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorRed + s + ColorReset
}

func Yellow(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorYellow + s + ColorReset
}

func Cyan(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorCyan + s + ColorReset
}

func BoldCyan(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorBoldCyan + s + ColorReset
}

func Gray(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorGray + s + ColorReset
}

func Bold(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return ColorBold + s + ColorReset
}
