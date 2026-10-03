package ui

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

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

// TerminalWidth returns the width of the terminal in columns.
// If stdout is not a terminal, or if dimensions cannot be determined, it returns 0.
func TerminalWidth() int {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err == nil && ws.Col > 0 {
		return int(ws.Col)
	}
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if c, err := strconv.Atoi(cols); err == nil && c > 0 {
			return c
		}
	}
	return 0
}

type wrapToken struct {
	text     string
	width    int
	isANSI   bool
	isSpace  bool
	canBreak bool
}

func tokenizeLine(rawLine string) []wrapToken {
	var tokens []wrapToken
	locs := ansiRegex.FindAllStringIndex(rawLine, -1)
	ansiIdx := 0

	i := 0
	for i < len(rawLine) {
		// Check if at an ANSI sequence
		if ansiIdx < len(locs) && locs[ansiIdx][0] == i {
			end := locs[ansiIdx][1]
			tokens = append(tokens, wrapToken{
				text:   rawLine[i:end],
				width:  0,
				isANSI: true,
			})
			i = end
			ansiIdx++
			continue
		}

		// Read next rune
		r, size := utf8.DecodeRuneInString(rawLine[i:])
		if r == ' ' || r == '\t' {
			tokens = append(tokens, wrapToken{
				text:     string(r),
				width:    1,
				isSpace:  true,
				canBreak: true,
			})
			i += size
			continue
		}

		rw := runewidth.RuneWidth(r)
		if rw == 2 {
			// CJK rune: can break after each CJK character
			tokens = append(tokens, wrapToken{
				text:     string(r),
				width:    2,
				canBreak: true,
			})
			i += size
			continue
		}

		// Non-CJK, non-space character: gather continuous word
		start := i
		for i < len(rawLine) {
			if ansiIdx < len(locs) && locs[ansiIdx][0] == i {
				break
			}
			nr, nsize := utf8.DecodeRuneInString(rawLine[i:])
			if nr == ' ' || nr == '\t' || runewidth.RuneWidth(nr) == 2 {
				break
			}
			i += nsize
		}
		word := rawLine[start:i]
		tokens = append(tokens, wrapToken{
			text:     word,
			width:    runewidth.StringWidth(word),
			canBreak: false,
		})
	}
	return tokens
}

// WrapVisual wraps a string so that each line has a visual width of at most maxWidth.
// It respects pre-existing newlines, breaks text at word or CJK boundaries, and safely
// preserves ANSI escape sequences without breaking or color bleeding.
func WrapVisual(s string, maxWidth int) []string {
	if maxWidth <= 0 {
		return strings.Split(s, "\n")
	}

	rawLines := strings.Split(s, "\n")
	var result []string

	for _, rawLine := range rawLines {
		if VisualWidth(rawLine) <= maxWidth {
			result = append(result, rawLine)
			continue
		}

		tokens := tokenizeLine(rawLine)
		var lines []string
		var curLine strings.Builder
		curWidth := 0
		activeStyle := ""

		flushLine := func() {
			if activeStyle != "" {
				curLine.WriteString(ColorReset)
			}
			lines = append(lines, curLine.String())
			curLine.Reset()
			curWidth = 0
			if activeStyle != "" {
				curLine.WriteString(activeStyle)
			}
		}

		for _, tok := range tokens {
			if tok.isANSI {
				curLine.WriteString(tok.text)
				if tok.text == ColorReset || tok.text == "\x1b[0m" || tok.text == "\x1b[m" {
					activeStyle = ""
				} else {
					activeStyle = tok.text
				}
				continue
			}

			if tok.isSpace {
				if curWidth == 0 {
					// Do not add leading whitespace at the beginning of a line
					continue
				}
				if curWidth+tok.width > maxWidth {
					flushLine()
					continue
				}
				curLine.WriteString(tok.text)
				curWidth += tok.width
				continue
			}

			if tok.width > maxWidth {
				// Token itself is wider than maxWidth! Break rune-by-rune
				for _, r := range tok.text {
					rw := runewidth.RuneWidth(r)
					if curWidth+rw > maxWidth && curWidth > 0 {
						flushLine()
					}
					curLine.WriteRune(r)
					curWidth += rw
				}
				continue
			}

			if curWidth+tok.width > maxWidth {
				flushLine()
			}

			curLine.WriteString(tok.text)
			curWidth += tok.width
		}

		if curLine.Len() > 0 {
			if activeStyle != "" {
				curLine.WriteString(ColorReset)
			}
			lines = append(lines, curLine.String())
		}

		if len(lines) == 0 {
			lines = []string{""}
		}
		result = append(result, lines...)
	}

	if len(result) == 0 {
		return []string{""}
	}
	return result
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
