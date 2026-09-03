package relaysub

import (
	"net/url"
	"strings"
)

// SanitizeRemark cleans up raw subscription remarks/tags:
// 1. Performs URL query unescaping.
// 2. Replaces slashes, whitespace, and shell-sensitive characters with '-'.
// 3. Merges consecutive hyphens and trims leading/trailing hyphens.
// 4. Preserves human-readable regional characters (Chinese, Japanese, ASCII, Emoji).
func SanitizeRemark(raw string) string {
	if unescaped, err := url.QueryUnescape(raw); err == nil && unescaped != "" {
		raw = unescaped
	}

	var b strings.Builder
	for _, r := range raw {
		switch {
		case r == '/' || r == '\\':
			b.WriteRune('-')
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\u00a0':
			b.WriteRune('-')
		case r == '[' || r == ']' || r == '(' || r == ')' || r == '{' || r == '}':
			b.WriteRune('-')
		case r == '<' || r == '>' || r == '\'' || r == '"' || r == '`':
			b.WriteRune('-')
		case r == '*' || r == '?' || r == '|' || r == '&' || r == ';' || r == '$':
			b.WriteRune('-')
		case r == '!' || r == '#' || r == ':' || r == '~' || r == '^' || r == ',':
			b.WriteRune('-')
		case r == '=' || r == '+' || r == '%' || r == '@':
			b.WriteRune('-')
		case r < 32 || r == 127: // ASCII control characters
			b.WriteRune('-')
		default:
			b.WriteRune(r)
		}
	}

	s := b.String()
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	return s
}
