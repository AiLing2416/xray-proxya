package ui

import (
	"fmt"
	"strings"
)

// Additional Glyphs
const (
	SymTriangle = "▲"
	SymInfo     = "ℹ"
)

// Success formats a single-line success feedback message with a green checkmark.
func Success(msg string) string {
	color := IsColorEnabled()
	return fmt.Sprintf("%s  %s", Green(SymCheck, color), msg)
}

// Warning formats a single-line warning feedback message with a yellow triangle.
func Warning(msg string) string {
	color := IsColorEnabled()
	return fmt.Sprintf("%s  %s", Yellow(SymTriangle, color), msg)
}

// Error formats a single-line error feedback message with a red cross.
func Error(msg string) string {
	color := IsColorEnabled()
	return fmt.Sprintf("%s  %s", Red(SymCross, color), msg)
}

// Notice formats a single-line notice/info feedback message with a cyan info glyph.
func Notice(msg string) string {
	color := IsColorEnabled()
	return fmt.Sprintf("%s  %s", Cyan(SymInfo, color), msg)
}

// Callout renders a framed callout box with a title and content lines.
func Callout(title string, lines ...string) string {
	maxWidth := VisualWidth(title) + 6
	for _, l := range lines {
		w := VisualWidth(l)
		if w > maxWidth {
			maxWidth = w
		}
	}
	if maxWidth < 40 {
		maxWidth = 40
	}

	var sb strings.Builder
	titleBarLen := maxWidth - VisualWidth(title) - 4
	if titleBarLen < 2 {
		titleBarLen = 2
	}
	sb.WriteString(fmt.Sprintf("┌─ %s %s┐\n", title, strings.Repeat("─", titleBarLen)))
	for _, l := range lines {
		padding := maxWidth - VisualWidth(l)
		if padding < 0 {
			padding = 0
		}
		sb.WriteString(fmt.Sprintf("│ %s%s │\n", l, strings.Repeat(" ", padding)))
	}
	sb.WriteString(fmt.Sprintf("└%s┘", strings.Repeat("─", maxWidth+2)))
	return sb.String()
}
