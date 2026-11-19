package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const tableGap = 2

func visualWidth(s string) int {
	return lipgloss.Width(s)
}

func isRegionalIndicator(r rune) bool {
	return r >= 0x1F1E6 && r <= 0x1F1FF
}

func isEmojiModifier(r rune) bool {
	return r >= 0x1F3FB && r <= 0x1F3FF
}

func normalizeGraphemeForTerminal(cluster string) string {
	if len(cluster) == 1 && cluster[0] < 0x80 {
		return cluster
	}

	runes := []rune(cluster)
	var hasZWJ, hasVS16, hasModifier, hasKeycap bool
	allRI := true
	for _, r := range runes {
		if !isRegionalIndicator(r) {
			allRI = false
		}
		switch {
		case r == 0x200D:
			hasZWJ = true
		case r == 0xFE0F:
			hasVS16 = true
		case r == 0x20E3:
			hasKeycap = true
		case isEmojiModifier(r):
			hasModifier = true
		}
	}

	// Keep regional indicator flag pairs (e.g. 🇭🇰, 🇺🇸) intact.
	if allRI {
		return cluster
	}

	if !hasZWJ && !hasVS16 && !hasModifier && !hasKeycap {
		return cluster
	}

	// For ZWJ sequences (e.g. 🏳️‍🌈, 👨‍💻), pick the first standalone 2-cell emoji
	// so terminals without Mode 2027 render the exact same width as x/ansi.
	if hasZWJ {
		for _, r := range runes {
			if r == 0x200D || r == 0xFE0F || r == 0xFE0E || r == 0x20E3 || isEmojiModifier(r) {
				continue
			}
			rs := string(r)
			if ansi.StringWidth(rs) == 2 && ansi.StringWidthWc(rs) == 2 {
				return rs
			}
		}
	}

	// Strip VS16, keycap, ZWJ, and skin-tone modifiers so terminal cursor advance
	// matches rendered glyph width (prevents emoji-text overlap and column shift).
	var b strings.Builder
	for _, r := range runes {
		if r == 0x200D || r == 0xFE0F || r == 0x20E3 || isEmojiModifier(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// normalizeDisplayText normalizes complex emoji clusters (VS16, ZWJ, skin-tone modifiers)
// for consistent rendering across terminals with or without Unicode Mode 2027,
// while preserving regional indicator flag emojis, CJK text, and single-codepoint emojis.
func normalizeDisplayText(s string) string {
	isPureASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			isPureASCII = false
			break
		}
	}
	if isPureASCII {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7E) {
				j++
			}
			if j < len(s) {
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		cluster, _ := ansi.FirstGraphemeCluster(s[i:], ansi.GraphemeWidth)
		if cluster == "" {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(normalizeGraphemeForTerminal(cluster))
		i += len(cluster)
	}
	return b.String()
}

func truncateVisual(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if visualWidth(s) <= width {
		return s
	}
	if width <= 2 {
		return ansi.Truncate(s, width, "")
	}
	return ansi.Truncate(s, width, "..")
}

func wrapVisual(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	if visualWidth(s) <= width {
		return []string{s}
	}
	wrapped := ansi.Wrap(s, width, "")
	lines := strings.Split(wrapped, "\n")
	for i := range lines {
		if visualWidth(lines[i]) > width {
			lines[i] = ansi.Truncate(lines[i], width, "")
		}
	}
	return lines
}

func fitTableWidths(headers []string, rows [][]string, minWidths []int, targetWidth int) []int {
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = max(visualWidth(normalizeDisplayText(header)), minWidths[i])
	}

	for _, row := range rows {
		for i := 0; i < len(row) && i < len(widths); i++ {
			widths[i] = max(widths[i], visualWidth(normalizeDisplayText(row[i])))
		}
	}

	if targetWidth <= 0 {
		return widths
	}

	total := tableWidth(widths)
	if total <= targetWidth {
		return widths
	}

	// Phase 1: shrink surplus above minWidths.
	for total > targetWidth {
		idx := -1
		maxRoom := 0
		for i := range widths {
			room := widths[i] - minWidths[i]
			if room > maxRoom {
				maxRoom = room
				idx = i
			}
		}
		if idx == -1 || maxRoom == 0 {
			break
		}
		widths[idx]--
		total--
	}

	// Phase 2: on narrow terminals (e.g. 80 cols where cWidth=68 < sum(minWidths)),
	// shrink widest columns further so the table never overflows and wraps.
	for total > targetWidth {
		idx := -1
		maxW := 3
		for i := range widths {
			if widths[i] > maxW {
				maxW = widths[i]
				idx = i
			}
		}
		if idx == -1 {
			// Fall back to shrinking any column > 1.
			maxW = 1
			for i := range widths {
				if widths[i] > maxW {
					maxW = widths[i]
					idx = i
				}
			}
		}
		if idx == -1 {
			break
		}
		widths[idx]--
		total--
	}

	return widths
}

func tableWidth(widths []int) int {
	total := 0
	for _, width := range widths {
		total += width
	}
	if len(widths) > 1 {
		total += (len(widths) - 1) * tableGap
	}
	return total
}

func renderRow(cols []string, widths []int, isHeader bool) string {
	var line []string
	for i, c := range cols {
		w := widths[i]
		if w < 1 {
			w = 1
		}
		c = normalizeDisplayText(c)
		c = truncateVisual(c, w)
		pad := w - visualWidth(c)
		if pad < 0 {
			pad = 0
		}
		padded := c + strings.Repeat(" ", pad)
		line = append(line, padded)
	}
	res := strings.Join(line, strings.Repeat(" ", tableGap))
	if isHeader {
		return headerStyle.Render(res)
	}
	return res
}

// clampScrollWindow calculates a visible slice [start, end) of length <= visibleRows
// while guaranteeing selectedIdx (when >= 0) stays inside the window.
func clampScrollWindow(total, selectedIdx, scrollOffset, visibleRows int) (start, end int) {
	if total <= 0 || visibleRows <= 0 {
		return 0, 0
	}
	if total <= visibleRows {
		return 0, total
	}

	maxStart := total - visibleRows
	start = scrollOffset
	if start < 0 {
		start = 0
	}
	if start > maxStart {
		start = maxStart
	}

	if selectedIdx >= 0 && selectedIdx < total {
		if selectedIdx < start {
			start = selectedIdx
		} else if selectedIdx >= start+visibleRows {
			start = selectedIdx - visibleRows + 1
		}
		if start < 0 {
			start = 0
		}
		if start > maxStart {
			start = maxStart
		}
	}

	end = start + visibleRows
	if end > total {
		end = total
	}
	return start, end
}

// renderTableBody renders the header block plus windowed/scrollable rows,
// ensuring total line count stays within maxHeight (when > 0) and line width within width (when > 0).
func renderTableBody(headerBlock string, rows [][]string, widths []int, disabled []bool, selectedIdx, width, maxHeight, scrollOffset int) string {
	headerLines := strings.Split(strings.TrimSuffix(headerBlock, "\n"), "\n")
	if width > 0 {
		for i := range headerLines {
			if visualWidth(headerLines[i]) > width {
				headerLines[i] = ansi.Truncate(headerLines[i], width, "")
			}
		}
	}

	var b strings.Builder
	writeLine := func(line string) {
		b.WriteString(line)
		b.WriteString("\n")
	}

	if maxHeight > 0 && len(headerLines) >= maxHeight {
		for i := 0; i < maxHeight; i++ {
			writeLine(headerLines[i])
		}
		return b.String()
	}

	for _, hl := range headerLines {
		writeLine(hl)
	}

	start, end := 0, len(rows)
	showIndicator := false
	if maxHeight > 0 {
		avail := maxHeight - len(headerLines)
		if len(rows) > avail {
			visibleRows := avail
			if avail >= 2 {
				visibleRows = avail - 1
				showIndicator = true
			}
			start, end = clampScrollWindow(len(rows), selectedIdx, scrollOffset, visibleRows)
		}
	}

	for i := start; i < end; i++ {
		s := renderRow(rows[i], widths, false)
		if width > 0 && visualWidth(s) > width {
			s = ansi.Truncate(s, width, "")
		}
		if i < len(disabled) && disabled[i] {
			s = faintStyle.Render(s)
		}
		if i == selectedIdx {
			b.WriteString(activeStyle.Render(s))
		} else {
			b.WriteString(s)
		}
		b.WriteString("\n")
	}

	if showIndicator {
		visibleCount := end - start
		if visibleCount < 1 {
			visibleCount = 1
		}
		page := start/visibleCount + 1
		totalPages := (len(rows) + visibleCount - 1) / visibleCount
		if end == len(rows) {
			page = totalPages
		}
		ind := fmt.Sprintf("  Rows %d-%d of %d (Page %d/%d)", start+1, end, len(rows), page, totalPages)
		if width > 0 {
			ind = truncateVisual(ind, width)
		}
		b.WriteString(faintStyle.Render(ind))
		b.WriteString("\n")
	}

	return b.String()
}
