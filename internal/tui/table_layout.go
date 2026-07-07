package tui

import "strings"

const tableGap = 2

func fitTableWidths(headers []string, rows [][]string, minWidths []int, targetWidth int) []int {
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = max(runeLen(header), minWidths[i])
	}

	for _, row := range rows {
		for i := 0; i < len(row) && i < len(widths); i++ {
			widths[i] = max(widths[i], runeLen(row[i]))
		}
	}

	if targetWidth <= 0 {
		return widths
	}

	total := tableWidth(widths)
	if total <= targetWidth {
		return widths
	}

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
		c = truncateRunes(c, w)
		padded := c + strings.Repeat(" ", w-runeLen(c))
		line = append(line, padded)
	}
	res := strings.Join(line, strings.Repeat(" ", tableGap))
	if isHeader {
		return headerStyle.Render(res)
	}
	return res
}

func truncateRunes(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 2 {
		return string(runes[:width])
	}
	return string(runes[:width-2]) + ".."
}
