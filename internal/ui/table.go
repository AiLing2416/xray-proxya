package ui

import (
	"strings"
)

// Alignment defines the text alignment within a column.
type Alignment int

const (
	AlignLeft Alignment = iota
	AlignCenter
	AlignRight
)

// TableStyle defines the borders and dividers of a table.
type TableStyle int

const (
	// StyleMinimalist (Style 3): Open borders, clean horizontal header divider with cross intersects.
	StyleMinimalist TableStyle = iota
	// StyleRounded (Style 1): Full outer border with rounded corners.
	StyleRounded
	// StyleClassic (Style 2): Full outer border with sharp box-drawing corners.
	StylePlain
)

type rowKind int

const (
	rowNormal rowKind = iota
	rowSpanned
)

type tableRow struct {
	kind        rowKind
	cells       []string
	spannedText string
}

// Table renders tabular data with ANSI-safe width calculation and configurable borders.
type Table struct {
	headers      []string
	alignments   []Alignment
	colMaxWidths []int
	autoWrap     bool
	rows         []tableRow
	style        TableStyle
}

// NewTable initializes a new table with the provided column headers.
func NewTable(headers ...string) *Table {
	aligns := make([]Alignment, len(headers))
	maxWidths := make([]int, len(headers))
	for i := range aligns {
		aligns[i] = AlignLeft
	}
	return &Table{
		headers:      headers,
		alignments:   aligns,
		colMaxWidths: maxWidths,
		autoWrap:     true,
		style:        StyleMinimalist,
	}
}

// SetStyle sets the border style for the table.
func (t *Table) SetStyle(style TableStyle) *Table {
	t.style = style
	return t
}

// SetAlignment sets the text alignment for a specific column index.
func (t *Table) SetAlignment(colIdx int, align Alignment) *Table {
	if colIdx >= 0 && colIdx < len(t.alignments) {
		t.alignments[colIdx] = align
	}
	return t
}

// SetAlignments sets the text alignment for multiple columns.
func (t *Table) SetAlignments(aligns ...Alignment) *Table {
	for i, a := range aligns {
		if i < len(t.alignments) {
			t.alignments[i] = a
		}
	}
	return t
}

// SetMaxWidth sets the maximum visual width for a specific column index, wrapping overflowing text.
func (t *Table) SetMaxWidth(colIdx int, width int) *Table {
	if colIdx >= 0 && colIdx < len(t.colMaxWidths) {
		t.colMaxWidths[colIdx] = width
	}
	return t
}

// SetAutoWrap controls whether the table automatically constrains columns to the terminal width.
func (t *Table) SetAutoWrap(autoWrap bool) *Table {
	t.autoWrap = autoWrap
	return t
}

// AddRow adds a standard data row.
func (t *Table) AddRow(cells ...string) *Table {
	t.rows = append(t.rows, tableRow{
		kind:  rowNormal,
		cells: cells,
	})
	return t
}

// AddSpannedRow adds a row where prefixCells occupy the first N columns,
// and spannedText spans across the remaining columns.
func (t *Table) AddSpannedRow(spannedText string, prefixCells ...string) *Table {
	t.rows = append(t.rows, tableRow{
		kind:        rowSpanned,
		cells:       prefixCells,
		spannedText: spannedText,
	})
	return t
}

// Render formats the table into a string.
func (t *Table) Render() string {
	numCols := len(t.headers)
	if numCols == 0 {
		return ""
	}

	// 1. Calculate column widths based on maximum VisualWidth across headers and cells
	colWidths := make([]int, numCols)
	for i, h := range t.headers {
		w := VisualWidth(h)
		if w > colWidths[i] {
			colWidths[i] = w
		}
	}

	for _, r := range t.rows {
		if r.kind == rowNormal {
			for i, c := range r.cells {
				if i < numCols {
					for _, line := range strings.Split(c, "\n") {
						w := VisualWidth(line)
						if w > colWidths[i] {
							colWidths[i] = w
						}
					}
				}
			}
		} else if r.kind == rowSpanned {
			for i, c := range r.cells {
				if i < numCols {
					for _, line := range strings.Split(c, "\n") {
						w := VisualWidth(line)
						if w > colWidths[i] {
							colWidths[i] = w
						}
					}
				}
			}
			leadCount := len(r.cells)
			if leadCount < numCols {
				currentRem := 0
				for i := leadCount; i < numCols; i++ {
					currentRem += colWidths[i]
				}
				currentRem += 3 * (numCols - leadCount - 1)

				maxSpannedLine := 0
				for _, line := range strings.Split(r.spannedText, "\n") {
					vw := VisualWidth(line)
					if vw > maxSpannedLine {
						maxSpannedLine = vw
					}
				}

				if maxSpannedLine > currentRem {
					diff := maxSpannedLine - currentRem
					colWidths[numCols-1] += diff
				}
			}
		}
	}

	// 2. Apply explicit column max widths if configured
	for i := 0; i < numCols; i++ {
		if t.colMaxWidths[i] > 0 && colWidths[i] > t.colMaxWidths[i] {
			hw := VisualWidth(t.headers[i])
			if t.colMaxWidths[i] >= hw {
				colWidths[i] = t.colMaxWidths[i]
			} else {
				colWidths[i] = hw
			}
		}
	}

	// 3. Auto-constrain to terminal width if enabled
	if t.autoWrap {
		termWidth := TerminalWidth()
		if termWidth > 0 {
			overhead := 3*(numCols-1) + 2
			if t.style == StyleRounded {
				overhead = 3*(numCols-1) + 4
			} else if t.style == StylePlain {
				overhead = 3 * (numCols - 1)
			}

			totalWidth := overhead
			for _, w := range colWidths {
				totalWidth += w
			}

			excess := totalWidth - termWidth
			for excess > 0 {
				bestCol := -1
				bestHeadroom := 0
				for i := 0; i < numCols; i++ {
					headroom := colWidths[i] - VisualWidth(t.headers[i])
					if headroom > bestHeadroom {
						bestHeadroom = headroom
						bestCol = i
					}
				}

				if bestCol == -1 || bestHeadroom <= 0 {
					break
				}

				colWidths[bestCol]--
				excess--
			}
		}
	}

	var sb strings.Builder

	switch t.style {
	case StyleMinimalist:
		t.renderMinimalist(&sb, colWidths)
	case StyleRounded:
		t.renderBox(&sb, colWidths, "╭", "─", "┬", "╮", "├", "┼", "┤", "╰", "┴", "╯", "│")
	case StylePlain:
		t.renderPlain(&sb, colWidths)
	default:
		t.renderMinimalist(&sb, colWidths)
	}

	return sb.String()
}

func (t *Table) renderMinimalist(sb *strings.Builder, colWidths []int) {
	numCols := len(t.headers)

	// Header line
	var hParts []string
	for i, h := range t.headers {
		align := t.alignments[i]
		hParts = append(hParts, padCell(h, colWidths[i], align))
	}
	sb.WriteString(" " + strings.Join(hParts, " │ ") + " \n")

	// Divider line: ─────────┼────────┼──────────
	var divParts []string
	for _, w := range colWidths {
		divParts = append(divParts, strings.Repeat("─", w+2))
	}
	sb.WriteString(strings.Join(divParts, "┼") + "\n")

	// Data rows
	for _, r := range t.rows {
		if r.kind == rowNormal {
			linesPerCol := make([][]string, numCols)
			maxLines := 1
			for i := 0; i < numCols; i++ {
				var cell string
				if i < len(r.cells) {
					cell = r.cells[i]
				}
				lines := WrapVisual(cell, colWidths[i])
				linesPerCol[i] = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}

			for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
				var rParts []string
				for i := 0; i < numCols; i++ {
					cellLine := ""
					if lineIdx < len(linesPerCol[i]) {
						cellLine = linesPerCol[i][lineIdx]
					}
					rParts = append(rParts, padCell(cellLine, colWidths[i], t.alignments[i]))
				}
				sb.WriteString(" " + strings.Join(rParts, " │ ") + " \n")
			}
		} else if r.kind == rowSpanned {
			leadCount := len(r.cells)
			remWidth := 0
			for i := leadCount; i < numCols; i++ {
				remWidth += colWidths[i] + 2 // +2 padding per col
			}
			if remWidth > 2 {
				remWidth += (numCols - leadCount - 1) * 1 // for each '│'
				remWidth -= 2                             // account for outer padding
			}

			linesPerCol := make([][]string, leadCount)
			maxLines := 1
			for i := 0; i < leadCount && i < numCols; i++ {
				lines := WrapVisual(r.cells[i], colWidths[i])
				linesPerCol[i] = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}

			spannedLines := WrapVisual(r.spannedText, remWidth)
			if len(spannedLines) > maxLines {
				maxLines = len(spannedLines)
			}

			for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
				var rParts []string
				for i := 0; i < leadCount && i < numCols; i++ {
					cellLine := ""
					if lineIdx < len(linesPerCol[i]) {
						cellLine = linesPerCol[i][lineIdx]
					}
					rParts = append(rParts, padCell(cellLine, colWidths[i], t.alignments[i]))
				}
				spannedLine := ""
				if lineIdx < len(spannedLines) {
					spannedLine = spannedLines[lineIdx]
				}
				rParts = append(rParts, padCell(spannedLine, remWidth, AlignLeft))
				sb.WriteString(" " + strings.Join(rParts, " │ ") + " \n")
			}
		}
	}
}

func (t *Table) renderBox(
	sb *strings.Builder,
	colWidths []int,
	topLeft, hLine, tTop, topRight string,
	tLeft, cross, tRight string,
	bottomLeft, tBottom, bottomRight string,
	vLine string,
) {
	numCols := len(t.headers)

	// Top border
	var topParts []string
	for _, w := range colWidths {
		topParts = append(topParts, strings.Repeat(hLine, w+2))
	}
	sb.WriteString(topLeft + strings.Join(topParts, tTop) + topRight + "\n")

	// Header line
	var hParts []string
	for i, h := range t.headers {
		align := t.alignments[i]
		hParts = append(hParts, padCell(h, colWidths[i], align))
	}
	sb.WriteString(vLine + " " + strings.Join(hParts, " "+vLine+" ") + " " + vLine + "\n")

	// Header separator
	var divParts []string
	for _, w := range colWidths {
		divParts = append(divParts, strings.Repeat(hLine, w+2))
	}
	sb.WriteString(tLeft + strings.Join(divParts, cross) + tRight + "\n")

	// Data rows
	for _, r := range t.rows {
		if r.kind == rowNormal {
			linesPerCol := make([][]string, numCols)
			maxLines := 1
			for i := 0; i < numCols; i++ {
				var cell string
				if i < len(r.cells) {
					cell = r.cells[i]
				}
				lines := WrapVisual(cell, colWidths[i])
				linesPerCol[i] = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}

			for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
				var rParts []string
				for i := 0; i < numCols; i++ {
					cellLine := ""
					if lineIdx < len(linesPerCol[i]) {
						cellLine = linesPerCol[i][lineIdx]
					}
					rParts = append(rParts, padCell(cellLine, colWidths[i], t.alignments[i]))
				}
				sb.WriteString(vLine + " " + strings.Join(rParts, " "+vLine+" ") + " " + vLine + "\n")
			}
		} else if r.kind == rowSpanned {
			leadCount := len(r.cells)
			remWidth := 0
			for i := leadCount; i < numCols; i++ {
				remWidth += colWidths[i] + 2
			}
			if remWidth > 2 {
				remWidth += (numCols - leadCount - 1) * 1
				remWidth -= 2
			}

			linesPerCol := make([][]string, leadCount)
			maxLines := 1
			for i := 0; i < leadCount && i < numCols; i++ {
				lines := WrapVisual(r.cells[i], colWidths[i])
				linesPerCol[i] = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}

			spannedLines := WrapVisual(r.spannedText, remWidth)
			if len(spannedLines) > maxLines {
				maxLines = len(spannedLines)
			}

			for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
				var rParts []string
				for i := 0; i < leadCount && i < numCols; i++ {
					cellLine := ""
					if lineIdx < len(linesPerCol[i]) {
						cellLine = linesPerCol[i][lineIdx]
					}
					rParts = append(rParts, padCell(cellLine, colWidths[i], t.alignments[i]))
				}
				spannedLine := ""
				if lineIdx < len(spannedLines) {
					spannedLine = spannedLines[lineIdx]
				}
				rParts = append(rParts, padCell(spannedLine, remWidth, AlignLeft))
				sb.WriteString(vLine + " " + strings.Join(rParts, " "+vLine+" ") + " " + vLine + "\n")
			}
		}
	}

	// Bottom border
	var botParts []string
	for _, w := range colWidths {
		botParts = append(botParts, strings.Repeat(hLine, w+2))
	}
	sb.WriteString(bottomLeft + strings.Join(botParts, tBottom) + bottomRight + "\n")
}

func (t *Table) renderPlain(sb *strings.Builder, colWidths []int) {
	numCols := len(t.headers)

	var hParts []string
	for i, h := range t.headers {
		align := t.alignments[i]
		hParts = append(hParts, padCell(h, colWidths[i], align))
	}
	sb.WriteString(strings.Join(hParts, " | ") + "\n")

	var divParts []string
	for _, w := range colWidths {
		divParts = append(divParts, strings.Repeat("-", w))
	}
	sb.WriteString(strings.Join(divParts, "-+-") + "\n")

	for _, r := range t.rows {
		if r.kind == rowNormal {
			linesPerCol := make([][]string, numCols)
			maxLines := 1
			for i := 0; i < numCols; i++ {
				var cell string
				if i < len(r.cells) {
					cell = r.cells[i]
				}
				lines := WrapVisual(cell, colWidths[i])
				linesPerCol[i] = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}

			for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
				var rParts []string
				for i := 0; i < numCols; i++ {
					cellLine := ""
					if lineIdx < len(linesPerCol[i]) {
						cellLine = linesPerCol[i][lineIdx]
					}
					rParts = append(rParts, padCell(cellLine, colWidths[i], t.alignments[i]))
				}
				sb.WriteString(strings.Join(rParts, " | ") + "\n")
			}
		} else if r.kind == rowSpanned {
			leadCount := len(r.cells)
			remWidth := 0
			for i := leadCount; i < numCols; i++ {
				remWidth += colWidths[i]
			}
			remWidth += (numCols - leadCount - 1) * 3

			linesPerCol := make([][]string, leadCount)
			maxLines := 1
			for i := 0; i < leadCount && i < numCols; i++ {
				lines := WrapVisual(r.cells[i], colWidths[i])
				linesPerCol[i] = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}

			spannedLines := WrapVisual(r.spannedText, remWidth)
			if len(spannedLines) > maxLines {
				maxLines = len(spannedLines)
			}

			for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
				var rParts []string
				for i := 0; i < leadCount && i < numCols; i++ {
					cellLine := ""
					if lineIdx < len(linesPerCol[i]) {
						cellLine = linesPerCol[i][lineIdx]
					}
					rParts = append(rParts, padCell(cellLine, colWidths[i], t.alignments[i]))
				}
				spannedLine := ""
				if lineIdx < len(spannedLines) {
					spannedLine = spannedLines[lineIdx]
				}
				rParts = append(rParts, padCell(spannedLine, remWidth, AlignLeft))
				sb.WriteString(strings.Join(rParts, " | ") + "\n")
			}
		}
	}
}

func padCell(s string, width int, align Alignment) string {
	vw := VisualWidth(s)
	if vw >= width {
		return s
	}
	diff := width - vw

	switch align {
	case AlignRight:
		return strings.Repeat(" ", diff) + s
	case AlignCenter:
		left := diff / 2
		right := diff - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	case AlignLeft:
		fallthrough
	default:
		return s + strings.Repeat(" ", diff)
	}
}
