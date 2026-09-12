package qrcode

import (
	"errors"
	"io"
	"strings"

	goqrcode "github.com/skip2/go-qrcode"
)

// RenderTerminal generates a compact, terminal-friendly QR code using Unicode half-block characters.
// By default (inverse = false), it outputs a positive QR code suited for dark-background terminals
// where character glyphs are light and the terminal background is dark.
// If inverse is true, the module mapping is inverted for light-background terminals.
func RenderTerminal(content string, inverse bool) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", errors.New("cannot generate QR code for empty content")
	}

	q, err := goqrcode.New(content, goqrcode.Medium)
	if err != nil {
		return "", err
	}

	return q.ToSmallString(inverse), nil
}

// PrintTerminal renders and writes the QR code directly to the provided writer.
func PrintTerminal(w io.Writer, content string, inverse bool) error {
	s, err := RenderTerminal(content, inverse)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, s)
	return err
}
