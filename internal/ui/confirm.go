package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Confirm prints a confirmation prompt ending with "[y/N]: " (if not already present)
// and reads a line from in. It returns true only when the trimmed, case-insensitive
// response is "y" or "yes". On empty EOF or non-yes input it returns false, nil.
func Confirm(in io.Reader, out io.Writer, prompt string) (bool, error) {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	formatted := prompt
	if !strings.Contains(formatted, "[y/N]: ") {
		trimmed := strings.TrimRight(formatted, " ")
		if trimmed == "" {
			formatted = "[y/N]: "
		} else {
			formatted = trimmed + " [y/N]: "
		}
	}
	if _, err := fmt.Fprint(out, formatted); err != nil {
		return false, err
	}

	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	if err == io.EOF && strings.TrimSpace(line) == "" {
		return false, nil
	}

	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}
