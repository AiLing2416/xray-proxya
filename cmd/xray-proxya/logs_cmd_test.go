package main

import "testing"

func TestTailLogContent(t *testing.T) {
	content := "line1\nline2\nline3\n"
	got := tailLogContent(content, 2)
	want := "line2\nline3\n"
	if got != want {
		t.Fatalf("tailLogContent() = %q, want %q", got, want)
	}
}

func TestTailLogContentWithoutTrailingNewline(t *testing.T) {
	content := "line1\nline2\nline3"
	got := tailLogContent(content, 1)
	want := "line3"
	if got != want {
		t.Fatalf("tailLogContent() = %q, want %q", got, want)
	}
}

func TestTailLogContentHandlesLargeN(t *testing.T) {
	content := "line1\nline2\n"
	got := tailLogContent(content, 10)
	if got != content {
		t.Fatalf("tailLogContent() = %q, want %q", got, content)
	}
}
