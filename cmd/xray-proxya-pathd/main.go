package main

import (
	"os"
	"xray-proxya/internal/pathd"
)

func main() {
	os.Exit(pathd.RunCLI(os.Args[1:]))
}
