package main

import (
	"os"
	"strings"
	"xray-proxya/internal/pathd"
)

func isPathdMultiCall(progName string) bool {
	slash := strings.LastIndexAny(progName, "/\\")
	base := progName
	if slash >= 0 {
		base = progName[slash+1:]
	}
	base = strings.TrimSuffix(base, ".exe")
	return base == "pathd" || base == "xray-proxya-pathd"
}

func main() {
	if isPathdMultiCall(os.Args[0]) {
		os.Exit(pathd.RunCLI(os.Args[1:]))
	}
	Execute()
}
