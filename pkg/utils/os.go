package utils

import (
	"fmt"
	"os"
)

// EnsureRoot checks if the current process is running with root privileges.
// If not, it prints an error message and exits.
func EnsureRoot() {
	if os.Geteuid() != 0 {
		fmt.Println("❌ Error: This command requires root privileges (sudo).")
		os.Exit(1)
	}
}

// IsRoot returns true if the current user is root.
func IsRoot() bool {
	return os.Geteuid() == 0
}
