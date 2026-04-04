package utils

import (
	"fmt"
	"net"
)

// IsPortFree checks if a TCP port is available on localhost.
func IsPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
