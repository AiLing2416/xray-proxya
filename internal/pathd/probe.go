package pathd

import (
	"fmt"
	"net"
	"time"
)

// ProbeResult preserves either a real echo reply or an ICMP diagnostic.
type ProbeResult struct {
	RTT       time.Duration
	Echo      bool
	ICMPType  uint8
	ICMPCode  uint8
	Responder net.IP
	MTU       int
}

func (r ProbeResult) Error() error {
	if r.Echo {
		return nil
	}
	label := fmt.Sprintf("ICMP type %d code %d", r.ICMPType, r.ICMPCode)
	if r.Responder != nil {
		label += " from " + r.Responder.String()
	}
	if r.MTU > 0 {
		label += fmt.Sprintf(" (MTU %d)", r.MTU)
	}
	return fmt.Errorf("%s", label)
}
