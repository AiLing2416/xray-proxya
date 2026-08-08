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

// ProbeOptions controls one real ICMP probe. PayloadSize is the size of ICMP
// echo data, excluding the ICMP and IP headers.
type ProbeOptions struct {
	TTL          int
	PayloadSize  int
	DontFragment bool
}

func (r ProbeResult) IsPacketTooBig(ip net.IP) bool {
	if ip.To4() != nil {
		return r.ICMPType == 3 && r.ICMPCode == 4
	}
	return r.ICMPType == 2
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
