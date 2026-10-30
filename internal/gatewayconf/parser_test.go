package gatewayconf

import (
	"strings"
	"testing"
)

func TestParse_FullConfiguration(t *testing.T) {
	input := `
# Global Comments at top of file
# Another comment line

def zone wan eth0 # Public WAN interface
def zone lan eth1, vmbr0 subnet=192.168.1.0/24,192.168.2.0/24
def zone iot eth2 subnet=192.168.10.0/24

# Devices
def device tv mac=52:54:00:84:00:11 zone=lan ip=192.168.1.50
def device guest-pad mac=52:54:00:84:00:12 zone=lan
def device sensor mac=52:54:00:84:00:20 zone=iot ip=192.168.10.5

# Groups
def group streaming tv, guest-pad

# Outbound rules
local -> relay-default dns=relay
zone lan => relay-default
zone iot -> block
device tv -> relay-jp backup=relay-us
group streaming -> relay-hk isolate=true
mac 52:54:00:12:34:56 -> direct
interface eth2 -> block
ip 192.168.1.50 -> relay-jp
ip 192.168.10.0/24 -> block
`

	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	// Verify Zones
	if len(ast.Zones) != 3 {
		t.Fatalf("expected 3 zones, got %d", len(ast.Zones))
	}
	wan := ast.FindZone("wan")
	if wan == nil || len(wan.Interfaces) != 1 || wan.Interfaces[0] != "eth0" {
		t.Errorf("invalid wan zone: %+v", wan)
	}
	lan := ast.FindZone("lan")
	if lan == nil || len(lan.Interfaces) != 2 || lan.Interfaces[0] != "eth1" || lan.Interfaces[1] != "vmbr0" {
		t.Errorf("invalid lan zone: %+v", lan)
	}
	if len(lan.Subnets) != 2 || lan.Subnets[0] != "192.168.1.0/24" || lan.Subnets[1] != "192.168.2.0/24" {
		t.Errorf("invalid lan subnets: %v", lan.Subnets)
	}

	// Verify Devices
	if len(ast.Devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(ast.Devices))
	}
	tv := ast.FindDevice("tv")
	if tv == nil || tv.MAC != "52:54:00:84:00:11" || tv.Zone != "lan" || tv.IP != "192.168.1.50" {
		t.Errorf("invalid tv device: %+v", tv)
	}

	// Verify Groups
	if len(ast.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(ast.Groups))
	}
	streaming := ast.FindGroup("streaming")
	if streaming == nil || len(streaming.Items) != 2 || streaming.Items[0] != "tv" || streaming.Items[1] != "guest-pad" {
		t.Errorf("invalid streaming group: %+v", streaming)
	}

	// Verify Rules
	if len(ast.Rules) != 9 {
		t.Fatalf("expected 9 rules, got %d", len(ast.Rules))
	}

	// Rule 0: local -> relay-default dns=relay
	r0 := ast.Rules[0]
	if r0.Kind != SubjectLocal || r0.Target != "relay-default" {
		t.Errorf("r0 mismatch: %+v", r0)
	}
	if val, ok := r0.Option("dns"); !ok || val != "relay" {
		t.Errorf("r0 dns option mismatch: %v, %v", val, ok)
	}

	// Rule 1: zone lan => relay-default
	r1 := ast.Rules[1]
	if r1.Kind != SubjectZone || r1.SubjectValue != "lan" || r1.Target != "relay-default" {
		t.Errorf("r1 mismatch: %+v", r1)
	}

	// Rule 3: device tv -> relay-jp backup=relay-us
	r3 := ast.Rules[3]
	if r3.Kind != SubjectDevice || r3.SubjectValue != "tv" || r3.Target != "relay-jp" {
		t.Errorf("r3 mismatch: %+v", r3)
	}
	if val, ok := r3.Option("backup"); !ok || val != "relay-us" {
		t.Errorf("r3 backup option mismatch: %v, %v", val, ok)
	}

	// Rule 4: group streaming -> relay-hk isolate=true
	r4 := ast.Rules[4]
	if r4.Kind != SubjectGroup || r4.SubjectValue != "streaming" || r4.Target != "relay-hk" {
		t.Errorf("r4 mismatch: %+v", r4)
	}
	if val, ok := r4.Option("isolate"); !ok || val != "true" {
		t.Errorf("r4 isolate option mismatch: %v, %v", val, ok)
	}

	// Rule 5: mac 52:54:00:12:34:56 -> direct
	r5 := ast.Rules[5]
	if r5.Kind != SubjectMAC || r5.SubjectValue != "52:54:00:12:34:56" || r5.Target != "direct" {
		t.Errorf("r5 mismatch: %+v", r5)
	}

	// Rule 6: interface eth2 -> block
	r6 := ast.Rules[6]
	if r6.Kind != SubjectInterface || r6.SubjectValue != "eth2" || r6.Target != "block" {
		t.Errorf("r6 mismatch: %+v", r6)
	}

	// Rule 7: ip 192.168.1.50 -> relay-jp
	r7 := ast.Rules[7]
	if r7.Kind != SubjectIP || r7.SubjectValue != "192.168.1.50" || r7.Target != "relay-jp" {
		t.Errorf("r7 mismatch: %+v", r7)
	}

	// Rule 8: ip 192.168.10.0/24 -> block
	r8 := ast.Rules[8]
	if r8.Kind != SubjectIP || r8.SubjectValue != "192.168.10.0/24" || r8.Target != "block" {
		t.Errorf("r8 mismatch: %+v", r8)
	}
}

func TestParse_ErrorLineNumbers(t *testing.T) {
	// Construct a multi-line input where error occurs on line 14 specifically
	var lines []string
	for i := 1; i <= 13; i++ {
		lines = append(lines, "# comment line")
	}
	lines = append(lines, "def device bad mac=invalid-mac-address") // Line 14

	_, err := Parse(strings.Join(lines, "\n"))
	if err == nil {
		t.Fatalf("expected error on line 14, got nil")
	}

	expectedPrefix := "line 14: invalid MAC address format"
	if !strings.HasPrefix(err.Error(), expectedPrefix) {
		t.Errorf("expected error to start with %q, got %q", expectedPrefix, err.Error())
	}
}

func TestParse_SyntaxErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
		errLine     int
	}{
		{
			name:        "unknown def directive",
			input:       "def unknown foo bar",
			errContains: "unknown definition type \"unknown\"",
			errLine:     1,
		},
		{
			name:        "incomplete def directive",
			input:       "def zone",
			errContains: "incomplete def directive",
			errLine:     1,
		},
		{
			name:        "zone without interfaces",
			input:       "def zone lan",
			errContains: "def zone requires at least one interface",
			errLine:     1,
		},
		{
			name:        "zone with only empty interfaces",
			input:       "def zone lan , ,",
			errContains: "def zone requires at least one interface",
			errLine:     1,
		},
		{
			name:        "duplicate zone",
			input:       "def zone lan eth1\ndef zone lan eth2",
			errContains: "duplicate zone definition \"lan\"",
			errLine:     2,
		},
		{
			name:        "invalid subnet CIDR",
			input:       "def zone lan eth1 subnet=192.168.1.999/24",
			errContains: "invalid subnet CIDR format",
			errLine:     1,
		},
		{
			name:        "invalid interface name",
			input:       "def zone lan eth1;rm -rf",
			errContains: "invalid interface name",
			errLine:     1,
		},
		{
			name:        "device missing mac",
			input:       "def device tv zone=lan",
			errContains: "def device \"tv\" requires mac=<mac>",
			errLine:     1,
		},
		{
			name:        "duplicate device",
			input:       "def device tv mac=52:54:00:11:22:33\ndef device tv mac=52:54:00:11:22:44",
			errContains: "duplicate device definition \"tv\"",
			errLine:     2,
		},
		{
			name:        "invalid device IP",
			input:       "def device tv mac=52:54:00:11:22:33 ip=999.999.1.1",
			errContains: "invalid IP address format",
			errLine:     1,
		},
		{
			name:        "group without members",
			input:       "def group streaming , ,",
			errContains: "def group \"streaming\" requires at least one member",
			errLine:     1,
		},
		{
			name:        "duplicate group",
			input:       "def group g1 tv\ndef group g1 pad",
			errContains: "duplicate group definition \"g1\"",
			errLine:     2,
		},
		{
			name:        "missing arrow",
			input:       "device tv direct",
			errContains: "unrecognized directive or missing '->'",
			errLine:     1,
		},
		{
			name:        "missing subject before arrow",
			input:       "-> direct",
			errContains: "missing subject before arrow",
			errLine:     1,
		},
		{
			name:        "unexpected args after local",
			input:       "local unexpected -> direct",
			errContains: "unexpected arguments after 'local'",
			errLine:     1,
		},
		{
			name:        "zone rule missing zone name",
			input:       "zone -> direct",
			errContains: "zone rule requires zone name",
			errLine:     1,
		},
		{
			name:        "mac rule invalid MAC",
			input:       "mac not-a-mac -> direct",
			errContains: "invalid MAC address format",
			errLine:     1,
		},
		{
			name:        "interface rule invalid name",
			input:       "interface bad!name -> direct",
			errContains: "invalid interface name",
			errLine:     1,
		},
		{
			name:        "ip rule invalid IP",
			input:       "ip invalid-ip -> direct",
			errContains: "invalid IP address or CIDR",
			errLine:     1,
		},
		{
			name:        "missing target after arrow",
			input:       "device tv ->",
			errContains: "missing target after arrow",
			errLine:     1,
		},
		{
			name:        "forward missing wan port",
			input:       "forward -> 192.168.1.100:80",
			errContains: "forward directive requires WAN port",
			errLine:     1,
		},
		{
			name:        "forward invalid wan port",
			input:       "forward abc -> 192.168.1.100:80",
			errContains: "invalid WAN port",
			errLine:     1,
		},
		{
			name:        "forward wan port 0",
			input:       "forward 0 -> 192.168.1.100:80",
			errContains: "invalid WAN port 0",
			errLine:     1,
		},
		{
			name:        "forward missing target",
			input:       "forward 80 ->",
			errContains: "missing target after arrow",
			errLine:     1,
		},
		{
			name:        "forward missing target port",
			input:       "forward 80 -> 192.168.1.100",
			errContains: "invalid target",
			errLine:     1,
		},
		{
			name:        "forward invalid target port",
			input:       "forward 80 -> 192.168.1.100:abc",
			errContains: "invalid target port",
			errLine:     1,
		},
		{
			name:        "forward invalid proto",
			input:       "forward 80 -> 192.168.1.100:80 proto=sctp",
			errContains: "invalid proto",
			errLine:     1,
		},
		{
			name:        "forward unknown option",
			input:       "forward 80 -> 192.168.1.100:80 extra=123",
			errContains: "unknown option",
			errLine:     1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("expected *ParseError, got %T: %v", err, err)
			}
			if pe.Line != tc.errLine {
				t.Errorf("line = %d, want %d", pe.Line, tc.errLine)
			}
			if !strings.Contains(pe.Error(), tc.errContains) {
				t.Errorf("error %q does not contain %q", pe.Error(), tc.errContains)
			}
		})
	}
}

func TestParse_PortForwarding(t *testing.T) {
	input := `
# Port forwarding rules
forward 80 -> 192.168.1.100:80
forward 8080 -> nas:80 proto=tcp
forward wan:443 -> 192.168.1.200:443 proto=udp
forward wan:2222 => 10.0.0.5:22 proto=tcp,udp
forward 53 -> [fd00::1]:53 proto=udp
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(ast.Forwards) != 5 {
		t.Fatalf("expected 5 forward rules, got %d", len(ast.Forwards))
	}

	f0 := ast.Forwards[0]
	if f0.WANPort != 80 || f0.Target != "192.168.1.100" || f0.TargetPort != 80 || f0.Proto != "tcp,udp" || f0.Line != 3 {
		t.Errorf("f0 mismatch: %+v", f0)
	}

	f1 := ast.Forwards[1]
	if f1.WANPort != 8080 || f1.Target != "nas" || f1.TargetPort != 80 || f1.Proto != "tcp" || f1.Line != 4 {
		t.Errorf("f1 mismatch: %+v", f1)
	}

	f2 := ast.Forwards[2]
	if f2.WANPort != 443 || f2.Target != "192.168.1.200" || f2.TargetPort != 443 || f2.Proto != "udp" || f2.Line != 5 {
		t.Errorf("f2 mismatch: %+v", f2)
	}

	f3 := ast.Forwards[3]
	if f3.WANPort != 2222 || f3.Target != "10.0.0.5" || f3.TargetPort != 22 || f3.Proto != "tcp,udp" || f3.Line != 6 {
		t.Errorf("f3 mismatch: %+v", f3)
	}

	f4 := ast.Forwards[4]
	if f4.WANPort != 53 || f4.Target != "fd00::1" || f4.TargetPort != 53 || f4.Proto != "udp" || f4.Line != 7 {
		t.Errorf("f4 mismatch: %+v", f4)
	}
}
