package gatewayconf

import (
	"fmt"
	"strings"
)

// RuleSubjectKind defines the kind of rule subject.
type RuleSubjectKind string

const (
	SubjectLocal     RuleSubjectKind = "local"
	SubjectZone      RuleSubjectKind = "zone"
	SubjectDevice    RuleSubjectKind = "device"
	SubjectGroup     RuleSubjectKind = "group"
	SubjectMAC       RuleSubjectKind = "mac"
	SubjectInterface RuleSubjectKind = "interface"
	SubjectIP        RuleSubjectKind = "ip"
	SubjectRule      RuleSubjectKind = "rule"
)

// ZoneDef defines a network zone (e.g. wan, lan, guest, iot).
type ZoneDef struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	Subnets    []string `json:"subnets,omitempty"`
	Isolate    bool     `json:"isolate,omitempty"`
	Line       int      `json:"line"`
}

// DeviceDef defines a named device with a MAC address and optional zone and IP.
type DeviceDef struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
	Zone string `json:"zone,omitempty"`
	IP   string `json:"ip,omitempty"`
	Line int    `json:"line"`
}

// GroupDef defines a named group of devices or items.
type GroupDef struct {
	Name  string   `json:"name"`
	Items []string `json:"items"`
	Line  int      `json:"line"`
}

// RuleOption represents a key-value option on a rule directive.
type RuleOption struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RuleAST represents a single parsed rule directive.
// Syntax: <kind> [<subject_value>] (->|=>) <target> [options...]
// Or: rule [mac=<mac>] [ip=<ip>] [interface=<iface>] (->|=>) <target> [options...]
type RuleAST struct {
	Kind         RuleSubjectKind `json:"kind"`
	SubjectValue string          `json:"subject_value,omitempty"`
	MAC          string          `json:"mac,omitempty"`
	IP           string          `json:"ip,omitempty"`
	Interface    string          `json:"interface,omitempty"`
	Target       string          `json:"target"`
	Options      []RuleOption    `json:"options,omitempty"`
	Line         int             `json:"line"`
}

// Option returns the value of the named option and whether it was present (case-insensitive key).
func (r *RuleAST) Option(key string) (string, bool) {
	for _, opt := range r.Options {
		if strings.EqualFold(opt.Key, key) {
			return opt.Value, true
		}
	}
	return "", false
}

// OptionsMap returns a map of all options lowercased.
func (r *RuleAST) OptionsMap() map[string]string {
	if len(r.Options) == 0 {
		return nil
	}
	m := make(map[string]string, len(r.Options))
	for _, opt := range r.Options {
		m[strings.ToLower(opt.Key)] = opt.Value
	}
	return m
}

// SetAST represents a global configuration parameter directive.
// Syntax: set <key> <value>
type SetAST struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Line  int    `json:"line"`
}

// DNSAST represents a static DNS mapping directive.
// Syntax: dns <domain> (->|=>) <ip1>[, <ip2>...]
type DNSAST struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	Line   int      `json:"line"`
}

// ForwardAST represents a parsed port forwarding directive.
// Syntax: forward [wan:]<wan_port> -> <target>:<target_port> [proto=tcp|udp]
type ForwardAST struct {
	WANPort    int    `json:"wan_port"`
	Target     string `json:"target"`
	TargetPort int    `json:"target_port"`
	Proto      string `json:"proto,omitempty"`
	Line       int    `json:"line"`
}

// ConfigAST represents the root abstract syntax tree of a parsed gateway.conf.
type ConfigAST struct {
	Zones      []ZoneDef    `json:"zones,omitempty"`
	Devices    []DeviceDef  `json:"devices,omitempty"`
	Groups     []GroupDef   `json:"groups,omitempty"`
	Sets       []SetAST     `json:"sets,omitempty"`
	DNSRecords []DNSAST     `json:"dns_records,omitempty"`
	Forwards   []ForwardAST `json:"forwards,omitempty"`
	Rules      []RuleAST    `json:"rules,omitempty"`
}

// FindZone returns the ZoneDef with the given name, or nil if not found.
func (c *ConfigAST) FindZone(name string) *ZoneDef {
	for i := range c.Zones {
		if strings.EqualFold(c.Zones[i].Name, name) {
			return &c.Zones[i]
		}
	}
	return nil
}

// FindDevice returns the DeviceDef with the given name, or nil if not found.
func (c *ConfigAST) FindDevice(name string) *DeviceDef {
	for i := range c.Devices {
		if strings.EqualFold(c.Devices[i].Name, name) {
			return &c.Devices[i]
		}
	}
	return nil
}

// FindGroup returns the GroupDef with the given name, or nil if not found.
func (c *ConfigAST) FindGroup(name string) *GroupDef {
	for i := range c.Groups {
		if strings.EqualFold(c.Groups[i].Name, name) {
			return &c.Groups[i]
		}
	}
	return nil
}

// ParseError indicates a syntax or validation error during parsing with a line number.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

// CompileError indicates an error during compiling AST to GatewayConfig.
type CompileError struct {
	Line int
	Msg  string
}

func (e *CompileError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}
