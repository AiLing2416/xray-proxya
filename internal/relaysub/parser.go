package relaysub

import (
	"encoding/base64"
	"fmt"
	"strings"
	"xray-proxya/internal/xray"
)

// ParsedNode represents a successfully parsed relay node from a subscription.
type ParsedNode struct {
	RawLink string
	Alias   string
	Remark  string
	Config  map[string]interface{}
}

// DecodePayload extracts individual link lines from the raw subscription body.
// It handles base64-encoded strings (standard and URL-safe, with or without padding)
// as well as plaintext line lists.
func DecodePayload(body []byte) ([]string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty subscription response")
	}

	var content string

	// Try base64 decoding
	decoded, err := decodeBase64Flexible(trimmed)
	if err == nil && strings.Contains(string(decoded), "://") {
		content = string(decoded)
	} else if strings.Contains(trimmed, "://") {
		// Plain text list
		content = trimmed
	} else {
		return nil, fmt.Errorf("unrecognized subscription format (neither valid base64 nor plaintext proxy links)")
	}

	rawLines := strings.Split(content, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, l := range rawLines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		lines = append(lines, l)
	}

	return lines, nil
}

// ParseSubscription parses raw subscription body bytes for an airport into a slice of ParsedNode.
// It skips non-proxy links (such as trojan, announcements, or invalid lines) and reports the count.
func ParseSubscription(airportName string, body []byte) (nodes []ParsedNode, skippedCount int, err error) {
	airportName = strings.TrimSpace(airportName)
	if airportName == "" {
		return nil, 0, fmt.Errorf("airport alias cannot be empty")
	}
	if strings.Contains(airportName, "/") {
		return nil, 0, fmt.Errorf("airport alias cannot contain '/'")
	}

	lines, err := DecodePayload(body)
	if err != nil {
		return nil, 0, err
	}

	seenAliases := make(map[string]int)
	nodes = make([]ParsedNode, 0, len(lines))

	for idx, line := range lines {
		// Only support vless, vmess, ss
		if !strings.HasPrefix(line, "vless://") &&
			!strings.HasPrefix(line, "vmess://") &&
			!strings.HasPrefix(line, "ss://") {
			skippedCount++
			continue
		}

		cfg, rawRemark, err := xray.ParseProxyLinkWithRemark(line)
		if err != nil {
			skippedCount++
			continue
		}

		cleanRemark := SanitizeRemark(rawRemark)
		if cleanRemark == "" {
			cleanRemark = fmt.Sprintf("node-%d", idx+1)
		}

		baseAlias := fmt.Sprintf("%s/%s", airportName, cleanRemark)
		alias := baseAlias
		if count, exists := seenAliases[baseAlias]; exists {
			alias = fmt.Sprintf("%s-%d", baseAlias, count+1)
			seenAliases[baseAlias] = count + 1
		} else {
			seenAliases[baseAlias] = 1
		}

		nodes = append(nodes, ParsedNode{
			RawLink: line,
			Alias:   alias,
			Remark:  cleanRemark,
			Config:  cfg,
		})
	}

	return nodes, skippedCount, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Try standard
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try URL
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try raw URL
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try raw Std
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Pad with == and try again
	padLen := (4 - len(s)%4) % 4
	if padLen > 0 {
		padded := s + strings.Repeat("=", padLen)
		if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return b, nil
		}
		if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("failed to decode base64")
}
