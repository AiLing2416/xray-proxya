package relaysub

import (
	"fmt"
	"strings"
	"xray-proxya/internal/sharelink"
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
func DecodePayload(body []byte) ([]string, error) {
	return sharelink.DecodePayload(body)
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

