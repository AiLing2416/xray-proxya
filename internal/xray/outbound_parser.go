package xray

import (
	"xray-proxya/internal/sharelink"
)

// ParseProxyLink parses any supported proxy link into an Xray outbound configuration.
func ParseProxyLink(link string) (map[string]interface{}, error) {
	out, _, err := ParseProxyLinkWithRemark(link)
	return out, err
}

// ParseProxyLinkWithRemark parses a proxy link and also returns the parsed remark/tag.
func ParseProxyLinkWithRemark(link string) (map[string]interface{}, string, error) {
	spec, err := sharelink.Parse(link)
	if err != nil {
		return nil, "", err
	}
	return spec.ToOutbound(), spec.Remark, nil
}

// ParseInterfaceBind creates a freedom outbound configuration bound to a network interface.
func ParseInterfaceBind(iface string, bindAddr string) (map[string]interface{}, error) {
	return sharelink.ParseInterfaceBind(iface, bindAddr)
}
