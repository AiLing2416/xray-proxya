package sharelink

import (
	"fmt"
	"strconv"
	"strings"
)

// FromOutbound safely parses an Xray outbound map configuration into a typed NodeSpec.
// It eliminates the need for manual type assertions across CLI, TUI, and runner packages.
func FromOutbound(outbound map[string]interface{}) *NodeSpec {
	if outbound == nil {
		return &NodeSpec{Protocol: "unknown"}
	}

	spec := &NodeSpec{}
	proto, _ := outbound["protocol"].(string)
	spec.Protocol = proto

	settings, _ := outbound["settings"].(map[string]interface{})
	stream, _ := outbound["streamSettings"].(map[string]interface{})

	switch proto {
	case ProtoVLESS, ProtoVMess:
		if vnext := getMapSlice(settings, "vnext"); len(vnext) > 0 {
			spec.Address = stringValue(vnext[0]["address"])
			spec.Port = intValue(vnext[0]["port"])
			if users := getMapSlice(vnext[0], "users"); len(users) > 0 {
				spec.UUID = stringValue(users[0]["id"])
				spec.Flow = stringValue(users[0]["flow"])
			}
		}
		if dec, ok := settings["decryption"].(string); ok {
			spec.Password = dec
		}

	case ProtoShadowsocks:
		if servers := getMapSlice(settings, "servers"); len(servers) > 0 {
			spec.Address = stringValue(servers[0]["address"])
			spec.Port = intValue(servers[0]["port"])
			spec.Method = stringValue(servers[0]["method"])
			spec.Password = stringValue(servers[0]["password"])
		}

	case ProtoSocks, ProtoHTTP:
		if servers := getMapSlice(settings, "servers"); len(servers) > 0 {
			spec.Address = stringValue(servers[0]["address"])
			spec.Port = intValue(servers[0]["port"])
			if users := getMapSlice(servers[0], "users"); len(users) > 0 {
				spec.User = stringValue(users[0]["user"])
				spec.Password = stringValue(users[0]["pass"])
			}
		}

	case ProtoFreedom:
		if sockopt, ok := stream["sockopt"].(map[string]interface{}); ok {
			spec.Address = stringValue(sockopt["interface"])
		}
		if sendThrough, ok := outbound["sendThrough"].(string); ok {
			spec.Host = sendThrough
		}
	}

	if stream != nil {
		spec.Transport = stringValue(stream["network"])
		spec.Security = stringValue(stream["security"])

		if reality, ok := stream["realitySettings"].(map[string]interface{}); ok {
			spec.SNI = stringValue(reality["serverName"])
			spec.PublicKey = stringValue(reality["publicKey"])
			spec.ShortID = stringValue(reality["shortId"])
			spec.Fingerprint = stringValue(reality["fingerprint"])
			spec.SpiderX = stringValue(reality["spiderX"])
		}

		if tls, ok := stream["tlsSettings"].(map[string]interface{}); ok {
			if spec.SNI == "" {
				spec.SNI = stringValue(tls["serverName"])
			}
		}

		if ws, ok := stream["wsSettings"].(map[string]interface{}); ok {
			spec.Path = stringValue(ws["path"])
			if headers, ok := ws["headers"].(map[string]interface{}); ok {
				spec.Host = stringValue(headers["Host"])
			}
		}

		if xhttp, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
			spec.Path = stringValue(xhttp["path"])
			spec.Host = stringValue(xhttp["host"])
		}

		if grpc, ok := stream["grpcSettings"].(map[string]interface{}); ok {
			spec.Path = stringValue(grpc["serviceName"])
		}

		if httpSet, ok := stream["httpSettings"].(map[string]interface{}); ok {
			spec.Path = stringValue(httpSet["path"])
		}
	}

	return spec
}

func getMapSlice(m map[string]interface{}, key string) []map[string]interface{} {
	if m == nil {
		return nil
	}
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	var res []map[string]interface{}
	for _, item := range raw {
		if asMap, ok := item.(map[string]interface{}); ok {
			res = append(res, asMap)
		}
	}
	return res
}

func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	default:
		return strings.TrimSpace(fmt.Sprint(val))
	}
}

func intValue(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case int64:
		return int(val)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(val))
		return i
	default:
		return 0
	}
}

func getSliceStrings(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		var res []string
		for _, item := range val {
			if s := stringValue(item); s != "" {
				res = append(res, s)
			}
		}
		return res
	default:
		return nil
	}
}

