package relaysub

import (
	"encoding/json"
	"reflect"
	"strings"
	"xray-proxya/internal/config"

	"github.com/google/uuid"
)

// DiffResult holds the results of comparing an existing set of custom outbounds
// against a newly parsed set of nodes from a subscription.
type DiffResult struct {
	Added           []config.CustomOutbound
	Updated         []config.CustomOutbound
	Unchanged       []config.CustomOutbound
	Removed         []config.CustomOutbound
	MergedOutbounds []config.CustomOutbound
}

// ComputeDiff calculates the diff between current staging outbounds and newly parsed nodes for airportName.
// It preserves other manual or other-airport outbounds, and retains existing attributes (UUID, ports, DNS)
// for existing nodes that are updated or unchanged.
func ComputeDiff(airportName string, currentOutbounds []config.CustomOutbound, newNodes []ParsedNode) DiffResult {
	prefix := airportName + "/"
	var otherOutbounds []config.CustomOutbound
	oldMap := make(map[string]config.CustomOutbound)

	for _, co := range currentOutbounds {
		if strings.HasPrefix(co.Alias, prefix) {
			oldMap[co.Alias] = co
		} else {
			otherOutbounds = append(otherOutbounds, co)
		}
	}

	newMap := make(map[string]ParsedNode, len(newNodes))
	var res DiffResult

	// Process new nodes
	var airportMerged []config.CustomOutbound
	for _, node := range newNodes {
		newMap[node.Alias] = node
		if old, exists := oldMap[node.Alias]; exists {
			if configsEqual(old.Config, node.Config) {
				res.Unchanged = append(res.Unchanged, old)
				airportMerged = append(airportMerged, old)
			} else {
				// Updated config, preserve custom outbound settings
				updated := old
				updated.Config = node.Config
				res.Updated = append(res.Updated, updated)
				airportMerged = append(airportMerged, updated)
			}
		} else {
			// Newly added
			newCO := config.CustomOutbound{
				Alias:    node.Alias,
				Enabled:  true,
				UserUUID: uuid.New().String(),
				Config:   node.Config,
			}
			res.Added = append(res.Added, newCO)
			airportMerged = append(airportMerged, newCO)
		}
	}

	// Identify removed nodes
	for alias, old := range oldMap {
		if _, exists := newMap[alias]; !exists {
			res.Removed = append(res.Removed, old)
		}
	}

	// Merged: other outbounds + new airport outbounds
	res.MergedOutbounds = append(append([]config.CustomOutbound{}, otherOutbounds...), airportMerged...)
	return res
}

func configsEqual(c1, c2 map[string]interface{}) bool {
	b1, err1 := json.Marshal(c1)
	b2, err2 := json.Marshal(c2)
	if err1 != nil || err2 != nil {
		return reflect.DeepEqual(c1, c2)
	}
	return string(b1) == string(b2)
}
