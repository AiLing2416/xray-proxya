package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
)

type pathRuntimeState struct {
	Connected    bool      `json:"connected"`
	InFlight     int       `json:"in_flight"`
	LastActivity time.Time `json:"last_activity,omitempty"`
	LastRTTMs    int64     `json:"last_rtt_ms,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func pathRuntimePath() string { return filepath.Join(config.GetConfigDir(), "path.runtime.json") }

func writePathRuntime(client *pathd.IdleClient) {
	snapshot := client.Snapshot()
	state := pathRuntimeState{Connected: snapshot.Connected, InFlight: snapshot.InFlight, LastActivity: snapshot.LastActivity, LastRTTMs: snapshot.LastRTT.Milliseconds(), LastError: snapshot.LastError, UpdatedAt: time.Now().UTC()}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	temporary := pathRuntimePath() + ".tmp"
	if os.WriteFile(temporary, data, 0600) == nil {
		_ = os.Rename(temporary, pathRuntimePath())
	}
}

func readPathRuntime() (pathRuntimeState, error) {
	data, err := os.ReadFile(pathRuntimePath())
	if err != nil {
		return pathRuntimeState{}, err
	}
	var state pathRuntimeState
	return state, json.Unmarshal(data, &state)
}
