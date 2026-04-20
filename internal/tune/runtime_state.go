package tune

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
	"xray-proxya/internal/config"
)

type RuntimeEntry struct {
	Key      string `json:"key"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type RuntimeState struct {
	Profile   string         `json:"profile"`
	AppliedAt time.Time      `json:"applied_at"`
	Entries   []RuntimeEntry `json:"entries"`
}

func runtimeStatePath() string {
	return filepath.Join(config.GetConfigDir(), "tune.runtime.json")
}

func LoadRuntimeState() (*RuntimeState, error) {
	data, err := os.ReadFile(runtimeStatePath())
	if err != nil {
		return nil, err
	}
	var state RuntimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func SaveRuntimeState(state *RuntimeState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(runtimeStatePath(), data, 0600)
}

func ClearRuntimeState() error {
	if err := os.Remove(runtimeStatePath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
