// Package casefile defines the portable WIRECASE evidence format.
package casefile

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const SchemaVersion = 1

// Case is one self-contained diagnostic capture. It contains no local IP,
// interface, or machine identity unless that information is part of DNS data.
type Case struct {
	SchemaVersion int           `json:"schema_version"`
	ID            string        `json:"id"`
	CapturedAt    time.Time     `json:"captured_at"`
	Target        string        `json:"target"`
	Host          string        `json:"host"`
	Port          string        `json:"port"`
	Results       []ProbeResult `json:"results"`
}

type ProbeResult struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	DurationMS int64          `json:"duration_ms"`
	Error      string         `json:"error,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

func Write(path string, c Case) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create case: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode case: %w", err)
	}
	return nil
}

func Read(path string) (Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return Case{}, fmt.Errorf("open case: %w", err)
	}
	defer f.Close()

	var c Case
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return Case{}, fmt.Errorf("decode case: %w", err)
	}
	if c.SchemaVersion != SchemaVersion {
		return Case{}, fmt.Errorf("unsupported case schema version %d", c.SchemaVersion)
	}
	if c.ID == "" || c.Target == "" || len(c.Results) == 0 {
		return Case{}, fmt.Errorf("invalid case: required metadata or probe results are missing")
	}
	return c, nil
}
