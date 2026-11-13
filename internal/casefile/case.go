// Package casefile defines the portable WIRECASE evidence format.
package casefile

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = 1
const maxCaseSize = 16 << 20
const manifestName = "case.json"

// Case is one self-contained diagnostic capture. It does not contain local
// interface or machine identity data.
type Case struct {
	SchemaVersion int           `json:"schema_version"`
	ID            string        `json:"id"`
	JobID         string        `json:"job_id,omitempty"`
	Vantage       string        `json:"vantage,omitempty"`
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
	if err := Validate(c); err != nil {
		return err
	}
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode case: %w", err)
	}
	if data.Len() > maxCaseSize {
		return fmt.Errorf("case exceeds maximum size of %d bytes", maxCaseSize)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	h := &zip.FileHeader{Name: manifestName, Method: zip.Deflate}
	h.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	h.SetMode(0o600)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return fmt.Errorf("create case archive: %w", err)
	}
	if _, err := w.Write(data.Bytes()); err != nil {
		return fmt.Errorf("write case archive: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finish case archive: %w", err)
	}
	if archive.Len() > maxCaseSize {
		return fmt.Errorf("case archive exceeds maximum size of %d bytes", maxCaseSize)
	}
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write case: %w", err)
	}
	return nil
}

func Read(path string) (Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Case{}, fmt.Errorf("open case: %w", err)
	}
	if len(data) > maxCaseSize {
		return Case{}, fmt.Errorf("case exceeds maximum size of %d bytes", maxCaseSize)
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		data, err = archiveManifest(data)
		if err != nil {
			return Case{}, err
		}
	}
	var c Case
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&c); err != nil {
		return Case{}, fmt.Errorf("decode case: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return Case{}, fmt.Errorf("case contains unexpected trailing data")
	}
	if err := Validate(c); err != nil {
		return Case{}, err
	}
	return c, nil
}

func archiveManifest(data []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("invalid case archive: %w", err)
	}
	if len(r.File) != 1 || r.File[0].Name != manifestName || r.File[0].UncompressedSize64 > maxCaseSize {
		return nil, fmt.Errorf("invalid case archive: expected one bounded %s manifest", manifestName)
	}
	f, err := r.File[0].Open()
	if err != nil {
		return nil, fmt.Errorf("open case manifest: %w", err)
	}
	defer f.Close()
	manifest, err := io.ReadAll(io.LimitReader(f, maxCaseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read case manifest: %w", err)
	}
	if len(manifest) > maxCaseSize {
		return nil, fmt.Errorf("case manifest exceeds maximum size of %d bytes", maxCaseSize)
	}
	return manifest, nil
}

// Validate checks the schema and rejects malformed or ambiguous evidence.
func Validate(c Case) error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported case schema version %d", c.SchemaVersion)
	}
	if len(c.ID) != 32 {
		return fmt.Errorf("invalid case: ID must be a 128-bit lowercase hexadecimal value")
	}
	for _, r := range c.ID {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return fmt.Errorf("invalid case: ID must be a 128-bit lowercase hexadecimal value")
		}
	}
	if c.JobID != "" {
		if len(c.JobID) != 32 {
			return fmt.Errorf("invalid case: job ID must be a 128-bit hexadecimal value")
		}
		if _, err := strconv.ParseUint(c.JobID[:16], 16, 64); err != nil {
			return fmt.Errorf("invalid case: job ID must be hexadecimal")
		}
		if _, err := strconv.ParseUint(c.JobID[16:], 16, 64); err != nil {
			return fmt.Errorf("invalid case: job ID must be hexadecimal")
		}
	}
	if len(c.Vantage) > 64 {
		return fmt.Errorf("invalid case: vantage label exceeds 64 characters")
	}
	u, err := url.Parse(c.Target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid case: target must be an HTTP(S) URL")
	}
	if u.Hostname() != c.Host {
		return fmt.Errorf("invalid case: target host does not match host field")
	}
	if u.User != nil {
		return fmt.Errorf("invalid case: target must not contain credentials")
	}
	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid case: port must be between 1 and 65535")
	}
	if c.CapturedAt.IsZero() || len(c.Results) == 0 {
		return fmt.Errorf("invalid case: capture time and probe results are required")
	}
	seen := make(map[string]bool, len(c.Results))
	for _, result := range c.Results {
		if result.Name == "" || seen[result.Name] {
			return fmt.Errorf("invalid case: probe names must be present and unique")
		}
		seen[result.Name] = true
		if result.Status != "ok" && result.Status != "failed" && result.Status != "skipped" {
			return fmt.Errorf("invalid case: unsupported status %q for probe %q", result.Status, result.Name)
		}
		if result.DurationMS < 0 {
			return fmt.Errorf("invalid case: negative duration for probe %q", result.Name)
		}
	}
	return nil
}

// Scrub removes URL query/fragment data and, optionally, resolved peer addresses.
// The returned case is a copy; the caller's evidence remains untouched.
func Scrub(c Case, redactAddresses bool) Case {
	out := c
	if u, err := url.Parse(out.Target); err == nil {
		u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
		out.Target = u.String()
	}
	out.Results = append([]ProbeResult(nil), c.Results...)
	for i := range out.Results {
		out.Results[i].Error = strings.ReplaceAll(out.Results[i].Error, c.Target, out.Target)
		if redactAddresses {
			out.Results[i].Details = redactDetailMap(out.Results[i].Details)
		}
	}
	return out
}

func redactDetailMap(details map[string]any) map[string]any {
	if details == nil {
		return nil
	}
	clean := make(map[string]any, len(details))
	for key, value := range details {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "address") {
			switch v := value.(type) {
			case []string:
				redacted := make([]string, len(v))
				for i := range redacted {
					redacted[i] = "[redacted]"
				}
				clean[key] = redacted
			case []any:
				redacted := make([]any, len(v))
				for i := range redacted {
					redacted[i] = "[redacted]"
				}
				clean[key] = redacted
			case string:
				clean[key] = "[redacted]"
			default:
				clean[key] = value
			}
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			clean[key] = redactDetailMap(nested)
		} else {
			clean[key] = value
		}
	}
	return clean
}
