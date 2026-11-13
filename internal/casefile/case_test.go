package casefile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validCase() Case {
	return Case{
		SchemaVersion: SchemaVersion,
		ID:            "0123456789abcdef0123456789abcdef",
		CapturedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Target:        "https://example.test/path?token=secret#fragment",
		Host:          "example.test",
		Port:          "443",
		Results: []ProbeResult{{Name: "dns", Status: "ok", Details: map[string]any{
			"addresses": []string{"192.0.2.10"},
			"hops":      []any{map[string]any{"address": "2001:db8::1", "ttl": float64(1)}},
		}}},
	}
}

func TestWriteReadArchiveAndLegacyJSON(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "capture.wcase")
	want := validCase()
	if err := Write(archivePath, want); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[:4]) != "PK\x03\x04" {
		t.Fatalf("archive has unexpected magic bytes: %q", data[:4])
	}
	second, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, second) {
		t.Fatal("the same case must produce deterministic archive bytes")
	}
	got, err := Read(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Target != want.Target || got.Results[0].Name != "dns" {
		t.Fatalf("round trip mismatch: %#v", got)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy.json")
	legacyJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, legacyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(legacyPath); err != nil {
		t.Fatalf("legacy JSON should remain readable: %v", err)
	}
}

func TestScrubRemovesURLSecretsAndNestedAddresses(t *testing.T) {
	c := Scrub(validCase(), true)
	if c.Target != "https://example.test/path" {
		t.Fatalf("target wasn't scrubbed: %s", c.Target)
	}
	if got := c.Results[0].Details["addresses"].([]string)[0]; got != "[redacted]" {
		t.Fatalf("DNS address wasn't redacted: %s", got)
	}
	hops := c.Results[0].Details["hops"].([]any)
	if got := hops[0].(map[string]any)["address"]; got != "[redacted]" {
		t.Fatalf("nested trace address wasn't redacted: %v", got)
	}
	if err := Validate(c); err != nil {
		t.Fatalf("scrubbed case is invalid: %v", err)
	}
}

func TestScrubRedactsIPLiteralTarget(t *testing.T) {
	c := validCase()
	c.Target = "https://[2001:db8::10]:8443/?token=secret"
	c.Host = "2001:db8::10"
	c.Port = "8443"
	c = Scrub(c, true)
	if c.Target != "https://redacted.invalid:8443/" || c.Host != "redacted.invalid" {
		t.Fatalf("IP target wasn't redacted consistently: target=%s host=%s", c.Target, c.Host)
	}
	if err := Validate(c); err != nil {
		t.Fatalf("redacted target is invalid: %v", err)
	}
}

func TestReadRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trailing.json")
	data, err := json.Marshal(validCase())
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(" {}")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}

func TestReadRejectsOversizedFileBeforeDecoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.wcase")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxEncodedSize + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("oversized case should be rejected")
	}
}
