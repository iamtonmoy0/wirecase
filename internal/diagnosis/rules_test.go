package diagnosis

import (
	"testing"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
)

func TestAnalyzeDNSFailure(t *testing.T) {
	c := casefile.Case{Results: []casefile.ProbeResult{{Name: "dns", Status: "failed"}}}
	findings := Analyze(c)
	if len(findings) == 0 || findings[0].Layer != "DNS" {
		t.Fatalf("expected DNS finding, got %#v", findings)
	}
}

func TestAnalyzeHTTPServerError(t *testing.T) {
	c := casefile.Case{Results: []casefile.ProbeResult{{Name: "http", Status: "ok", Details: map[string]any{"status_code": float64(503)}}}}
	findings := Analyze(c)
	found := false
	for _, finding := range findings {
		if finding.Title == "The server returned an error response" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected server error finding, got %#v", findings)
	}
}

func TestAnalyzeHighLatency(t *testing.T) {
	c := casefile.Case{CapturedAt: time.Now(), Results: []casefile.ProbeResult{{Name: "tcp", Status: "ok", DurationMS: 1200}}}
	findings := Analyze(c)
	found := false
	for _, finding := range findings {
		if finding.Title == "High probe latency" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected latency finding, got %#v", findings)
	}
}
