package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
)

func TestWriteHTMLEscapesEvidence(t *testing.T) {
	c := casefile.Case{
		SchemaVersion: casefile.SchemaVersion,
		ID:            "0123456789abcdef0123456789abcdef",
		CapturedAt:    time.Now().UTC(),
		Target:        "https://example.test",
		Host:          "example.test",
		Port:          "443",
		Results:       []casefile.ProbeResult{{Name: "http", Status: "failed", Error: "<script>alert(1)</script>"}},
	}
	var output bytes.Buffer
	if err := WriteHTML(&output, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "<script>alert(1)</script>") {
		t.Fatal("unescaped case evidence in HTML")
	}
	if !strings.Contains(output.String(), "&lt;script&gt;") {
		t.Fatal("escaped case evidence not present")
	}
}
