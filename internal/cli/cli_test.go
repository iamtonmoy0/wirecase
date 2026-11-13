package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiffComparesMultipleCases(t *testing.T) {
	base, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(base, "..", ".."))
	paths := []string{
		filepath.Join(root, "examples", "dns-failure", "dns-failure.wcase"),
		filepath.Join(root, "examples", "ipv6-failure", "ipv6-failure.wcase"),
		filepath.Join(root, "examples", "ipv6-failure", "ipv6-failure.wcase"),
	}
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"diff"}, paths...), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("diff returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Comparing 3 vantage cases") {
		t.Fatalf("multi-case comparison header missing: %s", stdout.String())
	}
	if strings.Count(stdout.String(), "Target differs:") != 2 {
		t.Fatalf("expected two baseline comparisons: %s", stdout.String())
	}
}

func TestVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version returned %d", code)
	}
	if !strings.Contains(stdout.String(), version) {
		t.Fatalf("version output %q does not contain %q", stdout.String(), version)
	}
}
