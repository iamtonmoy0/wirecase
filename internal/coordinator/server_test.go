package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/agent"
	"github.com/iamtonmoy0/wirecase/internal/casefile"
)

func TestProtectedJobAndResultEndpoints(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job, err := agent.NewJob("https://example.test", time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agent.Sign(job, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(signed, publicKey, "01234567890123456789012345678901", filepath.Join(t.TempDir(), "results"), 1)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/job", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized request status = %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/job", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorized job request status = %d", response.StatusCode)
	}

	results := make([]casefile.ProbeResult, 0, len(job.Probes))
	for _, name := range job.Probes {
		results = append(results, casefile.ProbeResult{Name: name, Status: "ok"})
	}
	result := casefile.Case{SchemaVersion: casefile.SchemaVersion, ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JobID: job.ID, Vantage: "test", CapturedAt: time.Now().UTC(), Target: job.Target, Host: "example.test", Port: "443", Results: results}
	invalid := result
	invalid.Results = results[:1]
	invalidData, err := casefile.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	postResult := func(body []byte) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/results", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if status := postResult(invalidData); status != http.StatusConflict {
		t.Fatalf("probe set mismatch status = %d", status)
	}
	data, err := casefile.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if status := postResult(data); status != http.StatusCreated {
		t.Fatalf("valid result status = %d", status)
	}
	if status := postResult(data); status != http.StatusConflict {
		t.Fatalf("duplicate result status = %d", status)
	}
	result.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	data, err = casefile.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if status := postResult(data); status != http.StatusTooManyRequests {
		t.Fatalf("limit status = %d", status)
	}
}

func TestNewRequiresLongToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job, err := agent.NewJob("https://example.test", time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agent.Sign(job, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(signed, publicKey, "short", t.TempDir(), 10); err == nil {
		t.Fatal("short token should be rejected")
	}
}
