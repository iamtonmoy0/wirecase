package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/agent"
	"github.com/iamtonmoy0/wirecase/internal/coordinator"
)

func TestJoinFetchesRunsAndSubmitsResult(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + listener.Addr().String()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job, err := agent.NewJob(serverURL, time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agent.Sign(job, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(t.TempDir(), "results")
	service, err := coordinator.New(signed, publicKey, "01234567890123456789012345678901", resultDir, 10)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", service.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "local demo service")
	})
	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	defer server.Close()

	result, err := agent.Join(context.Background(), server.URL, "01234567890123456789012345678901", publicKey, "127.0.0.1", "local-test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Vantage != "local-test" || result.JobID != job.ID {
		t.Fatalf("unexpected returned case metadata: %#v", result)
	}
	entries, err := os.ReadDir(resultDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one stored result, found %d", len(entries))
	}
}
