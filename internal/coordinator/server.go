// Package coordinator collects results from volunteers running signed jobs.
package coordinator

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/agent"
	"github.com/iamtonmoy0/wirecase/internal/casefile"
)

const MaxResults = 100

type Service struct {
	job       agent.SignedJob
	publicKey ed25519.PublicKey
	token     string
	directory string
	maxCases  int
	mu        sync.Mutex
	seen      map[string]bool
}

func New(job agent.SignedJob, publicKey ed25519.PublicKey, token, directory string, maxCases int) (*Service, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("coordinator token must contain at least 32 characters")
	}
	if err := agent.Verify(job, publicKey, time.Now()); err != nil {
		return nil, fmt.Errorf("invalid coordinator job: %w", err)
	}
	if directory == "" {
		return nil, fmt.Errorf("result directory is required")
	}
	if maxCases <= 0 || maxCases > MaxResults {
		maxCases = MaxResults
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create result directory: %w", err)
	}
	s := &Service{job: job, publicKey: publicKey, token: token, directory: directory, maxCases: maxCases, seen: make(map[string]bool)}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	prefix := job.Job.ID + "-"
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".wcase") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), prefix), ".wcase")
		if len(id) == 32 {
			if _, err := hex.DecodeString(id); err == nil {
				s.seen[id] = true
			}
		}
	}
	return s, nil
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/job", s.handleJob)
	mux.HandleFunc("/v1/results", s.handleResult)
	return securityHeaders(mux)
}

func (s *Service) handleJob(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := agent.Verify(s.job, s.publicKey, time.Now()); err != nil {
		http.Error(w, "job is unavailable or expired", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.job)
}

func (s *Service) handleResult(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, casefile.MaxEncodedSize))
	if err != nil {
		http.Error(w, "result body is too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	c, err := casefile.Decode(data)
	if err != nil {
		http.Error(w, "invalid case file", http.StatusBadRequest)
		return
	}
	if c.JobID != s.job.Job.ID || c.Target != s.job.Job.Target || c.Vantage == "" {
		http.Error(w, "case does not belong to this job or has no vantage label", http.StatusConflict)
		return
	}
	if len(c.Results) != len(s.job.Job.Probes) {
		http.Error(w, "case probe set does not match the signed job", http.StatusConflict)
		return
	}
	for i, result := range c.Results {
		if result.Name != s.job.Job.Probes[i] {
			http.Error(w, "case probe set does not match the signed job", http.StatusConflict)
			return
		}
	}
	if c.CapturedAt.Before(s.job.Job.IssuedAt.Add(-5*time.Minute)) || c.CapturedAt.After(s.job.Job.ExpiresAt) {
		http.Error(w, "case capture time is outside the job validity window", http.StatusConflict)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[c.ID] {
		http.Error(w, "case was already submitted", http.StatusConflict)
		return
	}
	if len(s.seen) >= s.maxCases {
		http.Error(w, "coordinator result limit reached", http.StatusTooManyRequests)
		return
	}
	path := filepath.Join(s.directory, s.job.Job.ID+"-"+c.ID+".wcase")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not store result", http.StatusInternalServerError)
		return
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		http.Error(w, "could not store result", http.StatusInternalServerError)
		return
	}
	s.seen[c.ID] = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"stored": true, "case_id": c.ID})
}

func (s *Service) authorized(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	provided := strings.TrimPrefix(authorization, "Bearer ")
	if len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
