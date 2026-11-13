// Package agent implements signed, single-target diagnostic jobs. Jobs never
// execute commands or accept arbitrary probe code.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
	"github.com/iamtonmoy0/wirecase/internal/probe"
)

const (
	LegacyJobVersion = 1
	JobVersion       = 2
	MaxTimeout       = 15 * time.Second
	MaxLifetime      = 7 * 24 * time.Hour
)

type Job struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Probes    []string  `json:"probes"`
	TimeoutMS int64     `json:"timeout_ms"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SignedJob struct {
	Job       Job    `json:"job"`
	Signature string `json:"signature"`
}

func NewJob(target string, timeout, lifetime time.Duration) (Job, error) {
	parsed, err := probe.ParseTarget(target)
	if err != nil {
		return Job{}, err
	}
	if parsed.URL.RawQuery != "" || parsed.URL.Fragment != "" || (parsed.URL.Path != "" && parsed.URL.Path != "/") {
		return Job{}, fmt.Errorf("agent jobs can target only the host root, without query or fragment data")
	}
	if timeout < time.Millisecond || timeout > MaxTimeout {
		return Job{}, fmt.Errorf("job timeout must be between 1ms and %s", MaxTimeout)
	}
	if lifetime <= 0 || lifetime > MaxLifetime {
		return Job{}, fmt.Errorf("job lifetime must be between 1ns and %s", MaxLifetime)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Job{}, fmt.Errorf("generate job ID: %w", err)
	}
	now := time.Now().UTC()
	return Job{Version: JobVersion, ID: hex.EncodeToString(id[:]), Target: parsed.Value, Probes: []string{"dns", "tcp", "ipv6", "route", "tls", "http"}, TimeoutMS: timeout.Milliseconds(), IssuedAt: now, ExpiresAt: now.Add(lifetime)}, nil
}

func Sign(job Job, privateKey ed25519.PrivateKey) (SignedJob, error) {
	if err := validate(job); err != nil {
		return SignedJob{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedJob{}, errors.New("invalid Ed25519 private key")
	}
	canonical, err := json.Marshal(job)
	if err != nil {
		return SignedJob{}, err
	}
	sig := ed25519.Sign(privateKey, canonical)
	return SignedJob{Job: job, Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

func Verify(signed SignedJob, publicKey ed25519.PublicKey, now time.Time) error {
	if err := validate(signed.Job); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key")
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(publicKey, mustJSON(signed.Job), sig) {
		return fmt.Errorf("job signature is invalid")
	}
	if now.Before(signed.Job.IssuedAt.Add(-5 * time.Minute)) {
		return fmt.Errorf("job issue time is in the future")
	}
	if !now.Before(signed.Job.ExpiresAt) {
		return fmt.Errorf("job has expired")
	}
	return nil
}

func Run(signed SignedJob, publicKey ed25519.PublicKey, allowedHost, label string, now time.Time) (casefile.Case, error) {
	return RunContext(context.Background(), signed, publicKey, allowedHost, label, now)
}

func RunContext(ctx context.Context, signed SignedJob, publicKey ed25519.PublicKey, allowedHost, label string, now time.Time) (casefile.Case, error) {
	if err := Verify(signed, publicKey, now); err != nil {
		return casefile.Case{}, err
	}
	target, err := probe.ParseTarget(signed.Job.Target)
	if err != nil {
		return casefile.Case{}, err
	}
	allowedHost = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowedHost), "."))
	if allowedHost == "" || !strings.EqualFold(target.Host, allowedHost) {
		return casefile.Case{}, fmt.Errorf("job host %q is not the explicitly allowed host %q", target.Host, allowedHost)
	}
	if label == "" || len(label) > 64 {
		return casefile.Case{}, fmt.Errorf("vantage label must be 1 to 64 characters")
	}
	var c casefile.Case
	if signed.Job.Version == LegacyJobVersion {
		c, err = probe.CaptureRestrictedLegacy(ctx, target, time.Duration(signed.Job.TimeoutMS)*time.Millisecond)
	} else {
		c, err = probe.CaptureRestricted(ctx, target, time.Duration(signed.Job.TimeoutMS)*time.Millisecond)
	}
	if err != nil {
		return casefile.Case{}, err
	}
	c.JobID, c.Vantage = signed.Job.ID, label
	return c, nil
}

func LoadSignedJob(path string) (SignedJob, error) {
	f, err := os.Open(path)
	if err != nil {
		return SignedJob{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return SignedJob{}, err
	}
	if len(data) > 1<<20 {
		return SignedJob{}, fmt.Errorf("signed job exceeds 1 MiB")
	}
	return DecodeSignedJob(data)
}

func DecodeSignedJob(data []byte) (SignedJob, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var signed SignedJob
	if err := dec.Decode(&signed); err != nil {
		return SignedJob{}, fmt.Errorf("decode signed job: %w", err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return SignedJob{}, fmt.Errorf("job has unexpected trailing data")
	}
	return signed, nil
}

// Join fetches a signed job from a token-protected coordinator, verifies it,
// runs the bounded probes, and posts the resulting capsule.
func Join(ctx context.Context, serverURL, token string, publicKey ed25519.PublicKey, allowedHost, label string) (casefile.Case, error) {
	base, err := url.Parse(serverURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return casefile.Case{}, fmt.Errorf("coordinator URL must be an HTTP(S) origin without credentials, path, or query")
	}
	if base.Scheme != "https" && !isLoopbackHost(base.Hostname()) {
		return casefile.Case{}, fmt.Errorf("coordinator connections must use HTTPS except on loopback")
	}
	if len(token) < 32 {
		return casefile.Case{}, fmt.Errorf("coordinator token must contain at least 32 characters")
	}
	base.Path = ""
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base.String(), "/")+"/v1/job", nil)
	if err != nil {
		return casefile.Case{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return casefile.Case{}, fmt.Errorf("fetch coordinator job: %w", err)
	}
	jobData, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	response.Body.Close()
	if readErr != nil {
		return casefile.Case{}, readErr
	}
	if response.StatusCode != http.StatusOK {
		return casefile.Case{}, fmt.Errorf("coordinator returned %s", response.Status)
	}
	if len(jobData) > 1<<20 {
		return casefile.Case{}, fmt.Errorf("coordinator job exceeds 1 MiB")
	}
	signed, err := DecodeSignedJob(jobData)
	if err != nil {
		return casefile.Case{}, err
	}
	result, err := RunContext(ctx, signed, publicKey, allowedHost, label, time.Now())
	if err != nil {
		return casefile.Case{}, err
	}
	caseData, err := casefile.Marshal(result)
	if err != nil {
		return casefile.Case{}, err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base.String(), "/")+"/v1/results", bytes.NewReader(caseData))
	if err != nil {
		return casefile.Case{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/vnd.wirecase+zip")
	response, err = client.Do(request)
	if err != nil {
		return casefile.Case{}, fmt.Errorf("submit coordinator result: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return casefile.Case{}, fmt.Errorf("coordinator rejected result: %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return result, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func WriteSignedJob(path string, signed SignedJob) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create job file: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	writeErr := enc.Encode(signed)
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be Ed25519")
	}
	return privateKey, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key is not PEM encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key must be Ed25519")
	}
	return publicKey, nil
}

func GenerateKeyFiles(privatePath, publicPath string) error {
	if privatePath == publicPath {
		return errors.New("private and public key paths must differ")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := writeNewFile(privatePath, privPEM, 0o600); err != nil {
		return err
	}
	if err := writeNewFile(publicPath, pubPEM, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func validate(job Job) error {
	if job.Version != LegacyJobVersion && job.Version != JobVersion {
		return fmt.Errorf("unsupported job version %d", job.Version)
	}
	if len(job.ID) != 32 {
		return errors.New("invalid job ID")
	}
	if _, err := hex.DecodeString(job.ID); err != nil {
		return errors.New("invalid job ID")
	}
	if _, err := probe.ParseTarget(job.Target); err != nil {
		return fmt.Errorf("invalid job target: %w", err)
	}
	parsed, _ := probe.ParseTarget(job.Target)
	if parsed.URL.RawQuery != "" || parsed.URL.Fragment != "" || (parsed.URL.Path != "" && parsed.URL.Path != "/") {
		return errors.New("agent jobs can target only the host root, without query or fragment data")
	}
	if job.TimeoutMS < 1 || time.Duration(job.TimeoutMS)*time.Millisecond > MaxTimeout {
		return fmt.Errorf("job timeout must be between 1ms and %s", MaxTimeout)
	}
	expectedProbes := []string{"dns", "tcp", "ipv6", "tls", "http"}
	if job.Version == JobVersion {
		expectedProbes = []string{"dns", "tcp", "ipv6", "route", "tls", "http"}
	}
	if strings.Join(job.Probes, ",") != strings.Join(expectedProbes, ",") {
		return fmt.Errorf("job version %d must request the fixed probe set: %s", job.Version, strings.Join(expectedProbes, ","))
	}
	if job.IssuedAt.IsZero() || !job.ExpiresAt.After(job.IssuedAt) || job.ExpiresAt.Sub(job.IssuedAt) > MaxLifetime {
		return errors.New("job issue and expiry times are invalid")
	}
	return nil
}

func mustJSON(job Job) []byte { data, _ := json.Marshal(job); return data }
