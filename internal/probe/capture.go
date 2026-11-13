// Package probe runs the network checks that make up a WIRECASE capture.
package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
)

type Target struct {
	URL   *url.URL
	Host  string
	Port  string
	Value string
}

func ParseTarget(value string) (Target, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Target{}, fmt.Errorf("target is required")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return Target{}, fmt.Errorf("invalid target %q", value)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fmt.Errorf("unsupported URL scheme %q (use http or https)", u.Scheme)
	}
	if u.User != nil {
		return Target{}, fmt.Errorf("URLs containing credentials are not supported")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return Target{URL: u, Host: u.Hostname(), Port: port, Value: u.String()}, nil
}

func Capture(ctx context.Context, target Target, timeout time.Duration) (casefile.Case, error) {
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return casefile.Case{}, fmt.Errorf("generate case ID: %w", err)
	}
	addresses, dnsResult := resolve(ctx, target.Host, timeout)
	results := []casefile.ProbeResult{dnsResult}
	results = append(results, tcp(ctx, target, addresses, timeout))
	if target.URL.Scheme == "https" {
		results = append(results, tlsProbe(ctx, target, timeout))
	} else {
		results = append(results, casefile.ProbeResult{Name: "tls", Status: "skipped", Details: map[string]any{"reason": "target uses HTTP"}})
	}
	results = append(results, httpProbe(ctx, target, timeout))
	return casefile.Case{
		SchemaVersion: casefile.SchemaVersion,
		ID:            hex.EncodeToString(idBytes[:]),
		CapturedAt:    time.Now().UTC(),
		Target:        target.Value,
		Host:          target.Host,
		Port:          target.Port,
		Results:       results,
	}, nil
}

func resolve(ctx context.Context, host string, timeout time.Duration) ([]net.IPAddr, casefile.ProbeResult) {
	start := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(probeCtx, host)
	result := casefile.ProbeResult{Name: "dns", Status: "ok", DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		result.Status, result.Error = "failed", err.Error()
		return nil, result
	}
	if len(addresses) == 0 {
		result.Status, result.Error = "failed", "no IP addresses returned"
		return nil, result
	}
	ips := make([]string, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, address.IP.String())
	}
	result.Details = map[string]any{"addresses": ips}
	return addresses, result
}

func tcp(ctx context.Context, target Target, addresses []net.IPAddr, timeout time.Duration) casefile.ProbeResult {
	start := time.Now()
	result := casefile.ProbeResult{Name: "tcp", Status: "failed"}
	if len(addresses) == 0 {
		result.Error = "skipped because DNS resolution failed"
		return result
	}
	var lastErr error
	for _, address := range addresses {
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", net.JoinHostPort(address.IP.String(), target.Port))
		cancel()
		if err == nil {
			_ = conn.Close()
			result.Status = "ok"
			result.Details = map[string]any{"address": address.IP.String(), "port": target.Port}
			break
		}
		lastErr = err
	}
	result.DurationMS = time.Since(start).Milliseconds()
	if result.Status != "ok" && lastErr != nil {
		result.Error = lastErr.Error()
	}
	return result
}

func tlsProbe(ctx context.Context, target Target, timeout time.Duration) casefile.ProbeResult {
	start := time.Now()
	result := casefile.ProbeResult{Name: "tls", Status: "failed"}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: target.Host, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(target.Host, target.Port))
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	result.Status = "ok"
	result.Details = map[string]any{
		"version":                tlsVersion(state.Version),
		"cipher_suite":           tls.CipherSuiteName(state.CipherSuite),
		"peer_certificate_count": len(state.PeerCertificates),
	}
	return result
}

func httpProbe(ctx context.Context, target Target, timeout time.Duration) casefile.ProbeResult {
	start := time.Now()
	result := casefile.ProbeResult{Name: "http", Status: "failed"}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target.URL.String(), nil)
	if err != nil {
		result.DurationMS = time.Since(start).Milliseconds()
		result.Error = err.Error()
		return result
	}
	resp, err := client.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Status = "ok"
	result.Details = map[string]any{"status_code": resp.StatusCode, "protocol": resp.Proto}
	return result
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return "TLS " + strconv.Itoa(int(version))
	}
}
