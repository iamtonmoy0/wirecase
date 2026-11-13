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
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
	return capture(ctx, target, timeout, true)
}

// CaptureRestricted runs the fixed probe set and does not follow HTTP redirects.
func CaptureRestricted(ctx context.Context, target Target, timeout time.Duration) (casefile.Case, error) {
	return capture(ctx, target, timeout, false)
}

func capture(ctx context.Context, target Target, timeout time.Duration, followRedirects bool) (casefile.Case, error) {
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return casefile.Case{}, fmt.Errorf("generate case ID: %w", err)
	}
	addresses, dnsResult := resolve(ctx, target.Host, timeout)
	results := []casefile.ProbeResult{dnsResult}
	results = append(results, tcp(ctx, target, addresses, timeout))
	results = append(results, ipv6(ctx, target, addresses, timeout))
	if target.URL.Scheme == "https" {
		results = append(results, tlsProbe(ctx, target, timeout))
	} else {
		results = append(results, casefile.ProbeResult{Name: "tls", Status: "skipped", Details: map[string]any{"reason": "target uses HTTP"}})
	}
	results = append(results, httpProbe(ctx, target, timeout, followRedirects))
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

func ipv6(ctx context.Context, target Target, addresses []net.IPAddr, timeout time.Duration) casefile.ProbeResult {
	result := casefile.ProbeResult{Name: "ipv6", Status: "failed"}
	if len(addresses) == 0 {
		result.Status, result.Error = "skipped", "skipped because DNS resolution failed"
		return result
	}
	var candidates []net.IP
	for _, address := range addresses {
		if address.IP.To4() == nil && address.IP.To16() != nil {
			candidates = append(candidates, address.IP)
		}
	}
	if len(candidates) == 0 {
		result.Status = "skipped"
		result.Details = map[string]any{"reason": "DNS returned no IPv6 address for this host"}
		return result
	}
	start := time.Now()
	var lastErr error
	for _, address := range candidates {
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp6", net.JoinHostPort(address.String(), target.Port))
		cancel()
		if err == nil {
			_ = conn.Close()
			result.Status = "ok"
			result.Details = map[string]any{"address": address.String(), "port": target.Port}
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

func httpProbe(ctx context.Context, target Target, timeout time.Duration, followRedirects bool) casefile.ProbeResult {
	start := time.Now()
	result := casefile.ProbeResult{Name: "http", Status: "failed"}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var timingMu sync.Mutex
	var dnsStart, connectStart, tlsStart time.Time
	timing := make(map[string]int64)
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { timingMu.Lock(); dnsStart = time.Now(); timingMu.Unlock() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			timingMu.Lock()
			if !dnsStart.IsZero() {
				timing["dns_ms"] += time.Since(dnsStart).Milliseconds()
			}
			timingMu.Unlock()
		},
		ConnectStart: func(_, _ string) { timingMu.Lock(); connectStart = time.Now(); timingMu.Unlock() },
		ConnectDone: func(_, _ string, _ error) {
			timingMu.Lock()
			if !connectStart.IsZero() {
				timing["connect_ms"] += time.Since(connectStart).Milliseconds()
			}
			timingMu.Unlock()
		},
		TLSHandshakeStart: func() { timingMu.Lock(); tlsStart = time.Now(); timingMu.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			timingMu.Lock()
			if !tlsStart.IsZero() {
				timing["tls_ms"] += time.Since(tlsStart).Milliseconds()
			}
			timingMu.Unlock()
		},
		GotFirstResponseByte: func() {
			timingMu.Lock()
			timing["time_to_first_byte_ms"] = time.Since(start).Milliseconds()
			timingMu.Unlock()
		},
	}
	probeCtx = httptrace.WithClientTrace(probeCtx, trace)
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}
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
	result.Details = map[string]any{"status_code": resp.StatusCode, "protocol": resp.Proto, "timing_ms": timing}
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
