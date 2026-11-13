// Package diagnosis turns probe evidence into cautious, evidence-linked hints.
package diagnosis

import "github.com/iamtonmoy0/wirecase/internal/casefile"

type Finding struct {
	Layer       string
	Severity    string
	Title       string
	Explanation string
}

func Analyze(c casefile.Case) []Finding {
	byName := make(map[string]casefile.ProbeResult, len(c.Results))
	for _, result := range c.Results {
		byName[result.Name] = result
	}
	var findings []Finding
	dns, hasDNS := byName["dns"]
	tcp, hasTCP := byName["tcp"]
	ipv6, hasIPv6 := byName["ipv6"]
	route, hasRoute := byName["route"]
	tls, hasTLS := byName["tls"]
	http, hasHTTP := byName["http"]
	trace, hasTrace := byName["trace"]
	if hasDNS && dns.Status == "failed" {
		findings = append(findings, Finding{"DNS", "high", "Name resolution failed", "The hostname did not resolve from this environment. Check the configured resolver, DNS policy, and whether the record exists."})
	}
	if hasDNS && dns.Status == "ok" && hasTCP && tcp.Status == "failed" {
		findings = append(findings, Finding{"TCP", "high", "The destination port could not be reached", "DNS succeeded but a TCP connection failed. Possible causes include routing, firewall policy, server availability, or a closed port."})
	}
	if hasTCP && tcp.Status == "ok" && hasTLS && tls.Status == "failed" {
		findings = append(findings, Finding{"TLS", "high", "The TLS handshake failed", "TCP connected, so investigate certificate validity, SNI, protocol compatibility, and TLS inspection on the path."})
	}
	if hasIPv6 && ipv6.Status == "failed" && hasTCP && tcp.Status == "ok" {
		findings = append(findings, Finding{"IPv6", "medium", "IPv6 could not reach the destination", "The general TCP check succeeded, but the IPv6 connection failed. Compare this result on another network and verify the server's IPv6 listener and route."})
	}
	if hasRoute && route.Status == "failed" && hasDNS && dns.Status == "ok" {
		findings = append(findings, Finding{"Route", "high", "No route is available to the resolved addresses", "DNS succeeded, but the local network stack could not select a route for the returned addresses. Check the active network, VPN, gateway, and local firewall policy."})
	}
	if hasTrace && trace.Status == "ok" && trace.Details["reached"] == false {
		findings = append(findings, Finding{"Route", "info", "Traceroute did not reach the destination", "The route probe timed out or stopped before a destination response. Routers often filter traceroute traffic, so this result does not prove that the application path is broken."})
	}
	if hasHTTP && http.Status == "failed" {
		findings = append(findings, Finding{"HTTP", "high", "The HTTP request did not complete", "The transport checks did not produce an HTTP response. Review the HTTP error and the preceding probe results."})
	} else if hasHTTP && http.Status == "ok" {
		if code, ok := httpStatusCode(http.Details["status_code"]); ok {
			switch {
			case code >= 500:
				findings = append(findings, Finding{"HTTP", "medium", "The server returned an error response", "The endpoint was reachable, but returned a 5xx status. This points to an application or upstream service failure."})
			case code >= 400:
				findings = append(findings, Finding{"HTTP", "low", "The endpoint returned a client error", "Network connectivity succeeded, but the server returned a 4xx status. Check the requested path, access policy, and authentication requirements."})
			case code >= 300:
				findings = append(findings, Finding{"HTTP", "info", "The endpoint returned a redirect", "The HTTP response redirects to another URL. Signed agent jobs intentionally do not follow redirects."})
			}
		}
	}
	for _, result := range c.Results {
		if result.DurationMS >= 1000 && result.Status == "ok" {
			findings = append(findings, Finding{result.Name, "low", "High probe latency", "This check took at least one second. Compare the same check from another network; one capture alone cannot identify where the delay originates."})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{"Overall", "info", "No failure pattern detected", "The recorded checks completed without a rule-based failure. This does not guarantee that every application path is healthy."})
	}
	return findings
}

func httpStatusCode(value any) (int, bool) {
	switch code := value.(type) {
	case float64:
		return int(code), true
	case int:
		return code, true
	default:
		return 0, false
	}
}
