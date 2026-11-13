# Security and privacy

WIRECASE is a local diagnostic CLI. Captures and reports are written to local files; there is no telemetry, account, or required backend.

## Captured data

Cases can contain the target URL, DNS answers, remote IP addresses, response status, protocol timing, TLS version and cipher suite, and error strings from the operating system. They do not include response bodies, request headers, local interface addresses, or machine identifiers. URLs may include query values; run `wirecase scrub` before sharing. Address redaction masks IP values in structured probe results and common IP forms in error text. Review the output, especially if future probe types are added.

Reports are standalone HTML and may contain the same data as the case. Treat them as sensitive files too.

## Signed jobs

Only run jobs signed by a key you trust. A runner verifies the Ed25519 signature and expiry, and also requires the operator to allow the exact hostname locally. Jobs have a versioned fixed probe list and bounded timeouts, target only an HTTP(S) host root, issue one GET without following redirects, and cannot run commands. A volunteer agent opens no listener. The optional coordinator uses a bearer token, caps collections at 100 results, and requires HTTPS for non-loopback listeners. Treat the token as a secret and use a trusted TLS certificate when exposing the coordinator remotely.

Keep the private signing key in a protected location. Share only its public key. A signed job can reveal the target's reachability and DNS answers from the runner's network, so the volunteer should understand the target before running it.

## Network behavior

Capturing a target makes DNS requests and attempts TCP, TLS, and HTTP connections. HTTP redirects are followed for ordinary captures (up to five hops); signed jobs do not follow redirects. The opt-in `--trace` mode sends up to 16 UDP probes and listens for raw ICMP responses; this can require elevated permissions and records intermediate hop addresses. Use only targets you are authorized to diagnose.

## Reporting vulnerabilities

Do not include private captures, signing keys, or unredacted target URLs in a public issue. Contact the repository maintainer privately with a concise reproduction and affected version.
