# WIRECASE

**The Git for Internet failures.** Capture a network problem as a portable case, share it, and compare what happens from another network or machine.

WIRECASE is an offline-first Go command-line tool. Its first release captures DNS, TCP, TLS, and HTTP evidence in a readable `.wcase` JSON file, then compares two captures.

## Quick start

Requires Go 1.22 or newer. No external services or Go dependencies are required.

```powershell
go run . capture --output home-wifi.wcase example.com
go run . capture --output mobile.wcase https://example.com
go run . diff home-wifi.wcase mobile.wcase
```

Build a local executable:

```powershell
go build -o wirecase.exe .
./wirecase.exe capture example.com
```

Targets without a scheme use HTTPS. Use an `http://` URL for a plain HTTP endpoint. Each network probe has a five-second timeout by default; change it with `--timeout 10s`.

## Commands

```text
wirecase capture [--output file.wcase] [--timeout 5s] <host-or-url>
wirecase diff <baseline.wcase> <comparison.wcase>
wirecase inspect <file.wcase>
wirecase version
```

Capture exits successfully when the case was saved, even if an individual network check failed. The failure is evidence in the case, not a CLI execution error.

## Case format and privacy

A `.wcase` file is UTF-8 JSON with a schema version, random case ID, UTC capture time, target, and probe results. It does not collect local interface details, machine identity, request headers, or response bodies. DNS answers and the requested URL are included, so review a case before sharing it. The HTTP check follows up to five redirects and records the final response status and protocol.

## Current scope

Implemented: DNS lookup, TCP connect, verified TLS handshake, HTTP request, portable JSON cases, case inspection, and evidence comparison.

Planned: richer timing breakdowns, privacy scrubbing, failure explanations, offline HTML reports, IPv6-specific and route probes, and signed remote vantage jobs. WIRECASE does not currently perform traceroute or infer root causes.

## Development

```powershell
go build ./...
```

The core uses only the Go standard library. See [docs/architecture.md](docs/architecture.md) for component boundaries and the case schema.

## License

MIT. See [LICENSE](LICENSE).
