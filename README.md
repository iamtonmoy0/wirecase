# WIRECASE

**The Git for Internet failures.** Capture a network problem as a portable case, share it, and compare what happens from another network or machine.

WIRECASE is an offline-first Go command-line tool. It captures DNS, TCP, IPv6, local route availability, TLS, and HTTP evidence in a portable `.wcase` capsule, compares captures, suggests likely failure layers, and creates offline HTML reports.

## Quick start

Requires Go 1.22 or newer. No external services or Go dependencies are required.

```powershell
go run . capture --output home-wifi.wcase example.com
go run . capture --output mobile.wcase example.com
go run . diff home-wifi.wcase mobile.wcase
go run . diagnose home-wifi.wcase
go run . report --output home-wifi.html home-wifi.wcase
```

Build a local executable:

```powershell
go build -o wirecase.exe .
./wirecase.exe capture example.com
```

## Reproduce a failure locally

The Docker Compose demo runs an isolated HTTP service that intentionally returns `503`, captures it, and saves the case under `captures/`:

```powershell
docker compose up --build --abort-on-container-exit wirecase
docker compose run --rm --no-deps wirecase diagnose /captures/http-503.wcase
docker compose down
```

The demo network has no external route. Prebuilt illustrative cases are in [examples/dns-failure](examples/dns-failure/) and [examples/ipv6-failure](examples/ipv6-failure/); they are fixtures, not measurements from a live network.

Targets without a scheme use HTTPS. Use an `http://` URL for a plain HTTP endpoint. Each network probe has a five-second timeout by default; change it with `--timeout 10s`.

## Commands

```text
wirecase capture [--output file.wcase] [--timeout 5s] <host-or-url>
wirecase diff <baseline.wcase> <comparison.wcase>
wirecase inspect <file.wcase>
wirecase scrub [--redact-addresses] <input.wcase> <output.wcase>
wirecase diagnose <file.wcase>
wirecase report --output report.html <file.wcase>
wirecase version
```

Capture exits successfully when the case was saved, even if an individual network check failed. The failure is evidence in the case, not a CLI execution error.

## Case format and privacy

A `.wcase` file is a ZIP archive containing one `case.json` manifest with a schema version, random case ID, UTC capture time, target, and probe results. Earlier plain JSON case files remain readable. The format is size bounded and validated when loaded. It does not collect local interface details, machine identity, request headers, or response bodies. DNS answers, the requested URL (including its query), and probe errors are included, so review a case before sharing it.

Create a scrubbed copy before sharing:

```powershell
go run . scrub --redact-addresses home-wifi.wcase shareable.wcase
```

Scrubbing removes URL query and fragment data. `--redact-addresses` also masks IP values in probe details. Diagnosis uses transparent rules and labels output as likely explanations, not proof. HTML reports are standalone and work without a network connection.

## Signed one-shot agents

WIRECASE can prepare a narrowly scoped, signed job for another WIRECASE user to run:

```powershell
go run . agent keygen --private signer-private.pem --public signer-public.pem
go run . agent create-job --private-key signer-private.pem --target https://example.com --output job.json
```

Share `job.json` and the public key with the volunteer using a trusted channel. The volunteer explicitly allows the exact hostname and supplies a non-identifying vantage label:

```powershell
go run . agent run-job --public-key signer-public.pem --job job.json --allow-host example.com --label mobile --output mobile.wcase
```

Jobs use Ed25519 signatures, expire within seven days, and are limited to DNS, TCP, IPv6, TLS, and one HTTP GET to the host root. The HTTP check does not follow redirects. Probe timeouts are capped at 15 seconds. An agent is a single-shot local command: it opens no listener, runs no shell commands, and contacts no coordinator. Each operator decides which hostname to allow. Keep the private signing key secret; the public key alone cannot authorize a job.

## Current scope

Implemented: DNS lookup, TCP connect, IPv6 connection and route-selection checks, verified TLS handshake, HTTP request timing, bounded `.wcase` archives, legacy case reading, case validation, privacy scrubbing, deterministic evidence comparison, rule-based diagnosis, offline HTML reports, and signed one-shot jobs.

Planned: traceroute (requires platform-specific raw-socket support) and optional coordination for collecting volunteer results. WIRECASE does not infer definitive root causes; its local rules provide evidence-linked hints.

## Development

```powershell
go build ./...
```

`make build` creates a local binary; `make check` compiles every package. GitHub Actions compiles on Linux, macOS, and Windows against Go 1.22 and the current stable Go release. Pushing a `v*` tag builds release archives for Linux, macOS, and Windows on amd64 and arm64.

The core uses only the Go standard library. See [docs/architecture.md](docs/architecture.md) for component boundaries, the case schema, and the signed-job model.

## License

MIT. See [LICENSE](LICENSE).
