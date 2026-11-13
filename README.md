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

Add `--trace` to a capture to request an IPv4 UDP traceroute; this can require elevated privileges.

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

## Signed agents and multi-vantage collection

WIRECASE can prepare a narrowly scoped, signed job for another WIRECASE user to run:

```powershell
go run . agent keygen --private signer-private.pem --public signer-public.pem
go run . agent create-job --private-key signer-private.pem --target https://example.com --output job.json
```

For manual sharing, pass `job.json` and the public key to the volunteer with a trusted channel. The volunteer explicitly allows the exact hostname and supplies a non-identifying vantage label:

```powershell
go run . agent run-job --public-key signer-public.pem --job job.json --allow-host example.com --label mobile --output mobile.wcase
```

For automatic collection, create a token containing at least 32 random characters and start the optional coordinator:

```powershell
$token = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
[IO.File]::WriteAllText('coordinator-token.txt', $token)
go run . coordinator --job job.json --public-key signer-public.pem --token-file coordinator-token.txt --listen 127.0.0.1:8484 --output-dir results
```

Share the server address, token file through a trusted channel, and the public key with each volunteer. They run:

```powershell
go run . agent join --server http://127.0.0.1:8484 --token-file coordinator-token.txt --public-key signer-public.pem --allow-host example.com --label mobile
```

Use HTTPS certificates and a non-loopback listen address when volunteers connect remotely. The coordinator accepts at most 100 cases for its job. Compare the collected cases from the coordinator machine:

```powershell
go run . diff baseline.wcase results\*.wcase
```

Jobs use Ed25519 signatures, expire within seven days, and are limited to a fixed probe list, one HTTP GET to the host root, and per-probe timeouts capped at 15 seconds. Agent HTTP checks do not follow redirects. Agents open no listener and run no shell commands. Each volunteer must allow the exact hostname locally. Keep the private signing key secret; the public key alone cannot authorize a job.

## Current scope

Implemented: DNS lookup, TCP connect, IPv6 connection and route-selection checks, opt-in IPv4 UDP traceroute, verified TLS handshake, HTTP request timing, bounded `.wcase` archives, legacy case reading, case validation, privacy scrubbing, multi-vantage evidence comparison, rule-based diagnosis, offline HTML reports, and signed jobs with optional coordinator collection.

Traceroute is opt-in because it needs a raw ICMP socket and may require elevated privileges; unsupported or restricted environments record it as skipped. WIRECASE does not infer definitive root causes; its local rules provide evidence-linked hints.

## Development

```powershell
go build ./...
```

`make build` creates a local binary; `make check` compiles every package. Run `go test ./...` for the unit and integration suite. GitHub Actions tests and compiles on Linux, macOS, and Windows against Go 1.22 and the current stable Go release. Pushing a `v*` tag builds release archives for Linux, macOS, and Windows on amd64 and arm64.

The core uses only the Go standard library. See [docs/architecture.md](docs/architecture.md) for component boundaries, the case schema, and the signed-job model.

## License

MIT. See [LICENSE](LICENSE).
