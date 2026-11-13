# Architecture

WIRECASE is a local CLI with no required server or database.

```text
CLI (internal/cli)
  ├── capture → probe runner (internal/probe)
  │                ├── DNS lookup
  │                ├── TCP connect (dual stack)
  │                ├── IPv6-only connect
  │                ├── local route selection (UDP, no packet sent)
  │                ├── TLS handshake
  │                └── HTTP request
  ├── case reader/writer (internal/casefile)
  ├── diagnosis rules and offline HTML (internal/diagnosis, internal/report)
  ├── signed jobs and coordinator (internal/agent, internal/coordinator)
  └── compare saved evidence
```

The capture flow resolves the target hostname, attempts TCP, IPv6-only, and local route-selection checks for the effective port, checks TLS for HTTPS targets, then issues an HTTP GET. UDP connect is used only to ask the OS whether a route can be selected; no UDP packet is sent and no local address is recorded. HTTP tracing records DNS, connection, TLS, and first-byte timing when available. Probe errors are recorded as evidence so a partial capture is still useful. Each network check has an independent timeout.

An optional `capture --trace` adds up to sixteen IPv4 UDP probes with increasing TTLs and listens for correlated ICMP responses. Raw socket restrictions produce a skipped result. Traceroute is opt-in and is excluded from signed volunteer jobs.

## `.wcase` version 1

The `.wcase` file is a bounded ZIP archive containing one indented `case.json` manifest. The reader also accepts legacy plain JSON. Its top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Format version; currently `1` |
| `id` | Random 128-bit capture identifier |
| `job_id`, `vantage` | Optional signed-job correlation and operator supplied label |
| `captured_at` | UTC timestamp |
| `target` | Normalized HTTP(S) URL |
| `host`, `port` | Host and effective connection port |
| `results` | DNS, TCP, TLS, and HTTP observations |

Each result includes a name, status (`ok`, `failed`, or `skipped`), elapsed milliseconds, an optional error, and optional structured details. New incompatible formats require a schema version change.

The scrub operation removes query and fragment values from the target URL and matching error strings. Optional address redaction masks address-valued result fields. Since new probe implementations could add additional sensitive fields, users should inspect captures before sharing.

## Signed jobs

Jobs are Ed25519-signed JSON with a versioned fixed probe list, an HTTP(S) hostname root, a maximum 15-second per-probe timeout, and a maximum seven-day lifetime. A runner verifies the signature and expiration, then requires the operator to allow the exact host on the command line. Agents can fetch jobs from an optional bearer-token coordinator and submit bounded result capsules. The coordinator requires TLS off loopback and stores at most 100 results per job. It is not required for local use. The public key is the trust anchor; private signing keys must stay with the job issuer. Version 1 jobs remain supported without route selection; new jobs use version 2.

## Boundaries

Probe implementation lives behind `internal/probe`; serialization and schema validation live in `internal/casefile`; terminal behavior lives in `internal/cli`. These boundaries let future reporters, probes, and comparison logic evolve without requiring a service backend.
