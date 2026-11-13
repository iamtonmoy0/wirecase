# Architecture

WIRECASE is a local CLI with no required server or database.

```text
CLI (internal/cli)
  ├── capture → probe runner (internal/probe)
  │                ├── DNS lookup
  │                ├── TCP connect (dual stack)
  │                ├── IPv6-only connect
  │                ├── TLS handshake
  │                └── HTTP request
  ├── case reader/writer (internal/casefile)
  ├── diagnosis rules and offline HTML (internal/diagnosis, internal/report)
  ├── signed one-shot jobs (internal/agent)
  └── compare saved evidence
```

The capture flow resolves the target hostname, attempts a TCP connection and an IPv6-only connection to the URL's effective port, checks TLS for HTTPS targets, then issues an HTTP GET. HTTP tracing records DNS, connection, TLS, and first-byte timing when available. Probe errors are recorded as evidence so a partial capture is still useful. Each network check has an independent timeout.

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

Jobs are Ed25519-signed JSON with a fixed probe list, an HTTP(S) hostname root, a maximum 15-second per-probe timeout, and a maximum seven-day lifetime. A runner verifies the signature and expiration, then requires the operator to allow the exact host on the command line. It runs as a one-shot local command and has no listener, shell, plugin, or coordinator. The public key is the trust anchor; private signing keys must stay with the job issuer.

## Boundaries

Probe implementation lives behind `internal/probe`; serialization and schema validation live in `internal/casefile`; terminal behavior lives in `internal/cli`. These boundaries let future reporters, probes, and comparison logic evolve without requiring a service backend.
