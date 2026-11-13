# Architecture

WIRECASE is a local CLI with no required server or database.

```text
CLI (internal/cli)
  ├── capture → probe runner (internal/probe)
  │                ├── DNS lookup
  │                ├── TCP connect
  │                ├── TLS handshake
  │                └── HTTP request
  ├── case reader/writer (internal/casefile)
  └── compare saved evidence
```

The capture flow resolves the target hostname, attempts a TCP connection to the URL's effective port, checks TLS for HTTPS targets, then issues an HTTP GET. Probe errors are recorded as evidence so a partial capture is still useful. Each network check has an independent timeout.

## `.wcase` version 1

The portable case is indented JSON. Its top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Format version; currently `1` |
| `id` | Random 128-bit capture identifier |
| `captured_at` | UTC timestamp |
| `target` | Normalized HTTP(S) URL |
| `host`, `port` | Host and effective connection port |
| `results` | DNS, TCP, TLS, and HTTP observations |

Each result includes a name, status (`ok`, `failed`, or `skipped`), elapsed milliseconds, an optional error, and optional structured details. New incompatible formats require a schema version change.

## Boundaries

Probe implementation lives behind `internal/probe`; serialization and schema validation live in `internal/casefile`; terminal behavior lives in `internal/cli`. These boundaries let future reporters, probes, and comparison logic evolve without requiring a service backend.
