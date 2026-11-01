# MuObserve-collector

Sandboxed node-level edge telemetry collector for the **MuObserve** distributed observability platform.

## Architectural Scope

- **Dual Ingestion (`OTLP` + Native `Apache Arrow IPC`)**:
  - Local `OTLP/gRPC` and `OTLP/HTTP` listeners for standard OpenTelemetry traces, metrics, and logs.
  - High-throughput zero-copy Apache Arrow IPC ingestion for `ActionRunner-rs`, `ActionRunner-tools`, `MuConDe-agent`, and `k3-manager`.
- **Streaming Edge Secret Redaction**:
  - Deterministic scrubbing of bearer tokens, webhook secrets, API keys, and PEM private keys before any record touches the local Edge WAL or leaves the node.
- **Bounded Edge Ring-Buffer WAL**:
  - Local DuckDB/Arrow write-ahead ring buffer (`/var/lib/muobserve-collector/wal.duckdb`, default `<= 256 MiB` / `24h`) providing zero-data-loss resilience across network partitions with priority-aware backpressure eviction.
- **Zero-Trust `step-ca` mTLS Upstream Streaming & `MuIsolation`**:
  - Streams compressed Arrow & Fory batches over `rustls` mutual TLS to the central `MuObserve` server with cryptographic client certificate SAN attribution, confined under `MuIsolation` (`KernelSandbox`: Landlock V3+ & `cgroupv2`).

## License

Licensed under `AGPL-3.0-only`. See [`LICENSE`](LICENSE) for details.
