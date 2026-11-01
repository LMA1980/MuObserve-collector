//! Error types for `muobserve-collector`.

use thiserror::Error;

/// Unified error type for `MuObserve-collector` ingestion, scrubbing, WAL storage,
/// `MuIsolation` sandboxing, and `step-ca` mTLS forwarding.
#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IPC wire/schema error: {0}")]
    Ipc(#[from] muobserve_ipc::IpcError),

    #[error("Sandbox isolation error: {0}")]
    Isolation(#[from] mu_isolation::IsolationError),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TLS configuration or handshake error: {0}")]
    Tls(String),

    #[error("Invalid telemetry payload: {0}")]
    InvalidPayload(String),

    #[error("Edge WAL capacity exceeded: {0}")]
    WalCapacityExceeded(String),

    #[error("Upstream MuObserve rejected batch: {0}")]
    UpstreamRejected(String),
}
