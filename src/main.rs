use muobserve_collector::{
    apply_collector_startup_sandbox, build_otlp_router, CollectorIngestState,
    CollectorSandboxConfig, EdgeRingWal, EdgeSecretScrubber, DEFAULT_MAX_AGE_SECS,
    DEFAULT_MAX_WAL_BYTES, DEFAULT_WAL_MAX_MB,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let node_id = std::env::var("MUOBSERVE_NODE_ID").unwrap_or_else(|_| "worker-node".to_string());
    let default_sandbox = CollectorSandboxConfig::default();
    let arch = default_sandbox.arch.clone();

    let sandbox_cfg = CollectorSandboxConfig {
        node_id: node_id.clone(),
        enforce_landlock_on_linux: std::env::var("MUOBSERVE_ENFORCE_LANDLOCK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        ..default_sandbox
    };
    let plan = apply_collector_startup_sandbox(&sandbox_cfg)?;
    tracing::info!(
        node_id = %node_id,
        arch = %arch,
        landlock_rules = plan.landlock_rules.len(),
        wal_ceiling_mib = DEFAULT_WAL_MAX_MB,
        "muobserve-collector v{} initialized under MuIsolation KernelSandbox",
        env!("CARGO_PKG_VERSION")
    );

    if std::env::var("MUOBSERVE_COLLECTOR_SERVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let wal = if let Ok(path) = std::env::var("MUOBSERVE_WAL_PATH") {
            EdgeRingWal::open(path, DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)?
        } else {
            EdgeRingWal::in_memory(DEFAULT_MAX_WAL_BYTES, DEFAULT_MAX_AGE_SECS)
        };
        let scrubber = EdgeSecretScrubber::from_env_vars([
            "GITHUB_WEBHOOK_SECRET",
            "GITHUB_TOKEN",
            "MUOBSERVE_SECRET_TOKEN",
        ]);
        let state =
            CollectorIngestState::new(Arc::new(Mutex::new(wal)), Arc::new(scrubber), node_id, arch);
        let listen_addr = std::env::var("MUOBSERVE_OTLP_HTTP_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:4318".to_string());
        let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
        tracing::info!(%listen_addr, "Listening for OTLP/HTTP telemetry");
        axum::serve(listener, build_otlp_router(state)).await?;
    }

    Ok(())
}
