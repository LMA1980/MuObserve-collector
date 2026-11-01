fn main() {
    println!(
        "muobserve-collector v{} initialized (default WAL ceiling: {} MiB)",
        env!("CARGO_PKG_VERSION"),
        muobserve_collector::DEFAULT_WAL_MAX_MB
    );
}
