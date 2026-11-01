//! `muobserve-collector`: Sandboxed node-level edge telemetry collector daemon.

/// Default maximum Edge WAL capacity in megabytes (`256 MiB`).
pub const DEFAULT_WAL_MAX_MB: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_wal_ceiling() {
        assert_eq!(DEFAULT_WAL_MAX_MB, 256);
    }
}
