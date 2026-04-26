/// Archive bomb detection.
///
/// Enforces depth and compression ratio limits.
///
/// Archive scan config.
#[derive(Clone, Debug)]
pub struct ArchiveConfig {
    pub max_depth: u32,
    pub max_compression_ratio: f64,
    pub max_total_size: u64,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_compression_ratio: 100.0,
            max_total_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// Archive scan result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveScanResult {
    Safe,
    BombDetected { reason: String },
    UnsupportedFormat,
}

/// Check a compressed payload for archive bomb indicators.
pub fn check_archive(
    compressed_size: u64,
    uncompressed_size: u64,
    depth: u32,
    config: &ArchiveConfig,
) -> ArchiveScanResult {
    if depth > config.max_depth {
        return ArchiveScanResult::BombDetected {
            reason: format!("nesting depth {depth} exceeds max {}", config.max_depth),
        };
    }

    if compressed_size > 0 {
        let ratio = uncompressed_size as f64 / compressed_size as f64;
        if ratio > config.max_compression_ratio {
            return ArchiveScanResult::BombDetected {
                reason: format!("compression ratio {ratio:.1} exceeds max {}", config.max_compression_ratio),
            };
        }
    }

    if uncompressed_size > config.max_total_size {
        return ArchiveScanResult::BombDetected {
            reason: format!("uncompressed size {} exceeds max {}", uncompressed_size, config.max_total_size),
        };
    }

    ArchiveScanResult::Safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_archive() {
        let result = check_archive(1000, 5000, 1, &ArchiveConfig::default());
        assert_eq!(result, ArchiveScanResult::Safe);
    }

    #[test]
    fn zip_bomb_ratio() {
        // 1KB compressed → 1GB uncompressed = ratio 1M.
        let result = check_archive(1024, 1024 * 1024 * 1024, 1, &ArchiveConfig::default());
        assert!(matches!(result, ArchiveScanResult::BombDetected { .. }));
    }

    #[test]
    fn excessive_depth() {
        let result = check_archive(1000, 2000, 10, &ArchiveConfig::default());
        assert!(matches!(result, ArchiveScanResult::BombDetected { .. }));
    }

    #[test]
    fn excessive_total_size() {
        let result = check_archive(1000, 200 * 1024 * 1024, 1, &ArchiveConfig::default());
        assert!(matches!(result, ArchiveScanResult::BombDetected { .. }));
    }

    #[test]
    fn custom_config() {
        let config = ArchiveConfig {
            max_depth: 1,
            max_compression_ratio: 10.0,
            max_total_size: 1024,
        };
        assert_eq!(check_archive(100, 500, 1, &config), ArchiveScanResult::Safe);
        assert!(matches!(check_archive(100, 5000, 1, &config), ArchiveScanResult::BombDetected { .. }));
    }

    #[test]
    fn zero_compressed_size() {
        // Edge case: don't divide by zero.
        let result = check_archive(0, 100, 1, &ArchiveConfig::default());
        assert_eq!(result, ArchiveScanResult::Safe);
    }
}
