//! # `ThreatFlux` Threat Detection Library
//!
//! A comprehensive threat detection framework for malware analysis, YARA scanning,
//! and security assessment. Supports multiple detection engines and rule sources.
//!
//! ## Features
//!
//! - **YARA Integration**: Full YARA-X support with custom rule compilation
//! - **Multi-Engine Support**: YARA, `ClamAV`, pattern matching engines
//! - **Rule Management**: Automatic rule updates from multiple sources
//! - **Threat Classification**: Comprehensive threat categorization and scoring
//! - **Async Scanning**: High-performance concurrent scanning
//! - **Metrics**: Prometheus metrics for monitoring and performance
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use threatflux_threat_detection::{ThreatDetector, ScanTarget};
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let detector = ThreatDetector::new().await?;
//!
//! let result = detector.scan_file("suspicious_file.exe").await?;
//!
//! println!("Threat Level: {:?}", result.threat_level);
//! println!("Classifications: {:?}", result.classifications);
//! println!("Matches: {}", result.matches.len());
//! # Ok(())
//! # }
//! ```

pub mod analysis;
pub mod engines;
pub mod error;
pub mod rules;
pub mod types;

// Re-export main types
pub use error::{Result, ThreatError};
pub use types::{
    DetectionEngine, EngineConfig, IndicatorType, ScanConfig, ScanStatistics, ScanTarget, Severity,
    ThreatAnalysis, ThreatClassification, ThreatIndicator, ThreatLevel, YaraMatch,
};

use std::path::Path;
use std::sync::Arc;

/// Main threat detection interface
pub struct ThreatDetector {
    #[cfg(feature = "yara-engine")]
    yara_engine: Option<engines::yara::YaraEngine>,
    #[cfg(feature = "pattern-matching")]
    pattern_engine: Option<engines::patterns::PatternEngine>,
    #[allow(dead_code)]
    config: Arc<ScanConfig>,
}

/// Configuration for threat detection
#[derive(Debug, Clone)]
pub struct ThreatDetectorConfig {
    /// Enable YARA engine (defaults to whether `yara-engine` is compiled)
    pub enable_yara: bool,
    /// Enable `ClamAV` engine
    pub enable_clamav: bool,
    /// Enable pattern matching (defaults to whether `pattern-matching` is compiled)
    pub enable_patterns: bool,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// Scan timeout (seconds)
    pub scan_timeout: u64,
    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,
    /// Custom rule sources
    pub rule_sources: Vec<String>,
}

impl Default for ThreatDetectorConfig {
    fn default() -> Self {
        Self {
            enable_yara: cfg!(feature = "yara-engine"),
            enable_clamav: false,
            enable_patterns: cfg!(feature = "pattern-matching"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            scan_timeout: 300,                // 5 minutes
            max_concurrent_scans: 4,
            rule_sources: Vec::new(),
        }
    }
}

impl ThreatDetector {
    /// Create a new threat detector with default configuration
    pub async fn new() -> Result<Self> {
        Self::with_config(ThreatDetectorConfig::default()).await
    }

    /// Create a new threat detector with custom configuration
    #[allow(clippy::unused_async)]
    pub async fn with_config(config: ThreatDetectorConfig) -> Result<Self> {
        // Initialize YARA engine
        #[cfg(feature = "yara-engine")]
        let yara_engine = if config.enable_yara {
            Some(engines::yara::YaraEngine::new()?)
        } else {
            None
        };

        // Initialize pattern matching engine
        #[cfg(feature = "pattern-matching")]
        let pattern_engine = if config.enable_patterns {
            Some(engines::patterns::PatternEngine::new()?)
        } else {
            None
        };

        let scan_config = Arc::new(ScanConfig {
            max_file_size: config.max_file_size,
            scan_timeout: std::time::Duration::from_secs(config.scan_timeout),
            max_concurrent_scans: config.max_concurrent_scans,
        });

        Ok(Self {
            #[cfg(feature = "yara-engine")]
            yara_engine,
            #[cfg(feature = "pattern-matching")]
            pattern_engine,
            config: scan_config,
        })
    }

    /// Scan a single file
    pub async fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ThreatAnalysis> {
        let target = ScanTarget::File(path.as_ref().to_path_buf());
        self.scan(target).await
    }

    /// Scan data in memory
    pub async fn scan_data(&self, data: &[u8], name: Option<&str>) -> Result<ThreatAnalysis> {
        let target = ScanTarget::Memory {
            data: data.to_vec(),
            name: name.map(std::string::ToString::to_string),
        };
        self.scan(target).await
    }

    /// Scan a directory recursively
    pub async fn scan_directory<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ThreatAnalysis>> {
        let target = ScanTarget::Directory(path.as_ref().to_path_buf());

        // This would implement directory scanning logic
        // For now, return a placeholder
        let single_result = self.scan(target).await?;
        Ok(vec![single_result])
    }

    /// Scan with custom YARA rule
    #[cfg_attr(not(feature = "yara-engine"), allow(clippy::unused_async))]
    pub async fn scan_with_rule(&self, target: ScanTarget, rule: &str) -> Result<ThreatAnalysis> {
        // Use YARA engine if available
        #[cfg(feature = "yara-engine")]
        if let Some(ref yara_engine) = self.yara_engine {
            return yara_engine.scan_with_custom_rule(target, rule).await;
        }

        #[cfg(not(feature = "yara-engine"))]
        let _ = (target, rule);

        Err(ThreatError::engine_not_available("YARA"))
    }

    /// Core scanning logic
    #[cfg_attr(
        not(any(feature = "yara-engine", feature = "pattern-matching")),
        allow(clippy::unused_async)
    )]
    async fn scan(&self, target: ScanTarget) -> Result<ThreatAnalysis> {
        let start_time = std::time::Instant::now();
        let all_matches = Vec::new();
        let all_indicators = Vec::new();
        let classifications = std::collections::HashSet::new();
        #[cfg(any(feature = "yara-engine", feature = "pattern-matching"))]
        let (mut all_matches, mut all_indicators, mut classifications) =
            (all_matches, all_indicators, classifications);

        match &target {
            ScanTarget::File(path) | ScanTarget::Directory(path) => {
                std::fs::metadata(path).map_err(ThreatError::from)?;
            }
            ScanTarget::Memory { .. } => {}
        }

        // Run YARA engine if available
        #[cfg(feature = "yara-engine")]
        if let Some(ref yara_engine) = self.yara_engine {
            match yara_engine.scan(target.clone()).await {
                Ok(result) => {
                    all_matches.extend(result.matches);
                    all_indicators.extend(result.indicators);
                    classifications.extend(result.classifications);
                }
                Err(e) => {
                    log::warn!("YARA engine failed: {e}");
                }
            }
        }

        // Run pattern engine if available
        #[cfg(feature = "pattern-matching")]
        if let Some(ref pattern_engine) = self.pattern_engine {
            match pattern_engine.scan(target.clone()).await {
                Ok(result) => {
                    all_matches.extend(result.matches);
                    all_indicators.extend(result.indicators);
                    classifications.extend(result.classifications);
                }
                Err(e) => {
                    log::warn!("Pattern engine failed: {e}");
                }
            }
        }

        let scan_duration = start_time.elapsed();

        // Analyze results
        let threat_level = analysis::calculate_threat_level(&all_matches, &all_indicators);
        let classifications_vec: Vec<_> = classifications.iter().cloned().collect();
        let recommendations =
            analysis::generate_recommendations(&threat_level, &all_matches, &classifications_vec);

        let file_size = match &target {
            ScanTarget::File(path) => std::fs::metadata(path).map_or(0, |m| m.len()),
            ScanTarget::Memory { data, .. } => data.len() as u64,
            ScanTarget::Directory(_) => 0,
        };

        Ok(ThreatAnalysis {
            matches: all_matches,
            threat_level,
            classifications: classifications.into_iter().collect(),
            indicators: all_indicators,
            scan_stats: ScanStatistics {
                scan_duration,
                rules_evaluated: 0,  // Would be populated by engines
                patterns_matched: 0, // Would be populated by engines
                file_size_scanned: file_size,
            },
            recommendations,
        })
    }

    /// Update threat detection rules
    #[cfg_attr(
        not(any(feature = "yara-engine", feature = "pattern-matching")),
        allow(clippy::unused_async)
    )]
    pub async fn update_rules(&mut self) -> Result<()> {
        // Update YARA engine if available
        #[cfg(feature = "yara-engine")]
        if let Some(ref mut yara_engine) = self.yara_engine {
            if let Err(e) = yara_engine.update_rules().await {
                log::warn!("Failed to update YARA rules: {e}");
            }
        }

        // Update pattern engine if available
        #[cfg(feature = "pattern-matching")]
        if let Some(ref mut pattern_engine) = self.pattern_engine {
            if let Err(e) = pattern_engine.update_rules().await {
                log::warn!("Failed to update pattern rules: {e}");
            }
        }

        Ok(())
    }

    /// Get engine information
    pub fn get_engine_info(&self) -> Vec<(String, String)> {
        let engines = Vec::new();
        #[cfg(any(feature = "yara-engine", feature = "pattern-matching"))]
        let mut engines = engines;

        #[cfg(feature = "yara-engine")]
        if let Some(ref yara_engine) = self.yara_engine {
            engines.push((
                yara_engine.engine_type().to_string(),
                yara_engine.version().to_string(),
            ));
        }

        #[cfg(feature = "pattern-matching")]
        if let Some(ref pattern_engine) = self.pattern_engine {
            engines.push((
                pattern_engine.engine_type().to_string(),
                pattern_engine.version().to_string(),
            ));
        }

        engines
    }

    /// Get the active scan configuration.
    pub fn scan_config(&self) -> &ScanConfig {
        self.config.as_ref()
    }
}

impl Default for ThreatDetector {
    fn default() -> Self {
        // This is a placeholder - the actual implementation would be async
        Self {
            #[cfg(feature = "yara-engine")]
            yara_engine: None,
            #[cfg(feature = "pattern-matching")]
            pattern_engine: None,
            config: Arc::new(ScanConfig {
                max_file_size: 100 * 1024 * 1024,
                scan_timeout: std::time::Duration::from_mins(5),
                max_concurrent_scans: 4,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detector_creation() {
        let config = ThreatDetectorConfig {
            enable_yara: false, // Disable to avoid dependency issues in tests
            enable_clamav: false,
            enable_patterns: false,
            ..Default::default()
        };

        let detector = ThreatDetector::with_config(config).await;
        assert!(detector.is_ok());
    }

    #[tokio::test]
    async fn default_detector_initializes_only_compiled_engines() {
        let detector = ThreatDetector::new().await.unwrap();
        let engines = detector.get_engine_info();
        assert_eq!(
            engines.iter().any(|(name, _)| name == "YARA"),
            cfg!(feature = "yara-engine")
        );
        assert_eq!(
            engines.iter().any(|(name, _)| name == "PatternMatching"),
            cfg!(feature = "pattern-matching")
        );
        assert_eq!(
            engines.len(),
            usize::from(cfg!(feature = "yara-engine"))
                + usize::from(cfg!(feature = "pattern-matching"))
        );
        let data = b"safe engine routing fixture";
        let analysis = detector.scan_data(data, Some("fixture.txt")).await.unwrap();
        assert_eq!(analysis.scan_stats.file_size_scanned, data.len() as u64);
    }

    #[cfg(feature = "yara-engine")]
    #[tokio::test]
    async fn compiled_yara_backend_receives_custom_rules() {
        let detector = ThreatDetector::new().await.unwrap();
        let target = ScanTarget::Memory {
            data: b"safe fixture".to_vec(),
            name: Some("fixture.txt".into()),
        };
        let error = detector.scan_with_rule(target, "").await.unwrap_err();
        assert!(
            matches!(error, ThreatError::RuleCompilationError(message) if message == "Invalid rule: Rule content cannot be empty")
        );
    }

    #[cfg(not(feature = "yara-engine"))]
    #[tokio::test]
    async fn custom_rule_reports_unavailable_when_yara_is_not_compiled() {
        let detector = ThreatDetector::new().await.unwrap();
        let target = ScanTarget::Memory {
            data: b"safe fixture".to_vec(),
            name: Some("fixture.txt".into()),
        };
        let error = detector
            .scan_with_rule(target, "intentionally invalid YARA syntax")
            .await
            .unwrap_err();
        assert!(matches!(error, ThreatError::EngineNotAvailable(engine) if engine == "YARA"));
    }

    #[cfg(not(any(feature = "yara-engine", feature = "pattern-matching")))]
    #[tokio::test]
    async fn featureless_detector_preserves_scan_config_and_memory_statistics() {
        let mut detector = ThreatDetector::with_config(ThreatDetectorConfig {
            max_file_size: 257,
            scan_timeout: 9,
            max_concurrent_scans: 3,
            ..ThreatDetectorConfig::default()
        })
        .await
        .unwrap();
        assert_eq!(detector.scan_config().max_file_size, 257);
        assert_eq!(
            detector.scan_config().scan_timeout,
            std::time::Duration::from_secs(9)
        );
        assert_eq!(detector.scan_config().max_concurrent_scans, 3);
        assert!(detector.get_engine_info().is_empty());
        let data = b"featureless fixture";
        let analysis = detector.scan_data(data, Some("fixture.txt")).await.unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        assert!(analysis.matches.is_empty());
        assert!(analysis.indicators.is_empty());
        assert!(analysis.classifications.is_empty());
        assert_eq!(analysis.scan_stats.file_size_scanned, data.len() as u64);
        detector.update_rules().await.unwrap();
        assert!(detector.get_engine_info().is_empty());
        assert!(ThreatDetector::default().get_engine_info().is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let config = ThreatDetectorConfig::default();
        assert_eq!(config.enable_yara, cfg!(feature = "yara-engine"));
        assert!(!config.enable_clamav);
        assert_eq!(config.enable_patterns, cfg!(feature = "pattern-matching"));
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert_eq!(config.scan_timeout, 300);
        assert_eq!(config.max_concurrent_scans, 4);
    }
}
