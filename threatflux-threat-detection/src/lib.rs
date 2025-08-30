//! # ThreatFlux Threat Detection Library
//!
//! A comprehensive threat detection framework for malware analysis, YARA scanning,
//! and security assessment. Supports multiple detection engines and rule sources.
//!
//! ## Features
//!
//! - **YARA Integration**: Full YARA-X support with custom rule compilation
//! - **Multi-Engine Support**: YARA, ClamAV, pattern matching engines
//! - **Rule Management**: Automatic rule updates from multiple sources
//! - **Threat Classification**: Comprehensive threat categorization and scoring
//! - **Async Scanning**: High-performance concurrent scanning
//! - **Metrics**: Prometheus metrics for monitoring and performance
//!
//! ## Quick Start
//!
//! ```rust
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
    yara_engine: Option<engines::yara::YaraEngine>,
    #[cfg(feature = "pattern-matching")]
    pattern_engine: Option<engines::patterns::PatternEngine>,
    config: Arc<ScanConfig>,
}

/// Configuration for threat detection
#[derive(Debug, Clone)]
pub struct ThreatDetectorConfig {
    /// Enable YARA engine
    pub enable_yara: bool,
    /// Enable ClamAV engine
    pub enable_clamav: bool,
    /// Enable pattern matching
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
            enable_yara: true,
            enable_clamav: false,
            enable_patterns: true,
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
    pub async fn with_config(config: ThreatDetectorConfig) -> Result<Self> {
        // Initialize YARA engine
        #[cfg(feature = "yara-engine")]
        let yara_engine = if config.enable_yara {
            Some(engines::yara::YaraEngine::new().await?)
        } else {
            None
        };

        #[cfg(not(feature = "yara-engine"))]
        let yara_engine = None;

        // Initialize pattern matching engine
        #[cfg(feature = "pattern-matching")]
        let pattern_engine = if config.enable_patterns {
            Some(engines::patterns::PatternEngine::new().await?)
        } else {
            None
        };

        let scan_config = Arc::new(ScanConfig {
            max_file_size: config.max_file_size,
            scan_timeout: std::time::Duration::from_secs(config.scan_timeout),
            max_concurrent_scans: config.max_concurrent_scans,
        });

        Ok(Self {
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
            name: name.map(|n| n.to_string()),
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
    pub async fn scan_with_rule(&self, target: ScanTarget, rule: &str) -> Result<ThreatAnalysis> {
        // Use YARA engine if available
        if let Some(ref yara_engine) = self.yara_engine {
            return yara_engine.scan_with_custom_rule(target, rule).await;
        }

        Err(ThreatError::engine_not_available("YARA"))
    }

    /// Core scanning logic
    async fn scan(&self, target: ScanTarget) -> Result<ThreatAnalysis> {
        let start_time = std::time::Instant::now();
        let mut all_matches = Vec::new();
        let mut all_indicators = Vec::new();
        let mut classifications = std::collections::HashSet::new();

        // Run YARA engine if available
        if let Some(ref yara_engine) = self.yara_engine {
            match yara_engine.scan(target.clone()).await {
                Ok(result) => {
                    all_matches.extend(result.matches);
                    all_indicators.extend(result.indicators);
                    classifications.extend(result.classifications);
                }
                Err(e) => {
                    log::warn!("YARA engine failed: {}", e);
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
                    log::warn!("Pattern engine failed: {}", e);
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
            ScanTarget::File(path) => std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
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
    pub async fn update_rules(&mut self) -> Result<()> {
        // Update YARA engine if available
        if let Some(ref mut yara_engine) = self.yara_engine {
            if let Err(e) = yara_engine.update_rules().await {
                log::warn!("Failed to update YARA rules: {}", e);
            }
        }

        // Update pattern engine if available
        #[cfg(feature = "pattern-matching")]
        if let Some(ref mut pattern_engine) = self.pattern_engine {
            if let Err(e) = pattern_engine.update_rules().await {
                log::warn!("Failed to update pattern rules: {}", e);
            }
        }

        Ok(())
    }

    /// Get engine information
    pub fn get_engine_info(&self) -> Vec<(String, String)> {
        let mut engines = Vec::new();

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
}

impl Default for ThreatDetector {
    fn default() -> Self {
        // This is a placeholder - the actual implementation would be async
        Self {
            yara_engine: None,
            #[cfg(feature = "pattern-matching")]
            pattern_engine: None,
            config: Arc::new(ScanConfig {
                max_file_size: 100 * 1024 * 1024,
                scan_timeout: std::time::Duration::from_secs(300),
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

    #[test]
    fn test_config_defaults() {
        let config = ThreatDetectorConfig::default();
        assert!(config.enable_yara);
        assert!(!config.enable_clamav);
        assert!(config.enable_patterns);
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert_eq!(config.scan_timeout, 300);
        assert_eq!(config.max_concurrent_scans, 4);
    }
}
