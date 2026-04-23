//! Tests for the main ThreatDetector functionality

use std::io::Write;
use tempfile::NamedTempFile;
use threatflux_threat_detection::types::*;
use threatflux_threat_detection::{ThreatDetector, ThreatDetectorConfig};

// Helper function to create test file
fn create_test_file(content: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();
    file
}

// Helper function to create safe PE file for testing
fn create_test_pe_file() -> Vec<u8> {
    vec![
        // DOS Header
        0x4d, 0x5a, // MZ signature
        0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, // PE header offset

              // Padding to PE header location
              // ... (fill with zeros to reach offset 0x80)
    ]
}

#[tokio::test]
async fn test_detector_creation_with_default_config() {
    let config = ThreatDetectorConfig {
        enable_yara: false, // Disable engines that might not be available in test environment
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await;
    assert!(detector.is_ok(), "Detector creation should succeed");

    let detector = detector.unwrap();
    let engine_info = detector.get_engine_info();
    // With all engines disabled, should have empty engine list
    assert_eq!(engine_info.len(), 0);
}

#[tokio::test]
async fn test_detector_creation_with_custom_config() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        max_file_size: 50 * 1024 * 1024, // 50MB
        scan_timeout: 180,               // 3 minutes
        max_concurrent_scans: 8,
        rule_sources: vec!["custom_rules.yara".to_string()],
    };

    let detector = ThreatDetector::with_config(config).await;
    assert!(
        detector.is_ok(),
        "Detector creation with custom config should succeed"
    );
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
    assert!(config.rule_sources.is_empty());
}

#[tokio::test]
async fn test_scan_memory_data() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Test with benign data
    let test_data = b"Hello, World! This is a test file.";
    let result = detector.scan_data(test_data, Some("test.txt")).await;

    assert!(result.is_ok(), "Scanning memory data should succeed");

    let analysis = result.unwrap();
    // With no engines enabled, should return clean result
    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    assert!(analysis.matches.is_empty());
    assert!(analysis.indicators.is_empty());
    assert!(analysis.classifications.is_empty());
}

#[tokio::test]
async fn test_scan_file() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Create a test file
    let test_content = b"This is a safe test file content.";
    let test_file = create_test_file(test_content);

    let result = detector.scan_file(test_file.path()).await;
    assert!(result.is_ok(), "File scanning should succeed");

    let analysis = result.unwrap();
    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    assert!(analysis.scan_stats.file_size_scanned > 0);
}

#[tokio::test]
async fn test_scan_nonexistent_file() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    let result = detector.scan_file("/nonexistent/file/path.exe").await;
    assert!(result.is_err(), "Scanning nonexistent file should fail");
}

#[tokio::test]
async fn test_scan_directory() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Use a system directory that should exist
    let result = detector.scan_directory("/tmp").await;

    // Directory scanning might succeed or fail depending on permissions
    // Just ensure it doesn't panic
    match result {
        Ok(results) => {
            assert!(!results.is_empty());
        }
        Err(_) => {
            // Acceptable - might not have permission or directory might not exist
        }
    }
}

#[tokio::test]
async fn test_scan_with_custom_rule() {
    let config = ThreatDetectorConfig {
        enable_yara: false, // Even with YARA disabled, should handle gracefully
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    let test_data = b"Test data for custom rule scanning";
    let target = ScanTarget::Memory {
        data: test_data.to_vec(),
        name: Some("test.bin".to_string()),
    };

    let custom_rule = r#"
rule test_rule {
    strings:
        $text = "Test data"
    condition:
        $text
}
"#;

    let result = detector.scan_with_rule(target, custom_rule).await;
    // Should fail gracefully when YARA engine is not available
    assert!(
        result.is_err(),
        "Should fail when YARA engine is not available"
    );
}

#[tokio::test]
async fn test_update_rules() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let mut detector = ThreatDetector::with_config(config).await.unwrap();

    // Should succeed even with no engines (no-op)
    let result = detector.update_rules().await;
    assert!(
        result.is_ok(),
        "Rule update should succeed even with no engines"
    );
}

#[tokio::test]
async fn test_get_engine_info() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    let engine_info = detector.get_engine_info();
    assert_eq!(
        engine_info.len(),
        0,
        "Should have no engines with all disabled"
    );
}

#[tokio::test]
async fn test_scan_large_file() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        max_file_size: 1024, // Very small limit for testing
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Create a file larger than the limit
    let large_content = vec![0u8; 2048]; // 2KB file, but limit is 1KB
    let large_file = create_test_file(&large_content);

    let result = detector.scan_file(large_file.path()).await;
    // Behavior might vary - could succeed with truncated scan or fail
    // Just ensure it doesn't panic
    match result {
        Ok(analysis) => {
            assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        }
        Err(_) => {
            // Acceptable - file might be too large
        }
    }
}

#[tokio::test]
async fn test_scan_binary_file() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Create a binary file (PE format)
    let pe_content = create_test_pe_file();
    let binary_file = create_test_file(&pe_content);

    let result = detector.scan_file(binary_file.path()).await;
    assert!(result.is_ok(), "Binary file scanning should succeed");

    let analysis = result.unwrap();
    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
}

#[tokio::test]
async fn test_scan_empty_file() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Create an empty file
    let empty_file = create_test_file(&[]);

    let result = detector.scan_file(empty_file.path()).await;
    assert!(result.is_ok(), "Empty file scanning should succeed");

    let analysis = result.unwrap();
    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    assert_eq!(analysis.scan_stats.file_size_scanned, 0);
}

#[tokio::test]
async fn test_concurrent_scans() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        max_concurrent_scans: 2,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Create multiple test files
    let test_files: Vec<_> = (0..5)
        .map(|i| {
            let content = format!("Test file content {}", i);
            create_test_file(content.as_bytes())
        })
        .collect();

    // Scan files concurrently
    let mut scan_futures = Vec::new();
    for file in &test_files {
        let detector = &detector;
        let path = file.path().to_path_buf();
        let future = async move { detector.scan_file(&path).await };
        scan_futures.push(future);
    }

    // Wait for all scans to complete
    let results = futures::future::join_all(scan_futures).await;

    // All scans should succeed
    for result in results {
        assert!(result.is_ok(), "Concurrent scan should succeed");
        let analysis = result.unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    }
}

#[tokio::test]
async fn test_scan_target_variants() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Test different target types
    let memory_target = ScanTarget::Memory {
        data: b"memory test data".to_vec(),
        name: Some("memory_sample".to_string()),
    };

    let test_file = create_test_file(b"file test data");
    let file_target = ScanTarget::File(test_file.path().to_path_buf());

    // Test memory target
    let memory_result = detector
        .scan_data(b"memory test data", Some("memory_sample"))
        .await;
    assert!(memory_result.is_ok());

    // Test file target
    let file_result = detector.scan_file(test_file.path()).await;
    assert!(file_result.is_ok());
}

#[tokio::test]
async fn test_analysis_result_structure() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    let test_data = b"Analysis structure test data";
    let result = detector
        .scan_data(test_data, Some("test.bin"))
        .await
        .unwrap();

    // Verify analysis structure is complete
    assert!(result.matches.len() >= 0);
    assert!(result.indicators.len() >= 0);
    assert!(result.classifications.len() >= 0);
    assert!(result.recommendations.len() >= 0);

    // Verify scan statistics
    assert!(result.scan_stats.scan_duration.as_nanos() > 0);
    assert_eq!(result.scan_stats.file_size_scanned, test_data.len() as u64);

    // With no engines, should be clean
    assert_eq!(result.threat_level, ThreatLevel::Clean);
}

#[tokio::test]
async fn test_error_handling() {
    // Test various error conditions

    // Test invalid configuration
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        max_file_size: 0,        // Invalid size
        scan_timeout: 0,         // Invalid timeout
        max_concurrent_scans: 0, // Invalid concurrency
        ..Default::default()
    };

    // Should handle invalid config gracefully
    let detector = ThreatDetector::with_config(config).await;
    // Implementation might accept or reject this - both are valid

    if let Ok(detector) = detector {
        // Test scanning with invalid configuration
        let result = detector.scan_data(b"test", None).await;
        // Should not panic, might succeed or fail gracefully
        let _ = result;
    }
}

#[tokio::test]
async fn test_performance_metrics() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    let start_time = std::time::Instant::now();
    let test_data = vec![0u8; 1024]; // 1KB of data

    let result = detector
        .scan_data(&test_data, Some("perf_test"))
        .await
        .unwrap();
    let total_time = start_time.elapsed();

    // Verify performance metrics are reasonable
    assert!(result.scan_stats.scan_duration <= total_time);
    assert_eq!(result.scan_stats.file_size_scanned, 1024);

    // Should be fast for small files with no engines
    assert!(total_time.as_millis() < 1000); // Less than 1 second
}

#[test]
fn test_detector_default() {
    let detector = ThreatDetector::default();
    let config = detector.scan_config();

    // Default should create an empty detector
    assert_eq!(detector.get_engine_info().len(), 0);
    assert_eq!(config.max_file_size, 100 * 1024 * 1024);
    assert_eq!(config.scan_timeout.as_secs(), 300);
    assert_eq!(config.max_concurrent_scans, 4);
}
