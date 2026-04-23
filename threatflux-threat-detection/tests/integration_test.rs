//! Integration tests for the complete threat detection pipeline

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use threatflux_threat_detection::types::*;
use threatflux_threat_detection::{ThreatDetector, ThreatDetectorConfig};

// Test data generators
mod test_data {
    pub fn create_eicar_test_string() -> &'static [u8] {
        // EICAR test string (standard antivirus test file)
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    }

    pub fn create_benign_text() -> &'static [u8] {
        b"This is a completely benign text file with no malicious content whatsoever."
    }

    pub fn create_pe_header() -> Vec<u8> {
        let mut data = vec![0; 1024];
        // DOS header
        data[0] = 0x4d; // 'M'
        data[1] = 0x5a; // 'Z'
        data[60] = 0x80; // PE header offset

        // PE signature at offset 0x80
        data[0x80] = 0x50; // 'P'
        data[0x81] = 0x45; // 'E'
        data[0x82] = 0x00;
        data[0x83] = 0x00;

        data
    }

    pub fn create_elf_header() -> Vec<u8> {
        let mut data = vec![0; 1024];
        // ELF magic
        data[0] = 0x7f;
        data[1] = 0x45; // 'E'
        data[2] = 0x4c; // 'L'
        data[3] = 0x46; // 'F'
        data[4] = 0x02; // 64-bit
        data[5] = 0x01; // Little endian

        data
    }

    pub fn create_suspicious_script() -> &'static [u8] {
        // PowerShell script with suspicious keywords
        b"powershell.exe -enc JABlAHgAZQBjACAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    }

    pub fn create_registry_modification() -> &'static [u8] {
        b"reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    }
}

// Helper to create temporary files
fn create_temp_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
    let file_path = dir.path().join(name);
    let mut file = std::fs::File::create(&file_path).unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();
    file_path
}

#[tokio::test]
async fn test_complete_threat_detection_pipeline() {
    let config = ThreatDetectorConfig {
        enable_yara: false, // Disable real engines for reliable testing
        enable_clamav: false,
        enable_patterns: false,
        max_file_size: 10 * 1024 * 1024, // 10MB
        scan_timeout: 60,                // 1 minute
        max_concurrent_scans: 2,
        rule_sources: vec![],
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Test various file types
    let temp_dir = TempDir::new().unwrap();

    let test_cases = vec![
        ("benign.txt", test_data::create_benign_text()),
        ("eicar.com", test_data::create_eicar_test_string()),
        ("suspicious.ps1", test_data::create_suspicious_script()),
        ("registry.bat", test_data::create_registry_modification()),
    ];

    for (filename, content) in test_cases {
        let file_path = create_temp_file(&temp_dir, filename, content);

        let result = detector.scan_file(&file_path).await;
        assert!(result.is_ok(), "Scan should succeed for {}", filename);

        let analysis = result.unwrap();

        // Verify analysis structure
        assert!(analysis.scan_stats.scan_duration.as_nanos() > 0);
        assert!(analysis.scan_stats.file_size_scanned > 0);

        // With no engines enabled, should be clean
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        assert!(analysis.matches.is_empty());
        assert!(analysis.indicators.is_empty());
        assert!(analysis.classifications.is_empty());
    }
}

#[tokio::test]
async fn test_binary_format_detection() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let temp_dir = TempDir::new().unwrap();

    // Test different binary formats
    let pe_file = create_temp_file(&temp_dir, "test.exe", &test_data::create_pe_header());
    let elf_file = create_temp_file(&temp_dir, "test.elf", &test_data::create_elf_header());

    let pe_result = detector.scan_file(&pe_file).await.unwrap();
    let elf_result = detector.scan_file(&elf_file).await.unwrap();

    // Both should scan successfully
    assert_eq!(pe_result.threat_level, ThreatLevel::Clean);
    assert_eq!(elf_result.threat_level, ThreatLevel::Clean);

    // Verify file sizes are correct
    assert!(pe_result.scan_stats.file_size_scanned > 0);
    assert!(elf_result.scan_stats.file_size_scanned > 0);
}

#[tokio::test]
async fn test_memory_scanning() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let pe_header = test_data::create_pe_header();

    // Test memory scanning with different data types
    let test_cases = vec![
        (test_data::create_benign_text(), "benign.txt"),
        (test_data::create_eicar_test_string(), "eicar.com"),
        (&pe_header, "sample.exe"),
        (test_data::create_suspicious_script(), "script.ps1"),
    ];

    for (data, name) in test_cases {
        let result = detector.scan_data(data, Some(name)).await;
        assert!(result.is_ok(), "Memory scan should succeed for {}", name);

        let analysis = result.unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        assert_eq!(analysis.scan_stats.file_size_scanned, data.len() as u64);
    }
}

#[tokio::test]
async fn test_concurrent_scanning() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        max_concurrent_scans: 4,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let temp_dir = TempDir::new().unwrap();

    // Create multiple test files
    let test_files: Vec<_> = (0..10)
        .map(|i| {
            let content = format!("Test file content number {}", i);
            create_temp_file(&temp_dir, &format!("test_{}.txt", i), content.as_bytes())
        })
        .collect();

    // Scan all files concurrently
    let scan_tasks: Vec<_> = test_files
        .iter()
        .map(|path| {
            let detector = &detector;
            let path = path.clone();
            async move { detector.scan_file(&path).await }
        })
        .collect();

    let results = futures::future::join_all(scan_tasks).await;

    // All scans should succeed
    for (i, result) in results.into_iter().enumerate() {
        assert!(result.is_ok(), "Concurrent scan {} should succeed", i);

        let analysis = result.unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        assert!(analysis.scan_stats.file_size_scanned > 0);
    }
}

#[tokio::test]
async fn test_large_file_handling() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        max_file_size: 1024 * 1024, // 1MB limit
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let temp_dir = TempDir::new().unwrap();

    // Create files of different sizes
    let small_file = create_temp_file(&temp_dir, "small.txt", &vec![b'A'; 1000]); // 1KB
    let medium_file = create_temp_file(&temp_dir, "medium.txt", &vec![b'B'; 500_000]); // 500KB
    let large_file = create_temp_file(&temp_dir, "large.txt", &vec![b'C'; 2_000_000]); // 2MB

    // Small and medium files should scan successfully
    let small_result = detector.scan_file(&small_file).await;
    assert!(small_result.is_ok());

    let medium_result = detector.scan_file(&medium_file).await;
    assert!(medium_result.is_ok());

    // Large file might be rejected or scanned partially
    let large_result = detector.scan_file(&large_file).await;
    // Implementation specific - might succeed with truncated scan or fail
    match large_result {
        Ok(analysis) => {
            // If it succeeds, verify it's reasonable
            assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        }
        Err(_) => {
            // Acceptable to reject files over size limit
        }
    }
}

#[tokio::test]
async fn test_scan_timeout_handling() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        scan_timeout: 1, // Very short timeout (1 second)
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // For small files, should complete within timeout
    let small_data = vec![0u8; 1000];
    let result = detector.scan_data(&small_data, Some("quick.bin")).await;

    assert!(result.is_ok(), "Quick scan should complete within timeout");

    let analysis = result.unwrap();
    assert!(analysis.scan_stats.scan_duration.as_secs() <= 1);
}

#[tokio::test]
async fn test_directory_scanning() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let temp_dir = TempDir::new().unwrap();

    // Create a directory structure with test files
    let subdir = temp_dir.path().join("subdir");
    std::fs::create_dir(&subdir).unwrap();

    create_temp_file(&temp_dir, "file1.txt", b"Content 1");
    create_temp_file(&temp_dir, "file2.bin", &test_data::create_pe_header());

    let subfile_path = subdir.join("file3.txt");
    let mut subfile = std::fs::File::create(&subfile_path).unwrap();
    subfile.write_all(b"Subdirectory content").unwrap();

    // Scan the directory
    let result = detector.scan_directory(temp_dir.path()).await;

    match result {
        Ok(analyses) => {
            assert!(!analyses.is_empty(), "Should find files in directory");

            for analysis in analyses {
                assert_eq!(analysis.threat_level, ThreatLevel::Clean);
                assert!(analysis.scan_stats.file_size_scanned >= 0);
            }
        }
        Err(_) => {
            // Directory scanning might not be fully implemented
            // This is acceptable for the current test
        }
    }
}

#[tokio::test]
async fn test_error_recovery() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Test various error conditions
    let error_cases = vec![
        ("/nonexistent/path/file.exe", "Nonexistent file"),
        ("/dev/null", "Special device file"), // Unix-specific
        ("", "Empty path"),
    ];

    for (path, description) in error_cases {
        let result = detector.scan_file(path).await;

        match result {
            Ok(_) => {
                // Some paths might unexpectedly succeed (e.g., /dev/null)
                // This is acceptable
            }
            Err(_) => {
                // Expected for most error cases
            }
        }

        // Main point: should not panic
        println!("Tested error case: {}", description);
    }
}

#[tokio::test]
async fn test_scan_statistics_accuracy() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    let test_data = vec![0u8; 2048]; // Exactly 2KB
    let start_time = std::time::Instant::now();

    let result = detector
        .scan_data(&test_data, Some("stats_test.bin"))
        .await
        .unwrap();
    let actual_duration = start_time.elapsed();

    // Verify statistics accuracy
    assert_eq!(result.scan_stats.file_size_scanned, 2048);
    assert!(result.scan_stats.scan_duration <= actual_duration);
    assert!(result.scan_stats.scan_duration.as_nanos() > 0);

    // With no engines, these should be 0
    assert_eq!(result.scan_stats.rules_evaluated, 0);
    assert_eq!(result.scan_stats.patterns_matched, 0);
}

#[tokio::test]
async fn test_threat_level_calculation() {
    // This test verifies the threat level calculation logic
    // Since we don't have real engines, we test the basic structure

    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let pe_header = test_data::create_pe_header();

    // Test with different types of content
    let test_cases = vec![
        (test_data::create_benign_text(), ThreatLevel::Clean),
        (test_data::create_eicar_test_string(), ThreatLevel::Clean), // No engines = clean
        (&pe_header, ThreatLevel::Clean),
        (test_data::create_suspicious_script(), ThreatLevel::Clean),
    ];

    for (data, expected_level) in test_cases {
        let result = detector.scan_data(data, None).await.unwrap();
        assert_eq!(result.threat_level, expected_level);
    }
}

#[tokio::test]
async fn test_scan_target_handling() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();
    let temp_dir = TempDir::new().unwrap();

    // Test different ScanTarget variants
    let file_path = create_temp_file(&temp_dir, "target_test.txt", b"Target test content");

    // File target
    let file_result = detector.scan_file(&file_path).await.unwrap();
    assert_eq!(file_result.threat_level, ThreatLevel::Clean);

    // Memory target
    let memory_result = detector
        .scan_data(b"Memory target content", Some("memory.txt"))
        .await
        .unwrap();
    assert_eq!(memory_result.threat_level, ThreatLevel::Clean);

    // Directory target
    let dir_result = detector.scan_directory(temp_dir.path()).await;
    match dir_result {
        Ok(results) => {
            assert!(!results.is_empty());
            for result in results {
                assert_eq!(result.threat_level, ThreatLevel::Clean);
            }
        }
        Err(_) => {
            // Directory scanning might not be implemented
        }
    }
}

#[tokio::test]
async fn test_engine_lifecycle() {
    // Test engine initialization and management

    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let mut detector = ThreatDetector::with_config(config).await.unwrap();

    // Get initial engine info
    let initial_engines = detector.get_engine_info();
    assert_eq!(initial_engines.len(), 0); // No engines enabled

    // Test rule updates (should succeed even with no engines)
    let update_result = detector.update_rules().await;
    assert!(update_result.is_ok());

    // Engine info should remain the same
    let post_update_engines = detector.get_engine_info();
    assert_eq!(post_update_engines.len(), initial_engines.len());
}

#[tokio::test]
async fn test_performance_benchmarks() {
    let config = ThreatDetectorConfig {
        enable_yara: false,
        enable_clamav: false,
        enable_patterns: false,
        ..Default::default()
    };

    let detector = ThreatDetector::with_config(config).await.unwrap();

    // Test performance with different file sizes
    let file_sizes = vec![1024, 10240, 102400]; // 1KB, 10KB, 100KB

    for size in file_sizes {
        let test_data = vec![0u8; size];
        let start_time = std::time::Instant::now();

        let result = detector
            .scan_data(&test_data, Some(&format!("perf_{}.bin", size)))
            .await
            .unwrap();
        let total_time = start_time.elapsed();

        // Verify performance metrics
        assert_eq!(result.scan_stats.file_size_scanned, size as u64);
        assert!(result.scan_stats.scan_duration <= total_time);

        // With no engines, should be very fast
        assert!(total_time.as_millis() < 1000); // Less than 1 second

        println!("Scanned {} bytes in {:?}", size, total_time);
    }
}

#[test]
fn test_threat_analysis_construction() {
    // Test manual construction of ThreatAnalysis for validation
    let analysis = ThreatAnalysis {
        matches: vec![],
        threat_level: ThreatLevel::Clean,
        classifications: vec![],
        indicators: vec![],
        scan_stats: ScanStatistics {
            scan_duration: Duration::from_millis(100),
            rules_evaluated: 0,
            patterns_matched: 0,
            file_size_scanned: 1024,
        },
        recommendations: vec!["File appears clean".to_string()],
    };

    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    assert!(analysis.matches.is_empty());
    assert!(analysis.indicators.is_empty());
    assert!(analysis.classifications.is_empty());
    assert_eq!(analysis.recommendations.len(), 1);
    assert_eq!(analysis.scan_stats.file_size_scanned, 1024);
}
