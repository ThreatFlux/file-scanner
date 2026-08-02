#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::field_reassign_with_default,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::ignore_without_reason,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::ref_option,
    clippy::redundant_clone,
    clippy::redundant_pattern_matching,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_debug_formatting,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::wildcard_enum_match_arm,
    clippy::ignored_unit_patterns
)]

use anyhow::Result;
use file_scanner::hash::{calculate_all_hashes, Hashes};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// Import shared test fixtures for performance
mod common;
use common::fixtures::*;

#[tokio::test]
async fn test_calculate_all_hashes_basic() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "Hello, World!")?;

    let hashes = calculate_all_hashes(&test_file).await?;

    // Known hashes for "Hello, World!"
    assert_eq!(hashes.md5, "65a8e27d8879283831b664bd8b7f0ad4");
    assert_eq!(
        hashes.sha256,
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    );
    assert_eq!(
        hashes.sha512,
        "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
    );
    // BLAKE3 hash is deterministic but let's just check format
    assert_eq!(hashes.blake3.len(), 64);
    assert!(hashes.blake3.chars().all(|c| c.is_ascii_hexdigit()));

    Ok(())
}

#[tokio::test]
async fn test_calculate_all_hashes_optimized() -> Result<()> {
    // Use shared empty file fixture instead of creating new temp file
    let hashes = calculate_all_hashes(&EMPTY_FILE).await?;

    // Use pre-computed known hashes for empty file
    assert_eq!(hashes.md5, known_hashes::EMPTY_FILE_HASHES.md5);
    assert_eq!(hashes.sha256, known_hashes::EMPTY_FILE_HASHES.sha256);
    assert_eq!(hashes.sha512, known_hashes::EMPTY_FILE_HASHES.sha512);
    assert_eq!(hashes.blake3, known_hashes::EMPTY_FILE_HASHES.blake3);

    Ok(())
}

#[tokio::test]
async fn test_calculate_hashes_small_file_optimized() -> Result<()> {
    // Use shared small file fixture (1KB) instead of creating 1MB file
    let hashes = calculate_all_hashes(&SMALL_TEST_FILE).await?;

    // Verify hash format without creating large files
    assert_eq!(hashes.md5.len(), 32);
    assert_eq!(hashes.sha256.len(), 64);
    assert_eq!(hashes.sha512.len(), 128);
    assert_eq!(hashes.blake3.len(), 64);

    // All should be valid hex
    for hash in [&hashes.md5, &hashes.sha256, &hashes.sha512, &hashes.blake3] {
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_file_hashes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("empty.txt");
    fs::write(&test_file, "")?;

    let hashes = calculate_all_hashes(&test_file).await?;

    // Known hashes for empty file
    assert_eq!(hashes.md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(
        hashes.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hashes.sha512,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    Ok(())
}

#[tokio::test]
async fn test_large_file_hashes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("large.txt");

    // Create a 1MB file
    let content = "x".repeat(1024 * 1024);
    fs::write(&test_file, &content)?;

    let hashes = calculate_all_hashes(&test_file).await?;

    // Verify hashes were calculated (exact values depend on content)
    assert!(!hashes.md5.is_empty());
    assert!(!hashes.sha256.is_empty());
    assert!(!hashes.sha512.is_empty());
    assert!(!hashes.blake3.is_empty());

    // Verify correct format
    assert_eq!(hashes.md5.len(), 32);
    assert_eq!(hashes.sha256.len(), 64);
    assert_eq!(hashes.sha512.len(), 128);
    assert_eq!(hashes.blake3.len(), 64);

    Ok(())
}

#[tokio::test]
async fn test_nonexistent_file_hash() {
    let result = calculate_all_hashes(Path::new("/nonexistent/file.txt")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_concurrent_hash_calculation() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create multiple files
    let mut files = Vec::new();
    for i in 0..5 {
        let file_path = temp_dir.path().join(format!("file{i}.txt"));
        fs::write(&file_path, format!("Content for file {i}"))?;
        files.push(file_path);
    }

    // Calculate hashes concurrently
    let mut handles = Vec::new();
    for file in files {
        let handle = tokio::spawn(async move { calculate_all_hashes(&file).await });
        handles.push(handle);
    }

    // Collect results
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await??;
        results.push(result);
    }

    // Verify all calculations completed
    assert_eq!(results.len(), 5);
    for (i, hashes) in results.iter().enumerate() {
        assert!(!hashes.md5.is_empty(), "MD5 hash missing for file {i}");
        assert!(
            !hashes.sha256.is_empty(),
            "SHA256 hash missing for file {i}"
        );
        assert!(
            !hashes.sha512.is_empty(),
            "SHA512 hash missing for file {i}"
        );
        assert!(
            !hashes.blake3.is_empty(),
            "BLAKE3 hash missing for file {i}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_hash_serialization() -> Result<()> {
    let hashes = Hashes {
        md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),
        blake3: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262".to_string(),
    };

    // Test JSON serialization
    let json = serde_json::to_string(&hashes)?;
    assert!(json.contains("md5"));
    assert!(json.contains("sha256"));
    assert!(json.contains("sha512"));
    assert!(json.contains("blake3"));

    // Test deserialization
    let deserialized: Hashes = serde_json::from_str(&json)?;
    assert_eq!(deserialized.md5, hashes.md5);
    assert_eq!(deserialized.sha256, hashes.sha256);
    assert_eq!(deserialized.sha512, hashes.sha512);
    assert_eq!(deserialized.blake3, hashes.blake3);

    Ok(())
}

#[tokio::test]
async fn test_special_characters_filename() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test file with spaces.txt");
    fs::write(&test_file, "content")?;

    let hashes = calculate_all_hashes(&test_file).await?;
    assert!(!hashes.md5.is_empty());
    assert!(!hashes.sha256.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_binary_file_hashes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("binary.bin");

    // Create binary content
    let binary_content: Vec<u8> = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x42];
    fs::write(&test_file, &binary_content)?;

    let hashes = calculate_all_hashes(&test_file).await?;

    // Verify all hashes calculated
    assert!(!hashes.md5.is_empty());
    assert!(!hashes.sha256.is_empty());
    assert!(!hashes.sha512.is_empty());
    assert!(!hashes.blake3.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_known_content_hashes() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Test with "The quick brown fox jumps over the lazy dog"
    let test_file = temp_dir.path().join("fox.txt");
    fs::write(&test_file, "The quick brown fox jumps over the lazy dog")?;

    let hashes = calculate_all_hashes(&test_file).await?;

    // Known hashes for this pangram
    assert_eq!(hashes.md5, "9e107d9d372bb6826bd81d3542a419d6");
    assert_eq!(
        hashes.sha256,
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    );

    Ok(())
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    #[ignore = "Performance test - run with --ignored"]
    async fn test_hash_performance() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("perf_test.bin");

        // Create a 10MB file
        let content = vec![0u8; 10 * 1024 * 1024];
        fs::write(&test_file, &content)?;

        let start = Instant::now();
        let hashes = calculate_all_hashes(&test_file).await?;
        let duration = start.elapsed();

        println!("Hash calculation for 10MB took: {duration:?}");
        println!("MD5: {}", &hashes.md5[..16]);
        println!("SHA256: {}", &hashes.sha256[..16]);
        println!("SHA512: {}", &hashes.sha512[..16]);
        println!("BLAKE3: {}", &hashes.blake3[..16]);

        // Should complete in reasonable time (< 1 second for 10MB)
        assert!(duration.as_secs() < 1);

        Ok(())
    }

    #[tokio::test]
    #[ignore = "Performance test - run with --ignored"]
    async fn test_concurrent_performance() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create 10 files of 1MB each
        let mut files = Vec::new();
        for i in 0..10 {
            let file_path = temp_dir.path().join(format!("perf{i}.bin"));
            let content = vec![i as u8; 1024 * 1024];
            fs::write(&file_path, content)?;
            files.push(file_path);
        }

        let start = Instant::now();

        // Calculate all hashes concurrently
        let mut handles = Vec::new();
        for file in files {
            handles.push(tokio::spawn(
                async move { calculate_all_hashes(&file).await },
            ));
        }

        for handle in handles {
            handle.await??;
        }

        let duration = start.elapsed();
        println!("Concurrent hash calculation for 10x1MB files took: {duration:?}");

        // Should benefit from concurrency
        assert!(duration.as_secs() < 3);

        Ok(())
    }
}
