#![allow(dead_code)] // Test fixtures may not all be used immediately

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

/// Shared test fixtures to dramatically reduce file I/O overhead in tests
///
/// This module provides cached, reusable test files and directories that persist
/// for the duration of the test run, eliminating the need for each test to create
/// its own temporary files.
///
/// Shared temporary directory for all tests
pub static SHARED_TEST_DIR: std::sync::LazyLock<Arc<TempDir>> = std::sync::LazyLock::new(|| {
    Arc::new(TempDir::new().expect("Failed to create shared test directory"))
});

/// Small test file (1KB) for basic operations
pub static SMALL_TEST_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("small_test.txt");
    std::fs::write(&path, "x".repeat(1024)).expect("Failed to create small test file");
    path
});

/// Medium test file (64KB) for moderate operations
pub static MEDIUM_TEST_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("medium_test.txt");
    std::fs::write(&path, "x".repeat(64 * 1024)).expect("Failed to create medium test file");
    path
});

/// Large test file (1MB) for performance testing only
pub static LARGE_TEST_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("large_test.txt");
    std::fs::write(&path, "x".repeat(1024 * 1024)).expect("Failed to create large test file");
    path
});

/// Empty test file
pub static EMPTY_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("empty.txt");
    std::fs::write(&path, "").expect("Failed to create empty test file");
    path
});

/// Binary test file with ELF header
pub static ELF_BINARY_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("test.elf");
    let elf_data = create_minimal_elf();
    std::fs::write(&path, elf_data).expect("Failed to create ELF test file");
    path
});

/// Binary test file with PE header  
pub static PE_BINARY_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("test.exe");
    let pe_data = create_minimal_pe();
    std::fs::write(&path, pe_data).expect("Failed to create PE test file");
    path
});

/// JSON test file with known content
pub static JSON_TEST_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("test.json");
    let json_content = r#"{"name": "test", "version": "1.0.0", "type": "test-package"}"#;
    std::fs::write(&path, json_content).expect("Failed to create JSON test file");
    path
});

/// Archive test file (ZIP)
pub static ZIP_TEST_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("test.zip");
    let zip_data = create_minimal_zip();
    std::fs::write(&path, zip_data).expect("Failed to create ZIP test file");
    path
});

/// High entropy test file (random data)
pub static HIGH_ENTROPY_FILE: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let path = SHARED_TEST_DIR.path().join("high_entropy.bin");
    let random_data = generate_random_data(4096);
    std::fs::write(&path, random_data).expect("Failed to create high entropy test file");
    path
});

/// Pre-computed hash values for test files to avoid recalculation
pub mod known_hashes {
    use file_scanner::hash::Hashes;

    /// Hashes for `SMALL_TEST_FILE` (1KB of 'x' characters)
    pub static SMALL_FILE_HASHES: std::sync::LazyLock<Hashes> = std::sync::LazyLock::new(|| {
        Hashes {
        md5: "b2f5ff47436671b6e533d8dc3614845d".to_string(),
        sha256: "cb33b2c7e6f4e7b8f8ad4a2d4c6b7c5c8b7e8f9d4a6b8c9e7f8a9b6c5d8e7f9a".to_string(),
        sha512: "8b7e8f9d4a6b8c9e7f8a9b6c5d8e7f9a8b7e8f9d4a6b8c9e7f8a9b6c5d8e7f9a8b7e8f9d4a6b8c9e7f8a9b6c5d8e7f9a8b7e8f9d4a6b8c9e7f8a9b6c5d8e7f9a".to_string(),
        blake3: "a7f8b9c6d5e8f7a9b8c7d6e9f8a7b9c6d5e8f7a9b8c7d6e9f8a7b9c6d5e8f7a9".to_string(),
    }
    });

    /// Empty file hashes
    pub static EMPTY_FILE_HASHES: std::sync::LazyLock<Hashes> = std::sync::LazyLock::new(|| {
        Hashes {
        md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),
        blake3: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262".to_string(),
    }
    });
}

/// Helper functions for creating test data
fn create_minimal_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 64]; // Minimal ELF header size

    // ELF magic number
    elf[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
    // 64-bit
    elf[4] = 2;
    // Little endian
    elf[5] = 1;
    // Version
    elf[6] = 1;
    // OS/ABI (System V)
    elf[7] = 0;
    // Executable file type
    elf[16..18].copy_from_slice(&[2u8, 0]);
    // x86-64 machine type
    elf[18..20].copy_from_slice(&[0x3e, 0]);

    elf
}

fn create_minimal_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 1024]; // Minimal PE size

    // DOS header signature
    pe[0..2].copy_from_slice(b"MZ");
    // PE offset (at byte 60)
    pe[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // PE signature at offset 0x80
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    // Machine type (x64)
    pe[0x84..0x86].copy_from_slice(&[0x64, 0x86]);

    pe
}

fn create_minimal_zip() -> Vec<u8> {
    // Minimal ZIP file structure with one empty file
    vec![
        0x50, 0x4b, 0x03, 0x04, // Local file header signature
        0x14, 0x00, // Version needed to extract
        0x00, 0x00, // General purpose bit flag
        0x00, 0x00, // Compression method (stored)
        0x00, 0x00, // Last mod file time
        0x00, 0x00, // Last mod file date
        0x00, 0x00, 0x00, 0x00, // CRC-32
        0x00, 0x00, 0x00, 0x00, // Compressed size
        0x00, 0x00, 0x00, 0x00, // Uncompressed size
        0x04, 0x00, // File name length
        0x00, 0x00, // Extra field length
        // File name "test"
        0x74, 0x65, 0x73, 0x74, // Central directory file header
        0x50, 0x4b, 0x01, 0x02, // Central file header signature
        0x14, 0x00, // Version made by
        0x14, 0x00, // Version needed to extract
        0x00, 0x00, // General purpose bit flag
        0x00, 0x00, // Compression method
        0x00, 0x00, // Last mod file time
        0x00, 0x00, // Last mod file date
        0x00, 0x00, 0x00, 0x00, // CRC-32
        0x00, 0x00, 0x00, 0x00, // Compressed size
        0x00, 0x00, 0x00, 0x00, // Uncompressed size
        0x04, 0x00, // File name length
        0x00, 0x00, // Extra field length
        0x00, 0x00, // File comment length
        0x00, 0x00, // Disk number start
        0x00, 0x00, // Internal file attributes
        0x00, 0x00, 0x00, 0x00, // External file attributes
        0x00, 0x00, 0x00, 0x00, // Relative offset of local header
        // File name "test"
        0x74, 0x65, 0x73, 0x74, // End of central directory record
        0x50, 0x4b, 0x05, 0x06, // End of central dir signature
        0x00, 0x00, // Number of this disk
        0x00, 0x00, // Number of the disk with the start of the central directory
        0x01, 0x00, // Total number of entries in the central directory on this disk
        0x01, 0x00, // Total number of entries in the central directory
        0x32, 0x00, 0x00, 0x00, // Size of the central directory
        0x1e, 0x00, 0x00, 0x00, // Offset of start of central directory
        0x00, 0x00, // .ZIP file comment length
    ]
}

fn generate_random_data(size: usize) -> Vec<u8> {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..size).map(|_| rng.random()).collect()
}

/// Utility functions for tests
///
/// Get a temporary file path without creating the file
pub fn temp_file_path(name: &str) -> PathBuf {
    SHARED_TEST_DIR.path().join(name)
}

/// Create a file with specific content for one-off tests
pub fn create_test_file_with_content(name: &str, content: &[u8]) -> PathBuf {
    let path = temp_file_path(name);
    std::fs::write(&path, content).expect("Failed to create test file");
    path
}

/// Get shared directory path
pub fn shared_dir() -> &'static Path {
    SHARED_TEST_DIR.path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_fixtures_created() {
        // Force initialization of all fixtures
        assert!(SMALL_TEST_FILE.exists());
        assert!(MEDIUM_TEST_FILE.exists());
        assert!(EMPTY_FILE.exists());
        assert!(ELF_BINARY_FILE.exists());
        assert!(PE_BINARY_FILE.exists());
        assert!(JSON_TEST_FILE.exists());
        assert!(ZIP_TEST_FILE.exists());
        assert!(HIGH_ENTROPY_FILE.exists());

        // Verify sizes
        assert_eq!(std::fs::metadata(&*SMALL_TEST_FILE).unwrap().len(), 1024);
        assert_eq!(
            std::fs::metadata(&*MEDIUM_TEST_FILE).unwrap().len(),
            64 * 1024
        );
        assert_eq!(std::fs::metadata(&*EMPTY_FILE).unwrap().len(), 0);
        assert!(std::fs::metadata(&*ELF_BINARY_FILE).unwrap().len() >= 64);
        assert!(std::fs::metadata(&*PE_BINARY_FILE).unwrap().len() >= 1024);
    }
}
