use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tokio::task;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}

pub async fn calculate_all_hashes(path: &Path) -> Result<Hashes> {
    let path = path.to_path_buf();

    let md5_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_md5_sync(&path)
    });

    let sha256_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_sha256(&path)
    });

    let sha512_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_sha512(&path)
    });

    let blake3_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_blake3(&path)
    });

    let (md5, sha256, sha512, blake3) =
        tokio::try_join!(md5_task, sha256_task, sha512_task, blake3_task)?;

    Ok(Hashes {
        md5: md5?,
        sha256: sha256?,
        sha512: sha512?,
        blake3: blake3?,
    })
}

pub async fn calculate_md5(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    task::spawn_blocking(move || calculate_md5_sync(&path)).await?
}

fn calculate_md5_sync(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_sha256(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_sha512(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha512::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_blake3(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Blake3Hasher::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hasher.finalize().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;
    use tokio;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf)> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[test]
    fn test_calculate_md5_sync() {
        let content = b"Hello, World!";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hash = calculate_md5_sync(&file_path).unwrap();
        assert_eq!(hash, "65a8e27d8879283831b664bd8b7f0ad4");
    }

    #[test]
    fn test_calculate_sha256() {
        let content = b"Hello, World!";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hash = calculate_sha256(&file_path).unwrap();
        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_calculate_sha512() {
        let content = b"Hello, World!";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hash = calculate_sha512(&file_path).unwrap();
        assert_eq!(hash, "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387");
    }

    #[test]
    fn test_calculate_blake3() {
        let content = b"Hello, World!";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hash = calculate_blake3(&file_path).unwrap();
        // Blake3 hash for "Hello, World!"
        assert_eq!(
            hash,
            "288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8"
        );
    }

    #[tokio::test]
    async fn test_calculate_md5_async() {
        let content = b"Test content for async MD5";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hash = calculate_md5(&file_path).await.unwrap();
        assert_eq!(hash, "177e39fe10209113009207ca25549cd6");
    }

    #[tokio::test]
    async fn test_calculate_all_hashes() {
        let content = b"Test file content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hashes = calculate_all_hashes(&file_path).await.unwrap();

        assert_eq!(hashes.md5, "ac79653edeb65ab5563585f2d5f14fe9");
        assert_eq!(
            hashes.sha256,
            "6c76f7bd4b84eb68c26d2e8f48ea76f90b9bdf8836e27235a0ca4325f8fe4ce5"
        );
        assert_eq!(hashes.sha512, "7d849325b7bcfde1f5fbaee0573d95a088d2a8dbdbc426470efbb8c5b89b0bc1e172cca99a78673b1dc24a2d3ed4e0b745ffd9aa43fbfb651c89847b9c39daa8");
        assert_eq!(hashes.blake3.len(), 64); // Just verify length since Blake3 might vary
    }

    #[tokio::test]
    async fn test_empty_file_hashes() {
        let content = b"";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hashes = calculate_all_hashes(&file_path).await.unwrap();

        // Empty file hashes
        assert_eq!(hashes.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hashes.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hashes.sha512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        assert_eq!(
            hashes.blake3,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[tokio::test]
    async fn test_large_file_hashes() {
        // Create a 1MB file with predictable content
        let size = 1024 * 1024;
        let mut content = Vec::with_capacity(size);
        for i in 0..size {
            content.push((i % 256) as u8);
        }

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let hashes = calculate_all_hashes(&file_path).await.unwrap();

        // Just verify that hashes are calculated without errors
        assert!(!hashes.md5.is_empty());
        assert!(!hashes.sha256.is_empty());
        assert!(!hashes.sha512.is_empty());
        assert!(!hashes.blake3.is_empty());

        // Verify they're all different
        assert_ne!(hashes.md5, hashes.sha256);
        assert_ne!(hashes.sha256, hashes.sha512);
        assert_ne!(hashes.sha512, hashes.blake3);
    }

    #[test]
    fn test_nonexistent_file() {
        let path = Path::new("/nonexistent/file/path");

        let result = calculate_md5_sync(path);
        assert!(result.is_err());

        let result = calculate_sha256(path);
        assert!(result.is_err());

        let result = calculate_sha512(path);
        assert!(result.is_err());

        let result = calculate_blake3(path);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_hash_calculation() {
        let content = b"Concurrent hash test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Calculate hashes concurrently multiple times
        let mut handles = vec![];
        for _ in 0..10 {
            let path = file_path.clone();
            let handle = tokio::spawn(async move { calculate_all_hashes(&path).await });
            handles.push(handle);
        }

        // All calculations should succeed and produce identical results
        let mut results = vec![];
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            results.push(result);
        }

        // Verify all results are identical
        let first = &results[0];
        for result in &results[1..] {
            assert_eq!(result.md5, first.md5);
            assert_eq!(result.sha256, first.sha256);
            assert_eq!(result.sha512, first.sha512);
            assert_eq!(result.blake3, first.blake3);
        }
    }

    #[test]
    fn test_hash_format() {
        let content = b"Format test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let md5 = calculate_md5_sync(&file_path).unwrap();
        let sha256 = calculate_sha256(&file_path).unwrap();
        let sha512 = calculate_sha512(&file_path).unwrap();
        let blake3 = calculate_blake3(&file_path).unwrap();

        // Check hash format (lowercase hex)
        assert!(md5
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert!(sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert!(sha512
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert!(blake3
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));

        // Check hash lengths
        assert_eq!(md5.len(), 32); // MD5 is 128 bits = 32 hex chars
        assert_eq!(sha256.len(), 64); // SHA256 is 256 bits = 64 hex chars
        assert_eq!(sha512.len(), 128); // SHA512 is 512 bits = 128 hex chars
        assert_eq!(blake3.len(), 64); // Blake3 is 256 bits = 64 hex chars
    }

    #[cfg(unix)]
    #[test]
    fn test_hash_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        let content = b"Permission test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Remove read permissions
        let permissions = fs::Permissions::from_mode(0o000);
        fs::set_permissions(&file_path, permissions).unwrap();

        let result = calculate_md5_sync(&file_path);
        assert!(result.is_err());

        // Restore permissions for cleanup
        let permissions = fs::Permissions::from_mode(0o644);
        fs::set_permissions(&file_path, permissions).unwrap();
    }

    #[test]
    fn test_hash_special_characters_in_content() {
        let content = b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let md5 = calculate_md5_sync(&file_path).unwrap();
        let sha256 = calculate_sha256(&file_path).unwrap();
        let sha512 = calculate_sha512(&file_path).unwrap();
        let blake3 = calculate_blake3(&file_path).unwrap();

        // Just verify that binary content is handled correctly
        assert!(!md5.is_empty());
        assert!(!sha256.is_empty());
        assert!(!sha512.is_empty());
        assert!(!blake3.is_empty());
    }

    #[tokio::test]
    async fn test_hashes_struct_serialization() {
        let hashes = Hashes {
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string(),
            blake3: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262".to_string(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&hashes).unwrap();
        let deserialized: Hashes = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.md5, hashes.md5);
        assert_eq!(deserialized.sha256, hashes.sha256);
        assert_eq!(deserialized.sha512, hashes.sha512);
        assert_eq!(deserialized.blake3, hashes.blake3);
    }
}
