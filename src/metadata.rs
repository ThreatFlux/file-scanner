use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::binary_parser::BinaryInfo;
use crate::hash::Hashes;
use crate::hexdump::HexDump;
use crate::signature::SignatureInfo;
use crate::strings::ExtractedStrings;

#[derive(Debug, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_path: PathBuf,
    pub file_name: String,
    pub file_size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub permissions: String,
    pub is_executable: bool,
    pub mime_type: Option<String>,
    pub hashes: Option<Hashes>,
    pub binary_info: Option<BinaryInfo>,
    pub extracted_strings: Option<ExtractedStrings>,
    pub signature_info: Option<SignatureInfo>,
    pub hex_dump: Option<HexDump>,
    pub owner_uid: u32,
    pub group_gid: u32,
}

impl FileMetadata {
    pub fn new(path: &Path) -> Result<Self> {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            file_path: path.to_path_buf(),
            file_name,
            file_size: 0,
            created: None,
            modified: None,
            accessed: None,
            permissions: String::new(),
            is_executable: false,
            mime_type: None,
            hashes: None,
            binary_info: None,
            extracted_strings: None,
            signature_info: None,
            hex_dump: None,
            owner_uid: 0,
            group_gid: 0,
        })
    }

    pub fn extract_basic_info(&mut self) -> Result<()> {
        let metadata = fs::metadata(&self.file_path)?;

        self.file_size = metadata.len();

        #[cfg(unix)]
        {
            self.owner_uid = metadata.uid();
            self.group_gid = metadata.gid();

            let mode = metadata.mode();
            self.permissions = format!("{:o}", mode & 0o777);
            self.is_executable = mode & 0o111 != 0;
        }

        #[cfg(windows)]
        {
            // Windows doesn't have uid/gid, use default values
            self.owner_uid = 0;
            self.group_gid = 0;

            // Use file attributes to determine if executable
            self.is_executable = self
                .file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| {
                    matches!(
                        ext.to_lowercase().as_str(),
                        "exe" | "bat" | "cmd" | "com" | "ps1"
                    )
                })
                .unwrap_or(false);

            // Windows permissions are more complex, use a simplified representation
            self.permissions = if metadata.permissions().readonly() {
                "r--".to_string()
            } else {
                "rw-".to_string()
            };
        }

        if let Ok(modified) = metadata.modified() {
            self.modified = Some(DateTime::from(modified));
        }

        if let Ok(accessed) = metadata.accessed() {
            self.accessed = Some(DateTime::from(accessed));
        }

        if let Ok(created) = metadata.created() {
            self.created = Some(DateTime::from(created));
        }

        self.detect_mime_type()?;

        Ok(())
    }

    fn detect_mime_type(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; 512];
        if let Ok(mut file) = fs::File::open(&self.file_path) {
            use std::io::Read;
            let _ = file.read(&mut buffer)?;

            self.mime_type = Some(
                match &buffer[..] {
                    b if b.starts_with(b"\x7FELF") => "application/x-elf",
                    b if b.starts_with(b"MZ") => "application/x-dosexec",
                    b if b.starts_with(b"\xCA\xFE\xBA\xBE") => "application/x-mach-binary",
                    b if b.starts_with(b"\xFE\xED\xFA") => "application/x-mach-binary",
                    b if b.starts_with(b"#!/") => "text/x-shellscript",
                    b if b.starts_with(b"\x89PNG") => "image/png",
                    b if b.starts_with(b"\xFF\xD8\xFF") => "image/jpeg",
                    b if b.starts_with(b"GIF8") => "image/gif",
                    b if b.starts_with(b"PK\x03\x04") => "application/zip",
                    b if b.starts_with(b"\x1F\x8B") => "application/gzip",
                    b if b.starts_with(b"BZh") => "application/x-bzip2",
                    b if b.starts_with(b"%PDF") => "application/pdf",
                    _ => "application/octet-stream",
                }
                .to_string(),
            );
        }

        Ok(())
    }

    pub async fn calculate_hashes(&mut self) -> Result<()> {
        self.hashes = Some(crate::hash::calculate_all_hashes(&self.file_path).await?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use test_case::test_case;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, PathBuf)> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file");
        let mut file = File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[test]
    fn test_new_metadata() {
        let path = Path::new("/tmp/test.txt");
        let metadata = FileMetadata::new(path).unwrap();

        assert_eq!(metadata.file_path, PathBuf::from("/tmp/test.txt"));
        assert_eq!(metadata.file_name, "test.txt");
        assert_eq!(metadata.file_size, 0);
        assert!(metadata.created.is_none());
        assert!(metadata.modified.is_none());
        assert!(metadata.accessed.is_none());
        assert_eq!(metadata.permissions, "");
        assert!(!metadata.is_executable);
        assert!(metadata.mime_type.is_none());
        assert!(metadata.hashes.is_none());
        assert!(metadata.binary_info.is_none());
        assert!(metadata.extracted_strings.is_none());
        assert!(metadata.signature_info.is_none());
        assert!(metadata.hex_dump.is_none());
        assert_eq!(metadata.owner_uid, 0);
        assert_eq!(metadata.group_gid, 0);
    }

    #[test]
    fn test_new_metadata_no_filename() {
        let path = Path::new("/");
        let metadata = FileMetadata::new(path).unwrap();
        assert_eq!(metadata.file_name, "unknown");
    }

    #[test]
    fn test_extract_basic_info() {
        let (_temp_dir, file_path) = create_test_file(b"Hello, World!").unwrap();
        let mut metadata = FileMetadata::new(&file_path).unwrap();

        metadata.extract_basic_info().unwrap();

        assert_eq!(metadata.file_size, 13);
        #[cfg(unix)]
        {
            assert!(metadata.owner_uid > 0);
            assert!(metadata.group_gid > 0);
        }
        #[cfg(windows)]
        {
            assert_eq!(metadata.owner_uid, 0);
            assert_eq!(metadata.group_gid, 0);
        }
        assert!(!metadata.permissions.is_empty());
        assert!(!metadata.is_executable);
        assert!(metadata.modified.is_some());
        assert!(metadata.accessed.is_some());
        // created might not be available on all filesystems
        assert_eq!(
            metadata.mime_type,
            Some("application/octet-stream".to_string())
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_basic_info_executable() {
        let (_temp_dir, file_path) = create_test_file(b"#!/bin/bash\necho hello").unwrap();

        // Set executable permissions
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&file_path, perms).unwrap();

        let mut metadata = FileMetadata::new(&file_path).unwrap();
        metadata.extract_basic_info().unwrap();

        assert!(metadata.is_executable);
        assert_eq!(metadata.permissions, "755");
        assert_eq!(metadata.mime_type, Some("text/x-shellscript".to_string()));
    }

    #[test]
    fn test_extract_basic_info_nonexistent_file() {
        let mut metadata = FileMetadata::new(Path::new("/nonexistent/file")).unwrap();
        let result = metadata.extract_basic_info();
        assert!(result.is_err());
    }

    #[test_case(b"\x7FELF\x02\x01\x01\x00", "application/x-elf"; "ELF binary")]
    #[test_case(b"MZ\x90\x00\x03\x00\x00\x00", "application/x-dosexec"; "PE binary")]
    #[test_case(b"\xCA\xFE\xBA\xBE", "application/x-mach-binary"; "Mach-O binary BE")]
    #[test_case(b"\xFE\xED\xFA\xCE", "application/x-mach-binary"; "Mach-O binary LE")]
    #[test_case(b"#!/bin/sh\n", "text/x-shellscript"; "Shell script")]
    #[test_case(b"\x89PNG\r\n\x1A\n", "image/png"; "PNG image")]
    #[test_case(b"\xFF\xD8\xFF\xE0", "image/jpeg"; "JPEG image")]
    #[test_case(b"GIF87a", "image/gif"; "GIF image")]
    #[test_case(b"PK\x03\x04", "application/zip"; "ZIP archive")]
    #[test_case(b"\x1F\x8B\x08", "application/gzip"; "GZIP archive")]
    #[test_case(b"BZh91AY", "application/x-bzip2"; "BZIP2 archive")]
    #[test_case(b"%PDF-1.4", "application/pdf"; "PDF document")]
    #[test_case(b"Random data", "application/octet-stream"; "Unknown binary")]
    fn test_mime_type_detection(content: &[u8], expected_mime: &str) {
        let (_temp_dir, file_path) = create_test_file(content).unwrap();
        let mut metadata = FileMetadata::new(&file_path).unwrap();
        metadata.extract_basic_info().unwrap();

        assert_eq!(metadata.mime_type, Some(expected_mime.to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_format() {
        let (_temp_dir, file_path) = create_test_file(b"test").unwrap();

        // Test different permission modes
        let test_modes = vec![
            (0o644, "644", false),
            (0o755, "755", true),
            (0o600, "600", false),
            (0o777, "777", true),
            (0o400, "400", false),
            (0o500, "500", true),
        ];

        for (mode, expected_perm, expected_exec) in test_modes {
            let perms = fs::Permissions::from_mode(mode);
            fs::set_permissions(&file_path, perms).unwrap();

            let mut metadata = FileMetadata::new(&file_path).unwrap();
            metadata.extract_basic_info().unwrap();

            assert_eq!(metadata.permissions, expected_perm, "Mode: {:#o}", mode);
            assert_eq!(metadata.is_executable, expected_exec, "Mode: {:#o}", mode);
        }
    }

    #[test]
    fn test_large_file_mime_detection() {
        // Test that MIME detection works with files larger than 512 bytes
        let mut content = vec![0u8; 1024];
        content[0..4].copy_from_slice(b"\x89PNG");

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();
        let mut metadata = FileMetadata::new(&file_path).unwrap();
        metadata.extract_basic_info().unwrap();

        assert_eq!(metadata.mime_type, Some("image/png".to_string()));
    }

    #[test]
    fn test_empty_file() {
        let (_temp_dir, file_path) = create_test_file(b"").unwrap();
        let mut metadata = FileMetadata::new(&file_path).unwrap();
        metadata.extract_basic_info().unwrap();

        assert_eq!(metadata.file_size, 0);
        assert_eq!(
            metadata.mime_type,
            Some("application/octet-stream".to_string())
        );
    }

    #[tokio::test]
    async fn test_calculate_hashes() {
        let content = b"Hello, World!";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();
        let mut metadata = FileMetadata::new(&file_path).unwrap();

        metadata.extract_basic_info().unwrap();
        metadata.calculate_hashes().await.unwrap();

        assert!(metadata.hashes.is_some());
        let hashes = metadata.hashes.unwrap();

        // Verify the hashes are calculated (exact values depend on hash implementation)
        assert!(!hashes.md5.is_empty());
        assert!(!hashes.sha256.is_empty());
        assert!(!hashes.sha512.is_empty());
        assert!(!hashes.blake3.is_empty());
    }

    #[test]
    fn test_file_timestamps() {
        let (_temp_dir, file_path) = create_test_file(b"test").unwrap();
        let mut metadata = FileMetadata::new(&file_path).unwrap();
        metadata.extract_basic_info().unwrap();

        // All files should have at least modified and accessed times
        assert!(metadata.modified.is_some());
        assert!(metadata.accessed.is_some());

        // Verify timestamps are recent (within last minute)
        let now = Utc::now();
        if let Some(modified) = metadata.modified {
            let diff = now.signed_duration_since(modified);
            assert!(diff.num_seconds() < 60 && diff.num_seconds() >= 0);
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_handling() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("target");
        let symlink_path = temp_dir.path().join("symlink");

        // Create target file
        File::create(&target_path)
            .unwrap()
            .write_all(b"target content")
            .unwrap();

        // Create symlink
        std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();

        let mut metadata = FileMetadata::new(&symlink_path).unwrap();
        let result = metadata.extract_basic_info();

        // Should successfully read through the symlink
        assert!(result.is_ok());
        assert_eq!(metadata.file_size, 14); // "target content"
    }
}
