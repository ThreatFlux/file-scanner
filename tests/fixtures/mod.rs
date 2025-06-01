use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

/// Creates a temporary directory with test files
pub struct TestFixture {
    pub temp_dir: TempDir,
    pub files: Vec<PathBuf>,
}

impl TestFixture {
    pub fn new() -> anyhow::Result<Self> {
        let temp_dir = TempDir::new()?;
        Ok(Self {
            temp_dir,
            files: Vec::new(),
        })
    }

    /// Create a simple text file
    pub fn create_text_file(&mut self, name: &str, content: &str) -> anyhow::Result<PathBuf> {
        let path = self.temp_dir.path().join(name);
        let mut file = File::create(&path)?;
        file.write_all(content.as_bytes())?;
        self.files.push(path.clone());
        Ok(path)
    }

    /// Create a binary file with specific bytes
    pub fn create_binary_file(&mut self, name: &str, content: &[u8]) -> anyhow::Result<PathBuf> {
        let path = self.temp_dir.path().join(name);
        let mut file = File::create(&path)?;
        file.write_all(content)?;
        self.files.push(path.clone());
        Ok(path)
    }

    /// Create a file with specific permissions (Unix only)
    #[cfg(unix)]
    pub fn create_file_with_permissions(
        &mut self,
        name: &str,
        content: &[u8],
        mode: u32,
    ) -> anyhow::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let path = self.create_binary_file(name, content)?;
        let permissions = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(&path, permissions)?;
        Ok(path)
    }

    /// Create a minimal ELF file for testing
    pub fn create_minimal_elf(&mut self, name: &str) -> anyhow::Result<PathBuf> {
        // Minimal ELF header (64-bit)
        let elf_header = vec![
            0x7f, 0x45, 0x4c, 0x46, // Magic number
            0x02, // 64-bit
            0x01, // Little endian
            0x01, // ELF version
            0x00, // System V ABI
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
            0x02, 0x00, // Executable file
            0x3e, 0x00, // x86-64
            0x01, 0x00, 0x00, 0x00, // Version 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
            0x00, 0x00, 0x00, 0x00, // Flags
            0x40, 0x00, // ELF header size
            0x38, 0x00, // Program header size
            0x01, 0x00, // Program header count
            0x00, 0x00, // Section header size
            0x00, 0x00, // Section header count
            0x00, 0x00, // Section header string index
        ];
        self.create_binary_file(name, &elf_header)
    }

    /// Create a minimal PE file for testing
    pub fn create_minimal_pe(&mut self, name: &str) -> anyhow::Result<PathBuf> {
        // DOS header
        let mut pe_data = vec![
            0x4d, 0x5a, // MZ signature
        ];
        pe_data.extend_from_slice(&[0x90; 58]); // Padding
        pe_data.extend_from_slice(&[0x3c, 0x00, 0x00, 0x00]); // PE header offset at 0x3c

        // Pad to PE header (should be at 0x3c = 60 bytes total)
        let current_len = pe_data.len();
        if current_len < 0x3c {
            let padding_size = 0x3c - current_len;
            pe_data.extend_from_slice(&vec![0x00; padding_size]);
        }

        // PE header
        pe_data.extend_from_slice(b"PE\x00\x00"); // PE signature
        pe_data.extend_from_slice(&[
            0x64, 0x86, // Machine (x64)
            0x01, 0x00, // Number of sections
        ]);

        self.create_binary_file(name, &pe_data)
    }

    /// Create a file with high entropy (compressed/encrypted appearance)
    pub fn create_high_entropy_file(&mut self, name: &str, size: usize) -> anyhow::Result<PathBuf> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let content: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        self.create_binary_file(name, &content)
    }

    /// Create a file with specific strings embedded
    pub fn create_file_with_strings(
        &mut self,
        name: &str,
        strings: &[&str],
    ) -> anyhow::Result<PathBuf> {
        let mut content = Vec::new();
        for s in strings {
            content.extend_from_slice(s.as_bytes());
            content.push(0); // Null terminator
                             // Add some random bytes between strings
            content.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        }
        self.create_binary_file(name, &content)
    }

    /// Get path to a test file
    pub fn path(&self, name: &str) -> PathBuf {
        self.temp_dir.path().join(name)
    }
}

/// Common test binary patterns
pub mod patterns {
    pub const ELF_MAGIC: &[u8] = &[0x7f, 0x45, 0x4c, 0x46];
    pub const PE_MAGIC: &[u8] = &[0x4d, 0x5a];
    pub const MACHO_MAGIC_64: &[u8] = &[0xcf, 0xfa, 0xed, 0xfe];
    pub const ZIP_MAGIC: &[u8] = &[0x50, 0x4b, 0x03, 0x04];
}

/// Helper to create test files quickly
pub fn create_test_file(content: &[u8]) -> anyhow::Result<PathBuf> {
    let mut fixture = TestFixture::new()?;
    fixture.create_binary_file("test_file", content)
}

/// Helper to create test text file
pub fn create_test_text_file(content: &str) -> anyhow::Result<PathBuf> {
    let mut fixture = TestFixture::new()?;
    fixture.create_text_file("test.txt", content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_creation() {
        let mut fixture = TestFixture::new().unwrap();
        let path = fixture
            .create_text_file("test.txt", "Hello, World!")
            .unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_binary_file_creation() {
        let mut fixture = TestFixture::new().unwrap();
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let path = fixture.create_binary_file("test.bin", &data).unwrap();

        let read_data = std::fs::read(&path).unwrap();
        assert_eq!(read_data, data);
    }
}
