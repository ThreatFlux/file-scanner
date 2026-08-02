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
use file_scanner::signature::{verify_signature, SignatureInfo};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Helper function to create a minimal ELF binary
fn create_minimal_elf(path: &Path) -> Result<()> {
    let elf_header = vec![
        0x7f, 0x45, 0x4c, 0x46, // ELF magic number
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Executable file
        0x3e, 0x00, // x86-64
        0x01, 0x00, 0x00, 0x00, // Version 1
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
        0x00, 0x00, 0x00, 0x00, // Flags
        0x40, 0x00, // ELF header size
        0x38, 0x00, // Program header size
        0x01, 0x00, // Program header count
        0x40, 0x00, // Section header size
        0x00, 0x00, // Section header count
        0x00, 0x00, // Section name string table index
    ];
    fs::write(path, elf_header)?;
    Ok(())
}

/// Helper function to create a minimal PE binary
fn create_minimal_pe(path: &Path) -> Result<()> {
    let mut pe_data = Vec::new();

    // DOS header
    pe_data.extend_from_slice(b"MZ"); // DOS signature
    pe_data.extend_from_slice(&[0x90; 58]); // Padding
    pe_data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // PE header offset at 0x80

    // DOS stub
    pe_data.extend_from_slice(&[0x00; 64]); // Minimal DOS stub

    // PE signature
    pe_data.extend_from_slice(b"PE\x00\x00"); // PE signature

    // COFF header
    pe_data.extend_from_slice(&[
        0x4c, 0x01, // Machine (i386)
        0x01, 0x00, // Number of sections
        0x00, 0x00, 0x00, 0x00, // Time stamp
        0x00, 0x00, 0x00, 0x00, // Symbol table pointer
        0x00, 0x00, 0x00, 0x00, // Number of symbols
        0xe0, 0x00, // Size of optional header
        0x02, 0x01, // Characteristics
    ]);

    // Optional header (minimal)
    pe_data.extend_from_slice(&[0x00; 224]); // Simplified optional header

    fs::write(path, pe_data)?;
    Ok(())
}

/// Helper function to create a minimal Mach-O binary (macOS)
fn create_minimal_macho(path: &Path) -> Result<()> {
    let macho_data = vec![
        0xcf, 0xfa, 0xed, 0xfe, // Mach-O 64-bit magic
        0x07, 0x00, 0x00, 0x01, // CPU type (x86_64)
        0x03, 0x00, 0x00, 0x00, // CPU subtype
        0x02, 0x00, 0x00, 0x00, // File type (executable)
        0x00, 0x00, 0x00, 0x00, // Number of load commands
        0x00, 0x00, 0x00, 0x00, // Size of load commands
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Reserved
    ];
    fs::write(path, macho_data)?;
    Ok(())
}

#[test]
fn test_verify_signature_unsigned_elf() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("test.elf");
    create_minimal_elf(&elf_path)?;

    let sig_info = verify_signature(&elf_path)?;

    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.signature_type, None);
    assert_eq!(sig_info.signer, None);
    assert_eq!(sig_info.timestamp, None);
    assert!(sig_info.certificate_chain.is_empty());
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

#[test]
fn test_verify_signature_unsigned_pe() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let pe_path = temp_dir.path().join("test.exe");
    create_minimal_pe(&pe_path)?;

    let sig_info = verify_signature(&pe_path)?;

    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.signature_type, None);
    assert_eq!(sig_info.signer, None);
    assert_eq!(sig_info.timestamp, None);
    assert!(sig_info.certificate_chain.is_empty());
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

#[test]
fn test_verify_signature_text_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let text_path = temp_dir.path().join("test.txt");
    fs::write(&text_path, "Hello, World!")?;

    let sig_info = verify_signature(&text_path)?;

    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

#[test]
fn test_verify_signature_empty_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let empty_path = temp_dir.path().join("empty.bin");
    fs::write(&empty_path, b"")?;

    let sig_info = verify_signature(&empty_path)?;

    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

#[test]
fn test_verify_signature_non_existent_file() {
    let result = verify_signature(Path::new("/non/existent/file.exe"));
    // The function returns Ok with unsigned status for non-existent files
    // because fs::read errors are caught internally
    assert!(result.is_ok());
    let sig_info = result.unwrap();
    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.verification_status, "No signature found");
}

#[test]
fn test_verify_signature_macho_on_non_macos() -> Result<()> {
    if cfg!(not(target_os = "macos")) {
        let temp_dir = TempDir::new()?;
        let macho_path = temp_dir.path().join("test.macho");
        create_minimal_macho(&macho_path)?;

        let sig_info = verify_signature(&macho_path)?;

        // On non-macOS systems, Mach-O files should just be treated as unsigned
        assert!(!sig_info.is_signed);
        assert_eq!(sig_info.verification_status, "No signature found");
    }

    Ok(())
}

#[test]
fn test_verify_signature_with_various_extensions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let extensions = vec!["exe", "dll", "so", "dylib", "bin", "elf"];

    for ext in extensions {
        let file_path = temp_dir.path().join(format!("test.{ext}"));
        fs::write(&file_path, b"fake binary content")?;

        let sig_info = verify_signature(&file_path)?;

        assert!(!sig_info.is_signed);
        assert_eq!(sig_info.verification_status, "No signature found");
    }

    Ok(())
}

#[test]
fn test_signature_info_serialization() -> Result<()> {
    let sig_info = SignatureInfo {
        is_signed: true,
        signature_type: Some("Authenticode".to_string()),
        signer: Some("Test Publisher".to_string()),
        timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        certificate_chain: vec![],
        verification_status: "Valid".to_string(),
    };

    // Test JSON serialization
    let json = serde_json::to_string(&sig_info)?;
    assert!(json.contains("\"is_signed\":true"));
    assert!(json.contains("\"signature_type\":\"Authenticode\""));
    assert!(json.contains("\"signer\":\"Test Publisher\""));

    // Test deserialization
    let deserialized: SignatureInfo = serde_json::from_str(&json)?;
    assert_eq!(deserialized.is_signed, sig_info.is_signed);
    assert_eq!(deserialized.signature_type, sig_info.signature_type);
    assert_eq!(deserialized.signer, sig_info.signer);

    Ok(())
}

#[test]
fn test_signature_verification_with_mock_gpg_signature() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("signed_file.tar");
    let sig_path = temp_dir.path().join("signed_file.tar.sig");

    // Create a file and a fake signature file
    fs::write(&file_path, b"file content")?;
    fs::write(&sig_path, b"fake gpg signature")?;

    // The actual GPG verification will fail unless gpg is installed and configured
    // But the function should still handle it gracefully
    let sig_info = verify_signature(&file_path)?;

    // Without a valid GPG setup, it should return unsigned
    assert!(!sig_info.is_signed);

    Ok(())
}

#[test]
fn test_large_binary_signature_verification() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let large_path = temp_dir.path().join("large.bin");

    // Create a 1MB file with PE header
    let mut large_data = Vec::new();
    large_data.extend_from_slice(b"MZ");
    large_data.extend_from_slice(&[0x00; 1024 * 1024 - 2]);
    fs::write(&large_path, large_data)?;

    let sig_info = verify_signature(&large_path)?;

    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

#[test]
fn test_signature_verification_corrupted_pe() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let corrupted_path = temp_dir.path().join("corrupted.exe");

    // Create a file that starts with MZ but is otherwise corrupted
    fs::write(&corrupted_path, b"MZ\x00\x01\x02\x03\x04\x05")?;

    let sig_info = verify_signature(&corrupted_path)?;

    // Should handle corrupted files gracefully
    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

#[test]
fn test_signature_verification_with_unicode_path() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let unicode_path = temp_dir.path().join("测试文件.exe");
    create_minimal_pe(&unicode_path)?;

    let sig_info = verify_signature(&unicode_path)?;

    assert!(!sig_info.is_signed);
    assert_eq!(sig_info.verification_status, "No signature found");

    Ok(())
}

// Platform-specific test
#[test]
#[cfg(target_os = "macos")]
fn test_verify_signature_macho_on_macos() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let macho_path = temp_dir.path().join("test.macho");
    create_minimal_macho(&macho_path)?;

    let sig_info = verify_signature(&macho_path)?;

    // On macOS, it might try to use codesign but our minimal Mach-O won't be signed
    assert!(!sig_info.is_signed);

    Ok(())
}

// Integration test simulating real-world usage
#[test]
fn test_verify_multiple_file_signatures() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create various file types
    let files = vec![
        ("binary.exe", create_minimal_pe as fn(&Path) -> Result<()>),
        ("library.so", create_minimal_elf),
        ("script.py", |p: &Path| {
            fs::write(p, "#!/usr/bin/env python3\nprint('hello')").map_err(Into::into)
        }),
        ("data.json", |p: &Path| {
            fs::write(p, "{}").map_err(Into::into)
        }),
    ];

    for (filename, create_fn) in files {
        let file_path = temp_dir.path().join(filename);
        create_fn(&file_path)?;

        let sig_info = verify_signature(&file_path)?;

        assert!(!sig_info.is_signed, "File {filename} should not be signed");
        assert_eq!(sig_info.verification_status, "No signature found");
    }

    Ok(())
}

// Test edge cases
#[test]
fn test_signature_verification_edge_cases() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Test with a file that has PE magic but is too small
    let small_pe = temp_dir.path().join("small.exe");
    fs::write(&small_pe, b"MZ")?;
    let sig_info = verify_signature(&small_pe)?;
    assert!(!sig_info.is_signed);

    // Test with a file containing only null bytes
    let null_file = temp_dir.path().join("null.bin");
    fs::write(&null_file, [0x00; 100])?;
    let sig_info = verify_signature(&null_file)?;
    assert!(!sig_info.is_signed);

    // Test with a symlink (if supported)
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = temp_dir.path().join("target.txt");
        let link = temp_dir.path().join("link.txt");
        fs::write(&target, "content")?;
        symlink(&target, &link)?;

        let sig_info = verify_signature(&link)?;
        assert!(!sig_info.is_signed);
    }

    Ok(())
}
