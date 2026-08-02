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

use file_scanner::strings::*;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn create_test_file(content: &[u8]) -> anyhow::Result<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("test_file");
    let mut file = fs::File::create(&file_path)?;
    file.write_all(content)?;
    Ok((temp_dir, file_path))
}

#[test]
fn test_extract_ascii_strings_basic() {
    let content = b"Hello, World!\x00This is a test\x00\x01\x02Binary data\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(!result.ascii_strings.is_empty());
    assert!(result.ascii_strings.contains(&"Hello, World!".to_string()));
    assert!(result.ascii_strings.contains(&"This is a test".to_string()));
    assert!(result.ascii_strings.contains(&"Binary data".to_string()));
}

#[test]
fn test_extract_strings_min_length_filter() {
    let content = b"Hi\x00Hello\x00This is a longer string\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 10).unwrap();

    // "Hi" and "Hello" should be filtered out (too short)
    assert!(!result.ascii_strings.contains(&"Hi".to_string()));
    assert!(!result.ascii_strings.contains(&"Hello".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"This is a longer string".to_string()));
}

#[test]
fn test_extract_unicode_strings() {
    // UTF-16 little endian string "Hello" - need proper null termination
    let utf16_hello = b"H\x00e\x00l\x00l\x00o\x00";
    let (_temp_dir, file_path) = create_test_file(utf16_hello).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(!result.unicode_strings.is_empty());
    assert!(result.unicode_strings.contains(&"Hello".to_string()));
}

#[test]
fn test_extract_strings_mixed_content() {
    let mut content = Vec::new();
    content.extend_from_slice(b"ASCII String\x00");
    // UTF-16 LE "Test"
    content.extend_from_slice(b"T\x00e\x00s\x00t\x00");
    content.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x00]); // Binary data
    content.extend_from_slice(b"Another ASCII\x00");

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"ASCII String".to_string()));
    assert!(result.ascii_strings.contains(&"Another ASCII".to_string()));
    assert!(result.unicode_strings.contains(&"Test".to_string()));
}

#[test]
fn test_extract_strings_special_characters() {
    let content = b"Normal string\x00String with @#$%^&*() symbols\x00URL: https://example.com\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"Normal string".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"String with @#$%^&*() symbols".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"URL: https://example.com".to_string()));
}

#[test]
fn test_extract_strings_empty_file() {
    let (_temp_dir, file_path) = create_test_file(b"").unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.is_empty());
    assert!(result.unicode_strings.is_empty());
    assert_eq!(result.total_count, 0);
}

#[test]
fn test_extract_strings_no_strings() {
    let content = vec![0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD]; // Only binary data
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.is_empty());
    assert!(result.unicode_strings.is_empty());
    assert_eq!(result.total_count, 0);
}

#[test]
fn test_extract_strings_boundary_conditions() {
    // Test exact minimum length
    let content = b"ABCD\x00ABCDE\x00ABC\x00"; // 4, 5, and 3 chars respectively
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"ABCD".to_string()));
    assert!(result.ascii_strings.contains(&"ABCDE".to_string()));
    assert!(!result.ascii_strings.contains(&"ABC".to_string()));
}

#[test]
fn test_extract_strings_newlines_and_tabs() {
    let content = b"String with\nnewlines\x00String with\ttabs\x00Multiple\n\nlines\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    // These strings will be split at newlines/tabs since they're not in ASCII printable range
    assert!(result.ascii_strings.contains(&"String with".to_string()));
    assert!(result.ascii_strings.contains(&"newlines".to_string()));
    assert!(result.ascii_strings.contains(&"tabs".to_string()));
    assert!(result.ascii_strings.contains(&"Multiple".to_string()));
    assert!(result.ascii_strings.contains(&"lines".to_string()));
}

#[test]
fn test_extract_strings_path_like_strings() {
    let content = b"/usr/bin/bash\x00C:\\Windows\\System32\\cmd.exe\x00./relative/path\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"/usr/bin/bash".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"C:\\Windows\\System32\\cmd.exe".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"./relative/path".to_string()));
}

#[test]
fn test_extract_strings_url_like_strings() {
    let content = b"https://malicious-site.com\x00http://example.org\x00ftp://files.server.net\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result
        .ascii_strings
        .contains(&"https://malicious-site.com".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"http://example.org".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"ftp://files.server.net".to_string()));
}

#[test]
fn test_extract_strings_version_strings() {
    let content = b"Version 1.2.3\x00v2.0.1-beta\x00FileVersion: 3.14.159\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"Version 1.2.3".to_string()));
    assert!(result.ascii_strings.contains(&"v2.0.1-beta".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"FileVersion: 3.14.159".to_string()));
}

#[test]
fn test_extract_strings_api_names() {
    let content = b"CreateProcessA\x00LoadLibraryA\x00GetProcAddress\x00VirtualAlloc\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"CreateProcessA".to_string()));
    assert!(result.ascii_strings.contains(&"LoadLibraryA".to_string()));
    assert!(result.ascii_strings.contains(&"GetProcAddress".to_string()));
    assert!(result.ascii_strings.contains(&"VirtualAlloc".to_string()));
}

#[test]
fn test_extract_strings_registry_keys() {
    let content = b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\x00HKCU\\Run\x00CurrentVersion\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result
        .ascii_strings
        .contains(&"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft".to_string()));
    assert!(result.ascii_strings.contains(&"HKCU\\Run".to_string()));
    assert!(result.ascii_strings.contains(&"CurrentVersion".to_string()));
}

#[test]
fn test_extract_strings_ip_addresses() {
    let content = b"192.168.1.1\x00127.0.0.1\x00255.255.255.0\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"192.168.1.1".to_string()));
    assert!(result.ascii_strings.contains(&"127.0.0.1".to_string()));
    assert!(result.ascii_strings.contains(&"255.255.255.0".to_string()));
}

#[test]
fn test_extract_strings_debug_info() {
    let content = b"DEBUG: Starting process\x00ERROR: Failed to allocate memory\x00WARNING: Deprecated function\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result
        .ascii_strings
        .contains(&"DEBUG: Starting process".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"ERROR: Failed to allocate memory".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"WARNING: Deprecated function".to_string()));
}

#[test]
fn test_extract_strings_file_extensions() {
    let content = b"document.pdf\x00image.jpg\x00script.bat\x00config.ini\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"document.pdf".to_string()));
    assert!(result.ascii_strings.contains(&"image.jpg".to_string()));
    assert!(result.ascii_strings.contains(&"script.bat".to_string()));
    assert!(result.ascii_strings.contains(&"config.ini".to_string()));
}

#[test]
fn test_extract_strings_utf16_big_endian() {
    // UTF-16 big endian string "Test"
    let utf16_be = b"\x00T\x00e\x00s\x00t\x00\x00";
    let (_temp_dir, file_path) = create_test_file(utf16_be).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    // Should detect UTF-16 BE strings
    assert!(!result.unicode_strings.is_empty());
}

#[test]
fn test_extract_strings_large_file_handling() {
    // Create a large file with strings scattered throughout
    let mut content = Vec::new();
    for i in 0..1000 {
        content.extend_from_slice(format!("String number {i}\x00").as_bytes());
        content.extend_from_slice(&[0xFF; 100]); // Add binary data between strings
    }

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    // Should find many strings
    assert!(result.total_count >= 900); // Allow for some filtering
    assert!(result
        .ascii_strings
        .contains(&"String number 0".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"String number 999".to_string()));
}

#[test]
fn test_extract_strings_serialization() {
    let content = b"Test string for serialization\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    // Test JSON serialization
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: ExtractedStrings = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.ascii_strings, result.ascii_strings);
    assert_eq!(deserialized.unicode_strings, result.unicode_strings);
    assert_eq!(deserialized.total_count, result.total_count);
}

#[test]
fn test_extract_strings_malicious_patterns() {
    let content = b"cmd.exe /c\x00powershell.exe\x00CreateRemoteThread\x00WriteProcessMemory\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    assert!(result.ascii_strings.contains(&"cmd.exe /c".to_string()));
    assert!(result.ascii_strings.contains(&"powershell.exe".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"CreateRemoteThread".to_string()));
    assert!(result
        .ascii_strings
        .contains(&"WriteProcessMemory".to_string()));
}

#[test]
fn test_extract_strings_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/file");
    let result = extract_strings(path, 4);
    assert!(result.is_err());
}

#[test]
fn test_extract_strings_min_length_zero() {
    let content = b"A\x00BB\x00CCC\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 0).unwrap();

    // Should include all strings when min_length is 0
    assert!(result.ascii_strings.contains(&"A".to_string()));
    assert!(result.ascii_strings.contains(&"BB".to_string()));
    assert!(result.ascii_strings.contains(&"CCC".to_string()));
}

#[test]
fn test_extract_strings_high_ascii_chars() {
    // Test with extended ASCII characters (128-255)
    let mut content = Vec::new();
    content.extend_from_slice(b"Normal");
    content.push(0xE9); // é
    content.push(0xF1); // ñ
    content.extend_from_slice(b"text\x00");

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    // Should handle extended ASCII characters
    assert!(!result.ascii_strings.is_empty());
}

#[test]
fn test_unique_string_counting() {
    let content = b"duplicate\x00duplicate\x00unique\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = extract_strings(&file_path, 4).unwrap();

    // ASCII strings may contain duplicates, but unique_count should be correct
    assert_eq!(result.unique_count, 2);
    assert!(result.ascii_strings.contains(&"duplicate".to_string()));
    assert!(result.ascii_strings.contains(&"unique".to_string()));
}
