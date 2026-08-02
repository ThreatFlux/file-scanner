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

use file_scanner::hexdump::{
    extract_footer_hex, extract_header_hex, format_hex_dump_text, generate_hex_dump, HexDump,
    HexDumpOptions, HexLine,
};
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
fn test_hex_dump_options_default() {
    let options = HexDumpOptions::default();
    assert_eq!(options.offset, 0);
    assert_eq!(options.length, None);
    assert_eq!(options.bytes_per_line, 16);
    assert_eq!(options.max_lines, Some(32));
}

#[test]
fn test_hex_dump_simple_content() {
    let content = b"Hello, World!";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 0,
        length: None,
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.offset, 0);
    assert_eq!(hex_dump.length, 13);
    assert_eq!(hex_dump.bytes_per_line, 16);
    assert_eq!(hex_dump.total_bytes, 13);
    assert_eq!(hex_dump.lines.len(), 1);

    let line = &hex_dump.lines[0];
    assert_eq!(line.offset, 0);
    assert_eq!(line.raw_bytes, content.to_vec());
    assert_eq!(line.ascii_repr, "Hello, World!");
    assert!(line.hex_bytes.contains("48 65 6c 6c 6f"));
}

#[test]
fn test_hex_dump_with_custom_offset() {
    let content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 10,
        length: Some(5),
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.offset, 10);
    assert_eq!(hex_dump.length, 5);
    assert_eq!(hex_dump.lines.len(), 1);
    assert_eq!(hex_dump.lines[0].ascii_repr, "KLMNO");
    assert_eq!(hex_dump.lines[0].offset, 10);
}

#[test]
fn test_hex_dump_custom_bytes_per_line() {
    let content = b"0123456789ABCDEF";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 0,
        length: None,
        bytes_per_line: 4,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.bytes_per_line, 4);
    assert_eq!(hex_dump.lines.len(), 4); // 16 bytes / 4 per line

    // Check each line has 4 bytes
    for line in &hex_dump.lines {
        assert_eq!(line.raw_bytes.len(), 4);
    }

    assert_eq!(hex_dump.lines[0].ascii_repr, "0123");
    assert_eq!(hex_dump.lines[1].ascii_repr, "4567");
    assert_eq!(hex_dump.lines[2].ascii_repr, "89AB");
    assert_eq!(hex_dump.lines[3].ascii_repr, "CDEF");
}

#[test]
fn test_hex_dump_max_lines_limit() {
    let content = vec![0x41; 256]; // 256 'A' bytes
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let options = HexDumpOptions {
        offset: 0,
        length: None,
        bytes_per_line: 16,
        max_lines: Some(3),
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.lines.len(), 3);
    assert_eq!(hex_dump.length, 48); // 3 lines * 16 bytes

    // Each line should contain 'A' characters
    for line in &hex_dump.lines {
        assert_eq!(line.ascii_repr, "AAAAAAAAAAAAAAAA");
        assert_eq!(line.raw_bytes, vec![0x41; 16]);
    }
}

#[test]
fn test_hex_dump_beyond_file_size() {
    let content = b"Short";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 0,
        length: Some(100), // Request more than file size
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.length, 5); // Only actual file content
    assert_eq!(hex_dump.lines[0].ascii_repr, "Short");
}

#[test]
fn test_hex_dump_offset_beyond_file() {
    let content = b"Test";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 100, // Beyond file size
        length: Some(10),
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.length, 0);
    assert_eq!(hex_dump.lines.len(), 0);
}

#[test]
fn test_hex_dump_ascii_representation() {
    // Test all printable ASCII and some non-printable
    let mut content = Vec::new();
    for i in 0..=255u8 {
        content.push(i);
    }

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let options = HexDumpOptions {
        offset: 30, // Start just before space (32)
        length: Some(100),
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    // Check ASCII representation
    let line = &hex_dump.lines[0];
    assert_eq!(&line.ascii_repr[0..2], ".."); // 30, 31 are non-printable
    assert_eq!(&line.ascii_repr[2..3], " "); // 32 is space
    assert_eq!(&line.ascii_repr[3..4], "!"); // 33 is !
}

#[test]
fn test_hex_dump_binary_data() {
    let content = vec![0x00, 0x01, 0xFF, 0xFE, 0x7F, 0x80];
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

    assert_eq!(hex_dump.lines[0].raw_bytes, content);
    assert!(hex_dump.lines[0].hex_bytes.contains("00 01 ff fe 7f 80"));

    // Check non-printable chars are replaced with dots
    assert_eq!(hex_dump.lines[0].ascii_repr, "......");
}

#[test]
fn test_hex_dump_partial_last_line() {
    let content = b"123456789ABCDEF012"; // 18 bytes (one full line + 2 bytes)
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

    assert_eq!(hex_dump.lines.len(), 2);
    assert_eq!(hex_dump.lines[0].raw_bytes.len(), 16);
    assert_eq!(hex_dump.lines[1].raw_bytes.len(), 2);

    // Check that the second line is properly padded in hex representation
    assert!(hex_dump.lines[1].hex_bytes.len() > 5); // Should have padding
    assert_eq!(hex_dump.lines[1].ascii_repr, "12");
}

#[test]
fn test_format_hex_dump_text() {
    let content = b"Test formatting output";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();
    let formatted = format_hex_dump_text(&hex_dump);

    assert!(formatted.contains("Hex dump"));
    assert!(formatted.contains("offset: 0x00000000"));
    assert!(formatted.contains("length: 22 bytes"));
    assert!(formatted.contains("total file size: 22 bytes"));
    assert!(formatted.contains("00000000"));
    assert!(formatted.contains("|Test formatting "));
    assert!(formatted.contains("---"));
}

#[test]
fn test_format_hex_dump_truncated() {
    let content = vec![0x41; 1000]; // Large file
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let options = HexDumpOptions {
        offset: 0,
        length: Some(32),
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();
    let formatted = format_hex_dump_text(&hex_dump);

    assert!(formatted.contains("... (truncated)"));
}

#[test]
fn test_extract_header_hex() {
    let content = b"HEADER_DATArest of file content that is longer";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = extract_header_hex(&file_path, 11).unwrap();

    assert_eq!(hex_dump.offset, 0);
    assert_eq!(hex_dump.length, 11);
    assert_eq!(hex_dump.lines[0].ascii_repr, "HEADER_DATA");
    assert_eq!(hex_dump.bytes_per_line, 16);
}

#[test]
fn test_extract_footer_hex() {
    let content = b"Beginning of file contentFOOTER_DATA";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = extract_footer_hex(&file_path, 11).unwrap();

    assert_eq!(hex_dump.offset, 25); // File is 36 bytes, footer is 11
    assert_eq!(hex_dump.length, 11);
    assert_eq!(hex_dump.lines[0].ascii_repr, "FOOTER_DATA");
}

#[test]
fn test_extract_footer_hex_larger_than_file() {
    let content = b"Small";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = extract_footer_hex(&file_path, 100).unwrap();

    assert_eq!(hex_dump.offset, 0); // saturating_sub returns 0
    assert_eq!(hex_dump.length, 5); // Entire file
    assert_eq!(hex_dump.lines[0].ascii_repr, "Small");
}

#[test]
fn test_extract_header_hex_larger_than_file() {
    let content = b"Tiny";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = extract_header_hex(&file_path, 100).unwrap();

    assert_eq!(hex_dump.offset, 0);
    assert_eq!(hex_dump.length, 4); // Entire file
    assert_eq!(hex_dump.lines[0].ascii_repr, "Tiny");
}

#[test]
fn test_hex_dump_empty_file() {
    let (_temp_dir, file_path) = create_test_file(b"").unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

    assert_eq!(hex_dump.length, 0);
    assert_eq!(hex_dump.lines.len(), 0);
    assert_eq!(hex_dump.total_bytes, 0);
    assert_eq!(hex_dump.offset, 0);
    assert_eq!(hex_dump.bytes_per_line, 16);
}

#[test]
fn test_hex_dump_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/file");
    let result = generate_hex_dump(path, HexDumpOptions::default());
    assert!(result.is_err());
}

#[test]
fn test_hex_dump_data_structures() {
    let hex_line = HexLine {
        offset: 0x100,
        hex_bytes: "41 42 43".to_string(),
        ascii_repr: "ABC".to_string(),
        raw_bytes: vec![0x41, 0x42, 0x43],
    };

    let hex_dump = HexDump {
        offset: 0,
        length: 3,
        bytes_per_line: 16,
        total_bytes: 100,
        lines: vec![hex_line],
    };

    assert_eq!(hex_dump.offset, 0);
    assert_eq!(hex_dump.length, 3);
    assert_eq!(hex_dump.bytes_per_line, 16);
    assert_eq!(hex_dump.total_bytes, 100);
    assert_eq!(hex_dump.lines.len(), 1);
    assert_eq!(hex_dump.lines[0].offset, 0x100);
    assert_eq!(hex_dump.lines[0].hex_bytes, "41 42 43");
    assert_eq!(hex_dump.lines[0].ascii_repr, "ABC");
    assert_eq!(hex_dump.lines[0].raw_bytes, vec![0x41, 0x42, 0x43]);
}

#[test]
fn test_hex_dump_serialization() {
    let hex_line = HexLine {
        offset: 0x200,
        hex_bytes: "44 45 46".to_string(),
        ascii_repr: "DEF".to_string(),
        raw_bytes: vec![0x44, 0x45, 0x46],
    };

    let hex_dump = HexDump {
        offset: 10,
        length: 3,
        bytes_per_line: 8,
        total_bytes: 50,
        lines: vec![hex_line],
    };

    // Test JSON serialization
    let json = serde_json::to_string(&hex_dump).unwrap();
    let deserialized: HexDump = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.offset, hex_dump.offset);
    assert_eq!(deserialized.length, hex_dump.length);
    assert_eq!(deserialized.bytes_per_line, hex_dump.bytes_per_line);
    assert_eq!(deserialized.total_bytes, hex_dump.total_bytes);
    assert_eq!(deserialized.lines.len(), 1);
    assert_eq!(deserialized.lines[0].offset, 0x200);
}

#[test]
fn test_hex_dump_large_offset_calculation() {
    let content = vec![0x42; 10000]; // Large file with 'B' bytes
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let options = HexDumpOptions {
        offset: 9990,
        length: Some(20),
        bytes_per_line: 5,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.offset, 9990);
    assert_eq!(hex_dump.length, 10); // Only 10 bytes left in file
    assert_eq!(hex_dump.lines.len(), 2); // 10 bytes / 5 per line

    // Each line should contain 'B' characters
    assert_eq!(hex_dump.lines[0].ascii_repr, "BBBBB");
    assert_eq!(hex_dump.lines[1].ascii_repr, "BBBBB");
}

#[test]
fn test_hex_dump_mixed_printable_non_printable() {
    let content = vec![
        0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        0x00, 0x01, 0x02, // Non-printable
        0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, // " World"
        0xFF, 0xFE, // Non-printable
    ];
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

    assert_eq!(hex_dump.lines[0].ascii_repr, "Hello... World..");
    assert_eq!(hex_dump.lines[0].raw_bytes, content);
}

#[test]
fn test_hex_dump_exact_boundary_conditions() {
    // Test file that's exactly multiple of bytes_per_line
    let content = vec![0x30; 32]; // Exactly 2 lines with 16 bytes each
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

    assert_eq!(hex_dump.lines.len(), 2);
    assert_eq!(hex_dump.lines[0].raw_bytes.len(), 16);
    assert_eq!(hex_dump.lines[1].raw_bytes.len(), 16);
    assert_eq!(hex_dump.lines[0].ascii_repr, "0000000000000000");
    assert_eq!(hex_dump.lines[1].ascii_repr, "0000000000000000");
}

#[test]
fn test_hex_dump_zero_length_request() {
    let content = b"Some content";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 5,
        length: Some(0),
        bytes_per_line: 16,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.length, 0);
    assert_eq!(hex_dump.lines.len(), 0);
}

#[test]
fn test_hex_dump_single_byte_per_line() {
    let content = b"ABCD";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let options = HexDumpOptions {
        offset: 0,
        length: None,
        bytes_per_line: 1,
        max_lines: None,
    };

    let hex_dump = generate_hex_dump(&file_path, options).unwrap();

    assert_eq!(hex_dump.lines.len(), 4);
    assert_eq!(hex_dump.lines[0].ascii_repr, "A");
    assert_eq!(hex_dump.lines[1].ascii_repr, "B");
    assert_eq!(hex_dump.lines[2].ascii_repr, "C");
    assert_eq!(hex_dump.lines[3].ascii_repr, "D");

    // Check offsets increment correctly
    assert_eq!(hex_dump.lines[0].offset, 0);
    assert_eq!(hex_dump.lines[1].offset, 1);
    assert_eq!(hex_dump.lines[2].offset, 2);
    assert_eq!(hex_dump.lines[3].offset, 3);
}

#[test]
fn test_hex_dump_control_characters() {
    let content = vec![
        0x09, // Tab
        0x0A, // Line feed
        0x0D, // Carriage return
        0x1B, // Escape
        0x7F, // DEL
    ];
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

    // All control characters should be replaced with dots
    assert_eq!(hex_dump.lines[0].ascii_repr, ".....");
    assert_eq!(hex_dump.lines[0].raw_bytes, content);
}

#[test]
fn test_format_hex_dump_text_no_truncation() {
    let content = b"Short content";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();
    let formatted = format_hex_dump_text(&hex_dump);

    // Should not contain truncation message for small files
    assert!(!formatted.contains("... (truncated)"));
    assert!(formatted.contains("Short content"));
}

#[test]
fn test_hex_dump_debug_format() {
    let hex_line = HexLine {
        offset: 0,
        hex_bytes: "41".to_string(),
        ascii_repr: "A".to_string(),
        raw_bytes: vec![0x41],
    };

    let debug_string = format!("{hex_line:?}");
    assert!(debug_string.contains("HexLine"));
    assert!(debug_string.contains("offset: 0"));
    assert!(debug_string.contains("41"));
    assert!(debug_string.contains('A'));
}
