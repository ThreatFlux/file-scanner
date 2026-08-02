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

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use file_scanner::binary_parser::parse_binary;
use file_scanner::strings::extract_strings;
use std::fs;
use std::hint::black_box;
use tempfile::TempDir;

fn create_elf_file() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.elf");

    // Minimal ELF header
    let mut elf_data = vec![
        0x7f, 0x45, 0x4c, 0x46, // Magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
    ];
    elf_data.extend_from_slice(&[0x00; 8]); // Padding
    elf_data.extend_from_slice(&[0x02, 0x00]); // Executable
    elf_data.extend_from_slice(&[0x3e, 0x00]); // x86-64
    elf_data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Version

    // Add some sections and data
    elf_data.extend_from_slice(&[0x00; 1000]);

    fs::write(&file_path, elf_data).unwrap();
    (temp_dir, file_path)
}

fn create_pe_file() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.exe");

    let mut pe_data = vec![0u8; 2048];

    pe_data[0..2].copy_from_slice(b"MZ");
    pe_data[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew
    pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: x86_64
    pe_data[0x86..0x88].copy_from_slice(&[0x00, 0x00]); // Number of sections
    pe_data[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // Optional header size
    pe_data[0x96..0x98].copy_from_slice(&[0x22, 0x00]); // Characteristics
    pe_data[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // Magic: PE32+
    pe_data[0x9A] = 14; // Major linker version

    fs::write(&file_path, pe_data).unwrap();
    (temp_dir, file_path)
}

fn create_string_file(string_count: usize) -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("strings.bin");

    let mut content = Vec::new();

    // Add various types of strings
    for i in 0..string_count {
        content.extend_from_slice(format!("String number {i}\x00").as_bytes());
        content.extend_from_slice(&[0xFF; 10]); // Binary data between strings

        if i % 10 == 0 {
            content.extend_from_slice(b"https://example.com/test\x00");
            content.extend_from_slice(b"error: something failed\x00");
            content.extend_from_slice(b"api_key: secret123\x00");
        }
    }

    fs::write(&file_path, content).unwrap();
    (temp_dir, file_path)
}

fn bench_binary_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("binary_parsing");

    let (_elf_dir, elf_path) = create_elf_file();
    let (_pe_dir, pe_path) = create_pe_file();

    group.bench_function("parse_elf", |b| {
        b.iter(|| parse_binary(black_box(&elf_path)).unwrap());
    });

    group.bench_function("parse_pe", |b| {
        b.iter(|| parse_binary(black_box(&pe_path)).unwrap());
    });

    // Test with larger binaries
    let (_large_dir, large_path) = {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("large.bin");
        let mut data = fs::read(&elf_path).unwrap();
        data.resize(1024 * 1024, 0);
        fs::write(&file_path, data).unwrap();
        (temp_dir, file_path)
    };

    group.bench_function("parse_large_binary", |b| {
        b.iter(|| parse_binary(black_box(&large_path)).unwrap());
    });

    group.finish();
}

fn bench_string_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_extraction");

    for string_count in &[100, 1000, 10000] {
        let (_temp_dir, file_path) = create_string_file(*string_count);

        group.bench_with_input(
            BenchmarkId::new("extract_strings", format!("{string_count}_strings")),
            string_count,
            |b, _| {
                b.iter(|| extract_strings(black_box(&file_path), 4).unwrap());
            },
        );

        // Test with different minimum string lengths
        for min_len in &[4, 8, 16] {
            group.bench_with_input(
                BenchmarkId::new(
                    "extract_strings_min_len",
                    format!("{string_count}_strings_min_{min_len}"),
                ),
                &(*string_count, *min_len),
                |b, (_, min_len)| {
                    b.iter(|| extract_strings(black_box(&file_path), *min_len).unwrap());
                },
            );
        }
    }

    group.finish();
}

fn bench_string_categorization(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_categorization");

    // Create a file with many categorizable strings
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("categorizable.bin");

    let mut content = Vec::new();

    // Add various categorizable strings
    let test_strings = vec![
        "https://example.com/api/v1/test",
        "user@example.com",
        "password: supersecret123",
        "API_KEY=sk-1234567890abcdef",
        "ERROR: Connection failed",
        "DEBUG: Starting process",
        "/usr/local/bin/application",
        "192.168.1.100",
        "version 2.3.4",
        "Copyright 2024 Example Corp",
    ];

    for _ in 0..100 {
        for s in &test_strings {
            content.extend_from_slice(s.as_bytes());
            content.push(0);
            content.extend_from_slice(&[0xFF; 20]);
        }
    }

    fs::write(&file_path, content).unwrap();

    group.bench_function("extract_with_categorization", |b| {
        b.iter(|| extract_strings(black_box(&file_path), 4).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_binary_parsing,
    bench_string_extraction,
    bench_string_categorization
);
criterion_main!(benches);
