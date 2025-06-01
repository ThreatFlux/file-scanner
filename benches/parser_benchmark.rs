use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use file_scanner::binary_parser::parse_binary;
use file_scanner::strings::extract_strings;
use std::fs;
use std::path::Path;
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

    // DOS header
    let mut pe_data = vec![0x4d, 0x5a]; // MZ signature
    pe_data.extend_from_slice(&[0x90; 58]); // Padding
    pe_data.extend_from_slice(&[0x3c, 0x00, 0x00, 0x00]); // PE header offset

    // Pad to PE header (should be at 0x3c = 60 bytes total)
    let current_len = pe_data.len();
    if current_len < 0x3c {
        let padding_size = 0x3c - current_len;
        pe_data.extend_from_slice(&vec![0x00; padding_size]);
    }

    // PE header
    pe_data.extend_from_slice(b"PE\x00\x00");
    pe_data.extend_from_slice(&[0x64, 0x86]); // Machine (x64)
    pe_data.extend_from_slice(&[0x01, 0x00]); // Number of sections

    // Add more data
    pe_data.extend_from_slice(&[0x00; 1000]);

    fs::write(&file_path, pe_data).unwrap();
    (temp_dir, file_path)
}

fn create_string_file(string_count: usize) -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("strings.bin");

    let mut content = Vec::new();

    // Add various types of strings
    for i in 0..string_count {
        content.extend_from_slice(format!("String number {}\x00", i).as_bytes());
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
        let mut data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
        data.extend_from_slice(&[0x00; 1024 * 1024]); // 1MB
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
            BenchmarkId::new("extract_strings", format!("{}_strings", string_count)),
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
                    format!("{}_strings_min_{}", string_count, min_len),
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
