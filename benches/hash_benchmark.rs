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
use file_scanner::hash::{calculate_all_hashes, calculate_md5};
use std::fs;
use std::hint::black_box;
use tempfile::TempDir;
use tokio::runtime::Runtime;

fn create_test_file(size: usize) -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("bench_file");

    // Create file with predictable content
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    fs::write(&file_path, content).unwrap();

    (temp_dir, file_path)
}

fn bench_hash_calculations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hash_calculations");

    // Test different file sizes
    for size in &[1024, 10 * 1024, 100 * 1024, 1024 * 1024] {
        let (_temp_dir, file_path) = create_test_file(*size);

        group.bench_with_input(
            BenchmarkId::new("calculate_all_hashes", format!("{}KB", size / 1024)),
            size,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        calculate_all_hashes(black_box(&file_path)).await.unwrap()
                    })
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("calculate_md5_only", format!("{}KB", size / 1024)),
            size,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async { calculate_md5(black_box(&file_path)).await.unwrap() })
                });
            },
        );
    }

    group.finish();
}

fn bench_concurrent_hashing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_hashing");

    // Create multiple files
    let file_count = 10;
    let file_size = 100 * 1024; // 100KB each

    let mut files = Vec::new();
    for _ in 0..file_count {
        let (_temp_dir, file_path) = create_test_file(file_size);
        files.push((_temp_dir, file_path));
    }

    group.bench_function("sequential_hashing", |b| {
        b.iter(|| {
            rt.block_on(async {
                for (_, file_path) in &files {
                    calculate_all_hashes(black_box(file_path)).await.unwrap();
                }
            });
        });
    });

    group.bench_function("concurrent_hashing", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = vec![];
                for (_, file_path) in &files {
                    let path = file_path.clone();
                    let handle =
                        tokio::spawn(async move { calculate_all_hashes(&path).await.unwrap() });
                    handles.push(handle);
                }

                for handle in handles {
                    handle.await.unwrap();
                }
            });
        });
    });

    group.finish();
}

fn bench_hash_algorithms(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("individual_hash_algorithms");

    let (_temp_dir, file_path) = create_test_file(1024 * 1024); // 1MB file

    // We can't benchmark individual hash functions directly as they're private,
    // but we can measure the overall performance difference
    group.bench_function("all_hashes_1mb", |b| {
        b.iter(|| {
            rt.block_on(async { calculate_all_hashes(black_box(&file_path)).await.unwrap() })
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_calculations,
    bench_concurrent_hashing,
    bench_hash_algorithms
);
criterion_main!(benches);
