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

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn run_json_command(label: &str, args: &[&str]) -> Value {
    let output = Command::cargo_bin("file-scanner")
        .unwrap()
        .args(args)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{label} failed: stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{label} returned invalid JSON ({error}); stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn llm_analyze_with_yara_suggestion_returns_real_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("sample.bin");
    let contents = b"CLI_LLM_ANALYSIS_MARKER\x00\x90\x90\x90\x90\x90";
    fs::write(&test_file, contents).unwrap();

    let analysis = run_json_command(
        "llm-analyze",
        &[
            "llm-analyze",
            test_file.to_str().unwrap(),
            "--suggest-yara-rule",
        ],
    );

    assert_eq!(analysis["file_size"].as_u64(), Some(contents.len() as u64));
    assert!(analysis["md5"].as_str().is_some_and(|md5| md5.len() == 32));
    assert!(analysis["key_strings"].as_array().is_some_and(|strings| {
        strings
            .iter()
            .any(|value| value.as_str() == Some("CLI_LLM_ANALYSIS_MARKER"))
    }));
    assert!(!analysis["hex_patterns"].as_array().unwrap().is_empty());
    assert!(analysis["yara_rule_suggestion"]
        .as_str()
        .is_some_and(|suggestion| !suggestion.is_empty()));
}

#[test]
fn yara_scan_detailed_matches_inline_rule() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("matching.txt");
    fs::write(&test_file, b"CLI_YARA_MATCH_MARKER").unwrap();
    let rule =
        r#"rule cli_match { strings: $marker = "CLI_YARA_MATCH_MARKER" condition: $marker }"#;

    let scan = run_json_command(
        "yara-scan",
        &[
            "yara-scan",
            temp_dir.path().to_str().unwrap(),
            "--rule",
            rule,
            "--detailed",
        ],
    );
    assert!(scan["total_files_scanned"].as_u64().unwrap() >= 1);
    assert!(scan["total_matches"].as_u64().unwrap() >= 1);
}

#[test]
fn yara_scan_accepts_rule_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("matching.txt");
    let rule_file = temp_dir.path().join("cli_match.yar");
    fs::write(&test_file, b"CLI_YARA_FILE_RULE_MARKER").unwrap();
    fs::write(
        &rule_file,
        r#"rule cli_file_match { strings: $marker = "CLI_YARA_FILE_RULE_MARKER" condition: $marker }"#,
    )
    .unwrap();

    let scan = run_json_command(
        "yara-scan with rule file",
        &[
            "yara-scan",
            temp_dir.path().to_str().unwrap(),
            "--rule",
            rule_file.to_str().unwrap(),
            "--detailed",
        ],
    );
    assert!(scan["total_files_scanned"].as_u64().unwrap() >= 1);
    assert!(scan["total_matches"].as_u64().unwrap() >= 1);
}
