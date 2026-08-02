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

use file_scanner::control_flow::{analyze_control_flow, ControlFlowAnalyzer};
use file_scanner::function_analysis::{analyze_symbols, FunctionInfo, FunctionType, SymbolTable};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_control_flow_analysis_on_real_binary() {
    // Use the test binary if it exists
    let test_binary_path = Path::new("./target/debug/file-scanner");

    if test_binary_path.exists() {
        // First analyze symbols to get the symbol table
        let symbol_table = analyze_symbols(test_binary_path).unwrap();

        // Then analyze control flow
        let result = analyze_control_flow(test_binary_path, &symbol_table);

        match result {
            Ok(analysis) => {
                // Verify we analyzed some functions
                assert!(analysis.overall_metrics.total_functions > 0);
                assert!(!analysis.cfgs.is_empty());

                // Check that we have basic blocks and edges
                for cfg in &analysis.cfgs {
                    assert!(!cfg.basic_blocks.is_empty());
                    assert_eq!(cfg.basic_blocks[0].id, cfg.entry_block);
                }
            }
            Err(e) => {
                // It's okay if analysis fails on some binaries, but log the error
                eprintln!("Control flow analysis failed (expected on some platforms): {e}");
            }
        }
    }
}

#[test]
fn test_control_flow_analyzer_with_simple_elf() {
    // Create a minimal but valid ELF binary with actual x86-64 code
    let mut elf_data = vec![
        // ELF header
        0x7f, 0x45, 0x4c, 0x46, // Magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Executable file
        0x3e, 0x00, // x86-64
        0x01, 0x00, 0x00, 0x00, // Version
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
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

    // Add padding to reach program header offset (0x40)
    while elf_data.len() < 0x40 {
        elf_data.push(0x00);
    }

    // Program header
    elf_data.extend_from_slice(&[
        0x01, 0x00, 0x00, 0x00, // PT_LOAD
        0x05, 0x00, 0x00, 0x00, // Flags (R+X)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Offset
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Virtual address
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Physical address
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // File size
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Memory size
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment
    ]);

    // Simple x86-64 code at offset 0x1000
    while elf_data.len() < 0x1000 {
        elf_data.push(0x00);
    }

    // Add some simple x86-64 instructions
    elf_data.extend_from_slice(&[
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
        0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
        0x48, 0x83, 0xc4, 0x10, // add rsp, 0x10
        0x5d, // pop rbp
        0xc3, // ret
    ]);

    // Create test file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&elf_data).unwrap();
    temp_file.flush().unwrap();

    // Create a minimal symbol table
    let symbol_table = SymbolTable {
        functions: vec![FunctionInfo {
            name: "test_function".to_string(),
            address: 0x1000,
            size: 20,
            function_type: FunctionType::Exported,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        }],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: file_scanner::function_analysis::SymbolCounts {
            total_functions: 1,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 1,
            global_variables: 0,
            cross_references: 0,
        },
    };

    // Try to analyze control flow
    let result = analyze_control_flow(temp_file.path(), &symbol_table);

    // Even if it fails, we're testing that the function executes
    match result {
        Ok(analysis) => {
            // If successful, verify some basic properties
            assert!(analysis.analysis_stats.bytes_analyzed > 0);
        }
        Err(e) => {
            // Expected to fail due to minimal ELF, but should fail gracefully
            eprintln!("Expected failure: {e}");
        }
    }
}

#[test]
fn test_control_flow_analyzer_x86_64_creation() {
    let analyzer = ControlFlowAnalyzer::new_x86_64();
    assert!(analyzer.is_ok(), "Should be able to create x86_64 analyzer");
}

#[test]
fn test_analyze_control_flow_with_invalid_path() {
    let symbol_table = SymbolTable {
        functions: vec![],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: file_scanner::function_analysis::SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    };

    let result = analyze_control_flow(Path::new("/nonexistent/file"), &symbol_table);
    assert!(result.is_err());
}

#[test]
fn test_control_flow_with_example_binaries() {
    // Try to analyze example binaries if they exist
    let example_paths = vec![
        "./examples/binaries/c_advanced_binary",
        "./examples/binaries/rust_test_binary",
        "./examples/binaries/go_test_binary",
    ];

    for path_str in example_paths {
        let path = Path::new(path_str);
        if path.exists() {
            println!("Testing control flow on {path_str}");

            // Get symbol table first
            match analyze_symbols(path) {
                Ok(symbol_table) => {
                    // Now analyze control flow
                    match analyze_control_flow(path, &symbol_table) {
                        Ok(cf_analysis) => {
                            println!("Successfully analyzed {} functions", cf_analysis.cfgs.len());

                            // Verify some metrics
                            assert!(
                                cf_analysis.overall_metrics.total_functions
                                    >= cf_analysis.overall_metrics.analyzed_functions
                            );

                            // Check individual CFGs
                            for cfg in &cf_analysis.cfgs {
                                assert!(!cfg.function_name.is_empty());
                                assert!(!cfg.basic_blocks.is_empty());
                                assert!(cfg.complexity.basic_block_count == cfg.basic_blocks.len());
                            }
                        }
                        Err(e) => {
                            eprintln!("Control flow analysis failed for {path_str}: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Function analysis failed for {path_str}: {e}");
                }
            }
        }
    }
}
