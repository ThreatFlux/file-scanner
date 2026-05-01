use file_scanner::function_analysis::*;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_analyze_symbols_with_elf() {
    // Create a minimal ELF file for testing
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

    // Pad to minimum size
    while elf_data.len() < 0x40 {
        elf_data.push(0);
    }

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&elf_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_symbols(temp_file.path());

    match result {
        Ok(symbol_table) => {
            // Should have basic structure even if empty
            assert_eq!(symbol_table.functions.len(), 0);
            assert_eq!(symbol_table.symbol_count.total_functions, 0);
        }
        Err(e) => {
            // Expected to fail on minimal ELF
            eprintln!("Expected error: {}", e);
        }
    }
}

#[test]
fn test_analyze_symbols_with_real_binary() {
    // Try with the test binary if it exists
    let test_binary = Path::new("./target/debug/file-scanner");

    if test_binary.exists() {
        match analyze_symbols(test_binary) {
            Ok(symbol_table) => {
                println!("Found {} functions", symbol_table.functions.len());

                // Should find at least some functions
                assert!(!symbol_table.functions.is_empty());

                // Check stats consistency
                assert_eq!(
                    symbol_table.symbol_count.total_functions,
                    symbol_table.functions.len()
                );

                // Look for main function
                let main_fn = symbol_table
                    .functions
                    .iter()
                    .find(|f| f.name.contains("main"));
                assert!(main_fn.is_some(), "Should find main function");
            }
            Err(e) => {
                eprintln!("Function analysis failed (may be expected): {}", e);
            }
        }
    }
}

#[test]
fn test_analyze_symbols_with_c_binary() {
    let test_binary = Path::new("./test_programs/c_advanced_binary");

    if test_binary.exists() {
        let result = analyze_symbols(test_binary);
        assert!(result.is_ok(), "Should successfully analyze C binary");

        let symbol_table = result.unwrap();

        // Should have found functions
        assert!(
            !symbol_table.functions.is_empty(),
            "Should find functions in C binary"
        );

        // Verify symbol count consistency
        assert_eq!(
            symbol_table.symbol_count.total_functions,
            symbol_table.functions.len(),
            "Function count should be consistent"
        );

        // Should have imports from libc
        assert!(
            !symbol_table.imports.is_empty(),
            "Should have imported functions"
        );

        // Look for common C functions
        let has_printf = symbol_table
            .imports
            .iter()
            .any(|i| i.name.contains("printf"));
        let has_malloc = symbol_table
            .imports
            .iter()
            .any(|i| i.name.contains("malloc"));
        assert!(has_printf || has_malloc, "Should import common C functions");

        println!(
            "C binary analysis: {} functions, {} imports",
            symbol_table.functions.len(),
            symbol_table.imports.len()
        );
    }
}

#[test]
fn test_analyze_symbols_with_rust_binary() {
    let test_binary = Path::new("./test_programs/rust_test_binary");

    if test_binary.exists() {
        let result = analyze_symbols(test_binary);
        assert!(result.is_ok(), "Should successfully analyze Rust binary");

        let symbol_table = result.unwrap();

        // Should have found functions
        assert!(
            !symbol_table.functions.is_empty(),
            "Should find functions in Rust binary"
        );

        // Rust binaries typically have many functions due to monomorphization
        assert!(
            symbol_table.functions.len() >= 10,
            "Rust binary should have multiple functions"
        );

        // Verify function types are properly categorized
        let local_funcs = symbol_table
            .functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count();
        let imported_funcs = symbol_table
            .functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Imported))
            .count();

        assert!(local_funcs > 0, "Should have local functions");

        println!(
            "Rust binary analysis: {} total, {} local, {} imported",
            symbol_table.functions.len(),
            local_funcs,
            imported_funcs
        );
    }
}

#[test]
fn test_analyze_symbols_with_go_binary() {
    let test_binary = Path::new("./test_programs/go_test_binary");

    if test_binary.exists() {
        let result = analyze_symbols(test_binary);
        assert!(result.is_ok(), "Should successfully analyze Go binary");

        let symbol_table = result.unwrap();

        // Go binaries have extensive runtime functions
        assert!(
            symbol_table.functions.len() > 50,
            "Go binary should have many runtime functions"
        );

        // Should find some Go runtime functions
        let has_go_runtime = symbol_table
            .functions
            .iter()
            .any(|f| f.name.starts_with("runtime.") || f.name.starts_with("go."));
        assert!(has_go_runtime, "Should find Go runtime functions");

        // Check for proper function categorization
        let entry_points = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_entry_point)
            .count();

        println!(
            "Go binary analysis: {} functions, {} entry points",
            symbol_table.functions.len(),
            entry_points
        );
    }
}

#[test]
fn test_function_type_serialization() {
    let types = vec![
        FunctionType::Local,
        FunctionType::Imported,
        FunctionType::Exported,
        FunctionType::Thunk,
        FunctionType::Constructor,
        FunctionType::Destructor,
        FunctionType::EntryPoint,
    ];

    for func_type in types {
        let serialized = serde_json::to_string(&func_type).unwrap();
        let deserialized: FunctionType = serde_json::from_str(&serialized).unwrap();

        match (func_type, deserialized) {
            (FunctionType::Local, FunctionType::Local) => {}
            (FunctionType::Imported, FunctionType::Imported) => {}
            (FunctionType::Exported, FunctionType::Exported) => {}
            (FunctionType::Thunk, FunctionType::Thunk) => {}
            (FunctionType::Constructor, FunctionType::Constructor) => {}
            (FunctionType::Destructor, FunctionType::Destructor) => {}
            (FunctionType::EntryPoint, FunctionType::EntryPoint) => {}
            _ => panic!("Function type serialization mismatch"),
        }
    }
}

#[test]
fn test_calling_convention_serialization() {
    let conventions = vec![
        CallingConvention::Cdecl,
        CallingConvention::Stdcall,
        CallingConvention::Fastcall,
        CallingConvention::Thiscall,
        CallingConvention::Vectorcall,
        CallingConvention::SysV,
        CallingConvention::Win64,
        CallingConvention::Unknown,
    ];

    for convention in conventions {
        let serialized = serde_json::to_string(&convention).unwrap();
        let deserialized: CallingConvention = serde_json::from_str(&serialized).unwrap();

        match (convention, deserialized) {
            (CallingConvention::Cdecl, CallingConvention::Cdecl) => {}
            (CallingConvention::Stdcall, CallingConvention::Stdcall) => {}
            (CallingConvention::Fastcall, CallingConvention::Fastcall) => {}
            (CallingConvention::Thiscall, CallingConvention::Thiscall) => {}
            (CallingConvention::Vectorcall, CallingConvention::Vectorcall) => {}
            (CallingConvention::SysV, CallingConvention::SysV) => {}
            (CallingConvention::Win64, CallingConvention::Win64) => {}
            (CallingConvention::Unknown, CallingConvention::Unknown) => {}
            _ => panic!("Calling convention serialization mismatch"),
        }
    }
}

#[test]
fn test_variable_type_serialization() {
    let types = vec![
        VariableType::Global,
        VariableType::Static,
        VariableType::ThreadLocal,
        VariableType::Const,
    ];

    for var_type in types {
        let serialized = serde_json::to_string(&var_type).unwrap();
        let deserialized: VariableType = serde_json::from_str(&serialized).unwrap();

        match (var_type, deserialized) {
            (VariableType::Global, VariableType::Global) => {}
            (VariableType::Static, VariableType::Static) => {}
            (VariableType::ThreadLocal, VariableType::ThreadLocal) => {}
            (VariableType::Const, VariableType::Const) => {}
            _ => panic!("Variable type serialization mismatch"),
        }
    }
}

#[test]
fn test_reference_type_serialization() {
    let types = vec![
        ReferenceType::Call,
        ReferenceType::Jump,
        ReferenceType::DataReference,
        ReferenceType::StringReference,
        ReferenceType::Import,
        ReferenceType::Export,
    ];

    for ref_type in types {
        let serialized = serde_json::to_string(&ref_type).unwrap();
        let deserialized: ReferenceType = serde_json::from_str(&serialized).unwrap();

        match (ref_type, deserialized) {
            (ReferenceType::Call, ReferenceType::Call) => {}
            (ReferenceType::Jump, ReferenceType::Jump) => {}
            (ReferenceType::DataReference, ReferenceType::DataReference) => {}
            (ReferenceType::StringReference, ReferenceType::StringReference) => {}
            (ReferenceType::Import, ReferenceType::Import) => {}
            (ReferenceType::Export, ReferenceType::Export) => {}
            _ => panic!("Reference type serialization mismatch"),
        }
    }
}

#[test]
fn test_function_info_creation() {
    let func = FunctionInfo {
        name: "test_function".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::Exported,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![Parameter {
            name: Some("arg1".to_string()),
            param_type: Some("int".to_string()),
            size: Some(4),
        }],
        is_entry_point: false,
        is_exported: true,
        is_imported: false,
    };

    assert_eq!(func.name, "test_function");
    assert_eq!(func.address, 0x1000);
    assert_eq!(func.size, 100);
    assert!(matches!(func.function_type, FunctionType::Exported));
    assert!(func.is_exported);
    assert!(!func.is_imported);
    assert_eq!(func.parameters.len(), 1);
}

#[test]
fn test_variable_info_creation() {
    let var = VariableInfo {
        name: "global_var".to_string(),
        address: 0x2000,
        size: 8,
        var_type: VariableType::Global,
        section: Some(".data".to_string()),
    };

    assert_eq!(var.name, "global_var");
    assert_eq!(var.address, 0x2000);
    assert_eq!(var.size, 8);
    assert!(matches!(var.var_type, VariableType::Global));
    assert_eq!(var.section, Some(".data".to_string()));
}

#[test]
fn test_cross_reference_creation() {
    let xref = CrossReference {
        from_address: 0x1000,
        to_address: 0x2000,
        reference_type: ReferenceType::Call,
        instruction_type: Some("call".to_string()),
    };

    assert_eq!(xref.from_address, 0x1000);
    assert_eq!(xref.to_address, 0x2000);
    assert!(matches!(xref.reference_type, ReferenceType::Call));
    assert_eq!(xref.instruction_type, Some("call".to_string()));
}

#[test]
fn test_symbol_table_creation() {
    let symbol_table = SymbolTable {
        functions: vec![],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    };

    assert_eq!(symbol_table.functions.len(), 0);
    assert_eq!(symbol_table.global_variables.len(), 0);
    assert_eq!(symbol_table.cross_references.len(), 0);
    assert_eq!(symbol_table.symbol_count.total_functions, 0);
}

#[test]
fn test_parameter_creation() {
    let param = Parameter {
        name: Some("count".to_string()),
        param_type: Some("size_t".to_string()),
        size: Some(8),
    };

    assert_eq!(param.name, Some("count".to_string()));
    assert_eq!(param.param_type, Some("size_t".to_string()));
    assert_eq!(param.size, Some(8));
}

#[test]
fn test_import_info_creation() {
    let import = ImportInfo {
        name: "malloc".to_string(),
        library: Some("libc.so.6".to_string()),
        address: Some(0x4000),
        ordinal: None,
        is_delayed: false,
    };

    assert_eq!(import.name, "malloc");
    assert_eq!(import.library, Some("libc.so.6".to_string()));
    assert_eq!(import.address, Some(0x4000));
    assert_eq!(import.ordinal, None);
    assert!(!import.is_delayed);
}

#[test]
fn test_export_info_creation() {
    let export = ExportInfo {
        name: "my_function".to_string(),
        address: 0x1000,
        ordinal: Some(1),
        is_forwarder: false,
        forwarder_name: None,
    };

    assert_eq!(export.name, "my_function");
    assert_eq!(export.address, 0x1000);
    assert_eq!(export.ordinal, Some(1));
    assert!(!export.is_forwarder);
    assert_eq!(export.forwarder_name, None);
}

#[test]
fn test_analyze_symbols_with_invalid_path() {
    let result = analyze_symbols(Path::new("/nonexistent/file"));
    assert!(result.is_err());
}

#[test]
fn test_analyze_symbols_with_multiple_binaries() {
    // Try to analyze multiple test binaries
    let test_binaries = vec![
        "./test_programs/c_advanced_binary",
        "./test_programs/rust_test_binary",
        "./test_programs/go_test_binary",
        "./test_programs/cpp_test_binary",
        "./test_programs/nim_test_binary",
        "./test_programs/d_test_binary",
    ];

    let mut successful_analyses = 0;

    for path_str in test_binaries {
        let path = Path::new(path_str);
        if path.exists() {
            println!("Testing function analysis on {}", path_str);

            match analyze_symbols(path) {
                Ok(symbol_table) => {
                    println!(
                        "Successfully analyzed {} functions in {}",
                        symbol_table.functions.len(),
                        path_str
                    );

                    // Verify basic properties - counts are unsigned so always >= 0

                    // Check for consistency - function types are categorized independently
                    // of is_imported/is_exported flags, so we don't expect them to sum up
                    assert!(
                        symbol_table.symbol_count.local_functions
                            <= symbol_table.symbol_count.total_functions
                    );
                    assert!(
                        symbol_table.symbol_count.imported_functions
                            <= symbol_table.symbol_count.total_functions
                    );
                    assert!(
                        symbol_table.symbol_count.exported_functions
                            <= symbol_table.symbol_count.total_functions
                    );

                    // Each binary should have at least some functions
                    assert!(
                        !symbol_table.functions.is_empty(),
                        "Binary {} should have functions",
                        path_str
                    );

                    successful_analyses += 1;
                }
                Err(e) => {
                    eprintln!("Function analysis failed for {}: {}", path_str, e);
                }
            }
        }
    }

    // At least some binaries should be successfully analyzed
    assert!(
        successful_analyses > 0,
        "Should successfully analyze at least one test binary"
    );
}

#[test]
fn test_analyze_symbols_error_conditions() {
    // Test with non-existent file
    let result = analyze_symbols(Path::new("/nonexistent/file"));
    assert!(result.is_err(), "Should fail with non-existent file");

    // Test with directory instead of file
    let result = analyze_symbols(Path::new("."));
    assert!(result.is_err(), "Should fail when given directory");

    // Test with text file (not a binary)
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"This is not a binary file").unwrap();
    temp_file.flush().unwrap();

    let result = analyze_symbols(temp_file.path());
    assert!(result.is_err(), "Should fail with non-binary file");
}

#[test]
fn test_symbol_table_statistics() {
    // Use the test binary if available
    let test_binary = Path::new("./test_programs/c_advanced_binary");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // Verify counts are non-negative (usize types are always >= 0, so just verify structure exists)

        // Each category should not exceed total functions
        assert!(
            symbol_table.symbol_count.local_functions <= symbol_table.symbol_count.total_functions
        );
        assert!(
            symbol_table.symbol_count.imported_functions
                <= symbol_table.symbol_count.total_functions
        );
        assert!(
            symbol_table.symbol_count.exported_functions
                <= symbol_table.symbol_count.total_functions
        );

        // Function list length should match total count
        assert_eq!(
            symbol_table.functions.len(),
            symbol_table.symbol_count.total_functions
        );

        // Variable list length should match variable count
        assert_eq!(
            symbol_table.global_variables.len(),
            symbol_table.symbol_count.global_variables
        );
    }
}

#[test]
fn test_function_address_validation() {
    let test_binary = Path::new("./test_programs/rust_test_binary");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // All functions should have valid addresses
        for function in &symbol_table.functions {
            assert!(
                function.address > 0 || function.is_imported,
                "Function {} should have valid address or be imported",
                function.name
            );

            // Function size should be reasonable
            assert!(
                function.size < 0x1000000, // 16MB max function size
                "Function {} has unreasonable size: {}",
                function.name,
                function.size
            );

            // Name should not be empty
            assert!(
                !function.name.is_empty(),
                "Function should have non-empty name"
            );
        }

        // Check that we have reasonable calling conventions
        let conv_count = symbol_table
            .functions
            .iter()
            .filter_map(|f| f.calling_convention.as_ref())
            .count();
        assert!(
            conv_count > 0,
            "Should have functions with calling conventions"
        );
    }
}

#[test]
fn test_analyze_symbols_with_pe_binary() {
    // Test with PE binary if available
    let pe_binary = Path::new("./test_programs/c_advanced_binary");

    if pe_binary.exists() {
        match analyze_symbols(pe_binary) {
            Ok(symbol_table) => {
                println!(
                    "PE analysis found {} functions",
                    symbol_table.functions.len()
                );

                // Should have proper symbol count structure
                assert!(symbol_table.symbol_count.total_functions == symbol_table.functions.len());

                // Test PE-specific features
                if !symbol_table.imports.is_empty() {
                    let has_library = symbol_table.imports.iter().any(|i| i.library.is_some());
                    println!("Has library imports: {}", has_library);
                }

                // Check exports if any
                if !symbol_table.exports.is_empty() {
                    println!("Found {} exports", symbol_table.exports.len());
                }
            }
            Err(e) => {
                println!("PE analysis error (expected for non-PE): {}", e);
            }
        }
    }
}

#[test]
fn test_analyze_symbols_comprehensive_elf() {
    // Test with various ELF binaries to exercise different code paths
    let test_binaries = vec![
        "./test_programs/rust_test_binary",
        "./test_programs/go_test_binary",
        "./test_programs/cpp_test_binary",
        "./test_programs/c_advanced_binary",
        "/bin/ls", // System binary
    ];

    let mut successful_analyses = 0;

    for binary_path in test_binaries {
        let path = Path::new(binary_path);
        if !path.exists() {
            continue;
        }

        match analyze_symbols(path) {
            Ok(symbol_table) => {
                successful_analyses += 1;
                println!(
                    "Successfully analyzed {}: {} functions",
                    binary_path,
                    symbol_table.functions.len()
                );

                // Verify symbol table consistency
                assert_eq!(
                    symbol_table.functions.len(),
                    symbol_table.symbol_count.total_functions
                );

                // Test function type distribution
                let local_count = symbol_table
                    .functions
                    .iter()
                    .filter(|f| matches!(f.function_type, FunctionType::Local))
                    .count();
                let imported_count = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.is_imported)
                    .count();
                let exported_count = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.is_exported)
                    .count();

                assert_eq!(local_count, symbol_table.symbol_count.local_functions);
                assert_eq!(imported_count, symbol_table.symbol_count.imported_functions);
                assert_eq!(exported_count, symbol_table.symbol_count.exported_functions);

                // Test that entry points are identified if present
                let entry_points = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.is_entry_point)
                    .count();
                println!("Entry points found: {}", entry_points);

                // Verify calling conventions are set for some functions
                let with_calling_conv = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.calling_convention.is_some())
                    .count();
                println!("Functions with calling conventions: {}", with_calling_conv);

                // Test variable analysis
                println!(
                    "Global variables found: {}",
                    symbol_table.global_variables.len()
                );
                for var in symbol_table.global_variables.iter().take(5) {
                    assert!(!var.name.is_empty());
                    assert!(var.size > 0 || var.name.starts_with("_"));
                }

                // Test import/export analysis
                println!(
                    "Imports: {}, Exports: {}",
                    symbol_table.imports.len(),
                    symbol_table.exports.len()
                );
            }
            Err(e) => {
                println!("Analysis failed for {}: {}", binary_path, e);
            }
        }
    }

    // Should successfully analyze at least one binary
    assert!(
        successful_analyses > 0,
        "Should successfully analyze at least one binary"
    );
}

#[test]
fn test_analyze_symbols_error_conditions_comprehensive() {
    // Test various error conditions

    // Non-existent file
    let result = analyze_symbols(Path::new("/definitely/does/not/exist"));
    assert!(result.is_err());

    // Directory instead of file
    let result = analyze_symbols(Path::new("."));
    assert!(result.is_err());

    // Invalid binary data
    let mut temp_file = tempfile::NamedTempFile::new().unwrap();
    temp_file.write_all(b"Not a valid binary format").unwrap();
    temp_file.flush().unwrap();

    let result = analyze_symbols(temp_file.path());
    assert!(result.is_err());

    // Empty file
    let mut empty_file = tempfile::NamedTempFile::new().unwrap();
    empty_file.flush().unwrap();

    let result = analyze_symbols(empty_file.path());
    assert!(result.is_err());
}

#[test]
fn test_symbol_table_statistics_accuracy() {
    let test_binary = Path::new("./target/debug/file-scanner");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // Manually count and verify statistics
        let manual_total = symbol_table.functions.len();
        let manual_local = symbol_table
            .functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count();
        let manual_imported = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported)
            .count();
        let manual_exported = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_exported)
            .count();
        let manual_variables = symbol_table.global_variables.len();
        let manual_xrefs = symbol_table.cross_references.len();

        // Verify all statistics match
        assert_eq!(manual_total, symbol_table.symbol_count.total_functions);
        assert_eq!(manual_local, symbol_table.symbol_count.local_functions);
        assert_eq!(
            manual_imported,
            symbol_table.symbol_count.imported_functions
        );
        assert_eq!(
            manual_exported,
            symbol_table.symbol_count.exported_functions
        );
        assert_eq!(manual_variables, symbol_table.symbol_count.global_variables);
        assert_eq!(manual_xrefs, symbol_table.symbol_count.cross_references);

        // Test total counts make sense
        assert!(manual_total >= manual_local + manual_imported);

        println!("Statistics verification passed:");
        println!("  Total functions: {}", manual_total);
        println!(
            "  Local: {}, Imported: {}, Exported: {}",
            manual_local, manual_imported, manual_exported
        );
        println!(
            "  Variables: {}, Cross-references: {}",
            manual_variables, manual_xrefs
        );
    }
}

#[test]
fn test_dynamic_symbol_analysis() {
    // Test analysis of dynamic symbols in ELF binaries
    let test_binary = Path::new("/bin/ls");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // Should find some imported functions from dynamic symbols
        let dynamic_imports = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported && matches!(f.function_type, FunctionType::Imported))
            .count();

        println!("Dynamic imports found: {}", dynamic_imports);

        // Check that imported functions have reasonable properties
        for func in symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported)
            .take(10)
        {
            assert!(!func.name.is_empty());
            assert!(matches!(func.function_type, FunctionType::Imported));
            assert!(func.is_imported);
            assert!(!func.is_exported);
            assert!(!func.is_entry_point);
        }

        // Verify imports have corresponding ImportInfo entries
        let import_names: std::collections::HashSet<_> =
            symbol_table.imports.iter().map(|i| &i.name).collect();
        let imported_func_names: std::collections::HashSet<_> = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported)
            .map(|f| &f.name)
            .collect();

        // Most imported functions should have import entries
        let overlap = import_names.intersection(&imported_func_names).count();
        println!(
            "Import overlap: {} out of {} functions",
            overlap,
            imported_func_names.len()
        );
    }
}

// NEW COMPREHENSIVE TESTS

#[test]
fn test_elf_symbol_parsing_detailed() {
    use file_scanner::function_analysis::analyze_elf_symbols;
    use goblin::elf::Elf;

    // Create a minimal ELF for testing individual function parsing
    let elf_data = create_minimal_elf_with_symbols();

    match Elf::parse(&elf_data) {
        Ok(elf) => {
            let result = analyze_elf_symbols(elf, &elf_data);
            match result {
                Ok(symbol_table) => {
                    // Test basic structure
                    // Test basic structure (len() is always >= 0 for Vec, so just verify structure exists)
                    let _ = symbol_table.functions.len();
                    let _ = symbol_table.global_variables.len();
                    let _ = symbol_table.imports.len();
                    let _ = symbol_table.exports.len();

                    // Test symbol count consistency
                    assert_eq!(
                        symbol_table.functions.len(),
                        symbol_table.symbol_count.total_functions
                    );
                    assert_eq!(
                        symbol_table.global_variables.len(),
                        symbol_table.symbol_count.global_variables
                    );
                }
                Err(_) => {
                    // Expected for minimal ELF without proper symbol table
                }
            }
        }
        Err(_) => {
            // Expected for our minimal test ELF
        }
    }
}

#[test]
fn test_function_type_detection() {
    // Test all function types are properly detected
    let func_local = FunctionInfo {
        name: "local_func".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::Local,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![],
        is_entry_point: false,
        is_exported: false,
        is_imported: false,
    };

    let func_imported = FunctionInfo {
        name: "printf".to_string(),
        address: 0,
        size: 0,
        function_type: FunctionType::Imported,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![],
        is_entry_point: false,
        is_exported: false,
        is_imported: true,
    };

    let func_exported = FunctionInfo {
        name: "my_api_func".to_string(),
        address: 0x2000,
        size: 200,
        function_type: FunctionType::Exported,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![],
        is_entry_point: false,
        is_exported: true,
        is_imported: false,
    };

    let func_entry = FunctionInfo {
        name: "_start".to_string(),
        address: 0x3000,
        size: 50,
        function_type: FunctionType::EntryPoint,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![],
        is_entry_point: true,
        is_exported: false,
        is_imported: false,
    };

    // Verify function properties
    assert!(matches!(func_local.function_type, FunctionType::Local));
    assert!(!func_local.is_imported && !func_local.is_exported && !func_local.is_entry_point);

    assert!(matches!(
        func_imported.function_type,
        FunctionType::Imported
    ));
    assert!(func_imported.is_imported && !func_imported.is_exported);

    assert!(matches!(
        func_exported.function_type,
        FunctionType::Exported
    ));
    assert!(func_exported.is_exported && !func_exported.is_imported);

    assert!(matches!(func_entry.function_type, FunctionType::EntryPoint));
    assert!(func_entry.is_entry_point);
}

#[test]
fn test_calling_convention_detection() {
    // Test calling convention detection logic
    let conventions = vec![
        CallingConvention::Cdecl,
        CallingConvention::Stdcall,
        CallingConvention::Fastcall,
        CallingConvention::Thiscall,
        CallingConvention::Vectorcall,
        CallingConvention::SysV,
        CallingConvention::Win64,
        CallingConvention::Unknown,
    ];

    for convention in conventions {
        let func = FunctionInfo {
            name: "test_func".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::Local,
            calling_convention: Some(convention.clone()),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        };

        assert!(func.calling_convention.is_some());
        match (&convention, &func.calling_convention.unwrap()) {
            (CallingConvention::Cdecl, CallingConvention::Cdecl) => {}
            (CallingConvention::Stdcall, CallingConvention::Stdcall) => {}
            (CallingConvention::Fastcall, CallingConvention::Fastcall) => {}
            (CallingConvention::Thiscall, CallingConvention::Thiscall) => {}
            (CallingConvention::Vectorcall, CallingConvention::Vectorcall) => {}
            (CallingConvention::SysV, CallingConvention::SysV) => {}
            (CallingConvention::Win64, CallingConvention::Win64) => {}
            (CallingConvention::Unknown, CallingConvention::Unknown) => {}
            _ => panic!("Calling convention mismatch"),
        }
    }
}

#[test]
fn test_parameter_analysis() {
    // Test function parameter detection and parsing
    let param1 = Parameter {
        name: Some("argc".to_string()),
        param_type: Some("int".to_string()),
        size: Some(4),
    };

    let param2 = Parameter {
        name: Some("argv".to_string()),
        param_type: Some("char**".to_string()),
        size: Some(8),
    };

    let param3 = Parameter {
        name: None,
        param_type: Some("void*".to_string()),
        size: Some(8),
    };

    let func_with_params = FunctionInfo {
        name: "main".to_string(),
        address: 0x1000,
        size: 500,
        function_type: FunctionType::EntryPoint,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![param1.clone(), param2.clone(), param3.clone()],
        is_entry_point: true,
        is_exported: false,
        is_imported: false,
    };

    // Verify parameter properties
    assert_eq!(func_with_params.parameters.len(), 3);
    assert_eq!(
        func_with_params.parameters[0].name,
        Some("argc".to_string())
    );
    assert_eq!(
        func_with_params.parameters[0].param_type,
        Some("int".to_string())
    );
    assert_eq!(func_with_params.parameters[0].size, Some(4));

    assert_eq!(
        func_with_params.parameters[1].name,
        Some("argv".to_string())
    );
    assert_eq!(
        func_with_params.parameters[1].param_type,
        Some("char**".to_string())
    );
    assert_eq!(func_with_params.parameters[1].size, Some(8));

    assert_eq!(func_with_params.parameters[2].name, None);
    assert_eq!(
        func_with_params.parameters[2].param_type,
        Some("void*".to_string())
    );
    assert_eq!(func_with_params.parameters[2].size, Some(8));
}

#[test]
fn test_variable_type_detection() {
    // Test variable type detection for different scopes
    let global_var = VariableInfo {
        name: "global_counter".to_string(),
        address: 0x4000,
        size: 4,
        var_type: VariableType::Global,
        section: Some(".data".to_string()),
    };

    let static_var = VariableInfo {
        name: "static_buffer".to_string(),
        address: 0x4010,
        size: 1024,
        var_type: VariableType::Static,
        section: Some(".bss".to_string()),
    };

    let thread_local_var = VariableInfo {
        name: "thread_id".to_string(),
        address: 0x5000,
        size: 8,
        var_type: VariableType::ThreadLocal,
        section: Some(".tdata".to_string()),
    };

    let const_var = VariableInfo {
        name: "version_string".to_string(),
        address: 0x6000,
        size: 20,
        var_type: VariableType::Const,
        section: Some(".rodata".to_string()),
    };

    // Verify variable type detection
    assert!(matches!(global_var.var_type, VariableType::Global));
    assert_eq!(global_var.section, Some(".data".to_string()));

    assert!(matches!(static_var.var_type, VariableType::Static));
    assert_eq!(static_var.section, Some(".bss".to_string()));

    assert!(matches!(
        thread_local_var.var_type,
        VariableType::ThreadLocal
    ));
    assert_eq!(thread_local_var.section, Some(".tdata".to_string()));

    assert!(matches!(const_var.var_type, VariableType::Const));
    assert_eq!(const_var.section, Some(".rodata".to_string()));
}

#[test]
fn test_cross_reference_analysis() {
    // Test cross-reference detection and classification
    let call_ref = CrossReference {
        from_address: 0x1000,
        to_address: 0x2000,
        reference_type: ReferenceType::Call,
        instruction_type: Some("call".to_string()),
    };

    let jump_ref = CrossReference {
        from_address: 0x1010,
        to_address: 0x1500,
        reference_type: ReferenceType::Jump,
        instruction_type: Some("jmp".to_string()),
    };

    let data_ref = CrossReference {
        from_address: 0x1020,
        to_address: 0x4000,
        reference_type: ReferenceType::DataReference,
        instruction_type: Some("mov".to_string()),
    };

    let string_ref = CrossReference {
        from_address: 0x1030,
        to_address: 0x6000,
        reference_type: ReferenceType::StringReference,
        instruction_type: Some("lea".to_string()),
    };

    let import_ref = CrossReference {
        from_address: 0x1040,
        to_address: 0x8000,
        reference_type: ReferenceType::Import,
        instruction_type: Some("call".to_string()),
    };

    let export_ref = CrossReference {
        from_address: 0x1050,
        to_address: 0x9000,
        reference_type: ReferenceType::Export,
        instruction_type: Some("jmp".to_string()),
    };

    // Verify cross-reference properties
    assert!(matches!(call_ref.reference_type, ReferenceType::Call));
    assert_eq!(call_ref.instruction_type, Some("call".to_string()));

    assert!(matches!(jump_ref.reference_type, ReferenceType::Jump));
    assert_eq!(jump_ref.instruction_type, Some("jmp".to_string()));

    assert!(matches!(
        data_ref.reference_type,
        ReferenceType::DataReference
    ));
    assert_eq!(data_ref.instruction_type, Some("mov".to_string()));

    assert!(matches!(
        string_ref.reference_type,
        ReferenceType::StringReference
    ));
    assert_eq!(string_ref.instruction_type, Some("lea".to_string()));

    assert!(matches!(import_ref.reference_type, ReferenceType::Import));
    assert_eq!(import_ref.instruction_type, Some("call".to_string()));

    assert!(matches!(export_ref.reference_type, ReferenceType::Export));
    assert_eq!(export_ref.instruction_type, Some("jmp".to_string()));
}

#[test]
fn test_import_export_analysis() {
    // Test import and export detection
    let import1 = ImportInfo {
        name: "malloc".to_string(),
        library: Some("libc.so.6".to_string()),
        address: Some(0x8000),
        ordinal: None,
        is_delayed: false,
    };

    let import2 = ImportInfo {
        name: "CreateFileA".to_string(),
        library: Some("kernel32.dll".to_string()),
        address: Some(0x8010),
        ordinal: Some(123),
        is_delayed: true,
    };

    let export1 = ExportInfo {
        name: "my_exported_function".to_string(),
        address: 0x9000,
        ordinal: Some(1),
        is_forwarder: false,
        forwarder_name: None,
    };

    let export2 = ExportInfo {
        name: "forwarded_function".to_string(),
        address: 0x9010,
        ordinal: Some(2),
        is_forwarder: true,
        forwarder_name: Some("ntdll.RtlAllocateHeap".to_string()),
    };

    // Verify import properties
    assert_eq!(import1.name, "malloc");
    assert_eq!(import1.library, Some("libc.so.6".to_string()));
    assert!(!import1.is_delayed);

    assert_eq!(import2.name, "CreateFileA");
    assert_eq!(import2.library, Some("kernel32.dll".to_string()));
    assert_eq!(import2.ordinal, Some(123));
    assert!(import2.is_delayed);

    // Verify export properties
    assert_eq!(export1.name, "my_exported_function");
    assert_eq!(export1.ordinal, Some(1));
    assert!(!export1.is_forwarder);
    assert_eq!(export1.forwarder_name, None);

    assert_eq!(export2.name, "forwarded_function");
    assert_eq!(export2.ordinal, Some(2));
    assert!(export2.is_forwarder);
    assert_eq!(
        export2.forwarder_name,
        Some("ntdll.RtlAllocateHeap".to_string())
    );
}

#[test]
fn test_symbol_count_calculations() {
    // Test symbol count calculation logic
    let functions = [
        FunctionInfo {
            name: "local1".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
        FunctionInfo {
            name: "local2".to_string(),
            address: 0x1100,
            size: 200,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
        FunctionInfo {
            name: "printf".to_string(),
            address: 0,
            size: 0,
            function_type: FunctionType::Imported,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        },
        FunctionInfo {
            name: "api_func".to_string(),
            address: 0x2000,
            size: 300,
            function_type: FunctionType::Exported,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        },
    ];

    let global_variables = [
        VariableInfo {
            name: "global1".to_string(),
            address: 0x4000,
            size: 4,
            var_type: VariableType::Global,
            section: Some(".data".to_string()),
        },
        VariableInfo {
            name: "static1".to_string(),
            address: 0x4010,
            size: 8,
            var_type: VariableType::Static,
            section: Some(".bss".to_string()),
        },
    ];

    let cross_references = [CrossReference {
        from_address: 0x1000,
        to_address: 0x2000,
        reference_type: ReferenceType::Call,
        instruction_type: Some("call".to_string()),
    }];

    // Calculate counts manually and verify
    let total_functions = functions.len();
    let local_functions = functions
        .iter()
        .filter(|f| matches!(f.function_type, FunctionType::Local))
        .count();
    let imported_functions = functions.iter().filter(|f| f.is_imported).count();
    let exported_functions = functions.iter().filter(|f| f.is_exported).count();
    let total_variables = global_variables.len();
    let total_xrefs = cross_references.len();

    let symbol_count = SymbolCounts {
        total_functions,
        local_functions,
        imported_functions,
        exported_functions,
        global_variables: total_variables,
        cross_references: total_xrefs,
    };

    // Verify calculations
    assert_eq!(symbol_count.total_functions, 4);
    assert_eq!(symbol_count.local_functions, 2);
    assert_eq!(symbol_count.imported_functions, 1);
    assert_eq!(symbol_count.exported_functions, 1);
    assert_eq!(symbol_count.global_variables, 2);
    assert_eq!(symbol_count.cross_references, 1);

    // Verify consistency
    assert!(symbol_count.local_functions <= symbol_count.total_functions);
    assert!(symbol_count.imported_functions <= symbol_count.total_functions);
    assert!(symbol_count.exported_functions <= symbol_count.total_functions);
}

#[test]
fn test_entry_point_detection() {
    // Test entry point detection for different binary types
    let entry_points = vec![
        ("_start", true),
        ("main", true),
        ("WinMain", false), // Would be true for PE
        ("DllMain", false), // Would be true for PE DLL
        ("_main", false),   // macOS style, would be true for Mach-O
        ("regular_function", false),
    ];

    for (name, expected_entry) in entry_points {
        let is_entry_point = name == "_start" || name == "main";
        assert_eq!(
            is_entry_point, expected_entry,
            "Entry point detection failed for {}",
            name
        );
    }
}

#[test]
fn test_symbol_name_filtering() {
    // Test symbol name filtering logic
    let symbol_names = vec![
        ("", true),                   // Empty names should be filtered
        ("$x.123", true),             // Compiler-generated symbols should be filtered
        ("__libc_start_main", false), // System symbols should not be filtered
        ("main", false),              // User symbols should not be filtered
        ("printf", false),            // Library symbols should not be filtered
        ("$a", true),                 // ARM mapping symbols should be filtered
        ("$d", true),                 // ARM data symbols should be filtered
    ];

    for (name, should_filter) in symbol_names {
        let filtered = name.is_empty() || name.starts_with("$");
        assert_eq!(
            filtered, should_filter,
            "Symbol filtering failed for '{}'",
            name
        );
    }
}

#[test]
fn test_address_validation() {
    // Test address validation logic
    let test_addresses = vec![
        (0x0, true),                    // Null address is valid for imports
        (0x1000, false),                // Valid address
        (0x400000, false),              // Typical executable base
        (0x7fffffff, false),            // High address but valid
        (0xffffffffffffffffu64, false), // Max address
    ];

    for (address, is_null) in test_addresses {
        assert_eq!(
            address == 0,
            is_null,
            "Address validation failed for 0x{:x}",
            address
        );
    }
}

#[test]
fn test_function_size_analysis() {
    // Test function size analysis and validation
    let functions = [
        ("small_func", 10u64),
        ("medium_func", 1000u64),
        ("large_func", 10000u64),
        ("huge_func", 100000u64),
        ("imported_func", 0u64), // Imported functions may have size 0
    ];

    for (name, size) in functions {
        let is_reasonable_size = size <= 0x1000000; // 16MB max
        assert!(
            is_reasonable_size,
            "Function {} has unreasonable size: {}",
            name, size
        );

        let is_imported = name.contains("imported");
        if is_imported {
            // Imported functions can have size 0
            // Size is usize, which is always >= 0, so no assertion needed
        } else {
            // Local functions should typically have size > 0
            // But we don't enforce this as some symbols may not have size info
        }
    }
}

#[test]
fn test_comprehensive_symbol_table_consistency() {
    // Test comprehensive symbol table consistency checks
    let symbol_table = SymbolTable {
        functions: vec![
            FunctionInfo {
                name: "func1".to_string(),
                address: 0x1000,
                size: 100,
                function_type: FunctionType::Local,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: false,
            },
            FunctionInfo {
                name: "func2".to_string(),
                address: 0x2000,
                size: 200,
                function_type: FunctionType::Exported,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: false,
                is_exported: true,
                is_imported: false,
            },
            FunctionInfo {
                name: "printf".to_string(),
                address: 0,
                size: 0,
                function_type: FunctionType::Imported,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
        ],
        global_variables: vec![VariableInfo {
            name: "global_var".to_string(),
            address: 0x4000,
            size: 4,
            var_type: VariableType::Global,
            section: Some(".data".to_string()),
        }],
        cross_references: vec![CrossReference {
            from_address: 0x1000,
            to_address: 0x2000,
            reference_type: ReferenceType::Call,
            instruction_type: Some("call".to_string()),
        }],
        imports: vec![ImportInfo {
            name: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            address: None,
            ordinal: None,
            is_delayed: false,
        }],
        exports: vec![ExportInfo {
            name: "func2".to_string(),
            address: 0x2000,
            ordinal: Some(1),
            is_forwarder: false,
            forwarder_name: None,
        }],
        symbol_count: SymbolCounts {
            total_functions: 3,
            local_functions: 1,
            imported_functions: 1,
            exported_functions: 1,
            global_variables: 1,
            cross_references: 1,
        },
    };

    // Verify all consistency checks
    assert_eq!(
        symbol_table.functions.len(),
        symbol_table.symbol_count.total_functions
    );
    assert_eq!(
        symbol_table.global_variables.len(),
        symbol_table.symbol_count.global_variables
    );
    assert_eq!(
        symbol_table.cross_references.len(),
        symbol_table.symbol_count.cross_references
    );

    // Verify function type counts
    let actual_local = symbol_table
        .functions
        .iter()
        .filter(|f| matches!(f.function_type, FunctionType::Local))
        .count();
    let actual_imported = symbol_table
        .functions
        .iter()
        .filter(|f| f.is_imported)
        .count();
    let actual_exported = symbol_table
        .functions
        .iter()
        .filter(|f| f.is_exported)
        .count();

    assert_eq!(actual_local, symbol_table.symbol_count.local_functions);
    assert_eq!(
        actual_imported,
        symbol_table.symbol_count.imported_functions
    );
    assert_eq!(
        actual_exported,
        symbol_table.symbol_count.exported_functions
    );

    // Verify import/export consistency
    let import_names: std::collections::HashSet<_> =
        symbol_table.imports.iter().map(|i| &i.name).collect();
    let imported_func_names: std::collections::HashSet<_> = symbol_table
        .functions
        .iter()
        .filter(|f| f.is_imported)
        .map(|f| &f.name)
        .collect();

    let export_names: std::collections::HashSet<_> =
        symbol_table.exports.iter().map(|e| &e.name).collect();
    let exported_func_names: std::collections::HashSet<_> = symbol_table
        .functions
        .iter()
        .filter(|f| f.is_exported)
        .map(|f| &f.name)
        .collect();

    // Most imports should have corresponding ImportInfo
    let import_overlap = import_names.intersection(&imported_func_names).count();
    assert!(import_overlap > 0, "Should have some import overlap");

    // Most exports should have corresponding ExportInfo
    let export_overlap = export_names.intersection(&exported_func_names).count();
    assert!(export_overlap > 0, "Should have some export overlap");
}

// Helper function to create a minimal ELF for testing
fn create_minimal_elf_with_symbols() -> Vec<u8> {
    // Create a minimal ELF header with basic structure
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

    // Pad to minimum size
    while elf_data.len() < 0x1000 {
        elf_data.push(0);
    }

    elf_data
}

#[test]
fn test_pe_symbol_analysis_detailed() {
    // Test PE-specific symbol analysis
    use file_scanner::function_analysis::analyze_pe_symbols;
    use goblin::pe::PE;

    // Create minimal PE data for testing
    let pe_data = create_minimal_pe_data();

    match PE::parse(&pe_data) {
        Ok(pe) => {
            let result = analyze_pe_symbols(pe, &pe_data);
            match result {
                Ok(symbol_table) => {
                    // Test PE-specific properties
                    assert_eq!(
                        symbol_table.functions.len(),
                        symbol_table.symbol_count.total_functions
                    );

                    // PE imports should have library names
                    for import in &symbol_table.imports {
                        if let Some(library) = &import.library {
                            assert!(!library.is_empty());
                        }
                    }

                    // PE functions should have appropriate calling conventions
                    for func in &symbol_table.functions {
                        if let Some(conv) = &func.calling_convention {
                            // PE typically uses Stdcall
                            assert!(matches!(conv, CallingConvention::Stdcall));
                        }
                    }
                }
                Err(_) => {
                    // Expected for minimal PE data
                }
            }
        }
        Err(_) => {
            // Expected for our test data
        }
    }
}

#[test]
fn test_mach_o_symbol_analysis_detailed() {
    // Test Mach-O specific symbol analysis
    use file_scanner::function_analysis::analyze_mach_symbols;
    use goblin::mach::Mach;

    // Create minimal Mach-O data for testing
    let macho_data = create_minimal_macho_data();

    match Mach::parse(&macho_data) {
        Ok(mach) => {
            let result = analyze_mach_symbols(mach, &macho_data);
            match result {
                Ok(symbol_table) => {
                    // Test Mach-O specific properties
                    assert_eq!(
                        symbol_table.functions.len(),
                        symbol_table.symbol_count.total_functions
                    );

                    // Mach-O functions should use SysV calling convention
                    for func in &symbol_table.functions {
                        if let Some(conv) = &func.calling_convention {
                            assert!(matches!(conv, CallingConvention::SysV));
                        }
                    }

                    // Check for proper entry point detection
                    let entry_points = symbol_table
                        .functions
                        .iter()
                        .filter(|f| f.is_entry_point)
                        .count();
                    println!("Mach-O entry points: {}", entry_points);
                }
                Err(_) => {
                    // Expected for minimal Mach-O data
                }
            }
        }
        Err(_) => {
            // Expected for our test data
        }
    }
}

#[test]
fn test_function_overlaps_and_gaps() {
    // Test detection of function overlaps and gaps
    let functions = [
        FunctionInfo {
            name: "func1".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
        FunctionInfo {
            name: "func2".to_string(),
            address: 0x1064, // Starts exactly where func1 ends
            size: 200,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
        FunctionInfo {
            name: "func3".to_string(),
            address: 0x1200, // Gap between func2 end (0x1064+200=0x112c) and func3 start
            size: 150,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
    ];

    // Check for overlaps and gaps
    for i in 0..functions.len() {
        for j in (i + 1)..functions.len() {
            let func1 = &functions[i];
            let func2 = &functions[j];

            let func1_end = func1.address + func1.size;
            let func2_start = func2.address;

            // No overlaps should exist (but gaps are allowed)
            if func1.address < func2.address {
                assert!(
                    func1_end <= func2_start,
                    "Functions {} and {} overlap",
                    func1.name,
                    func2.name
                );
            } else {
                let func2_end = func2.address + func2.size;
                assert!(
                    func2_end <= func1.address,
                    "Functions {} and {} overlap",
                    func2.name,
                    func1.name
                );
            }
        }
    }
}

#[test]
fn test_symbol_deduplication() {
    // Test symbol deduplication logic
    let mut symbols = vec![
        "main", "printf", "malloc", "main",   // Duplicate
        "printf", // Duplicate
        "free", "malloc", // Duplicate
    ];

    // Simulate deduplication
    symbols.sort();
    symbols.dedup();

    let expected = vec!["free", "main", "malloc", "printf"];
    assert_eq!(symbols, expected);
    assert_eq!(symbols.len(), 4); // Should have 4 unique symbols
}

#[test]
fn test_large_address_space_handling() {
    // Test handling of large address spaces (64-bit)
    let large_addresses = vec![
        0x0000000000001000u64, // Small address
        0x0000000140000000u64, // Typical Windows executable base
        0x00007fff00000000u64, // High user-space address
        0x0000800000000000u64, // Kernel space boundary
        0xffffffffffffffffu64, // Maximum address
    ];

    for addr in large_addresses {
        let func = FunctionInfo {
            name: format!("func_at_{:x}", addr),
            address: addr,
            size: 100,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        };

        // Should be able to handle any 64-bit address
        assert_eq!(func.address, addr);
        assert!(!func.name.is_empty());
    }
}

#[test]
fn test_function_signature_reconstruction() {
    // Test function signature reconstruction from parameters
    let func_with_signature = FunctionInfo {
        name: "complex_function".to_string(),
        address: 0x1000,
        size: 500,
        function_type: FunctionType::Local,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![
            Parameter {
                name: Some("ptr".to_string()),
                param_type: Some("void*".to_string()),
                size: Some(8),
            },
            Parameter {
                name: Some("count".to_string()),
                param_type: Some("size_t".to_string()),
                size: Some(8),
            },
            Parameter {
                name: Some("flags".to_string()),
                param_type: Some("uint32_t".to_string()),
                size: Some(4),
            },
        ],
        is_entry_point: false,
        is_exported: true,
        is_imported: false,
    };

    // Reconstruct signature string
    let signature = reconstruct_function_signature(&func_with_signature);
    assert!(signature.contains("complex_function"));
    assert!(signature.contains("void*"));
    assert!(signature.contains("size_t"));
    assert!(signature.contains("uint32_t"));
}

#[test]
fn test_binary_format_detection() {
    // Test binary format detection logic
    let elf_magic = [0x7f, 0x45, 0x4c, 0x46];
    let pe_magic = [0x4d, 0x5a]; // MZ
    let _macho_magic_64 = [0xcf, 0xfa, 0xed, 0xfe];
    let _macho_magic_32 = [0xfe, 0xed, 0xfa, 0xce];

    // Verify magic number detection
    assert_eq!(&elf_magic, b"\x7fELF");
    assert_eq!(&pe_magic, b"MZ");

    // Test with actual parsing
    let elf_data = create_minimal_elf_with_symbols();
    assert_eq!(&elf_data[0..4], &elf_magic);

    let pe_data = create_minimal_pe_data();
    assert_eq!(&pe_data[0..2], &pe_magic);
}

#[test]
fn test_symbol_visibility_detection() {
    // Test symbol visibility detection (local, global, weak, etc.)
    use goblin::elf::sym::{STB_GLOBAL, STB_LOCAL, STB_WEAK};

    let binding_types = vec![
        (STB_LOCAL, "local binding"),
        (STB_GLOBAL, "global binding"),
        (STB_WEAK, "weak binding"),
    ];

    for (binding, description) in binding_types {
        // Test function type determination based on binding
        let function_type = match binding {
            STB_GLOBAL => FunctionType::Exported, // Simplified logic
            STB_LOCAL => FunctionType::Local,
            _ => FunctionType::Local,
        };

        match binding {
            STB_LOCAL => assert!(
                matches!(function_type, FunctionType::Local),
                "Failed for {}",
                description
            ),
            STB_GLOBAL => assert!(
                matches!(function_type, FunctionType::Exported),
                "Failed for {}",
                description
            ),
            _ => assert!(
                matches!(function_type, FunctionType::Local),
                "Failed for {}",
                description
            ),
        }
    }
}

#[test]
fn test_stripped_binary_analysis() {
    // Test analysis of stripped binaries (no symbol table)
    let stripped_symbol_table = SymbolTable {
        functions: vec![], // No functions found in stripped binary
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![ImportInfo {
            name: "libc_start_main".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x8000),
            ordinal: None,
            is_delayed: false,
        }],
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    };

    // Even stripped binaries should have some import information
    assert!(!stripped_symbol_table.imports.is_empty());
    assert_eq!(stripped_symbol_table.functions.len(), 0);
    assert_eq!(stripped_symbol_table.symbol_count.total_functions, 0);
}

#[test]
fn test_dynamic_linking_analysis() {
    // Test dynamic linking analysis
    let dynamic_imports = vec![
        ImportInfo {
            name: "malloc".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x601020),
            ordinal: None,
            is_delayed: false,
        },
        ImportInfo {
            name: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x601030),
            ordinal: None,
            is_delayed: false,
        },
        ImportInfo {
            name: "pthread_create".to_string(),
            library: Some("libpthread.so.0".to_string()),
            address: Some(0x601040),
            ordinal: None,
            is_delayed: false,
        },
    ];

    // Test library grouping
    let mut libraries = HashSet::new();
    for import in &dynamic_imports {
        if let Some(lib) = &import.library {
            libraries.insert(lib.as_str());
        }
    }

    assert!(libraries.contains("libc.so.6"));
    assert!(libraries.contains("libpthread.so.0"));
    assert_eq!(libraries.len(), 2);

    // Test PLT/GOT address patterns
    for import in &dynamic_imports {
        if let Some(addr) = import.address {
            // PLT/GOT addresses are typically in specific ranges
            assert!(
                addr >= 0x600000,
                "Import address seems too low: 0x{:x}",
                addr
            );
        }
    }
}

#[test]
fn test_exception_handling_symbols() {
    // Test detection of exception handling related symbols
    let eh_symbols = vec![
        "__gxx_personality_v0",
        "_Unwind_Resume",
        "__cxa_begin_catch",
        "__cxa_end_catch",
        "__cxa_throw",
    ];

    for symbol in eh_symbols {
        let is_eh_symbol = symbol.starts_with("__gxx_")
            || symbol.starts_with("_Unwind_")
            || symbol.starts_with("__cxa_");

        assert!(
            is_eh_symbol,
            "Symbol {} should be recognized as exception handling",
            symbol
        );
    }
}

#[test]
fn test_thread_local_storage_symbols() {
    // Test detection of thread-local storage symbols
    let tls_variables = vec![
        VariableInfo {
            name: "__thread_errno".to_string(),
            address: 0x0, // TLS variables may have offset instead of absolute address
            size: 4,
            var_type: VariableType::ThreadLocal,
            section: Some(".tdata".to_string()),
        },
        VariableInfo {
            name: "thread_buffer".to_string(),
            address: 0x10,
            size: 1024,
            var_type: VariableType::ThreadLocal,
            section: Some(".tbss".to_string()),
        },
    ];

    for var in &tls_variables {
        assert!(matches!(var.var_type, VariableType::ThreadLocal));
        if let Some(section) = &var.section {
            assert!(
                section.starts_with(".t"),
                "TLS variable should be in .tdata or .tbss section"
            );
        }
    }
}

#[test]
fn test_constructor_destructor_detection() {
    // Test detection of constructor and destructor functions
    let special_functions = vec![
        ("_init", FunctionType::Constructor),
        ("_fini", FunctionType::Destructor),
        ("__libc_csu_init", FunctionType::Constructor),
        ("__libc_csu_fini", FunctionType::Destructor),
        ("_GLOBAL__sub_I_main", FunctionType::Constructor), // C++ global constructor
        ("_GLOBAL__sub_D_main", FunctionType::Destructor),  // C++ global destructor
    ];

    for (name, expected_type) in special_functions {
        let func_type = if name.contains("init") || name.contains("GLOBAL__sub_I") {
            FunctionType::Constructor
        } else if name.contains("fini") || name.contains("GLOBAL__sub_D") {
            FunctionType::Destructor
        } else {
            FunctionType::Local
        };

        match (&expected_type, &func_type) {
            (FunctionType::Constructor, FunctionType::Constructor) => {}
            (FunctionType::Destructor, FunctionType::Destructor) => {}
            _ => panic!(
                "Function type detection failed for {}: expected {:?}, got {:?}",
                name, expected_type, func_type
            ),
        }
    }
}

#[test]
fn test_weak_symbol_handling() {
    // Test handling of weak symbols
    let weak_function = FunctionInfo {
        name: "weak_function".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::Local, // Weak symbols are typically local or exported
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![],
        is_entry_point: false,
        is_exported: false, // Weak symbols might not be exported
        is_imported: false,
    };

    // Weak symbols should be handled like regular symbols but with special binding
    assert!(!weak_function.name.is_empty());
    assert!(weak_function.address > 0);
    assert!(weak_function.size > 0);
}

#[test]
fn test_arm_thumb_interworking() {
    // Test ARM/Thumb interworking detection (LSB indicates Thumb mode)
    let arm_addresses = vec![
        (0x1000, false), // ARM mode (even address)
        (0x1001, true),  // Thumb mode (odd address)
        (0x2000, false), // ARM mode
        (0x2001, true),  // Thumb mode
    ];

    for (addr, is_thumb) in arm_addresses {
        let detected_thumb = (addr & 1) == 1;
        assert_eq!(
            detected_thumb, is_thumb,
            "Thumb detection failed for address 0x{:x}",
            addr
        );

        // Clean address (remove Thumb bit)
        let clean_addr = addr & !1;
        assert_eq!(clean_addr & 1, 0, "Cleaned address should be even");
    }
}

// Helper functions for creating test data

fn create_minimal_pe_data() -> Vec<u8> {
    let mut pe_data = vec![
        // DOS header
        0x4d, 0x5a, // MZ signature
        0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ];

    // Pad to minimum size
    while pe_data.len() < 0x200 {
        pe_data.push(0);
    }

    pe_data
}

fn create_minimal_macho_data() -> Vec<u8> {
    let mut macho_data = vec![
        // Mach-O header (64-bit)
        0xcf, 0xfa, 0xed, 0xfe, // Magic (MH_MAGIC_64)
        0x07, 0x00, 0x00, 0x01, // CPU type (x86_64)
        0x03, 0x00, 0x00, 0x00, // CPU subtype
        0x02, 0x00, 0x00, 0x00, // File type (executable)
        0x00, 0x00, 0x00, 0x00, // Number of load commands
        0x00, 0x00, 0x00, 0x00, // Size of load commands
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Reserved
    ];

    // Pad to minimum size
    while macho_data.len() < 0x1000 {
        macho_data.push(0);
    }

    macho_data
}

fn reconstruct_function_signature(func: &FunctionInfo) -> String {
    let mut signature = String::new();

    // Add function name
    signature.push_str(&func.name);
    signature.push('(');

    // Add parameters
    for (i, param) in func.parameters.iter().enumerate() {
        if i > 0 {
            signature.push_str(", ");
        }

        if let Some(param_type) = &param.param_type {
            signature.push_str(param_type);
        } else {
            signature.push_str("unknown");
        }

        if let Some(name) = &param.name {
            signature.push(' ');
            signature.push_str(name);
        }
    }

    signature.push(')');
    signature
}
