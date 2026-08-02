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

use file_scanner::function_analysis::*;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

// Test individual functions with direct calls rather than complex binary parsing
#[test]
fn test_function_type_variants() {
    // Test all FunctionType variants for serialization coverage
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
        let json = serde_json::to_string(&func_type).unwrap();
        let deserialized: FunctionType = serde_json::from_str(&json).unwrap();
        // Test equality through Debug representation since FunctionType doesn't implement PartialEq
        assert_eq!(format!("{func_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_calling_convention_variants() {
    // Test all CallingConvention variants
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
        let json = serde_json::to_string(&convention).unwrap();
        let deserialized: CallingConvention = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{convention:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_variable_type_variants() {
    // Test all VariableType variants
    let types = vec![
        VariableType::Global,
        VariableType::Static,
        VariableType::ThreadLocal,
        VariableType::Const,
    ];

    for var_type in types {
        let json = serde_json::to_string(&var_type).unwrap();
        let deserialized: VariableType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{var_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_reference_type_variants() {
    // Test all ReferenceType variants
    let types = vec![
        ReferenceType::Call,
        ReferenceType::Jump,
        ReferenceType::DataReference,
        ReferenceType::StringReference,
        ReferenceType::Import,
        ReferenceType::Export,
    ];

    for ref_type in types {
        let json = serde_json::to_string(&ref_type).unwrap();
        let deserialized: ReferenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{ref_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_function_info_all_fields() {
    // Test FunctionInfo with all fields populated
    let func = FunctionInfo {
        name: "comprehensive_test_function".to_string(),
        address: 0xDEADBEEF,
        size: 12345,
        function_type: FunctionType::Exported,
        calling_convention: Some(CallingConvention::Win64),
        parameters: vec![
            Parameter {
                name: Some("param1".to_string()),
                param_type: Some("uint64_t".to_string()),
                size: Some(8),
            },
            Parameter {
                name: Some("param2".to_string()),
                param_type: Some("char*".to_string()),
                size: Some(8),
            },
            Parameter {
                name: None, // Test None case
                param_type: Some("void*".to_string()),
                size: None, // Test None case
            },
        ],
        is_entry_point: true,
        is_exported: true,
        is_imported: false,
    };

    // Test serialization
    let json = serde_json::to_string(&func).unwrap();
    let deserialized: FunctionInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(func.name, deserialized.name);
    assert_eq!(func.address, deserialized.address);
    assert_eq!(func.size, deserialized.size);
    assert_eq!(func.parameters.len(), deserialized.parameters.len());
    assert_eq!(func.is_entry_point, deserialized.is_entry_point);
    assert_eq!(func.is_exported, deserialized.is_exported);
    assert_eq!(func.is_imported, deserialized.is_imported);
}

#[test]
fn test_symbol_table_comprehensive() {
    // Test SymbolTable with comprehensive data
    let symbol_table = SymbolTable {
        functions: vec![
            FunctionInfo {
                name: "main".to_string(),
                address: 0x1000,
                size: 100,
                function_type: FunctionType::EntryPoint,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: true,
                is_exported: true,
                is_imported: false,
            },
            FunctionInfo {
                name: "helper".to_string(),
                address: 0x2000,
                size: 50,
                function_type: FunctionType::Local,
                calling_convention: Some(CallingConvention::Cdecl),
                parameters: vec![Parameter {
                    name: Some("arg".to_string()),
                    param_type: Some("int".to_string()),
                    size: Some(4),
                }],
                is_entry_point: false,
                is_exported: false,
                is_imported: false,
            },
        ],
        global_variables: vec![
            VariableInfo {
                name: "global_var".to_string(),
                address: 0x3000,
                size: 8,
                var_type: VariableType::Global,
                section: Some(".data".to_string()),
            },
            VariableInfo {
                name: "static_var".to_string(),
                address: 0x3008,
                size: 4,
                var_type: VariableType::Static,
                section: Some(".bss".to_string()),
            },
        ],
        cross_references: vec![
            CrossReference {
                from_address: 0x1010,
                to_address: 0x2000,
                reference_type: ReferenceType::Call,
                instruction_type: Some("call".to_string()),
            },
            CrossReference {
                from_address: 0x1020,
                to_address: 0x3000,
                reference_type: ReferenceType::DataReference,
                instruction_type: Some("mov".to_string()),
            },
        ],
        imports: vec![
            ImportInfo {
                name: "printf".to_string(),
                library: Some("libc.so.6".to_string()),
                address: Some(0x4000),
                ordinal: None,
                is_delayed: false,
            },
            ImportInfo {
                name: "ExitProcess".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x4100),
                ordinal: Some(1),
                is_delayed: true,
            },
        ],
        exports: vec![
            ExportInfo {
                name: "exported_func".to_string(),
                address: 0x5000,
                ordinal: Some(1),
                is_forwarder: false,
                forwarder_name: None,
            },
            ExportInfo {
                name: "forwarded_func".to_string(),
                address: 0x5100,
                ordinal: Some(2),
                is_forwarder: true,
                forwarder_name: Some("other.dll.real_func".to_string()),
            },
        ],
        symbol_count: SymbolCounts {
            total_functions: 2,
            local_functions: 1,
            imported_functions: 2,
            exported_functions: 1,
            global_variables: 2,
            cross_references: 2,
        },
    };

    // Test serialization
    let json = serde_json::to_string(&symbol_table).unwrap();
    let deserialized: SymbolTable = serde_json::from_str(&json).unwrap();

    assert_eq!(symbol_table.functions.len(), deserialized.functions.len());
    assert_eq!(
        symbol_table.global_variables.len(),
        deserialized.global_variables.len()
    );
    assert_eq!(
        symbol_table.cross_references.len(),
        deserialized.cross_references.len()
    );
    assert_eq!(symbol_table.imports.len(), deserialized.imports.len());
    assert_eq!(symbol_table.exports.len(), deserialized.exports.len());
}

#[test]
fn test_edge_cases_and_error_conditions() {
    // Test with empty file
    let mut empty_file = NamedTempFile::new().unwrap();
    empty_file.flush().unwrap();

    let result = analyze_symbols(empty_file.path());
    assert!(result.is_err());

    // Test with very small file
    let mut small_file = NamedTempFile::new().unwrap();
    small_file.write_all(b"AB").unwrap();
    small_file.flush().unwrap();

    let result = analyze_symbols(small_file.path());
    assert!(result.is_err());

    // Test with invalid text file
    let mut text_file = NamedTempFile::new().unwrap();
    text_file
        .write_all(b"This is not a binary file at all!")
        .unwrap();
    text_file.flush().unwrap();

    let result = analyze_symbols(text_file.path());
    assert!(result.is_err());

    // Test with truncated ELF header
    let mut truncated_elf = NamedTempFile::new().unwrap();
    truncated_elf
        .write_all(&[0x7f, 0x45, 0x4c, 0x46, 0x02])
        .unwrap(); // ELF magic + 1 byte
    truncated_elf.flush().unwrap();

    let result = analyze_symbols(truncated_elf.path());
    assert!(result.is_err());
}

#[test]
fn test_parameter_edge_cases() {
    // Test Parameter with all None values
    let param_none = Parameter {
        name: None,
        param_type: None,
        size: None,
    };

    let json = serde_json::to_string(&param_none).unwrap();
    let deserialized: Parameter = serde_json::from_str(&json).unwrap();

    assert_eq!(param_none.name, deserialized.name);
    assert_eq!(param_none.param_type, deserialized.param_type);
    assert_eq!(param_none.size, deserialized.size);

    // Test Parameter with all Some values
    let param_some = Parameter {
        name: Some("test_param".to_string()),
        param_type: Some("test_type".to_string()),
        size: Some(42),
    };

    let json = serde_json::to_string(&param_some).unwrap();
    let deserialized: Parameter = serde_json::from_str(&json).unwrap();

    assert_eq!(param_some.name, deserialized.name);
    assert_eq!(param_some.param_type, deserialized.param_type);
    assert_eq!(param_some.size, deserialized.size);
}

#[test]
fn test_import_export_edge_cases() {
    // Test ImportInfo with minimal data
    let import_minimal = ImportInfo {
        name: "minimal_import".to_string(),
        library: None,
        address: None,
        ordinal: None,
        is_delayed: false,
    };

    let json = serde_json::to_string(&import_minimal).unwrap();
    let deserialized: ImportInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(import_minimal.name, deserialized.name);
    assert_eq!(import_minimal.library, deserialized.library);
    assert_eq!(import_minimal.address, deserialized.address);
    assert_eq!(import_minimal.ordinal, deserialized.ordinal);
    assert_eq!(import_minimal.is_delayed, deserialized.is_delayed);

    // Test ExportInfo with minimal data
    let export_minimal = ExportInfo {
        name: "minimal_export".to_string(),
        address: 0x1000,
        ordinal: None,
        is_forwarder: false,
        forwarder_name: None,
    };

    let json = serde_json::to_string(&export_minimal).unwrap();
    let deserialized: ExportInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(export_minimal.name, deserialized.name);
    assert_eq!(export_minimal.address, deserialized.address);
    assert_eq!(export_minimal.ordinal, deserialized.ordinal);
    assert_eq!(export_minimal.is_forwarder, deserialized.is_forwarder);
    assert_eq!(export_minimal.forwarder_name, deserialized.forwarder_name);
}

#[test]
fn test_cross_reference_comprehensive() {
    let xref = CrossReference {
        from_address: 0xABCDEF12,
        to_address: 0x12345678,
        reference_type: ReferenceType::StringReference,
        instruction_type: Some("lea".to_string()),
    };

    let json = serde_json::to_string(&xref).unwrap();
    let deserialized: CrossReference = serde_json::from_str(&json).unwrap();

    assert_eq!(xref.from_address, deserialized.from_address);
    assert_eq!(xref.to_address, deserialized.to_address);
    assert_eq!(xref.instruction_type, deserialized.instruction_type);

    // Test with None instruction_type
    let xref_none = CrossReference {
        from_address: 0x1000,
        to_address: 0x2000,
        reference_type: ReferenceType::Jump,
        instruction_type: None,
    };

    let json = serde_json::to_string(&xref_none).unwrap();
    let deserialized: CrossReference = serde_json::from_str(&json).unwrap();

    assert_eq!(xref_none.instruction_type, deserialized.instruction_type);
}

#[test]
fn test_variable_info_comprehensive() {
    // Test with section
    let var_with_section = VariableInfo {
        name: "var_with_section".to_string(),
        address: 0x10000,
        size: 16,
        var_type: VariableType::ThreadLocal,
        section: Some(".tdata".to_string()),
    };

    let json = serde_json::to_string(&var_with_section).unwrap();
    let deserialized: VariableInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(var_with_section.name, deserialized.name);
    assert_eq!(var_with_section.address, deserialized.address);
    assert_eq!(var_with_section.size, deserialized.size);
    assert_eq!(var_with_section.section, deserialized.section);

    // Test without section
    let var_no_section = VariableInfo {
        name: "var_no_section".to_string(),
        address: 0x20000,
        size: 32,
        var_type: VariableType::Const,
        section: None,
    };

    let json = serde_json::to_string(&var_no_section).unwrap();
    let deserialized: VariableInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(var_no_section.section, deserialized.section);
}

#[test]
fn test_symbol_counts_comprehensive() {
    let counts = SymbolCounts {
        total_functions: 1000,
        local_functions: 800,
        imported_functions: 150,
        exported_functions: 50,
        global_variables: 200,
        cross_references: 5000,
    };

    let json = serde_json::to_string(&counts).unwrap();
    let deserialized: SymbolCounts = serde_json::from_str(&json).unwrap();

    assert_eq!(counts.total_functions, deserialized.total_functions);
    assert_eq!(counts.local_functions, deserialized.local_functions);
    assert_eq!(counts.imported_functions, deserialized.imported_functions);
    assert_eq!(counts.exported_functions, deserialized.exported_functions);
    assert_eq!(counts.global_variables, deserialized.global_variables);
    assert_eq!(counts.cross_references, deserialized.cross_references);
}

#[test]
fn test_analyze_symbols_with_real_binaries() {
    // Test with actual system binaries if available
    let test_binaries = vec!["/bin/ls", "/usr/bin/cat", "/bin/echo"];

    for binary_path in test_binaries {
        let path = Path::new(binary_path);
        if !path.exists() {
            continue;
        }

        match analyze_symbols(path) {
            Ok(symbol_table) => {
                // Basic validation for successful analysis
                assert_eq!(
                    symbol_table.symbol_count.total_functions,
                    symbol_table.functions.len()
                );
                assert_eq!(
                    symbol_table.symbol_count.global_variables,
                    symbol_table.global_variables.len()
                );
                assert_eq!(
                    symbol_table.symbol_count.cross_references,
                    symbol_table.cross_references.len()
                );

                // Validate function counts consistency
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

                println!(
                    "Successfully analyzed {}: {} functions",
                    binary_path,
                    symbol_table.functions.len()
                );
            }
            Err(e) => {
                // It's acceptable for some binaries to fail analysis
                println!("Failed to analyze {binary_path}: {e}");
            }
        }
    }
}

#[test]
fn test_function_info_validation() {
    // Test various function configurations
    let function_configs = vec![
        // Entry point function
        FunctionInfo {
            name: "entry".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::EntryPoint,
            calling_convention: Some(CallingConvention::SysV),
            parameters: vec![],
            is_entry_point: true,
            is_exported: true,
            is_imported: false,
        },
        // Imported function
        FunctionInfo {
            name: "imported".to_string(),
            address: 0x0, // Imported functions may have no address
            size: 0,
            function_type: FunctionType::Imported,
            calling_convention: Some(CallingConvention::Unknown),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        },
        // Constructor function
        FunctionInfo {
            name: "__init".to_string(),
            address: 0x2000,
            size: 50,
            function_type: FunctionType::Constructor,
            calling_convention: None, // Test None case
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
        // Thunk function
        FunctionInfo {
            name: "thunk_func".to_string(),
            address: 0x3000,
            size: 8,
            function_type: FunctionType::Thunk,
            calling_convention: Some(CallingConvention::Fastcall),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
    ];

    for func in function_configs {
        // Test JSON serialization
        let json = serde_json::to_string(&func).unwrap();
        let deserialized: FunctionInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(func.name, deserialized.name);
        assert_eq!(func.address, deserialized.address);
        assert_eq!(func.size, deserialized.size);
        assert_eq!(func.is_entry_point, deserialized.is_entry_point);
        assert_eq!(func.is_exported, deserialized.is_exported);
        assert_eq!(func.is_imported, deserialized.is_imported);

        // Test YAML serialization as well
        let yaml = serde_yaml::to_string(&func).unwrap();
        let deserialized_yaml: FunctionInfo = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(func.name, deserialized_yaml.name);
        assert_eq!(func.address, deserialized_yaml.address);
    }
}

#[test]
fn test_error_handling_comprehensive() {
    // Test nonexistent file
    let result = analyze_symbols(Path::new("/definitely/does/not/exist"));
    assert!(result.is_err());

    // Test directory instead of file
    let result = analyze_symbols(Path::new("/tmp"));
    assert!(result.is_err());

    // Test with various invalid file contents
    let invalid_contents = vec![
        vec![],                 // Empty
        vec![0],                // Single byte
        vec![0x7f],             // Partial ELF magic
        vec![0x7f, 0x45],       // More partial ELF magic
        vec![0x7f, 0x45, 0x4c], // Even more partial ELF magic
        vec![0x4d],             // Partial PE magic
        vec![0x4d, 0x5a],       // Complete PE magic but no more data
        vec![0xca, 0xfe],       // Partial Mach-O magic
        b"Not a binary at all".to_vec(),
        vec![0xff; 1000], // Large file of invalid data
    ];

    for content in invalid_contents {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&content).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_symbols(temp_file.path());
        assert!(result.is_err(), "Expected error for content: {content:?}");
    }
}

#[test]
fn test_yaml_serialization_all_types() {
    // Test YAML serialization for all data types
    let symbol_table = SymbolTable {
        functions: vec![FunctionInfo {
            name: "yaml_test".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::Cdecl),
            parameters: vec![Parameter {
                name: Some("param".to_string()),
                param_type: Some("int".to_string()),
                size: Some(4),
            }],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        }],
        global_variables: vec![VariableInfo {
            name: "yaml_var".to_string(),
            address: 0x2000,
            size: 8,
            var_type: VariableType::Global,
            section: Some(".data".to_string()),
        }],
        cross_references: vec![CrossReference {
            from_address: 0x1010,
            to_address: 0x2000,
            reference_type: ReferenceType::DataReference,
            instruction_type: Some("mov".to_string()),
        }],
        imports: vec![ImportInfo {
            name: "yaml_import".to_string(),
            library: Some("lib.so".to_string()),
            address: Some(0x3000),
            ordinal: Some(42),
            is_delayed: true,
        }],
        exports: vec![ExportInfo {
            name: "yaml_export".to_string(),
            address: 0x4000,
            ordinal: Some(1),
            is_forwarder: false,
            forwarder_name: None,
        }],
        symbol_count: SymbolCounts {
            total_functions: 1,
            local_functions: 1,
            imported_functions: 1,
            exported_functions: 1,
            global_variables: 1,
            cross_references: 1,
        },
    };

    // Test YAML round-trip
    let yaml = serde_yaml::to_string(&symbol_table).unwrap();
    assert!(yaml.contains("yaml_test"));
    assert!(yaml.contains("yaml_var"));
    assert!(yaml.contains("yaml_import"));
    assert!(yaml.contains("yaml_export"));

    let deserialized: SymbolTable = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(symbol_table.functions.len(), deserialized.functions.len());
    assert_eq!(
        symbol_table.global_variables.len(),
        deserialized.global_variables.len()
    );
}
