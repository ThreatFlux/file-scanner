use file_scanner::function_analysis::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

/// Creates a simple ELF binary for testing
fn create_test_elf_binary() -> Vec<u8> {
    // Minimal ELF header with some fake symbols
    let mut elf_data = vec![
        // ELF header
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
    ];

    // Pad to 64 bytes (ELF header size)
    elf_data.resize(64, 0x00);

    // Add some fake section data to make it a valid-looking ELF
    elf_data.extend_from_slice(&[0x00; 200]);

    elf_data
}

/// Creates a simple PE binary for testing
fn create_test_pe_binary() -> Vec<u8> {
    let mut pe_data = vec![
        // DOS header
        0x4d, 0x5a, // MZ signature
    ];

    // Pad DOS header to 60 bytes and add PE offset
    pe_data.resize(58, 0x00);
    pe_data.extend_from_slice(&[0x80, 0x00]); // PE header offset at 0x80

    // Add padding to PE header location
    pe_data.resize(0x80, 0x00);

    // PE header
    pe_data.extend_from_slice(&[
        0x50, 0x45, 0x00, 0x00, // PE signature
        0x64, 0x86, // Machine type (x64)
        0x01, 0x00, // Number of sections
    ]);

    // Add more PE structure
    pe_data.resize(0x200, 0x00);

    pe_data
}

#[test]
fn test_function_info_creation() {
    let func = FunctionInfo {
        name: "test_function".to_string(),
        address: 0x1000,
        size: 256,
        function_type: FunctionType::Local,
        calling_convention: Some(CallingConvention::Cdecl),
        parameters: vec![],
        is_entry_point: false,
        is_exported: false,
        is_imported: false,
    };

    assert_eq!(func.name, "test_function");
    assert_eq!(func.address, 0x1000);
    assert_eq!(func.size, 256);
    assert!(matches!(func.function_type, FunctionType::Local));
    assert!(matches!(
        func.calling_convention,
        Some(CallingConvention::Cdecl)
    ));
    assert!(!func.is_entry_point);
    assert!(!func.is_exported);
    assert!(!func.is_imported);
}

#[test]
fn test_function_type_variants() {
    // Test all function type variants
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
        let func = FunctionInfo {
            name: "test".to_string(),
            address: 0x1000,
            size: 100,
            function_type: func_type.clone(),
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        };

        // Verify the type is set correctly
        assert!(std::mem::discriminant(&func.function_type) == std::mem::discriminant(&func_type));
    }
}

#[test]
fn test_calling_convention_variants() {
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
            name: "test".to_string(),
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
        assert!(
            std::mem::discriminant(&func.calling_convention.unwrap())
                == std::mem::discriminant(&convention)
        );
    }
}

#[test]
fn test_parameter_creation() {
    let param = Parameter {
        name: Some("arg1".to_string()),
        param_type: Some("int".to_string()),
        size: Some(4),
    };

    assert_eq!(param.name.unwrap(), "arg1");
    assert_eq!(param.param_type.unwrap(), "int");
    assert_eq!(param.size.unwrap(), 4);
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
    assert_eq!(var.section.unwrap(), ".data");
}

#[test]
fn test_variable_type_variants() {
    let types = vec![
        VariableType::Global,
        VariableType::Static,
        VariableType::ThreadLocal,
        VariableType::Const,
    ];

    for var_type in types {
        let var = VariableInfo {
            name: "test_var".to_string(),
            address: 0x2000,
            size: 4,
            var_type: var_type.clone(),
            section: None,
        };

        assert!(std::mem::discriminant(&var.var_type) == std::mem::discriminant(&var_type));
    }
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
    assert_eq!(xref.instruction_type.unwrap(), "call");
}

#[test]
fn test_reference_type_variants() {
    let types = vec![
        ReferenceType::Call,
        ReferenceType::Jump,
        ReferenceType::DataReference,
        ReferenceType::StringReference,
        ReferenceType::Import,
        ReferenceType::Export,
    ];

    for ref_type in types {
        let xref = CrossReference {
            from_address: 0x1000,
            to_address: 0x2000,
            reference_type: ref_type.clone(),
            instruction_type: None,
        };

        assert!(std::mem::discriminant(&xref.reference_type) == std::mem::discriminant(&ref_type));
    }
}

#[test]
fn test_import_info_creation() {
    let import = ImportInfo {
        name: "LoadLibraryA".to_string(),
        library: Some("kernel32.dll".to_string()),
        address: Some(0x1000),
        ordinal: Some(100),
        is_delayed: false,
    };

    assert_eq!(import.name, "LoadLibraryA");
    assert_eq!(import.library.unwrap(), "kernel32.dll");
    assert_eq!(import.address.unwrap(), 0x1000);
    assert_eq!(import.ordinal.unwrap(), 100);
    assert!(!import.is_delayed);
}

#[test]
fn test_export_info_creation() {
    let export = ExportInfo {
        name: "DllMain".to_string(),
        address: 0x1000,
        ordinal: Some(1),
        is_forwarder: false,
        forwarder_name: None,
    };

    assert_eq!(export.name, "DllMain");
    assert_eq!(export.address, 0x1000);
    assert_eq!(export.ordinal.unwrap(), 1);
    assert!(!export.is_forwarder);
    assert!(export.forwarder_name.is_none());
}

#[test]
fn test_symbol_counts_creation() {
    let counts = SymbolCounts {
        total_functions: 10,
        local_functions: 5,
        imported_functions: 3,
        exported_functions: 2,
        global_variables: 8,
        cross_references: 15,
    };

    assert_eq!(counts.total_functions, 10);
    assert_eq!(counts.local_functions, 5);
    assert_eq!(counts.imported_functions, 3);
    assert_eq!(counts.exported_functions, 2);
    assert_eq!(counts.global_variables, 8);
    assert_eq!(counts.cross_references, 15);
}

#[test]
fn test_symbol_table_creation() {
    let functions = vec![FunctionInfo {
        name: "main".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::EntryPoint,
        calling_convention: Some(CallingConvention::Cdecl),
        parameters: vec![],
        is_entry_point: true,
        is_exported: false,
        is_imported: false,
    }];

    let imports = vec![ImportInfo {
        name: "printf".to_string(),
        library: Some("libc.so.6".to_string()),
        address: None,
        ordinal: None,
        is_delayed: false,
    }];

    let symbol_table = SymbolTable {
        functions: functions.clone(),
        global_variables: vec![],
        cross_references: vec![],
        imports: imports.clone(),
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 1,
            local_functions: 0,
            imported_functions: 1,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    };

    assert_eq!(symbol_table.functions.len(), 1);
    assert_eq!(symbol_table.imports.len(), 1);
    assert_eq!(symbol_table.symbol_count.total_functions, 1);
    assert_eq!(symbol_table.functions[0].name, "main");
    assert_eq!(symbol_table.imports[0].name, "printf");
}

#[test]
fn test_analyze_symbols_invalid_file() {
    let temp_dir = tempdir().unwrap();
    let invalid_path = temp_dir.path().join("nonexistent.bin");

    let result = analyze_symbols(&invalid_path);
    assert!(result.is_err());
}

#[test]
fn test_analyze_symbols_invalid_binary() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("invalid.bin");

    // Create file with invalid binary data
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"This is not a valid binary").unwrap();

    let result = analyze_symbols(&file_path);
    assert!(result.is_err());
}

#[test]
fn test_entry_point_detection() {
    // Test main function detection
    let main_func = FunctionInfo {
        name: "main".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::EntryPoint,
        calling_convention: Some(CallingConvention::Cdecl),
        parameters: vec![],
        is_entry_point: true,
        is_exported: false,
        is_imported: false,
    };

    assert!(main_func.is_entry_point);
    assert!(matches!(main_func.function_type, FunctionType::EntryPoint));

    // Test _start function detection
    let start_func = FunctionInfo {
        name: "_start".to_string(),
        address: 0x1000,
        size: 50,
        function_type: FunctionType::EntryPoint,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![],
        is_entry_point: true,
        is_exported: false,
        is_imported: false,
    };

    assert!(start_func.is_entry_point);
    assert_eq!(start_func.name, "_start");
}

#[test]
fn test_import_export_classification() {
    // Test imported function
    let import_func = FunctionInfo {
        name: "CreateFileA".to_string(),
        address: 0x0,
        size: 0,
        function_type: FunctionType::Imported,
        calling_convention: Some(CallingConvention::Stdcall),
        parameters: vec![],
        is_entry_point: false,
        is_exported: false,
        is_imported: true,
    };

    assert!(import_func.is_imported);
    assert!(!import_func.is_exported);
    assert!(matches!(import_func.function_type, FunctionType::Imported));

    // Test exported function
    let export_func = FunctionInfo {
        name: "DllEntryPoint".to_string(),
        address: 0x2000,
        size: 150,
        function_type: FunctionType::Exported,
        calling_convention: Some(CallingConvention::Stdcall),
        parameters: vec![],
        is_entry_point: false,
        is_exported: true,
        is_imported: false,
    };

    assert!(export_func.is_exported);
    assert!(!export_func.is_imported);
    assert!(matches!(export_func.function_type, FunctionType::Exported));
}

#[test]
fn test_function_parameters() {
    let params = vec![
        Parameter {
            name: Some("hInstance".to_string()),
            param_type: Some("HINSTANCE".to_string()),
            size: Some(8),
        },
        Parameter {
            name: Some("lpCmdLine".to_string()),
            param_type: Some("LPSTR".to_string()),
            size: Some(8),
        },
        Parameter {
            name: Some("nCmdShow".to_string()),
            param_type: Some("int".to_string()),
            size: Some(4),
        },
    ];

    let func = FunctionInfo {
        name: "WinMain".to_string(),
        address: 0x1000,
        size: 200,
        function_type: FunctionType::EntryPoint,
        calling_convention: Some(CallingConvention::Stdcall),
        parameters: params.clone(),
        is_entry_point: true,
        is_exported: false,
        is_imported: false,
    };

    assert_eq!(func.parameters.len(), 3);
    assert_eq!(func.parameters[0].name.as_ref().unwrap(), "hInstance");
    assert_eq!(func.parameters[1].param_type.as_ref().unwrap(), "LPSTR");
    assert_eq!(func.parameters[2].size.unwrap(), 4);
}

#[test]
fn test_global_variables() {
    let global_vars = vec![
        VariableInfo {
            name: "g_instance".to_string(),
            address: 0x3000,
            size: 8,
            var_type: VariableType::Global,
            section: Some(".data".to_string()),
        },
        VariableInfo {
            name: "static_counter".to_string(),
            address: 0x3008,
            size: 4,
            var_type: VariableType::Static,
            section: Some(".bss".to_string()),
        },
    ];

    assert_eq!(global_vars.len(), 2);
    assert!(matches!(global_vars[0].var_type, VariableType::Global));
    assert!(matches!(global_vars[1].var_type, VariableType::Static));
    assert_eq!(global_vars[0].section.as_ref().unwrap(), ".data");
    assert_eq!(global_vars[1].section.as_ref().unwrap(), ".bss");
}

#[test]
fn test_cross_references() {
    let xrefs = vec![
        CrossReference {
            from_address: 0x1000,
            to_address: 0x2000,
            reference_type: ReferenceType::Call,
            instruction_type: Some("call".to_string()),
        },
        CrossReference {
            from_address: 0x1004,
            to_address: 0x3000,
            reference_type: ReferenceType::DataReference,
            instruction_type: Some("mov".to_string()),
        },
        CrossReference {
            from_address: 0x1008,
            to_address: 0x4000,
            reference_type: ReferenceType::Jump,
            instruction_type: Some("jmp".to_string()),
        },
    ];

    assert_eq!(xrefs.len(), 3);
    assert!(matches!(xrefs[0].reference_type, ReferenceType::Call));
    assert!(matches!(
        xrefs[1].reference_type,
        ReferenceType::DataReference
    ));
    assert!(matches!(xrefs[2].reference_type, ReferenceType::Jump));
}

#[test]
fn test_delayed_imports() {
    let delayed_import = ImportInfo {
        name: "MessageBoxA".to_string(),
        library: Some("user32.dll".to_string()),
        address: Some(0x5000),
        ordinal: Some(256),
        is_delayed: true,
    };

    assert!(delayed_import.is_delayed);
    assert_eq!(delayed_import.library.as_ref().unwrap(), "user32.dll");

    let regular_import = ImportInfo {
        name: "ExitProcess".to_string(),
        library: Some("kernel32.dll".to_string()),
        address: Some(0x5008),
        ordinal: Some(60),
        is_delayed: false,
    };

    assert!(!regular_import.is_delayed);
}

#[test]
fn test_forwarder_exports() {
    let forwarder_export = ExportInfo {
        name: "HeapAlloc".to_string(),
        address: 0x0,
        ordinal: Some(1),
        is_forwarder: true,
        forwarder_name: Some("ntdll.RtlAllocateHeap".to_string()),
    };

    assert!(forwarder_export.is_forwarder);
    assert_eq!(
        forwarder_export.forwarder_name.as_ref().unwrap(),
        "ntdll.RtlAllocateHeap"
    );

    let regular_export = ExportInfo {
        name: "MyFunction".to_string(),
        address: 0x6000,
        ordinal: Some(2),
        is_forwarder: false,
        forwarder_name: None,
    };

    assert!(!regular_export.is_forwarder);
    assert!(regular_export.forwarder_name.is_none());
}

#[test]
fn test_section_analysis() {
    let vars_by_section = vec![
        VariableInfo {
            name: "initialized_data".to_string(),
            address: 0x3000,
            size: 4,
            var_type: VariableType::Global,
            section: Some(".data".to_string()),
        },
        VariableInfo {
            name: "uninitialized_data".to_string(),
            address: 0x4000,
            size: 4,
            var_type: VariableType::Global,
            section: Some(".bss".to_string()),
        },
        VariableInfo {
            name: "readonly_data".to_string(),
            address: 0x5000,
            size: 4,
            var_type: VariableType::Const,
            section: Some(".rodata".to_string()),
        },
    ];

    // Group by section
    let mut sections = HashMap::new();
    for var in &vars_by_section {
        if let Some(section) = &var.section {
            sections
                .entry(section.clone())
                .or_insert_with(Vec::new)
                .push(var);
        }
    }

    assert_eq!(sections.len(), 3);
    assert!(sections.contains_key(".data"));
    assert!(sections.contains_key(".bss"));
    assert!(sections.contains_key(".rodata"));
}

#[test]
fn test_symbol_count_accuracy() {
    let functions = vec![
        FunctionInfo {
            name: "local_func".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::Cdecl),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        },
        FunctionInfo {
            name: "imported_func".to_string(),
            address: 0x0,
            size: 0,
            function_type: FunctionType::Imported,
            calling_convention: Some(CallingConvention::Stdcall),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        },
        FunctionInfo {
            name: "exported_func".to_string(),
            address: 0x2000,
            size: 150,
            function_type: FunctionType::Exported,
            calling_convention: Some(CallingConvention::Cdecl),
            parameters: vec![],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        },
    ];

    let symbol_counts = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: 0,
        cross_references: 0,
    };

    assert_eq!(symbol_counts.total_functions, 3);
    assert_eq!(symbol_counts.local_functions, 1);
    assert_eq!(symbol_counts.imported_functions, 1);
    assert_eq!(symbol_counts.exported_functions, 1);
}

#[test]
fn test_serialization_deserialization() {
    let func = FunctionInfo {
        name: "test_func".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::Local,
        calling_convention: Some(CallingConvention::Cdecl),
        parameters: vec![Parameter {
            name: Some("arg1".to_string()),
            param_type: Some("int".to_string()),
            size: Some(4),
        }],
        is_entry_point: false,
        is_exported: false,
        is_imported: false,
    };

    // Test JSON serialization
    let json = serde_json::to_string(&func).unwrap();
    let deserialized: FunctionInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(func.name, deserialized.name);
    assert_eq!(func.address, deserialized.address);
    assert_eq!(func.size, deserialized.size);
    assert_eq!(func.parameters.len(), deserialized.parameters.len());
}
