use anyhow::Result;
use goblin::{elf, mach, pe, Object};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub function_type: FunctionType,
    pub calling_convention: Option<CallingConvention>,
    pub parameters: Vec<Parameter>,
    pub is_entry_point: bool,
    pub is_exported: bool,
    pub is_imported: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FunctionType {
    Local,
    Imported,
    Exported,
    Thunk,
    Constructor,
    Destructor,
    EntryPoint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    SysV,
    Win64,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameter {
    pub name: Option<String>,
    pub param_type: Option<String>,
    pub size: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VariableInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub var_type: VariableType,
    pub section: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VariableType {
    Global,
    Static,
    ThreadLocal,
    Const,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrossReference {
    pub from_address: u64,
    pub to_address: u64,
    pub reference_type: ReferenceType,
    pub instruction_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ReferenceType {
    Call,
    Jump,
    DataReference,
    StringReference,
    Import,
    Export,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SymbolTable {
    pub functions: Vec<FunctionInfo>,
    pub global_variables: Vec<VariableInfo>,
    pub cross_references: Vec<CrossReference>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub symbol_count: SymbolCounts,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImportInfo {
    pub name: String,
    pub library: Option<String>,
    pub address: Option<u64>,
    pub ordinal: Option<u16>,
    pub is_delayed: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
    pub is_forwarder: bool,
    pub forwarder_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SymbolCounts {
    pub total_functions: usize,
    pub local_functions: usize,
    pub imported_functions: usize,
    pub exported_functions: usize,
    pub global_variables: usize,
    pub cross_references: usize,
}

pub fn analyze_symbols(path: &Path) -> Result<SymbolTable> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    match Object::parse(&buffer)? {
        Object::Elf(elf) => analyze_elf_symbols(elf, &buffer),
        Object::PE(pe) => analyze_pe_symbols(pe, &buffer),
        Object::Mach(mach) => analyze_mach_symbols(mach, &buffer),
        _ => Err(anyhow::anyhow!(
            "Unsupported binary format for symbol analysis"
        )),
    }
}

fn analyze_elf_symbols(elf: elf::Elf, _buffer: &[u8]) -> Result<SymbolTable> {
    let mut functions = Vec::new();
    let mut global_variables = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let cross_references = Vec::new();

    // Analyze ELF symbols
    for sym in elf.syms.iter() {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();

        if name.is_empty() || name.starts_with("$") {
            continue;
        }

        let sym_type = sym.st_type();
        let binding = sym.st_bind();
        let address = sym.st_value;
        let size = sym.st_size;

        match sym_type {
            goblin::elf::sym::STT_FUNC => {
                let function_type = match binding {
                    goblin::elf::sym::STB_GLOBAL => {
                        if sym.st_shndx == 0 {
                            FunctionType::Imported
                        } else {
                            FunctionType::Exported
                        }
                    }
                    goblin::elf::sym::STB_LOCAL => FunctionType::Local,
                    _ => FunctionType::Local,
                };

                let is_entry_point =
                    name == "_start" || name == "main" || address == elf.header.e_entry;
                let is_exported = binding == goblin::elf::sym::STB_GLOBAL && sym.st_shndx != 0;
                let is_imported = sym.st_shndx == 0;

                functions.push(FunctionInfo {
                    name: name.clone(),
                    address,
                    size,
                    function_type,
                    calling_convention: Some(CallingConvention::SysV),
                    parameters: Vec::new(), // Would need debug info for this
                    is_entry_point,
                    is_exported,
                    is_imported,
                });

                // Add to imports/exports lists
                if is_imported {
                    imports.push(ImportInfo {
                        name: name.clone(),
                        library: None, // ELF doesn't directly specify library
                        address: if address != 0 { Some(address) } else { None },
                        ordinal: None,
                        is_delayed: false,
                    });
                } else if is_exported {
                    exports.push(ExportInfo {
                        name: name.clone(),
                        address,
                        ordinal: None,
                        is_forwarder: false,
                        forwarder_name: None,
                    });
                }
            }
            goblin::elf::sym::STT_OBJECT => {
                if binding == goblin::elf::sym::STB_GLOBAL || binding == goblin::elf::sym::STB_LOCAL
                {
                    global_variables.push(VariableInfo {
                        name: name.clone(),
                        address,
                        size,
                        var_type: if binding == goblin::elf::sym::STB_GLOBAL {
                            VariableType::Global
                        } else {
                            VariableType::Static
                        },
                        section: None, // Could be enhanced to include section name
                    });
                }
            }
            _ => {}
        }
    }

    // Analyze dynamic symbols if available
    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();

        if name.is_empty() || functions.iter().any(|f| f.name == name) {
            continue;
        }

        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_shndx == 0 {
            // This is an imported function
            functions.push(FunctionInfo {
                name: name.clone(),
                address: sym.st_value,
                size: sym.st_size,
                function_type: FunctionType::Imported,
                calling_convention: Some(CallingConvention::SysV),
                parameters: Vec::new(),
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            });

            imports.push(ImportInfo {
                name: name.clone(),
                library: None,
                address: if sym.st_value != 0 {
                    Some(sym.st_value)
                } else {
                    None
                },
                ordinal: None,
                is_delayed: false,
            });
        }
    }

    let symbol_count = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: global_variables.len(),
        cross_references: cross_references.len(),
    };

    Ok(SymbolTable {
        functions,
        global_variables,
        cross_references,
        imports,
        exports,
        symbol_count,
    })
}

fn analyze_pe_symbols(pe: pe::PE, _buffer: &[u8]) -> Result<SymbolTable> {
    let mut functions = Vec::new();
    let global_variables = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let cross_references = Vec::new();

    // Analyze PE imports
    for import in pe.imports.iter() {
        imports.push(ImportInfo {
            name: import.name.to_string(),
            library: Some(import.dll.to_string()),
            address: Some(import.rva as u64),
            ordinal: Some(import.ordinal),
            is_delayed: false, // Would need to check delay import table
        });

        // Add imported functions to function list
        functions.push(FunctionInfo {
            name: import.name.to_string(),
            address: import.rva as u64,
            size: 0, // PE imports don't have size info
            function_type: FunctionType::Imported,
            calling_convention: Some(CallingConvention::Stdcall), // Common for Windows
            parameters: Vec::new(),
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        });
    }

    // Analyze PE exports
    for export in pe.exports.iter() {
        let export_name = export.name.unwrap_or("").to_string();
        let export_address = export.rva as u64;

        exports.push(ExportInfo {
            name: export_name.clone(),
            address: export_address,
            ordinal: None, // PE exports don't always have ordinals in goblin
            is_forwarder: export.reexport.is_some(),
            forwarder_name: if export.reexport.is_some() {
                Some("forwarded".to_string())
            } else {
                None
            },
        });

        // Add exported functions to function list
        if export.name.is_some() {
            // For PE files, we'll consider main/WinMain/DllMain as potential entry points
            let name = export.name.unwrap();
            let is_entry_point = name == "main" || name == "WinMain" || name == "DllMain";

            functions.push(FunctionInfo {
                name: export_name.clone(),
                address: export_address,
                size: 0, // PE doesn't provide function sizes
                function_type: FunctionType::Exported,
                calling_convention: Some(CallingConvention::Stdcall),
                parameters: Vec::new(),
                is_entry_point,
                is_exported: true,
                is_imported: false,
            });
        }
    }

    let symbol_count = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: global_variables.len(),
        cross_references: cross_references.len(),
    };

    Ok(SymbolTable {
        functions,
        global_variables,
        cross_references,
        imports,
        exports,
        symbol_count,
    })
}

fn analyze_mach_symbols(mach: mach::Mach, _buffer: &[u8]) -> Result<SymbolTable> {
    let mut functions = Vec::new();
    let mut global_variables = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let cross_references = Vec::new();

    match mach {
        mach::Mach::Fat(_) => {
            // For fat binaries, we'd need to choose an architecture
            // For now, return empty symbol table
        }
        mach::Mach::Binary(macho) => {
            // Analyze Mach-O symbols
            for sym in macho.symbols().flatten() {
                let name = sym.0.to_string();
                let nlist = sym.1;

                if name.is_empty() || name.starts_with("__") {
                    continue;
                }

                let address = nlist.n_value;
                let is_external = nlist.is_global();

                // Check if this is a function symbol (simplified check)
                if nlist.n_type & mach::symbols::N_TYPE == mach::symbols::N_SECT {
                    let function_type = if is_external {
                        FunctionType::Exported
                    } else {
                        FunctionType::Local
                    };

                    let is_entry_point = name == "_main" || name == "main";

                    functions.push(FunctionInfo {
                        name: name.clone(),
                        address,
                        size: 0, // Mach-O doesn't provide function sizes directly
                        function_type,
                        calling_convention: Some(CallingConvention::SysV),
                        parameters: Vec::new(),
                        is_entry_point,
                        is_exported: is_external,
                        is_imported: false,
                    });

                    if is_external {
                        exports.push(ExportInfo {
                            name: name.clone(),
                            address,
                            ordinal: None,
                            is_forwarder: false,
                            forwarder_name: None,
                        });
                    }
                } else if nlist.n_type & mach::symbols::N_TYPE == mach::symbols::N_SECT
                    && !name.contains("func")
                {
                    global_variables.push(VariableInfo {
                        name: name.clone(),
                        address,
                        size: 0, // Size not available
                        var_type: if is_external {
                            VariableType::Global
                        } else {
                            VariableType::Static
                        },
                        section: None,
                    });
                }
            }

            // Analyze imports (undefined symbols)
            for sym in macho.symbols().flatten() {
                let name = sym.0.to_string();
                let nlist = sym.1;

                if nlist.is_undefined() && !name.is_empty() {
                    imports.push(ImportInfo {
                        name: name.clone(),
                        library: None, // Mach-O doesn't specify library directly
                        address: None,
                        ordinal: None,
                        is_delayed: false,
                    });

                    functions.push(FunctionInfo {
                        name: name.clone(),
                        address: 0,
                        size: 0,
                        function_type: FunctionType::Imported,
                        calling_convention: Some(CallingConvention::SysV),
                        parameters: Vec::new(),
                        is_entry_point: false,
                        is_exported: false,
                        is_imported: true,
                    });
                }
            }
        }
    }

    let symbol_count = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: global_variables.len(),
        cross_references: cross_references.len(),
    };

    Ok(SymbolTable {
        functions,
        global_variables,
        cross_references,
        imports,
        exports,
        symbol_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_function_info_creation() {
        let func = FunctionInfo {
            name: "test_function".to_string(),
            address: 0x1000,
            size: 64,
            function_type: FunctionType::Local,
            calling_convention: Some(CallingConvention::Cdecl),
            parameters: vec![Parameter {
                name: Some("param1".to_string()),
                param_type: Some("int".to_string()),
                size: Some(4),
            }],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        };

        assert_eq!(func.name, "test_function");
        assert_eq!(func.address, 0x1000);
        assert_eq!(func.size, 64);
        assert!(matches!(func.function_type, FunctionType::Local));
        assert!(matches!(
            func.calling_convention,
            Some(CallingConvention::Cdecl)
        ));
        assert_eq!(func.parameters.len(), 1);
        assert_eq!(func.parameters[0].name, Some("param1".to_string()));
        assert!(!func.is_entry_point);
        assert!(!func.is_exported);
        assert!(!func.is_imported);
    }

    #[test]
    fn test_function_type_variants() {
        let types = vec![
            FunctionType::Local,
            FunctionType::Imported,
            FunctionType::Exported,
            FunctionType::Thunk,
            FunctionType::Constructor,
            FunctionType::Destructor,
            FunctionType::EntryPoint,
        ];

        // Test that all variants can be created and are distinct
        for (i, func_type) in types.iter().enumerate() {
            let serialized = serde_json::to_string(func_type).unwrap();
            assert!(!serialized.is_empty());

            // Each variant should serialize differently
            for (j, other_type) in types.iter().enumerate() {
                if i != j {
                    let other_serialized = serde_json::to_string(other_type).unwrap();
                    assert_ne!(serialized, other_serialized);
                }
            }
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
            let serialized = serde_json::to_string(&convention).unwrap();
            let deserialized: CallingConvention = serde_json::from_str(&serialized).unwrap();

            // Test round-trip serialization
            match convention {
                CallingConvention::Cdecl => {
                    assert!(matches!(deserialized, CallingConvention::Cdecl))
                }
                CallingConvention::Stdcall => {
                    assert!(matches!(deserialized, CallingConvention::Stdcall))
                }
                CallingConvention::Fastcall => {
                    assert!(matches!(deserialized, CallingConvention::Fastcall))
                }
                CallingConvention::Thiscall => {
                    assert!(matches!(deserialized, CallingConvention::Thiscall))
                }
                CallingConvention::Vectorcall => {
                    assert!(matches!(deserialized, CallingConvention::Vectorcall))
                }
                CallingConvention::SysV => assert!(matches!(deserialized, CallingConvention::SysV)),
                CallingConvention::Win64 => {
                    assert!(matches!(deserialized, CallingConvention::Win64))
                }
                CallingConvention::Unknown => {
                    assert!(matches!(deserialized, CallingConvention::Unknown))
                }
            }
        }
    }

    #[test]
    fn test_parameter_creation() {
        let param = Parameter {
            name: Some("test_param".to_string()),
            param_type: Some("const char*".to_string()),
            size: Some(8),
        };

        assert_eq!(param.name, Some("test_param".to_string()));
        assert_eq!(param.param_type, Some("const char*".to_string()));
        assert_eq!(param.size, Some(8));

        // Test parameter with no information
        let empty_param = Parameter {
            name: None,
            param_type: None,
            size: None,
        };

        assert!(empty_param.name.is_none());
        assert!(empty_param.param_type.is_none());
        assert!(empty_param.size.is_none());
    }

    #[test]
    fn test_variable_info_creation() {
        let var = VariableInfo {
            name: "global_var".to_string(),
            address: 0x2000,
            size: 4,
            var_type: VariableType::Global,
            section: Some(".data".to_string()),
        };

        assert_eq!(var.name, "global_var");
        assert_eq!(var.address, 0x2000);
        assert_eq!(var.size, 4);
        assert!(matches!(var.var_type, VariableType::Global));
        assert_eq!(var.section, Some(".data".to_string()));
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
            let serialized = serde_json::to_string(&var_type).unwrap();
            let deserialized: VariableType = serde_json::from_str(&serialized).unwrap();

            match var_type {
                VariableType::Global => assert!(matches!(deserialized, VariableType::Global)),
                VariableType::Static => assert!(matches!(deserialized, VariableType::Static)),
                VariableType::ThreadLocal => {
                    assert!(matches!(deserialized, VariableType::ThreadLocal))
                }
                VariableType::Const => assert!(matches!(deserialized, VariableType::Const)),
            }
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
        assert_eq!(xref.instruction_type, Some("call".to_string()));
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
            let serialized = serde_json::to_string(&ref_type).unwrap();
            let deserialized: ReferenceType = serde_json::from_str(&serialized).unwrap();

            match ref_type {
                ReferenceType::Call => assert!(matches!(deserialized, ReferenceType::Call)),
                ReferenceType::Jump => assert!(matches!(deserialized, ReferenceType::Jump)),
                ReferenceType::DataReference => {
                    assert!(matches!(deserialized, ReferenceType::DataReference))
                }
                ReferenceType::StringReference => {
                    assert!(matches!(deserialized, ReferenceType::StringReference))
                }
                ReferenceType::Import => assert!(matches!(deserialized, ReferenceType::Import)),
                ReferenceType::Export => assert!(matches!(deserialized, ReferenceType::Export)),
            }
        }
    }

    #[test]
    fn test_import_info_creation() {
        let import = ImportInfo {
            name: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x3000),
            ordinal: Some(42),
            is_delayed: false,
        };

        assert_eq!(import.name, "printf");
        assert_eq!(import.library, Some("libc.so.6".to_string()));
        assert_eq!(import.address, Some(0x3000));
        assert_eq!(import.ordinal, Some(42));
        assert!(!import.is_delayed);

        // Test delayed import
        let delayed_import = ImportInfo {
            name: "DelayedFunc".to_string(),
            library: Some("kernel32.dll".to_string()),
            address: None,
            ordinal: None,
            is_delayed: true,
        };

        assert!(delayed_import.is_delayed);
        assert!(delayed_import.address.is_none());
        assert!(delayed_import.ordinal.is_none());
    }

    #[test]
    fn test_export_info_creation() {
        let export = ExportInfo {
            name: "exported_func".to_string(),
            address: 0x4000,
            ordinal: Some(1),
            is_forwarder: false,
            forwarder_name: None,
        };

        assert_eq!(export.name, "exported_func");
        assert_eq!(export.address, 0x4000);
        assert_eq!(export.ordinal, Some(1));
        assert!(!export.is_forwarder);
        assert!(export.forwarder_name.is_none());

        // Test forwarder export
        let forwarder = ExportInfo {
            name: "forwarder_func".to_string(),
            address: 0,
            ordinal: None,
            is_forwarder: true,
            forwarder_name: Some("other_dll.real_func".to_string()),
        };

        assert!(forwarder.is_forwarder);
        assert_eq!(
            forwarder.forwarder_name,
            Some("other_dll.real_func".to_string())
        );
    }

    #[test]
    fn test_symbol_counts_calculation() {
        let functions = vec![
            FunctionInfo {
                name: "local_func".to_string(),
                address: 0x1000,
                size: 32,
                function_type: FunctionType::Local,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: false,
            },
            FunctionInfo {
                name: "imported_func".to_string(),
                address: 0x2000,
                size: 0,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "exported_func".to_string(),
                address: 0x3000,
                size: 64,
                function_type: FunctionType::Exported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: true,
                is_imported: false,
            },
        ];

        let global_variables = vec![
            VariableInfo {
                name: "var1".to_string(),
                address: 0x5000,
                size: 4,
                var_type: VariableType::Global,
                section: None,
            },
            VariableInfo {
                name: "var2".to_string(),
                address: 0x5004,
                size: 8,
                var_type: VariableType::Static,
                section: None,
            },
        ];

        let cross_references = vec![CrossReference {
            from_address: 0x1000,
            to_address: 0x2000,
            reference_type: ReferenceType::Call,
            instruction_type: None,
        }];

        let symbol_count = SymbolCounts {
            total_functions: functions.len(),
            local_functions: functions
                .iter()
                .filter(|f| matches!(f.function_type, FunctionType::Local))
                .count(),
            imported_functions: functions.iter().filter(|f| f.is_imported).count(),
            exported_functions: functions.iter().filter(|f| f.is_exported).count(),
            global_variables: global_variables.len(),
            cross_references: cross_references.len(),
        };

        assert_eq!(symbol_count.total_functions, 3);
        assert_eq!(symbol_count.local_functions, 1);
        assert_eq!(symbol_count.imported_functions, 1);
        assert_eq!(symbol_count.exported_functions, 1);
        assert_eq!(symbol_count.global_variables, 2);
        assert_eq!(symbol_count.cross_references, 1);
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

        assert!(symbol_table.functions.is_empty());
        assert!(symbol_table.global_variables.is_empty());
        assert!(symbol_table.cross_references.is_empty());
        assert!(symbol_table.imports.is_empty());
        assert!(symbol_table.exports.is_empty());
        assert_eq!(symbol_table.symbol_count.total_functions, 0);
    }

    #[test]
    fn test_analyze_symbols_invalid_file() {
        let result = analyze_symbols(Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_symbols_unsupported_format() {
        // Create a temporary file with invalid binary format
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Invalid binary format").unwrap();

        let result = analyze_symbols(temp_file.path());
        assert!(result.is_err());

        if let Err(e) = result {
            let error_msg = e.to_string();
            // Should get a parsing error from goblin or unsupported format error
            assert!(
                error_msg.contains("Unsupported")
                    || error_msg.contains("parse")
                    || error_msg.contains("magic")
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let function = FunctionInfo {
            name: "test_func".to_string(),
            address: 0x1000,
            size: 64,
            function_type: FunctionType::Exported,
            calling_convention: Some(CallingConvention::Stdcall),
            parameters: vec![
                Parameter {
                    name: Some("param1".to_string()),
                    param_type: Some("int".to_string()),
                    size: Some(4),
                },
                Parameter {
                    name: None,
                    param_type: Some("void*".to_string()),
                    size: Some(8),
                },
            ],
            is_entry_point: true,
            is_exported: true,
            is_imported: false,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&function).unwrap();
        let deserialized: FunctionInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(function.name, deserialized.name);
        assert_eq!(function.address, deserialized.address);
        assert_eq!(function.size, deserialized.size);
        assert!(matches!(deserialized.function_type, FunctionType::Exported));
        assert!(matches!(
            deserialized.calling_convention,
            Some(CallingConvention::Stdcall)
        ));
        assert_eq!(function.parameters.len(), deserialized.parameters.len());
        assert_eq!(function.is_entry_point, deserialized.is_entry_point);
        assert_eq!(function.is_exported, deserialized.is_exported);
        assert_eq!(function.is_imported, deserialized.is_imported);
    }

    #[test]
    fn test_complex_symbol_table_serialization() {
        let symbol_table = SymbolTable {
            functions: vec![
                FunctionInfo {
                    name: "main".to_string(),
                    address: 0x1000,
                    size: 128,
                    function_type: FunctionType::EntryPoint,
                    calling_convention: Some(CallingConvention::Cdecl),
                    parameters: vec![],
                    is_entry_point: true,
                    is_exported: false,
                    is_imported: false,
                },
                FunctionInfo {
                    name: "printf".to_string(),
                    address: 0x0,
                    size: 0,
                    function_type: FunctionType::Imported,
                    calling_convention: Some(CallingConvention::Cdecl),
                    parameters: vec![],
                    is_entry_point: false,
                    is_exported: false,
                    is_imported: true,
                },
            ],
            global_variables: vec![VariableInfo {
                name: "global_counter".to_string(),
                address: 0x3000,
                size: 4,
                var_type: VariableType::Global,
                section: Some(".data".to_string()),
            }],
            cross_references: vec![CrossReference {
                from_address: 0x1050,
                to_address: 0x0,
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
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 2,
                local_functions: 0,
                imported_functions: 1,
                exported_functions: 0,
                global_variables: 1,
                cross_references: 1,
            },
        };

        // Test JSON serialization of complete symbol table
        let json = serde_json::to_string_pretty(&symbol_table).unwrap();
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

        // Verify symbol counts match
        assert_eq!(
            symbol_table.symbol_count.total_functions,
            deserialized.symbol_count.total_functions
        );
        assert_eq!(
            symbol_table.symbol_count.imported_functions,
            deserialized.symbol_count.imported_functions
        );
        assert_eq!(
            symbol_table.symbol_count.global_variables,
            deserialized.symbol_count.global_variables
        );
    }

    #[test]
    fn test_empty_symbol_table_analysis() {
        // Test behavior with empty collections
        let empty_functions: Vec<FunctionInfo> = vec![];
        let empty_variables: Vec<VariableInfo> = vec![];
        let empty_xrefs: Vec<CrossReference> = vec![];

        let symbol_count = SymbolCounts {
            total_functions: empty_functions.len(),
            local_functions: empty_functions
                .iter()
                .filter(|f| matches!(f.function_type, FunctionType::Local))
                .count(),
            imported_functions: empty_functions.iter().filter(|f| f.is_imported).count(),
            exported_functions: empty_functions.iter().filter(|f| f.is_exported).count(),
            global_variables: empty_variables.len(),
            cross_references: empty_xrefs.len(),
        };

        assert_eq!(symbol_count.total_functions, 0);
        assert_eq!(symbol_count.local_functions, 0);
        assert_eq!(symbol_count.imported_functions, 0);
        assert_eq!(symbol_count.exported_functions, 0);
        assert_eq!(symbol_count.global_variables, 0);
        assert_eq!(symbol_count.cross_references, 0);
    }

    #[test]
    fn test_function_classification() {
        // Test entry point detection for different scenarios
        let functions = vec![
            // Linux entry point
            FunctionInfo {
                name: "_start".to_string(),
                address: 0x1000,
                size: 32,
                function_type: FunctionType::EntryPoint,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: true,
                is_exported: false,
                is_imported: false,
            },
            // Main function
            FunctionInfo {
                name: "main".to_string(),
                address: 0x1100,
                size: 64,
                function_type: FunctionType::EntryPoint,
                calling_convention: Some(CallingConvention::Cdecl),
                parameters: vec![],
                is_entry_point: true,
                is_exported: false,
                is_imported: false,
            },
            // Constructor
            FunctionInfo {
                name: "__constructor".to_string(),
                address: 0x1200,
                size: 16,
                function_type: FunctionType::Constructor,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: false,
            },
            // Destructor
            FunctionInfo {
                name: "__destructor".to_string(),
                address: 0x1300,
                size: 16,
                function_type: FunctionType::Destructor,
                calling_convention: Some(CallingConvention::SysV),
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: false,
            },
            // Thunk function
            FunctionInfo {
                name: "__thunk_func".to_string(),
                address: 0x1400,
                size: 8,
                function_type: FunctionType::Thunk,
                calling_convention: Some(CallingConvention::Unknown),
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: false,
            },
        ];

        // Verify function type classification
        assert!(matches!(
            functions[0].function_type,
            FunctionType::EntryPoint
        ));
        assert!(matches!(
            functions[1].function_type,
            FunctionType::EntryPoint
        ));
        assert!(matches!(
            functions[2].function_type,
            FunctionType::Constructor
        ));
        assert!(matches!(
            functions[3].function_type,
            FunctionType::Destructor
        ));
        assert!(matches!(functions[4].function_type, FunctionType::Thunk));

        // Verify entry point flags
        assert!(functions[0].is_entry_point);
        assert!(functions[1].is_entry_point);
        assert!(!functions[2].is_entry_point);
        assert!(!functions[3].is_entry_point);
        assert!(!functions[4].is_entry_point);
    }

    #[test]
    fn test_edge_cases_and_error_handling() {
        // Test function with extremely large address
        let large_addr_func = FunctionInfo {
            name: "large_addr".to_string(),
            address: u64::MAX,
            size: 0,
            function_type: FunctionType::Local,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: false,
        };

        assert_eq!(large_addr_func.address, u64::MAX);
        assert_eq!(large_addr_func.size, 0);

        // Test parameter with extreme values
        let extreme_param = Parameter {
            name: Some("".to_string()), // Empty name
            param_type: Some("very_long_type_name_that_exceeds_normal_bounds".to_string()),
            size: Some(u32::MAX),
        };

        assert_eq!(extreme_param.name, Some("".to_string()));
        assert_eq!(extreme_param.size, Some(u32::MAX));

        // Test cross-reference with same from/to address
        let self_ref = CrossReference {
            from_address: 0x1000,
            to_address: 0x1000,
            reference_type: ReferenceType::Jump,
            instruction_type: Some("jmp".to_string()),
        };

        assert_eq!(self_ref.from_address, self_ref.to_address);
    }

    #[test]
    fn test_import_export_consistency() {
        // Test that imported functions are properly marked
        let import = ImportInfo {
            name: "test_import".to_string(),
            library: Some("test.dll".to_string()),
            address: Some(0x1000),
            ordinal: Some(1),
            is_delayed: false,
        };

        let imported_func = FunctionInfo {
            name: import.name.clone(),
            address: import.address.unwrap_or(0),
            size: 0,
            function_type: FunctionType::Imported,
            calling_convention: Some(CallingConvention::Stdcall),
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        };

        assert_eq!(import.name, imported_func.name);
        assert!(imported_func.is_imported);
        assert!(!imported_func.is_exported);
        assert!(matches!(
            imported_func.function_type,
            FunctionType::Imported
        ));

        // Test that exported functions are properly marked
        let export = ExportInfo {
            name: "test_export".to_string(),
            address: 0x2000,
            ordinal: Some(2),
            is_forwarder: false,
            forwarder_name: None,
        };

        let exported_func = FunctionInfo {
            name: export.name.clone(),
            address: export.address,
            size: 64,
            function_type: FunctionType::Exported,
            calling_convention: Some(CallingConvention::Cdecl),
            parameters: vec![],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        };

        assert_eq!(export.name, exported_func.name);
        assert_eq!(export.address, exported_func.address);
        assert!(exported_func.is_exported);
        assert!(!exported_func.is_imported);
        assert!(matches!(
            exported_func.function_type,
            FunctionType::Exported
        ));
    }
}
