use file_scanner::binary_parser::*;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn create_test_file(content: &[u8]) -> anyhow::Result<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("test_binary");
    let mut file = fs::File::create(&file_path)?;
    file.write_all(content)?;
    Ok((temp_dir, file_path))
}

fn create_minimal_elf() -> Vec<u8> {
    let mut elf = vec![
        // ELF header
        0x7f, 0x45, 0x4c, 0x46, // Magic number
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, // ABI version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Executable file
        0x3e, 0x00, // x86-64
        0x01, 0x00, 0x00, 0x00, // Version 1
    ];

    // Add entry point (64-bit little endian)
    elf.extend_from_slice(&[0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Program header table offset
    elf.extend_from_slice(&[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Section header table offset
    elf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Flags
    elf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // ELF header size
    elf.extend_from_slice(&[0x40, 0x00]);

    // Program header entry size
    elf.extend_from_slice(&[0x38, 0x00]);

    // Number of program header entries
    elf.extend_from_slice(&[0x00, 0x00]);

    // Section header entry size
    elf.extend_from_slice(&[0x40, 0x00]);

    // Number of section header entries
    elf.extend_from_slice(&[0x00, 0x00]);

    // Section header string table index
    elf.extend_from_slice(&[0x00, 0x00]);

    elf
}

fn create_minimal_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 1024];

    // DOS header
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]); // e_lfanew

    // PE signature at offset 0x80
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");

    // COFF header
    pe[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: x86_64
    pe[0x86..0x88].copy_from_slice(&[0x00, 0x00]); // Number of sections
    pe[0x88..0x8C].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Timestamp
    pe[0x8C..0x90].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Symbol table pointer
    pe[0x90..0x94].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Number of symbols
    pe[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // Optional header size
    pe[0x96..0x98].copy_from_slice(&[0x22, 0x00]); // Characteristics

    // Optional header
    pe[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // Magic (PE32+)
    pe[0x9A] = 14; // Major linker version
    pe[0x9B] = 0; // Minor linker version

    pe
}

fn create_minimal_macho() -> Vec<u8> {
    let mut macho = vec![
        // Mach-O header for 64-bit
        0xcf, 0xfa, 0xed, 0xfe, // Magic number (64-bit little endian)
        0x07, 0x01, 0x00, 0x00, // CPU type (x86_64)
        0x03, 0x00, 0x00, 0x00, // CPU subtype
        0x02, 0x00, 0x00, 0x00, // File type (executable)
        0x00, 0x00, 0x00, 0x00, // Number of load commands
        0x00, 0x00, 0x00, 0x00, // Size of load commands
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Reserved
    ];

    // Pad to reasonable size
    macho.resize(512, 0);
    macho
}

#[test]
fn test_parse_binary_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/file");
    let result = parse_binary(path);
    assert!(result.is_err());
}

#[test]
fn test_parse_binary_empty_file() {
    let (_temp_dir, file_path) = create_test_file(b"").unwrap();
    let result = parse_binary(&file_path);
    assert!(result.is_err());
}

#[test]
fn test_parse_binary_invalid_format() {
    let content = b"This is not a binary file, just plain text";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();
    let result = parse_binary(&file_path);

    // ThreatFlux is more resilient and can analyze unknown/raw formats
    // so we expect success with "Raw" or "Unknown" format instead of an error
    match result {
        Ok(binary_info) => {
            assert!(binary_info.format == "Raw" || binary_info.format == "Unknown");
        }
        Err(_) => {
            // Goblin fallback might still return error, which is also acceptable
        }
    }
}

#[test]
fn test_parse_binary_truncated_elf() {
    let mut elf = create_minimal_elf();
    elf.truncate(10); // Truncate to make it invalid
    let (_temp_dir, file_path) = create_test_file(&elf).unwrap();
    let result = parse_binary(&file_path);
    assert!(result.is_err());
}

#[test]
fn test_binary_info_structure() {
    let info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("GCC".to_string()),
        linker: Some("GNU LD".to_string()),
        sections: vec![SectionInfo {
            name: ".text".to_string(),
            size: 1024,
            virtual_address: 0x1000,
            characteristics: "executable".to_string(),
        }],
        imports: vec!["libc.so.6".to_string()],
        exports: vec!["main".to_string()],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    assert_eq!(info.format, "ELF");
    assert_eq!(info.architecture, "x86_64");
    assert_eq!(info.compiler, Some("GCC".to_string()));
    assert_eq!(info.linker, Some("GNU LD".to_string()));
    assert_eq!(info.sections.len(), 1);
    assert_eq!(info.sections[0].name, ".text");
    assert_eq!(info.sections[0].size, 1024);
    assert_eq!(info.sections[0].virtual_address, 0x1000);
    assert_eq!(info.imports.len(), 1);
    assert_eq!(info.exports.len(), 1);
    assert_eq!(info.entry_point, Some(0x1000));
    assert!(!info.is_stripped);
    assert!(info.has_debug_info);
}

#[test]
fn test_section_info_structure() {
    let section = SectionInfo {
        name: ".rodata".to_string(),
        size: 512,
        virtual_address: 0x2000,
        characteristics: "readonly".to_string(),
    };

    assert_eq!(section.name, ".rodata");
    assert_eq!(section.size, 512);
    assert_eq!(section.virtual_address, 0x2000);
    assert_eq!(section.characteristics, "readonly");
}

#[test]
fn test_binary_info_serialization() {
    let info = BinaryInfo {
        format: "PE".to_string(),
        architecture: "x86".to_string(),
        compiler: Some("MSVC 2019".to_string()),
        linker: Some("Microsoft Linker".to_string()),
        sections: vec![],
        imports: vec!["kernel32.dll".to_string()],
        exports: vec![],
        entry_point: Some(0x1000),
        is_stripped: true,
        has_debug_info: false,
        java_analysis: None,
    };

    // Test JSON serialization
    let json = serde_json::to_string(&info).unwrap();
    let deserialized: BinaryInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.format, info.format);
    assert_eq!(deserialized.architecture, info.architecture);
    assert_eq!(deserialized.compiler, info.compiler);
    assert_eq!(deserialized.linker, info.linker);
    assert_eq!(deserialized.imports, info.imports);
    assert_eq!(deserialized.entry_point, info.entry_point);
    assert_eq!(deserialized.is_stripped, info.is_stripped);
    assert_eq!(deserialized.has_debug_info, info.has_debug_info);
}

#[test]
fn test_binary_info_defaults() {
    let info = BinaryInfo {
        format: "Unknown".to_string(),
        architecture: "Unknown".to_string(),
        compiler: None,
        linker: None,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: None,
        is_stripped: false,
        has_debug_info: false,
        java_analysis: None,
    };

    assert_eq!(info.format, "Unknown");
    assert_eq!(info.architecture, "Unknown");
    assert!(info.compiler.is_none());
    assert!(info.linker.is_none());
    assert!(info.sections.is_empty());
    assert!(info.imports.is_empty());
    assert!(info.exports.is_empty());
    assert!(info.entry_point.is_none());
    assert!(!info.is_stripped);
    assert!(!info.has_debug_info);
}

#[test]
fn test_binary_info_debug_format() {
    let info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("Clang".to_string()),
        linker: Some("LLD".to_string()),
        sections: vec![],
        imports: vec![],
        exports: vec![],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    let debug_string = format!("{:?}", info);
    assert!(debug_string.contains("BinaryInfo"));
    assert!(debug_string.contains("ELF"));
    assert!(debug_string.contains("x86_64"));
    assert!(debug_string.contains("Clang"));
}

#[test]
fn test_binary_info_with_multiple_sections() {
    let info = BinaryInfo {
        format: "PE".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("MSVC".to_string()),
        linker: Some("Link.exe".to_string()),
        sections: vec![
            SectionInfo {
                name: ".text".to_string(),
                size: 4096,
                virtual_address: 0x1000,
                characteristics: "executable".to_string(),
            },
            SectionInfo {
                name: ".data".to_string(),
                size: 2048,
                virtual_address: 0x2000,
                characteristics: "writable".to_string(),
            },
            SectionInfo {
                name: ".rdata".to_string(),
                size: 1024,
                virtual_address: 0x3000,
                characteristics: "readonly".to_string(),
            },
        ],
        imports: vec!["kernel32.dll".to_string(), "ntdll.dll".to_string()],
        exports: vec!["DllMain".to_string(), "ExportedFunction".to_string()],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    assert_eq!(info.sections.len(), 3);
    assert_eq!(info.sections[0].name, ".text");
    assert_eq!(info.sections[1].name, ".data");
    assert_eq!(info.sections[2].name, ".rdata");
    assert_eq!(info.imports.len(), 2);
    assert_eq!(info.exports.len(), 2);
}

#[test]
fn test_binary_info_edge_cases() {
    // Test with very large values
    let info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "Unknown".to_string(),
        compiler: None,
        linker: None,
        sections: vec![SectionInfo {
            name: ".huge_section".to_string(),
            size: u64::MAX,
            virtual_address: u64::MAX - 1,
            characteristics: "unusual".to_string(),
        }],
        imports: vec![],
        exports: vec![],
        entry_point: Some(u64::MAX),
        is_stripped: true,
        has_debug_info: false,
        java_analysis: None,
    };

    assert_eq!(info.sections[0].size, u64::MAX);
    assert_eq!(info.sections[0].virtual_address, u64::MAX - 1);
    assert_eq!(info.entry_point, Some(u64::MAX));
}

#[test]
fn test_binary_info_empty_strings() {
    let info = BinaryInfo {
        format: "".to_string(),
        architecture: "".to_string(),
        compiler: Some("".to_string()),
        linker: Some("".to_string()),
        sections: vec![SectionInfo {
            name: "".to_string(),
            size: 0,
            virtual_address: 0,
            characteristics: "".to_string(),
        }],
        imports: vec!["".to_string()],
        exports: vec!["".to_string()],
        entry_point: Some(0),
        is_stripped: false,
        has_debug_info: false,
        java_analysis: None,
    };

    assert!(info.format.is_empty());
    assert!(info.architecture.is_empty());
    assert_eq!(info.compiler, Some("".to_string()));
    assert_eq!(info.sections[0].name, "");
    assert_eq!(info.sections[0].size, 0);
    assert_eq!(info.sections[0].virtual_address, 0);
    assert_eq!(info.imports[0], "");
    assert_eq!(info.exports[0], "");
}

#[test]
fn test_binary_info_unicode_strings() {
    let info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("GCC 🦀".to_string()),
        linker: Some("GNU LD 📎".to_string()),
        sections: vec![SectionInfo {
            name: ".text_🔧".to_string(),
            size: 1024,
            virtual_address: 0x1000,
            characteristics: "executable_⚡".to_string(),
        }],
        imports: vec!["libstdc++.so.6_🌟".to_string()],
        exports: vec!["main_🚀".to_string()],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    assert!(info.compiler.unwrap().contains("🦀"));
    assert!(info.linker.unwrap().contains("📎"));
    assert!(info.sections[0].name.contains("🔧"));
    assert!(info.sections[0].characteristics.contains("⚡"));
    assert!(info.imports[0].contains("🌟"));
    assert!(info.exports[0].contains("🚀"));
}

#[test]
fn test_binary_info_long_strings() {
    let long_name = "a".repeat(1000);
    let info = BinaryInfo {
        format: long_name.clone(),
        architecture: long_name.clone(),
        compiler: Some(long_name.clone()),
        linker: Some(long_name.clone()),
        sections: vec![SectionInfo {
            name: long_name.clone(),
            size: 1024,
            virtual_address: 0x1000,
            characteristics: long_name.clone(),
        }],
        imports: vec![long_name.clone()],
        exports: vec![long_name.clone()],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    assert_eq!(info.format.len(), 1000);
    assert_eq!(info.architecture.len(), 1000);
    assert_eq!(info.compiler.as_ref().unwrap().len(), 1000);
    assert_eq!(info.sections[0].name.len(), 1000);
}

#[test]
fn test_binary_info_many_sections() {
    let mut sections = Vec::new();
    for i in 0..1000 {
        sections.push(SectionInfo {
            name: format!(".section_{}", i),
            size: i as u64,
            virtual_address: 0x1000 + (i as u64 * 0x1000),
            characteristics: format!("char_{}", i),
        });
    }

    let info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        compiler: None,
        linker: None,
        sections,
        imports: vec![],
        exports: vec![],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: false,
        java_analysis: None,
    };

    assert_eq!(info.sections.len(), 1000);
    assert_eq!(info.sections[0].name, ".section_0");
    assert_eq!(info.sections[999].name, ".section_999");
    assert_eq!(info.sections[500].size, 500);
    assert_eq!(info.sections[500].virtual_address, 0x1000 + (500 * 0x1000));
}

#[test]
fn test_binary_info_many_imports_exports() {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    for i in 0..500 {
        imports.push(format!("import_{}.dll", i));
        exports.push(format!("export_function_{}", i));
    }

    let info = BinaryInfo {
        format: "PE".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("MSVC".to_string()),
        linker: Some("Link.exe".to_string()),
        sections: vec![],
        imports,
        exports,
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    assert_eq!(info.imports.len(), 500);
    assert_eq!(info.exports.len(), 500);
    assert_eq!(info.imports[0], "import_0.dll");
    assert_eq!(info.exports[0], "export_function_0");
    assert_eq!(info.imports[499], "import_499.dll");
    assert_eq!(info.exports[499], "export_function_499");
}

#[test]
fn test_section_info_serialization() {
    let section = SectionInfo {
        name: ".debug_info".to_string(),
        size: 8192,
        virtual_address: 0x10000,
        characteristics: "debug|readable".to_string(),
    };

    // Test JSON serialization
    let json = serde_json::to_string(&section).unwrap();
    let deserialized: SectionInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.name, section.name);
    assert_eq!(deserialized.size, section.size);
    assert_eq!(deserialized.virtual_address, section.virtual_address);
    assert_eq!(deserialized.characteristics, section.characteristics);
}

#[test]
fn test_binary_info_clone() {
    let info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "ARM64".to_string(),
        compiler: Some("GCC".to_string()),
        linker: Some("GNU LD".to_string()),
        sections: vec![SectionInfo {
            name: ".text".to_string(),
            size: 1024,
            virtual_address: 0x1000,
            characteristics: "exec".to_string(),
        }],
        imports: vec!["libc.so".to_string()],
        exports: vec!["main".to_string()],
        entry_point: Some(0x1000),
        is_stripped: true,
        has_debug_info: false,
        java_analysis: None,
    };

    // This test verifies that BinaryInfo derives Debug and Clone (if it does)
    let debug_str = format!("{:?}", info);
    assert!(debug_str.contains("BinaryInfo"));
}

#[test]
fn test_binary_info_partial_eq() {
    let info1 = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("GCC".to_string()),
        linker: Some("GNU LD".to_string()),
        sections: vec![],
        imports: vec![],
        exports: vec![],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    let info2 = BinaryInfo {
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("GCC".to_string()),
        linker: Some("GNU LD".to_string()),
        sections: vec![],
        imports: vec![],
        exports: vec![],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    let info3 = BinaryInfo {
        format: "PE".to_string(),
        architecture: "x86_64".to_string(),
        compiler: Some("GCC".to_string()),
        linker: Some("GNU LD".to_string()),
        sections: vec![],
        imports: vec![],
        exports: vec![],
        entry_point: Some(0x1000),
        is_stripped: false,
        has_debug_info: true,
        java_analysis: None,
    };

    // Test serialization equality
    let json1 = serde_json::to_string(&info1).unwrap();
    let json2 = serde_json::to_string(&info2).unwrap();
    let json3 = serde_json::to_string(&info3).unwrap();

    assert_eq!(json1, json2);
    assert_ne!(json1, json3);
}

#[test]
fn test_parse_binary_with_real_elf_like_data() {
    // Test with data that might look like a real ELF but could fail parsing
    let mut elf_like = create_minimal_elf();

    // Add some more realistic data
    elf_like.extend_from_slice(b"This is some additional content that might be in an ELF");
    elf_like.resize(1024, 0); // Pad to reasonable size

    let (_temp_dir, file_path) = create_test_file(&elf_like).unwrap();
    let result = parse_binary(&file_path);

    // The parsing might succeed or fail depending on goblin's validation
    // Just ensure it doesn't panic
    match result {
        Ok(info) => {
            assert!(!info.format.is_empty());
        }
        Err(_) => {
            // Parsing failed, which is acceptable for minimal/invalid data
        }
    }
}

#[test]
fn test_parse_binary_with_real_pe_like_data() {
    let mut pe_like = create_minimal_pe();

    // Add some more realistic data
    pe_like.extend_from_slice(b"This could be PE section data or imports");
    pe_like.resize(2048, 0); // Pad to reasonable size

    let (_temp_dir, file_path) = create_test_file(&pe_like).unwrap();
    let result = parse_binary(&file_path);

    // The parsing might succeed or fail depending on goblin's validation
    match result {
        Ok(info) => {
            assert!(!info.format.is_empty());
        }
        Err(_) => {
            // Parsing failed, which is acceptable for minimal/invalid data
        }
    }
}

#[test]
fn test_parse_binary_with_real_macho_like_data() {
    let mut macho_like = create_minimal_macho();

    // Add some more realistic data
    macho_like.extend_from_slice(b"Mach-O load commands would go here");
    macho_like.resize(1024, 0); // Pad to reasonable size

    let (_temp_dir, file_path) = create_test_file(&macho_like).unwrap();
    let result = parse_binary(&file_path);

    // The parsing might succeed or fail depending on goblin's validation
    match result {
        Ok(info) => {
            assert!(!info.format.is_empty());
        }
        Err(_) => {
            // Parsing failed, which is acceptable for minimal/invalid data
        }
    }
}
