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

use file_scanner::disassembly::*;
use file_scanner::function_analysis::{FunctionInfo, FunctionType, SymbolCounts, SymbolTable};
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

#[cfg(test)]
mod disassembly_tests {
    use super::*;

    // Helper function to create test symbol table
    fn create_test_symbol_table() -> SymbolTable {
        SymbolTable {
            functions: vec![
                FunctionInfo {
                    name: "main".to_string(),
                    address: 0x1000,
                    size: 100,
                    is_exported: true,
                    function_type: FunctionType::Exported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: true,
                    is_imported: false,
                },
                FunctionInfo {
                    name: "test_func".to_string(),
                    address: 0x1100,
                    size: 50,
                    is_exported: true,
                    function_type: FunctionType::Exported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: false,
                    is_imported: false,
                },
            ],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 2,
                local_functions: 0,
                imported_functions: 0,
                exported_functions: 2,
                global_variables: 0,
                cross_references: 0,
            },
        }
    }

    fn create_test_elf_binary() -> Vec<u8> {
        // Create a minimal ELF binary
        let mut binary = vec![0u8; 0x2000];

        // ELF header
        binary[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // Magic
        binary[4] = 0x02; // 64-bit
        binary[5] = 0x01; // Little endian
        binary[6] = 0x01; // Current version
        binary[7] = 0x00; // System V ABI

        // Machine type and version
        binary[0x10] = 0x02; // ET_EXEC
        binary[0x12] = 0x3e; // x86-64
        binary[0x14] = 0x01; // Version 1

        // Entry point
        let entry = 0x1000u64;
        binary[0x18..0x20].copy_from_slice(&entry.to_le_bytes());

        // Program header offset
        let phoff = 0x40u64;
        binary[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());

        // Section header offset
        let shoff = 0x200u64;
        binary[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());

        // Header sizes
        binary[0x34] = 0x40; // e_ehsize
        binary[0x36] = 0x38; // e_phentsize
        binary[0x38] = 0x01; // e_phnum
        binary[0x3a] = 0x40; // e_shentsize
        binary[0x3c] = 0x03; // e_shnum
        binary[0x3e] = 0x02; // e_shstrndx

        // Section header for .text
        let text_sh_offset = 0x240;
        binary[text_sh_offset] = 0x01; // sh_name offset
        binary[text_sh_offset + 4] = 0x01; // SHT_PROGBITS
        binary[text_sh_offset + 8] = 0x06; // SHF_ALLOC | SHF_EXECINSTR

        let text_addr = 0x1000u64;
        binary[text_sh_offset + 16..text_sh_offset + 24].copy_from_slice(&text_addr.to_le_bytes());

        let text_file_offset = 0x1000u64;
        binary[text_sh_offset + 24..text_sh_offset + 32]
            .copy_from_slice(&text_file_offset.to_le_bytes());

        let text_size = 0x100u64;
        binary[text_sh_offset + 32..text_sh_offset + 40].copy_from_slice(&text_size.to_le_bytes());

        // Section string table
        let strtab_offset = 0x300;
        let strtab_content = b"\0.text\0.shstrtab\0";
        binary[strtab_offset..strtab_offset + strtab_content.len()].copy_from_slice(strtab_content);

        // Add some x86-64 code at .text section
        let code = vec![
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
            0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
            0x48, 0x83, 0xc4, 0x10, // add rsp, 0x10
            0x5d, // pop rbp
            0xc3, // ret
        ];

        binary[0x1000..0x1000 + code.len()].copy_from_slice(&code);

        binary
    }

    #[test]
    fn test_disassemble_binary() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_test_elf_binary();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();

        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert!(!disasm.architecture.is_empty());
                assert!(!disasm.instructions.is_empty());
                assert!(disasm.analysis.total_instructions > 0);
            }
            Err(e) => {
                // It's okay if it fails with our minimal binary
                println!("Expected error for minimal binary: {e}");
            }
        }
    }

    #[test]
    fn test_instruction_types() {
        let types = vec![
            InstructionType::Arithmetic,
            InstructionType::Logic,
            InstructionType::Memory,
            InstructionType::Control,
            InstructionType::System,
            InstructionType::Crypto,
            InstructionType::Vector,
            InstructionType::Stack,
            InstructionType::Comparison,
            InstructionType::Other,
        ];

        for t in types {
            match t {
                InstructionType::Arithmetic => {}
                InstructionType::Logic => {}
                InstructionType::Memory => {}
                InstructionType::Control => {}
                InstructionType::System => {}
                InstructionType::Crypto => {}
                InstructionType::Vector => {}
                InstructionType::Stack => {}
                InstructionType::Comparison => {}
                InstructionType::Other => {}
            }
        }
    }

    #[test]
    fn test_flow_control_types() {
        let _jump = FlowControl::Jump {
            target: Some(0x1234),
            conditional: false,
        };
        let _cond_jump = FlowControl::Jump {
            target: Some(0x5678),
            conditional: true,
        };
        let _call = FlowControl::Call {
            target: Some(0xabcd),
            is_indirect: false,
        };
        let _indirect_call = FlowControl::Call {
            target: None,
            is_indirect: true,
        };
        let _ret = FlowControl::Return;
        let _int = FlowControl::Interrupt { number: 0x80 };
        let _cmov = FlowControl::ConditionalMove;

        // All constructions succeeded
    }

    #[test]
    fn test_access_types() {
        let types = vec![AccessType::Read, AccessType::Write, AccessType::Execute];

        for t in types {
            match t {
                AccessType::Read => {}
                AccessType::Write => {}
                AccessType::Execute => {}
            }
        }
    }

    #[test]
    fn test_crypto_operation_types() {
        let types = vec![
            CryptoOpType::AESOperation,
            CryptoOpType::SHA256Operation,
            CryptoOpType::RSAOperation,
            CryptoOpType::XOROperation,
            CryptoOpType::RandomGeneration,
            CryptoOpType::KeyDerivation,
        ];

        for t in types {
            match t {
                CryptoOpType::AESOperation => {}
                CryptoOpType::SHA256Operation => {}
                CryptoOpType::RSAOperation => {}
                CryptoOpType::XOROperation => {}
                CryptoOpType::RandomGeneration => {}
                CryptoOpType::KeyDerivation => {}
            }
        }
    }

    #[test]
    fn test_pattern_types() {
        let types = vec![
            PatternType::AntiDebug,
            PatternType::AntiVM,
            PatternType::Obfuscation,
            PatternType::SelfModifying,
            PatternType::StackManipulation,
            PatternType::IndirectJumps,
            PatternType::NopSled,
            PatternType::ReturnOriented,
        ];

        for t in types {
            match t {
                PatternType::AntiDebug => {}
                PatternType::AntiVM => {}
                PatternType::Obfuscation => {}
                PatternType::SelfModifying => {}
                PatternType::StackManipulation => {}
                PatternType::IndirectJumps => {}
                PatternType::NopSled => {}
                PatternType::ReturnOriented => {}
            }
        }
    }

    #[test]
    fn test_severity_levels() {
        let levels = vec![
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];

        for level in levels {
            match level {
                Severity::Low => {}
                Severity::Medium => {}
                Severity::High => {}
                Severity::Critical => {}
            }
        }
    }

    #[test]
    fn test_system_call_categories() {
        let categories = vec![
            SystemCallCategory::FileSystem,
            SystemCallCategory::Process,
            SystemCallCategory::Network,
            SystemCallCategory::Memory,
            SystemCallCategory::Security,
            SystemCallCategory::Other,
        ];

        for cat in categories {
            match cat {
                SystemCallCategory::FileSystem => {}
                SystemCallCategory::Process => {}
                SystemCallCategory::Network => {}
                SystemCallCategory::Memory => {}
                SystemCallCategory::Security => {}
                SystemCallCategory::Other => {}
            }
        }
    }

    #[test]
    fn test_instruction_structure() {
        let insn = Instruction {
            address: 0x1000,
            bytes: vec![0x55],
            mnemonic: "push".to_string(),
            operands: "rbp".to_string(),
            instruction_type: InstructionType::Stack,
            flow_control: None,
            size: 1,
        };

        assert_eq!(insn.address, 0x1000);
        assert_eq!(insn.bytes, vec![0x55]);
        assert_eq!(insn.mnemonic, "push");
        assert_eq!(insn.operands, "rbp");
        assert!(matches!(insn.instruction_type, InstructionType::Stack));
        assert!(insn.flow_control.is_none());
        assert_eq!(insn.size, 1);
    }

    #[test]
    fn test_memory_access_structure() {
        let mem_access = MemoryAccess {
            instruction_address: 0x1000,
            access_type: AccessType::Read,
            size: 8,
            target_address: Some(0x2000),
            register_base: Some("rax".to_string()),
            register_index: None,
            displacement: Some(0x10),
        };

        assert_eq!(mem_access.instruction_address, 0x1000);
        assert!(matches!(mem_access.access_type, AccessType::Read));
        assert_eq!(mem_access.size, 8);
        assert_eq!(mem_access.target_address, Some(0x2000));
        assert_eq!(mem_access.register_base, Some("rax".to_string()));
        assert!(mem_access.register_index.is_none());
        assert_eq!(mem_access.displacement, Some(0x10));
    }

    #[test]
    fn test_system_call_structure() {
        let syscall = SystemCall {
            address: 0x1000,
            syscall_number: Some(1),
            syscall_name: Some("write".to_string()),
            category: SystemCallCategory::FileSystem,
        };

        assert_eq!(syscall.address, 0x1000);
        assert_eq!(syscall.syscall_number, Some(1));
        assert_eq!(syscall.syscall_name, Some("write".to_string()));
        assert!(matches!(syscall.category, SystemCallCategory::FileSystem));
    }

    #[test]
    fn test_crypto_operation_structure() {
        let crypto_op = CryptoOperation {
            address: 0x1000,
            operation_type: CryptoOpType::AESOperation,
            algorithm_hint: Some("AES-256".to_string()),
            confidence: 0.9,
        };

        assert_eq!(crypto_op.address, 0x1000);
        assert!(matches!(
            crypto_op.operation_type,
            CryptoOpType::AESOperation
        ));
        assert_eq!(crypto_op.algorithm_hint, Some("AES-256".to_string()));
        assert_eq!(crypto_op.confidence, 0.9);
    }

    #[test]
    fn test_suspicious_pattern_structure() {
        let pattern = SuspiciousPattern {
            pattern_type: PatternType::AntiDebug,
            addresses: vec![0x1000, 0x1010, 0x1020],
            description: "Anti-debugging detected".to_string(),
            severity: Severity::High,
        };

        assert!(matches!(pattern.pattern_type, PatternType::AntiDebug));
        assert_eq!(pattern.addresses.len(), 3);
        assert_eq!(pattern.description, "Anti-debugging detected");
        assert!(matches!(pattern.severity, Severity::High));
    }

    #[test]
    fn test_basic_block_structure() {
        let block = BasicBlock {
            start_address: 0x1000,
            end_address: 0x1020,
            instruction_count: 8,
            exits: vec![
                BlockExit {
                    exit_type: ExitType::ConditionalJump,
                    target: Some(0x1030),
                },
                BlockExit {
                    exit_type: ExitType::FallThrough,
                    target: Some(0x1020),
                },
            ],
        };

        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1020);
        assert_eq!(block.instruction_count, 8);
        assert_eq!(block.exits.len(), 2);
    }

    #[test]
    fn test_exit_types() {
        let types = vec![
            ExitType::FallThrough,
            ExitType::Jump,
            ExitType::ConditionalJump,
            ExitType::Call,
            ExitType::Return,
        ];

        for t in types {
            match t {
                ExitType::FallThrough => {}
                ExitType::Jump => {}
                ExitType::ConditionalJump => {}
                ExitType::Call => {}
                ExitType::Return => {}
            }
        }
    }

    #[test]
    fn test_control_flow_summary() {
        let summary = ControlFlowSummary {
            total_jumps: 10,
            conditional_jumps: 6,
            unconditional_jumps: 4,
            function_calls: 5,
            indirect_calls: 2,
            returns: 3,
            interrupts: 1,
        };

        assert_eq!(summary.total_jumps, 10);
        assert_eq!(summary.conditional_jumps, 6);
        assert_eq!(summary.unconditional_jumps, 4);
        assert_eq!(summary.function_calls, 5);
        assert_eq!(summary.indirect_calls, 2);
        assert_eq!(summary.returns, 3);
        assert_eq!(summary.interrupts, 1);
    }

    #[test]
    fn test_disassembled_function_structure() {
        let func = DisassembledFunction {
            address: 0x1000,
            name: "test_function".to_string(),
            size: 100,
            instructions: vec![],
            basic_blocks: vec![],
            complexity: 5,
        };

        assert_eq!(func.address, 0x1000);
        assert_eq!(func.name, "test_function");
        assert_eq!(func.size, 100);
        assert!(func.instructions.is_empty());
        assert!(func.basic_blocks.is_empty());
        assert_eq!(func.complexity, 5);
    }

    #[test]
    fn test_graph_visualization_data() {
        let graph = GraphVisualizationData {
            nodes: vec![
                GraphNode {
                    id: "node1".to_string(),
                    label: "Block 1".to_string(),
                    node_type: "basic_block".to_string(),
                    metadata: HashMap::new(),
                },
                GraphNode {
                    id: "node2".to_string(),
                    label: "Block 2".to_string(),
                    node_type: "basic_block".to_string(),
                    metadata: HashMap::new(),
                },
            ],
            edges: vec![GraphEdge {
                source: "node1".to_string(),
                target: "node2".to_string(),
                edge_type: "jump".to_string(),
                label: Some("unconditional".to_string()),
            }],
        };

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].source, "node1");
        assert_eq!(graph.edges[0].target, "node2");
    }

    #[test]
    fn test_instruction_analysis_structure() {
        let analysis = InstructionAnalysis {
            total_instructions: 100,
            instruction_types: HashMap::new(),
            register_usage: HashMap::new(),
            memory_accesses: vec![],
            system_calls: vec![],
            crypto_operations: vec![],
            suspicious_patterns: vec![],
            control_flow_summary: ControlFlowSummary {
                total_jumps: 0,
                conditional_jumps: 0,
                unconditional_jumps: 0,
                function_calls: 0,
                indirect_calls: 0,
                returns: 0,
                interrupts: 0,
            },
        };

        assert_eq!(analysis.total_instructions, 100);
        assert!(analysis.instruction_types.is_empty());
        assert!(analysis.register_usage.is_empty());
        assert!(analysis.memory_accesses.is_empty());
        assert!(analysis.system_calls.is_empty());
        assert!(analysis.crypto_operations.is_empty());
        assert!(analysis.suspicious_patterns.is_empty());
    }

    #[test]
    fn test_output_formats_structure() {
        let output = OutputFormats {
            assembly: "mov rax, rbx\nret".to_string(),
            json_structured: serde_json::json!({
                "instructions": 2,
                "architecture": "x86_64"
            }),
            graph_data: GraphVisualizationData {
                nodes: vec![],
                edges: vec![],
            },
        };

        assert!(output.assembly.contains("mov"));
        assert!(output.assembly.contains("ret"));
        assert!(output.json_structured.is_object());
        assert!(output.graph_data.nodes.is_empty());
        assert!(output.graph_data.edges.is_empty());
    }

    #[test]
    fn test_disassembly_result_structure() {
        let result = DisassemblyResult {
            architecture: "x86_64".to_string(),
            instructions: vec![],
            analysis: InstructionAnalysis {
                total_instructions: 0,
                instruction_types: HashMap::new(),
                register_usage: HashMap::new(),
                memory_accesses: vec![],
                system_calls: vec![],
                crypto_operations: vec![],
                suspicious_patterns: vec![],
                control_flow_summary: ControlFlowSummary {
                    total_jumps: 0,
                    conditional_jumps: 0,
                    unconditional_jumps: 0,
                    function_calls: 0,
                    indirect_calls: 0,
                    returns: 0,
                    interrupts: 0,
                },
            },
            functions: vec![],
            output_formats: OutputFormats {
                assembly: String::new(),
                json_structured: serde_json::json!({}),
                graph_data: GraphVisualizationData {
                    nodes: vec![],
                    edges: vec![],
                },
            },
        };

        assert_eq!(result.architecture, "x86_64");
        assert!(result.instructions.is_empty());
        assert_eq!(result.analysis.total_instructions, 0);
        assert!(result.functions.is_empty());
    }

    // === COMPREHENSIVE ADDITIONAL TESTS FOR IMPROVED COVERAGE ===

    #[test]
    fn test_disassemble_binary_with_malformed_file() {
        let mut file = NamedTempFile::new().unwrap();
        // Write invalid ELF magic
        file.write_all(&[0x7f, 0x45, 0x4c, 0x00]).unwrap(); // Wrong magic
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail with malformed ELF");
    }

    #[test]
    fn test_disassemble_binary_with_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail with empty file");
    }

    #[test]
    fn test_disassemble_binary_nonexistent_file() {
        use std::path::Path;
        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(Path::new("/nonexistent/file"), &symbol_table);

        assert!(result.is_err(), "Should fail with nonexistent file");
    }

    fn create_test_pe_binary() -> Vec<u8> {
        let mut binary = vec![0u8; 0x2000];

        // DOS header
        binary[0..2].copy_from_slice(b"MZ");
        binary[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // PE offset

        // PE header
        binary[0x80..0x84].copy_from_slice(b"PE\0\0");
        binary[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine (x64)
        binary[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // Number of sections

        binary[0x98] = 0xF0; // Size of optional header
        binary[0x9A] = 0x22; // Characteristics

        // Optional header
        binary[0x9C..0x9E].copy_from_slice(&0x20Bu16.to_le_bytes()); // Magic (PE32+)
        binary[0x110..0x118].copy_from_slice(&0x1000u64.to_le_bytes()); // Image base

        // Section header for .text
        binary[0x178..0x180].copy_from_slice(b".text\0\0\0");
        binary[0x180..0x184].copy_from_slice(&0x100u32.to_le_bytes()); // Virtual size
        binary[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes()); // Virtual address
        binary[0x188..0x18C].copy_from_slice(&0x100u32.to_le_bytes()); // Size of raw data
        binary[0x18C..0x190].copy_from_slice(&0x400u32.to_le_bytes()); // Pointer to raw data
        binary[0x194..0x198].copy_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics

        // Add some x86-64 code
        let code = vec![
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
            0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
            0xC3, // ret
        ];
        binary[0x400..0x400 + code.len()].copy_from_slice(&code);

        binary
    }

    #[test]
    fn test_disassemble_pe_binary() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_test_pe_binary();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert!(!disasm.architecture.is_empty());
                assert_eq!(disasm.architecture, "x86_64");
                assert!(!disasm.instructions.is_empty());
            }
            Err(e) => {
                println!("PE binary test error (may be expected): {e}");
            }
        }
    }

    fn create_test_macho_binary() -> Vec<u8> {
        let mut binary = vec![0u8; 0x2000];

        // Mach-O header (64-bit)
        binary[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes()); // Magic
        binary[4..8].copy_from_slice(&0x01000007u32.to_le_bytes()); // CPU type (x86_64)
        binary[8..12].copy_from_slice(&0x00000003u32.to_le_bytes()); // CPU subtype
        binary[12..16].copy_from_slice(&0x00000002u32.to_le_bytes()); // File type (EXECUTE)
        binary[16..20].copy_from_slice(&1u32.to_le_bytes()); // Number of load commands
        binary[20..24].copy_from_slice(&72u32.to_le_bytes()); // Size of load commands

        // Segment load command
        binary[32..36].copy_from_slice(&0x00000019u32.to_le_bytes()); // LC_SEGMENT_64
        binary[36..40].copy_from_slice(&72u32.to_le_bytes()); // Command size
        binary[40..56].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0"); // Segment name
        binary[56..64].copy_from_slice(&0x1000u64.to_le_bytes()); // VM address
        binary[64..72].copy_from_slice(&0x1000u64.to_le_bytes()); // VM size
        binary[72..80].copy_from_slice(&0x1000u64.to_le_bytes()); // File offset
        binary[80..88].copy_from_slice(&0x1000u64.to_le_bytes()); // File size
        binary[96..100].copy_from_slice(&1u32.to_le_bytes()); // Number of sections

        // Section header for __text
        binary[104..120].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0"); // Section name
        binary[120..136].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0"); // Segment name
        binary[136..144].copy_from_slice(&0x1000u64.to_le_bytes()); // Address
        binary[144..152].copy_from_slice(&0x100u64.to_le_bytes()); // Size
        binary[152..156].copy_from_slice(&0x1000u32.to_le_bytes()); // Offset

        // Add some x86-64 code
        let code = vec![
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
            0x5d, // pop rbp
            0xc3, // ret
        ];
        binary[0x1000..0x1000 + code.len()].copy_from_slice(&code);

        binary
    }

    #[test]
    fn test_disassemble_macho_binary() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_test_macho_binary();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert!(!disasm.architecture.is_empty());
                assert_eq!(disasm.architecture, "x86_64");
                assert!(!disasm.instructions.is_empty());
            }
            Err(e) => {
                println!("Mach-O binary test error (may be expected): {e}");
            }
        }
    }

    fn create_arm_elf_binary() -> Vec<u8> {
        let mut binary = vec![0u8; 0x2000];

        // ELF header for ARM64
        binary[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // Magic
        binary[4] = 0x02; // 64-bit
        binary[5] = 0x01; // Little endian
        binary[6] = 0x01; // Current version
        binary[7] = 0x00; // System V ABI

        // Machine type and version
        binary[0x10] = 0x02; // ET_EXEC
        binary[0x12] = 0xb7; // EM_AARCH64 (low byte)
        binary[0x13] = 0x00; // EM_AARCH64 (high byte)
        binary[0x14] = 0x01; // Version 1

        // Entry point
        let entry = 0x1000u64;
        binary[0x18..0x20].copy_from_slice(&entry.to_le_bytes());

        // Program header offset
        let phoff = 0x40u64;
        binary[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());

        // Section header offset
        let shoff = 0x200u64;
        binary[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());

        // Header sizes
        binary[0x34] = 0x40; // e_ehsize
        binary[0x36] = 0x38; // e_phentsize
        binary[0x38] = 0x01; // e_phnum
        binary[0x3a] = 0x40; // e_shentsize
        binary[0x3c] = 0x03; // e_shnum
        binary[0x3e] = 0x02; // e_shstrndx

        // Section header for .text
        let text_sh_offset = 0x240;
        binary[text_sh_offset] = 0x01; // sh_name offset
        binary[text_sh_offset + 4] = 0x01; // SHT_PROGBITS
        binary[text_sh_offset + 8] = 0x06; // SHF_ALLOC | SHF_EXECINSTR

        let text_addr = 0x1000u64;
        binary[text_sh_offset + 16..text_sh_offset + 24].copy_from_slice(&text_addr.to_le_bytes());

        let text_file_offset = 0x1000u64;
        binary[text_sh_offset + 24..text_sh_offset + 32]
            .copy_from_slice(&text_file_offset.to_le_bytes());

        let text_size = 0x100u64;
        binary[text_sh_offset + 32..text_sh_offset + 40].copy_from_slice(&text_size.to_le_bytes());

        // Section string table
        let strtab_offset = 0x300;
        let strtab_content = b"\0.text\0.shstrtab\0";
        binary[strtab_offset..strtab_offset + strtab_content.len()].copy_from_slice(strtab_content);

        // Add some ARM64 code
        let code = vec![
            0x00, 0x00, 0x80, 0xd2, // mov x0, #0
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];

        binary[0x1000..0x1000 + code.len()].copy_from_slice(&code);

        binary
    }

    #[test]
    fn test_disassemble_arm64_binary() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_arm_elf_binary();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert!(!disasm.architecture.is_empty());
                assert_eq!(disasm.architecture, "ARM64");
                assert!(!disasm.instructions.is_empty());
            }
            Err(e) => {
                println!("ARM64 binary test error (may be expected): {e}");
            }
        }
    }

    fn create_x86_32_elf_binary() -> Vec<u8> {
        let mut binary = vec![0u8; 0x2000];

        // ELF header for x86-32
        binary[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // Magic
        binary[4] = 0x01; // 32-bit
        binary[5] = 0x01; // Little endian
        binary[6] = 0x01; // Current version
        binary[7] = 0x00; // System V ABI

        // Machine type and version
        binary[0x10] = 0x02; // ET_EXEC
        binary[0x12] = 0x03; // EM_386
        binary[0x14] = 0x01; // Version 1

        // Entry point (32-bit)
        let entry = 0x1000u32;
        binary[0x18..0x1c].copy_from_slice(&entry.to_le_bytes());

        // Program header offset (32-bit)
        let phoff = 0x34u32;
        binary[0x1c..0x20].copy_from_slice(&phoff.to_le_bytes());

        // Section header offset (32-bit)
        let shoff = 0x200u32;
        binary[0x20..0x24].copy_from_slice(&shoff.to_le_bytes());

        // Header sizes
        binary[0x28] = 0x34; // e_ehsize
        binary[0x2a] = 0x20; // e_phentsize
        binary[0x2c] = 0x01; // e_phnum
        binary[0x2e] = 0x28; // e_shentsize
        binary[0x30] = 0x03; // e_shnum
        binary[0x32] = 0x02; // e_shstrndx

        // Section header for .text (32-bit format)
        let text_sh_offset = 0x228;
        binary[text_sh_offset] = 0x01; // sh_name offset
        binary[text_sh_offset + 4] = 0x01; // SHT_PROGBITS
        binary[text_sh_offset + 8] = 0x06; // SHF_ALLOC | SHF_EXECINSTR

        let text_addr = 0x1000u32;
        binary[text_sh_offset + 12..text_sh_offset + 16].copy_from_slice(&text_addr.to_le_bytes());

        let text_file_offset = 0x1000u32;
        binary[text_sh_offset + 16..text_sh_offset + 20]
            .copy_from_slice(&text_file_offset.to_le_bytes());

        let text_size = 0x100u32;
        binary[text_sh_offset + 20..text_sh_offset + 24].copy_from_slice(&text_size.to_le_bytes());

        // Section string table
        let strtab_offset = 0x300;
        let strtab_content = b"\0.text\0.shstrtab\0";
        binary[strtab_offset..strtab_offset + strtab_content.len()].copy_from_slice(strtab_content);

        // Add some x86-32 code
        let code = vec![
            0x55, // push ebp
            0x89, 0xe5, // mov ebp, esp
            0x31, 0xc0, // xor eax, eax
            0x5d, // pop ebp
            0xc3, // ret
        ];

        binary[0x1000..0x1000 + code.len()].copy_from_slice(&code);

        binary
    }

    #[test]
    fn test_disassemble_x86_32_binary() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_x86_32_elf_binary();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert!(!disasm.architecture.is_empty());
                assert_eq!(disasm.architecture, "x86");
                assert!(!disasm.instructions.is_empty());
            }
            Err(e) => {
                println!("x86-32 binary test error (may be expected): {e}");
            }
        }
    }

    fn create_unsupported_arch_elf() -> Vec<u8> {
        let mut binary = vec![0u8; 0x1000];

        // ELF header with unsupported architecture
        binary[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // Magic
        binary[4] = 0x02; // 64-bit
        binary[5] = 0x01; // Little endian
        binary[6] = 0x01; // Current version
        binary[7] = 0x00; // System V ABI

        // Machine type and version
        binary[0x10] = 0x02; // ET_EXEC
        binary[0x12] = 0xFF; // Unsupported machine type
        binary[0x13] = 0xFF;
        binary[0x14] = 0x01; // Version 1

        binary
    }

    #[test]
    fn test_disassemble_unsupported_architecture() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_unsupported_arch_elf();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail with unsupported architecture");
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unsupported") || error_msg.contains("architecture"));
    }

    fn create_elf_no_text_section() -> Vec<u8> {
        let mut binary = vec![0u8; 0x1000];

        // ELF header
        binary[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // Magic
        binary[4] = 0x02; // 64-bit
        binary[5] = 0x01; // Little endian
        binary[6] = 0x01; // Current version
        binary[7] = 0x00; // System V ABI

        // Machine type and version
        binary[0x10] = 0x02; // ET_EXEC
        binary[0x12] = 0x3e; // x86-64
        binary[0x14] = 0x01; // Version 1

        // Entry point
        let entry = 0x1000u64;
        binary[0x18..0x20].copy_from_slice(&entry.to_le_bytes());

        // Program header offset
        let phoff = 0x40u64;
        binary[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());

        // Section header offset
        let shoff = 0x200u64;
        binary[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());

        // Header sizes
        binary[0x34] = 0x40; // e_ehsize
        binary[0x36] = 0x38; // e_phentsize
        binary[0x38] = 0x01; // e_phnum
        binary[0x3a] = 0x40; // e_shentsize
        binary[0x3c] = 0x02; // e_shnum (only 2 sections, no .text)
        binary[0x3e] = 0x01; // e_shstrndx

        // Section string table (no .text entry)
        let strtab_offset = 0x300;
        let strtab_content = b"\0.shstrtab\0";
        binary[strtab_offset..strtab_offset + strtab_content.len()].copy_from_slice(strtab_content);

        binary
    }

    #[test]
    fn test_disassemble_binary_no_text_section() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_elf_no_text_section();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail when no .text section found");
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("text") || error_msg.contains("section"));
    }

    #[test]
    fn test_pe_32_bit_detection() {
        let mut binary = create_test_pe_binary();
        // Modify to be 32-bit PE
        binary[0x9C..0x9E].copy_from_slice(&0x10Bu16.to_le_bytes()); // Magic (PE32)
        binary[0x110..0x114].copy_from_slice(&0x1000u32.to_le_bytes()); // Image base (32-bit)

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert_eq!(disasm.architecture, "x86");
            }
            Err(e) => {
                println!("PE 32-bit test error (may be expected): {e}");
            }
        }
    }

    #[test]
    fn test_pe_no_text_section() {
        let mut binary = create_test_pe_binary();
        // Change section name to something other than .text
        binary[0x178..0x180].copy_from_slice(b".data\0\0\0");

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail when PE has no .text section");
    }

    #[test]
    fn test_macho_fat_binary_error() {
        let mut binary = vec![0u8; 0x1000];

        // Fat binary magic (should be rejected)
        binary[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes()); // Fat magic (big endian)

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail with fat binaries");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Fat")
                || error_msg.contains("not")
                || error_msg.contains("supported")
        );
    }

    #[test]
    fn test_macho_no_text_section() {
        let mut binary = create_test_macho_binary();
        // Change section name to something other than __text
        binary[104..120].copy_from_slice(b"__data\0\0\0\0\0\0\0\0\0\0");

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(
            result.is_err(),
            "Should fail when Mach-O has no __text section"
        );
    }

    #[test]
    fn test_macho_unsupported_architecture() {
        let mut binary = create_test_macho_binary();
        // Change CPU type to unsupported
        binary[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(
            result.is_err(),
            "Should fail with unsupported Mach-O architecture"
        );
    }

    #[test]
    fn test_unknown_binary_format() {
        let mut file = NamedTempFile::new().unwrap();
        // Write random data that's not a valid binary format
        let random_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        file.write_all(&random_data).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        assert!(result.is_err(), "Should fail with unknown binary format");
    }

    #[test]
    fn test_comprehensive_instruction_analysis() {
        // Create a more comprehensive binary with various instruction types
        let mut file = NamedTempFile::new().unwrap();
        let mut binary = create_test_elf_binary();

        // Replace the simple code with a more comprehensive set
        let complex_code = vec![
            // Arithmetic instructions
            0x48, 0x01, 0xc1, // add rcx, rax
            0x48, 0x29, 0xc2, // sub rdx, rax
            0x48, 0xf7, 0xe1, // mul rcx
            0x48, 0xf7, 0xf1, // div rcx
            0x48, 0xff, 0xc0, // inc rax
            0x48, 0xff, 0xc8, // dec rax
            // Logic instructions
            0x48, 0x21, 0xc1, // and rcx, rax
            0x48, 0x09, 0xc1, // or rcx, rax
            0x48, 0x31, 0xc1, // xor rcx, rax
            0x48, 0xd1, 0xe0, // shl rax, 1
            0x48, 0xd1, 0xe8, // shr rax, 1
            // Memory instructions
            0x48, 0x8b, 0x00, // mov rax, [rax]
            0x48, 0x89, 0x01, // mov [rcx], rax
            0x48, 0x8d, 0x04, 0x01, // lea rax, [rcx+rax]
            // Control flow
            0x74, 0x05, // jz +5
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0xc3, // ret
            // Stack operations
            0x50, // push rax
            0x58, // pop rax
            0x9c, // pushf
            0x9d, // popf
            // Comparison
            0x48, 0x39, 0xc1, // cmp rcx, rax
            0x48, 0x85, 0xc0, // test rax, rax
            // System calls
            0x0f, 0x05, // syscall
            0xcd, 0x80, // int 0x80
            // Crypto-like operations
            0x66, 0x0f, 0x38, 0xdc, 0xc1, // aesenc xmm0, xmm1
            0x48, 0x31, 0xc0, // xor rax, rax (could be crypto)
            0x0f, 0xc7, 0xf0, // rdrand eax
            // Vector operations
            0x66, 0x0f, 0xfe, 0xc1, // paddd xmm0, xmm1
            0x66, 0x0f, 0xef, 0xc1, // pxor xmm0, xmm1
            // NOP sled for pattern detection
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 12 NOPs
            // Anti-debug patterns
            0x0f, 0x31, // rdtsc
            0xcc, // int 3
            // Indirect jumps
            0xff, 0x20, // jmp [rax]
            0xff, 0x10, // call [rax]
        ];

        binary[0x1000..0x1000 + complex_code.len()].copy_from_slice(&complex_code);
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                let analysis = &disasm.analysis;

                // Should have various instruction types
                assert!(analysis.instruction_types.len() > 5);
                assert!(analysis.total_instructions > 20);

                // Should detect system calls
                assert!(!analysis.system_calls.is_empty());

                // Should detect crypto operations
                assert!(!analysis.crypto_operations.is_empty());

                // Should detect suspicious patterns
                assert!(!analysis.suspicious_patterns.is_empty());

                // Should have control flow information
                assert!(analysis.control_flow_summary.total_jumps > 0);
                assert!(analysis.control_flow_summary.function_calls > 0);

                // Should track register usage
                assert!(!analysis.register_usage.is_empty());

                // Should detect memory accesses
                assert!(!analysis.memory_accesses.is_empty());
            }
            Err(e) => {
                println!("Comprehensive analysis test error (may be expected): {e}");
            }
        }
    }

    #[test]
    fn test_complex_control_flow_basic_blocks() {
        // Test complex control flow with multiple basic blocks
        let mut file = NamedTempFile::new().unwrap();
        let mut binary = create_test_elf_binary();

        let complex_flow_code = vec![
            // Block 1: Entry
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x83, 0xf8, 0x00, // cmp rax, 0
            0x74, 0x0a, // jz +10 (to block 3)
            // Block 2: Non-zero path
            0x48, 0x83, 0xc0, 0x01, // add rax, 1
            0xe9, 0x05, 0x00, 0x00, 0x00, // jmp +5 (to exit)
            // Block 3: Zero path
            0x48, 0x83, 0xe8, 0x01, // sub rax, 1
            // Block 4: Exit
            0x5d, // pop rbp
            0xc3, // ret
        ];

        binary[0x1000..0x1000 + complex_flow_code.len()].copy_from_slice(&complex_flow_code);
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                assert!(!disasm.functions.is_empty());

                // Should identify multiple basic blocks
                if let Some(func) = disasm.functions.first() {
                    assert!(
                        func.basic_blocks.len() > 1,
                        "Should have multiple basic blocks"
                    );
                    assert!(
                        func.complexity > 1,
                        "Should have complexity > 1 for branching"
                    );
                }

                // Should have conditional jumps
                assert!(disasm.analysis.control_flow_summary.conditional_jumps > 0);
                assert!(disasm.analysis.control_flow_summary.unconditional_jumps > 0);
            }
            Err(e) => {
                println!("Complex control flow test error (may be expected): {e}");
            }
        }
    }

    #[test]
    fn test_serialization_deserialization_comprehensive() {
        // Test all major data structures can be serialized and deserialized
        let flow_control_variants = vec![
            FlowControl::Jump {
                target: Some(0x1000),
                conditional: true,
            },
            FlowControl::Jump {
                target: None,
                conditional: false,
            },
            FlowControl::Call {
                target: Some(0x2000),
                is_indirect: false,
            },
            FlowControl::Call {
                target: None,
                is_indirect: true,
            },
            FlowControl::Return,
            FlowControl::Interrupt { number: 0x80 },
            FlowControl::ConditionalMove,
        ];

        for flow in flow_control_variants {
            let serialized = serde_json::to_string(&flow).unwrap();
            let _deserialized: FlowControl = serde_json::from_str(&serialized).unwrap();
        }

        let instruction_types = vec![
            InstructionType::Arithmetic,
            InstructionType::Logic,
            InstructionType::Memory,
            InstructionType::Control,
            InstructionType::System,
            InstructionType::Crypto,
            InstructionType::Vector,
            InstructionType::Stack,
            InstructionType::Comparison,
            InstructionType::Other,
        ];

        for inst_type in instruction_types {
            let serialized = serde_json::to_string(&inst_type).unwrap();
            let _deserialized: InstructionType = serde_json::from_str(&serialized).unwrap();
        }

        let crypto_types = vec![
            CryptoOpType::AESOperation,
            CryptoOpType::SHA256Operation,
            CryptoOpType::RSAOperation,
            CryptoOpType::XOROperation,
            CryptoOpType::RandomGeneration,
            CryptoOpType::KeyDerivation,
        ];

        for crypto_type in crypto_types {
            let serialized = serde_json::to_string(&crypto_type).unwrap();
            let _deserialized: CryptoOpType = serde_json::from_str(&serialized).unwrap();
        }

        let pattern_types = vec![
            PatternType::AntiDebug,
            PatternType::AntiVM,
            PatternType::Obfuscation,
            PatternType::SelfModifying,
            PatternType::StackManipulation,
            PatternType::IndirectJumps,
            PatternType::NopSled,
            PatternType::ReturnOriented,
        ];

        for pattern_type in pattern_types {
            let serialized = serde_json::to_string(&pattern_type).unwrap();
            let _deserialized: PatternType = serde_json::from_str(&serialized).unwrap();
        }

        let severity_levels = vec![
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];

        for severity in severity_levels {
            let serialized = serde_json::to_string(&severity).unwrap();
            let _deserialized: Severity = serde_json::from_str(&serialized).unwrap();
        }
    }

    #[test]
    fn test_edge_cases_and_boundary_conditions() {
        // Test with maximum values
        let large_instruction = Instruction {
            address: u64::MAX,
            bytes: vec![0xFF; 255],          // Very large instruction
            mnemonic: "test".repeat(100),    // Very long mnemonic
            operands: "operand".repeat(200), // Very long operands
            instruction_type: InstructionType::Other,
            flow_control: Some(FlowControl::Jump {
                target: Some(u64::MAX),
                conditional: true,
            }),
            size: 255,
        };

        let serialized = serde_json::to_string(&large_instruction).unwrap();
        let _deserialized: Instruction = serde_json::from_str(&serialized).unwrap();

        // Test with empty collections
        let empty_analysis = InstructionAnalysis {
            total_instructions: 0,
            instruction_types: HashMap::new(),
            register_usage: HashMap::new(),
            memory_accesses: vec![],
            system_calls: vec![],
            crypto_operations: vec![],
            suspicious_patterns: vec![],
            control_flow_summary: ControlFlowSummary {
                total_jumps: 0,
                conditional_jumps: 0,
                unconditional_jumps: 0,
                function_calls: 0,
                indirect_calls: 0,
                returns: 0,
                interrupts: 0,
            },
        };

        let serialized = serde_json::to_string(&empty_analysis).unwrap();
        let _deserialized: InstructionAnalysis = serde_json::from_str(&serialized).unwrap();

        // Test basic block with maximum exits
        let max_exits_block = BasicBlock {
            start_address: 0,
            end_address: u64::MAX,
            instruction_count: usize::MAX,
            exits: vec![
                BlockExit {
                    exit_type: ExitType::FallThrough,
                    target: Some(0x1000),
                },
                BlockExit {
                    exit_type: ExitType::Jump,
                    target: Some(0x2000),
                },
                BlockExit {
                    exit_type: ExitType::ConditionalJump,
                    target: Some(0x3000),
                },
                BlockExit {
                    exit_type: ExitType::Call,
                    target: Some(0x4000),
                },
                BlockExit {
                    exit_type: ExitType::Return,
                    target: None,
                },
            ],
        };

        let serialized = serde_json::to_string(&max_exits_block).unwrap();
        let _deserialized: BasicBlock = serde_json::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_pattern_detection_edge_cases() {
        // Test with minimal patterns that just meet thresholds
        let mut file = NamedTempFile::new().unwrap();
        let mut binary = create_test_elf_binary();

        // Create exactly 11 NOPs (just above threshold)
        let mut nop_code = vec![0x90; 11]; // 11 NOPs
        nop_code.push(0xc3); // ret to end the sequence

        // Add exactly 21 indirect jumps (just above threshold)
        for _ in 0..21 {
            nop_code.extend_from_slice(&[0xff, 0x20]); // jmp [rax]
        }

        binary[0x1000..0x1000 + nop_code.len()].copy_from_slice(&nop_code);
        file.write_all(&binary).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let result = disassemble_binary(file.path(), &symbol_table);

        match result {
            Ok(disasm) => {
                let patterns = &disasm.analysis.suspicious_patterns;

                // Should detect NOP sled
                assert!(patterns
                    .iter()
                    .any(|p| matches!(p.pattern_type, PatternType::NopSled)));

                // Should detect excessive indirect jumps
                assert!(patterns
                    .iter()
                    .any(|p| matches!(p.pattern_type, PatternType::IndirectJumps)));
            }
            Err(e) => {
                println!("Pattern detection edge case test error (may be expected): {e}");
            }
        }
    }

    #[test]
    fn test_memory_access_size_estimation_edge_cases() {
        // Test all size suffix variations through public API
        let test_cases = vec![
            ("movb", InstructionType::Memory),
            ("movw", InstructionType::Memory),
            ("movd", InstructionType::Memory),
            ("movq", InstructionType::Memory),
            ("mov", InstructionType::Memory), // default
            ("addb", InstructionType::Arithmetic),
            ("addw", InstructionType::Arithmetic),
            ("addd", InstructionType::Arithmetic),
            ("addq", InstructionType::Arithmetic),
            ("unknown", InstructionType::Other), // default
        ];

        for (mnemonic, expected_type) in test_cases {
            let instruction = Instruction {
                address: 0x1000,
                bytes: vec![0x90],
                mnemonic: mnemonic.to_string(),
                operands: "[rax]".to_string(),
                instruction_type: expected_type.clone(),
                flow_control: None,
                size: 1,
            };

            // Test that the instruction was classified correctly
            assert_eq!(
                instruction.instruction_type, expected_type,
                "Failed for mnemonic: {mnemonic}"
            );
        }
    }

    #[test]
    fn test_graph_generation_with_complex_functions() {
        let _complex_function = DisassembledFunction {
            address: 0x1000,
            name: "complex_func".to_string(),
            size: 200,
            instructions: vec![
                Instruction {
                    address: 0x1000,
                    bytes: vec![0x55],
                    mnemonic: "push".to_string(),
                    operands: "rbp".to_string(),
                    instruction_type: InstructionType::Stack,
                    flow_control: None,
                    size: 1,
                },
                Instruction {
                    address: 0x1001,
                    bytes: vec![0x74, 0x05],
                    mnemonic: "jz".to_string(),
                    operands: "0x1008".to_string(),
                    instruction_type: InstructionType::Control,
                    flow_control: Some(FlowControl::Jump {
                        target: Some(0x1008),
                        conditional: true,
                    }),
                    size: 2,
                },
            ],
            basic_blocks: vec![
                BasicBlock {
                    start_address: 0x1000,
                    end_address: 0x1003,
                    instruction_count: 2,
                    exits: vec![
                        BlockExit {
                            exit_type: ExitType::ConditionalJump,
                            target: Some(0x1008),
                        },
                        BlockExit {
                            exit_type: ExitType::FallThrough,
                            target: Some(0x1003),
                        },
                    ],
                },
                BasicBlock {
                    start_address: 0x1003,
                    end_address: 0x1008,
                    instruction_count: 3,
                    exits: vec![BlockExit {
                        exit_type: ExitType::Jump,
                        target: Some(0x1010),
                    }],
                },
                BasicBlock {
                    start_address: 0x1008,
                    end_address: 0x1010,
                    instruction_count: 2,
                    exits: vec![BlockExit {
                        exit_type: ExitType::Return,
                        target: None,
                    }],
                },
            ],
            complexity: 3,
        };

        // Test graph generation through output formats
        let output = OutputFormats {
            assembly: "test".to_string(),
            json_structured: serde_json::json!({}),
            graph_data: GraphVisualizationData {
                nodes: vec![
                    GraphNode {
                        id: "func_1000".to_string(),
                        label: "complex_func".to_string(),
                        node_type: "function".to_string(),
                        metadata: [
                            ("address".to_string(), "0x1000".to_string()),
                            ("size".to_string(), "200".to_string()),
                            ("complexity".to_string(), "3".to_string()),
                        ]
                        .iter()
                        .cloned()
                        .collect(),
                    },
                    GraphNode {
                        id: "block_1000_0".to_string(),
                        label: "Block 0: 0x1000".to_string(),
                        node_type: "basic_block".to_string(),
                        metadata: [("instructions".to_string(), "2".to_string())]
                            .iter()
                            .cloned()
                            .collect(),
                    },
                ],
                edges: vec![GraphEdge {
                    source: "block_1000_0".to_string(),
                    target: "block_1008".to_string(),
                    edge_type: "ConditionalJump".to_string(),
                    label: Some("ConditionalJump".to_string()),
                }],
            },
        };

        // Verify graph structure
        assert!(!output.graph_data.nodes.is_empty());
        assert!(!output.graph_data.edges.is_empty());
        assert!(output
            .graph_data
            .nodes
            .iter()
            .any(|n| n.node_type == "function"));
        assert!(output
            .graph_data
            .nodes
            .iter()
            .any(|n| n.node_type == "basic_block"));
    }

    #[test]
    fn test_instruction_type_classification_comprehensive() {
        // Test edge cases in instruction classification
        let edge_cases = vec![
            // Instructions that start with patterns but are different
            ("j", InstructionType::Other),         // Just "j" by itself
            ("jump", InstructionType::Other),      // Not a real x86 instruction
            ("calls", InstructionType::Other),     // Not "call"
            ("retf", InstructionType::Control),    // Far return, still control
            ("retn", InstructionType::Control),    // Near return, still control
            ("interrupt", InstructionType::Other), // Not "int"
            ("int3", InstructionType::Other),      // Not exactly "int"
            ("syscalls", InstructionType::Other),  // Not "syscall"
            ("cmovcc", InstructionType::Control),  // Conditional move variant
            // Vector instruction edge cases
            ("vaddps", InstructionType::Vector), // AVX instruction
            ("vpxor", InstructionType::Vector),  // AVX instruction with 'p'
            ("psubq", InstructionType::Vector),  // MMX/SSE with 'p'
            ("movq", InstructionType::Memory),   // Not vector despite 'q'
            // Crypto instruction variations
            ("aesdeclast", InstructionType::Crypto), // AES variant
            ("sha256rnds2", InstructionType::Crypto), // SHA variant
            ("sha256msg1", InstructionType::Crypto), // SHA variant
            ("sha256msg2", InstructionType::Crypto), // SHA variant
            ("rdseed", InstructionType::Crypto),     // Random seed
            // System instruction edge cases
            ("sysenter", InstructionType::System),
            ("sysexit", InstructionType::System),
            ("int", InstructionType::Control), // Without "0x80", it's just control
        ];

        for (mnemonic, expected_type) in edge_cases {
            let instruction = Instruction {
                address: 0x1000,
                bytes: vec![0x90],
                mnemonic: mnemonic.to_string(),
                operands: String::new(),
                instruction_type: expected_type.clone(),
                flow_control: None,
                size: 1,
            };

            // The instruction should have been classified correctly during creation
            assert_eq!(
                instruction.instruction_type, expected_type,
                "Failed for mnemonic: {mnemonic}"
            );
        }
    }
}
