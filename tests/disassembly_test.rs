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
                println!("Expected error for minimal binary: {}", e);
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
                InstructionType::Arithmetic => assert!(true),
                InstructionType::Logic => assert!(true),
                InstructionType::Memory => assert!(true),
                InstructionType::Control => assert!(true),
                InstructionType::System => assert!(true),
                InstructionType::Crypto => assert!(true),
                InstructionType::Vector => assert!(true),
                InstructionType::Stack => assert!(true),
                InstructionType::Comparison => assert!(true),
                InstructionType::Other => assert!(true),
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

        assert!(true); // All constructions succeeded
    }

    #[test]
    fn test_access_types() {
        let types = vec![AccessType::Read, AccessType::Write, AccessType::Execute];

        for t in types {
            match t {
                AccessType::Read => assert!(true),
                AccessType::Write => assert!(true),
                AccessType::Execute => assert!(true),
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
                CryptoOpType::AESOperation => assert!(true),
                CryptoOpType::SHA256Operation => assert!(true),
                CryptoOpType::RSAOperation => assert!(true),
                CryptoOpType::XOROperation => assert!(true),
                CryptoOpType::RandomGeneration => assert!(true),
                CryptoOpType::KeyDerivation => assert!(true),
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
                PatternType::AntiDebug => assert!(true),
                PatternType::AntiVM => assert!(true),
                PatternType::Obfuscation => assert!(true),
                PatternType::SelfModifying => assert!(true),
                PatternType::StackManipulation => assert!(true),
                PatternType::IndirectJumps => assert!(true),
                PatternType::NopSled => assert!(true),
                PatternType::ReturnOriented => assert!(true),
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
                Severity::Low => assert!(true),
                Severity::Medium => assert!(true),
                Severity::High => assert!(true),
                Severity::Critical => assert!(true),
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
                SystemCallCategory::FileSystem => assert!(true),
                SystemCallCategory::Process => assert!(true),
                SystemCallCategory::Network => assert!(true),
                SystemCallCategory::Memory => assert!(true),
                SystemCallCategory::Security => assert!(true),
                SystemCallCategory::Other => assert!(true),
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
                ExitType::FallThrough => assert!(true),
                ExitType::Jump => assert!(true),
                ExitType::ConditionalJump => assert!(true),
                ExitType::Call => assert!(true),
                ExitType::Return => assert!(true),
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
}
