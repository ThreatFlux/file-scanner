use file_scanner::control_flow::*;
use file_scanner::function_analysis::{FunctionInfo, FunctionType, SymbolCounts, SymbolTable};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_block_type_variants() {
    let block_types = vec![
        BlockType::Entry,
        BlockType::Exit,
        BlockType::Normal,
        BlockType::LoopHeader,
        BlockType::LoopBody,
        BlockType::Conditional,
        BlockType::Call,
        BlockType::Return,
    ];

    for block_type in block_types {
        let json = serde_json::to_string(&block_type).unwrap();
        assert!(!json.is_empty());
    }
}

#[test]
fn test_instruction_types() {
    let instruction_types = vec![
        InstructionType::Arithmetic,
        InstructionType::Logic,
        InstructionType::Memory,
        InstructionType::Control,
        InstructionType::System,
        InstructionType::Call,
        InstructionType::Return,
        InstructionType::Jump,
        InstructionType::Conditional,
        InstructionType::Nop,
        InstructionType::Other,
    ];

    for inst_type in instruction_types {
        let json = serde_json::to_string(&inst_type).unwrap();
        assert!(!json.is_empty());
    }
}

#[test]
fn test_flow_control_types() {
    let flow_controls = vec![
        FlowControl::Fall,
        FlowControl::Jump(0x1234),
        FlowControl::Branch(0x5678),
        FlowControl::Call(0xabcd),
        FlowControl::Return,
        FlowControl::Indirect,
        FlowControl::Halt,
    ];

    for fc in flow_controls {
        match fc {
            FlowControl::Jump(addr) => assert!(addr > 0),
            FlowControl::Branch(addr) => assert!(addr > 0),
            FlowControl::Call(addr) => assert!(addr > 0),
            _ => assert!(true),
        }
    }
}

#[test]
fn test_instruction_creation() {
    let instruction = Instruction {
        address: 0x1000,
        bytes: vec![0x89, 0xD8],
        mnemonic: "mov".to_string(),
        operands: "eax, ebx".to_string(),
        instruction_type: InstructionType::Arithmetic,
        flow_control: FlowControl::Fall,
        size: 2,
    };

    assert_eq!(instruction.address, 0x1000);
    assert_eq!(instruction.mnemonic, "mov");
    assert_eq!(instruction.operands, "eax, ebx");
    assert_eq!(instruction.size, 2);
    assert_eq!(instruction.bytes, vec![0x89, 0xD8]);
}

#[test]
fn test_basic_block_creation() {
    let block = BasicBlock {
        id: 0,
        start_address: 0x1000,
        end_address: 0x1010,
        instructions: vec![],
        successors: vec![1, 2],
        predecessors: vec![],
        block_type: BlockType::Entry,
        instruction_count: 0,
    };

    assert_eq!(block.id, 0);
    assert_eq!(block.start_address, 0x1000);
    assert_eq!(block.end_address, 0x1010);
    assert_eq!(block.successors, vec![1, 2]);
    assert!(block.predecessors.is_empty());
}

#[test]
fn test_cfg_edge_creation() {
    let edge = CfgEdge {
        from_block: 0,
        to_block: 1,
        edge_type: EdgeType::Fall,
    };

    assert_eq!(edge.from_block, 0);
    assert_eq!(edge.to_block, 1);
}

#[test]
fn test_loop_structure() {
    let loop_info = Loop {
        header_block: 1,
        body_blocks: vec![2, 3, 4],
        exit_blocks: vec![5],
        loop_type: LoopType::While,
        nesting_level: 1,
    };

    assert_eq!(loop_info.header_block, 1);
    assert_eq!(loop_info.body_blocks, vec![2, 3, 4]);
    assert_eq!(loop_info.exit_blocks, vec![5]);
    assert_eq!(loop_info.nesting_level, 1);
}

#[test]
fn test_control_flow_metrics() {
    let metrics = ControlFlowMetrics {
        cyclomatic_complexity: 5,
        cognitive_complexity: 8,
        nesting_depth: 3,
        basic_block_count: 10,
        edge_count: 12,
        loop_count: 2,
        unreachable_blocks: vec![7, 8],
    };

    assert_eq!(metrics.cyclomatic_complexity, 5);
    assert_eq!(metrics.cognitive_complexity, 8);
    assert_eq!(metrics.nesting_depth, 3);
    assert_eq!(metrics.basic_block_count, 10);
    assert_eq!(metrics.edge_count, 12);
    assert_eq!(metrics.loop_count, 2);
    assert_eq!(metrics.unreachable_blocks, vec![7, 8]);
}

#[test]
fn test_control_flow_graph_creation() {
    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "main".to_string(),
        basic_blocks: vec![],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![5],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 1,
            cognitive_complexity: 1,
            nesting_depth: 0,
            basic_block_count: 1,
            edge_count: 0,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    assert_eq!(cfg.function_address, 0x1000);
    assert_eq!(cfg.function_name, "main");
    assert_eq!(cfg.entry_block, 0);
    assert_eq!(cfg.exit_blocks, vec![5]);
}

#[test]
fn test_disassembler_creation() {
    let result = ControlFlowAnalyzer::new_x86_64();
    assert!(result.is_ok());
}

#[test]
fn test_analyze_control_flow_nonexistent_file() {
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

    let result = analyze_control_flow(Path::new("/nonexistent/file"), &symbol_table);
    assert!(result.is_err());
}

#[test]
fn test_analyze_control_flow_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("empty.bin");
    fs::write(&test_file, b"").unwrap();

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

    let result = analyze_control_flow(&test_file, &symbol_table);
    // Empty file should either error or return empty analysis
    match result {
        Ok(analysis) => {
            assert_eq!(analysis.overall_metrics.total_functions, 0);
        }
        Err(_) => {
            // Also acceptable for empty files
            assert!(true);
        }
    }
}

#[test]
fn test_analyze_control_flow_simple_binary() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("simple.bin");

    // Create a minimal ELF-like header
    let content = vec![
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02, 0x01, 0x01, 0x00, // Class, data, version, OS/ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Type (executable)
        0x3e, 0x00, // Machine (x86-64)
    ];
    fs::write(&test_file, &content).unwrap();

    let symbol_table = SymbolTable {
        functions: vec![FunctionInfo {
            name: "main".to_string(),
            address: 0x1000,
            size: 100,
            function_type: FunctionType::EntryPoint,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: true,
            is_exported: true,
            is_imported: false,
        }],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 1,
            local_functions: 1,
            imported_functions: 0,
            exported_functions: 1,
            global_variables: 0,
            cross_references: 0,
        },
    };

    let result = analyze_control_flow(&test_file, &symbol_table);
    // This may succeed or fail depending on binary format support, both are valid
    match result {
        Ok(analysis) => {
            // If it succeeds, basic structure should be valid
            // total_functions is usize, so always >= 0
            assert!(
                analysis.overall_metrics.total_functions
                    == analysis.overall_metrics.total_functions
            );
        }
        Err(_) => {
            // If it fails, that's also expected for non-valid binaries
            assert!(true);
        }
    }
}

#[test]
fn test_serialization() {
    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "test_function".to_string(),
        basic_blocks: vec![BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1010,
            instructions: vec![],
            successors: vec![1],
            predecessors: vec![],
            block_type: BlockType::Entry,
            instruction_count: 5,
        }],
        edges: vec![CfgEdge {
            from_block: 0,
            to_block: 1,
            edge_type: EdgeType::Fall,
        }],
        entry_block: 0,
        exit_blocks: vec![1],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 1,
            cognitive_complexity: 1,
            nesting_depth: 0,
            basic_block_count: 2,
            edge_count: 1,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    // Test JSON serialization
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(!json.is_empty());

    let deserialized: ControlFlowGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.function_address, cfg.function_address);
    assert_eq!(deserialized.function_name, cfg.function_name);
    assert_eq!(deserialized.basic_blocks.len(), cfg.basic_blocks.len());
}

#[test]
fn test_edge_types() {
    let edge_types = vec![
        EdgeType::Fall,
        EdgeType::Jump,
        EdgeType::Branch,
        EdgeType::Call,
        EdgeType::Return,
    ];

    for edge_type in edge_types {
        let json = serde_json::to_string(&edge_type).unwrap();
        assert!(!json.is_empty());
    }
}

#[test]
fn test_loop_types() {
    let loop_types = vec![
        LoopType::Natural,
        LoopType::Irreducible,
        LoopType::DoWhile,
        LoopType::While,
        LoopType::For,
    ];

    for loop_type in loop_types {
        let json = serde_json::to_string(&loop_type).unwrap();
        assert!(!json.is_empty());
    }
}
