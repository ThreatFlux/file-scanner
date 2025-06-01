use file_scanner::code_metrics::*;
use file_scanner::control_flow::{
    AnalysisStats, BasicBlock, BlockType, CfgEdge, ControlFlowAnalysis, ControlFlowGraph,
    ControlFlowMetrics, EdgeType, FlowControl, Instruction, InstructionType, Loop, LoopType,
    OverallMetrics,
};
use file_scanner::function_analysis::{SymbolCounts, SymbolTable};

// Helper function to create an empty symbol table
fn create_empty_symbol_table() -> SymbolTable {
    SymbolTable {
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
    }
}

// Helper function to create a mock instruction
fn create_instruction(
    address: u64,
    mnemonic: &str,
    operands: &str,
    instruction_type: InstructionType,
    flow_control: FlowControl,
) -> Instruction {
    Instruction {
        address,
        bytes: vec![0x90], // NOP for simplicity
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
        instruction_type,
        flow_control,
        size: 1,
    }
}

// Helper function to create a basic block with instructions
fn create_basic_block(
    id: usize,
    start_address: u64,
    instructions: Vec<Instruction>,
    block_type: BlockType,
) -> BasicBlock {
    let instruction_count = instructions.len();
    let end_address = if instructions.is_empty() {
        start_address
    } else {
        instructions.last().unwrap().address + 1
    };

    BasicBlock {
        id,
        start_address,
        end_address,
        instructions,
        successors: vec![],
        predecessors: vec![],
        block_type,
        instruction_count,
    }
}

// Helper function to create a simple CFG
fn create_simple_cfg(
    function_name: &str,
    function_address: u64,
    complexity: u32,
    cognitive_complexity: u32,
    nesting_depth: u32,
) -> ControlFlowGraph {
    let mut blocks = vec![];

    // Entry block with some arithmetic instructions
    let entry_instructions = vec![
        create_instruction(
            function_address,
            "push",
            "rbp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 1,
            "mov",
            "rbp, rsp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 2,
            "add",
            "rax, rbx",
            InstructionType::Arithmetic,
            FlowControl::Fall,
        ),
    ];
    blocks.push(create_basic_block(
        0,
        function_address,
        entry_instructions,
        BlockType::Entry,
    ));

    // Main block with control flow
    let main_instructions = vec![
        create_instruction(
            function_address + 10,
            "cmp",
            "rax, 0",
            InstructionType::Conditional,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 11,
            "je",
            "0x1100",
            InstructionType::Conditional,
            FlowControl::Branch(0x1100),
        ),
    ];
    blocks.push(create_basic_block(
        1,
        function_address + 10,
        main_instructions,
        BlockType::Conditional,
    ));

    // Exit block
    let exit_instructions = vec![
        create_instruction(
            function_address + 20,
            "pop",
            "rbp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 21,
            "ret",
            "",
            InstructionType::Return,
            FlowControl::Return,
        ),
    ];
    blocks.push(create_basic_block(
        2,
        function_address + 20,
        exit_instructions,
        BlockType::Exit,
    ));

    ControlFlowGraph {
        function_address,
        function_name: function_name.to_string(),
        basic_blocks: blocks,
        edges: vec![
            CfgEdge {
                from_block: 0,
                to_block: 1,
                edge_type: EdgeType::Fall,
            },
            CfgEdge {
                from_block: 1,
                to_block: 2,
                edge_type: EdgeType::Branch,
            },
        ],
        entry_block: 0,
        exit_blocks: vec![2],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: complexity,
            cognitive_complexity,
            nesting_depth,
            basic_block_count: 3,
            edge_count: 2,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    }
}

// Helper function to create a complex CFG with loops
fn create_complex_cfg(function_name: &str, function_address: u64) -> ControlFlowGraph {
    let mut blocks = vec![];

    // Entry block
    let entry_instructions = vec![
        create_instruction(
            function_address,
            "push",
            "rbp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 1,
            "mov",
            "rbp, rsp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 2,
            "mov",
            "rcx, 10",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
    ];
    blocks.push(create_basic_block(
        0,
        function_address,
        entry_instructions,
        BlockType::Entry,
    ));

    // Loop header
    let loop_header_instructions = vec![
        create_instruction(
            function_address + 10,
            "cmp",
            "rcx, 0",
            InstructionType::Conditional,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 11,
            "jle",
            "0x1200",
            InstructionType::Conditional,
            FlowControl::Branch(0x1200),
        ),
    ];
    blocks.push(create_basic_block(
        1,
        function_address + 10,
        loop_header_instructions,
        BlockType::LoopHeader,
    ));

    // Loop body with nested complexity
    let loop_body_instructions = vec![
        create_instruction(
            function_address + 20,
            "call",
            "process_item",
            InstructionType::Call,
            FlowControl::Call(0x2000),
        ),
        create_instruction(
            function_address + 21,
            "dec",
            "rcx",
            InstructionType::Arithmetic,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 22,
            "cmp",
            "rax, 0",
            InstructionType::Conditional,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 23,
            "je",
            "0x1100",
            InstructionType::Conditional,
            FlowControl::Branch(0x1100),
        ),
        create_instruction(
            function_address + 24,
            "mul",
            "rax, rbx",
            InstructionType::Arithmetic,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 25,
            "div",
            "rax, rdx",
            InstructionType::Arithmetic,
            FlowControl::Fall,
        ),
    ];
    blocks.push(create_basic_block(
        2,
        function_address + 20,
        loop_body_instructions,
        BlockType::LoopBody,
    ));

    // Exit block
    let exit_instructions = vec![
        create_instruction(
            function_address + 30,
            "xor",
            "rax, rax",
            InstructionType::Logic,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 31,
            "pop",
            "rbp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            function_address + 32,
            "ret",
            "",
            InstructionType::Return,
            FlowControl::Return,
        ),
    ];
    blocks.push(create_basic_block(
        3,
        function_address + 30,
        exit_instructions,
        BlockType::Exit,
    ));

    ControlFlowGraph {
        function_address,
        function_name: function_name.to_string(),
        basic_blocks: blocks,
        edges: vec![
            CfgEdge {
                from_block: 0,
                to_block: 1,
                edge_type: EdgeType::Fall,
            },
            CfgEdge {
                from_block: 1,
                to_block: 2,
                edge_type: EdgeType::Branch,
            },
            CfgEdge {
                from_block: 1,
                to_block: 3,
                edge_type: EdgeType::Branch,
            },
            CfgEdge {
                from_block: 2,
                to_block: 1,
                edge_type: EdgeType::Jump,
            }, // Loop back
        ],
        entry_block: 0,
        exit_blocks: vec![3],
        loops: vec![Loop {
            header_block: 1,
            body_blocks: vec![2],
            exit_blocks: vec![3],
            loop_type: LoopType::While,
            nesting_level: 0,
        }],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 15,
            cognitive_complexity: 18,
            nesting_depth: 3,
            basic_block_count: 4,
            edge_count: 4,
            loop_count: 1,
            unreachable_blocks: vec![],
        },
    }
}

// Helper to create control flow analysis with given CFGs
fn create_control_flow_analysis(cfgs: Vec<ControlFlowGraph>) -> ControlFlowAnalysis {
    let total_functions = cfgs.len();
    let total_basic_blocks = cfgs.iter().map(|cfg| cfg.basic_blocks.len()).sum();
    let average_complexity = if total_functions > 0 {
        cfgs.iter()
            .map(|cfg| cfg.complexity.cyclomatic_complexity as f64)
            .sum::<f64>()
            / total_functions as f64
    } else {
        0.0
    };
    let (max_complexity, function_with_max_complexity) = cfgs
        .iter()
        .max_by_key(|cfg| cfg.complexity.cyclomatic_complexity)
        .map(|cfg| {
            (
                cfg.complexity.cyclomatic_complexity,
                Some(cfg.function_name.clone()),
            )
        })
        .unwrap_or((0, None));

    ControlFlowAnalysis {
        cfgs,
        overall_metrics: OverallMetrics {
            total_functions,
            analyzed_functions: total_functions,
            total_basic_blocks,
            average_complexity,
            max_complexity,
            function_with_max_complexity,
        },
        analysis_stats: AnalysisStats {
            analysis_duration: 10,
            bytes_analyzed: 1000,
            instructions_analyzed: 100,
            errors: vec![],
        },
    }
}

#[test]
fn test_code_quality_analyzer_creation() {
    let analyzer = CodeQualityAnalyzer::new();
    // Simple creation test - analyzer is created successfully
    let _ = analyzer; // Use it to avoid unused variable warning
}

#[test]
fn test_basic_analysis() {
    let analyzer = CodeQualityAnalyzer::new();
    let cfg = create_simple_cfg("test_function", 0x1000, 5, 7, 2);
    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();

    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert_eq!(analysis.function_metrics.len(), 1);
    assert_eq!(analysis.function_metrics[0].function_name, "test_function");
    assert_eq!(analysis.function_metrics[0].cyclomatic_complexity, 5);
    assert_eq!(analysis.function_metrics[0].cognitive_complexity, 7);
    assert_eq!(analysis.function_metrics[0].nesting_depth, 2);
    assert!(analysis.function_metrics[0].function_length > 0);
    assert!(analysis.function_metrics[0].maintainability_index > 0.0);
}

#[test]
fn test_halstead_metrics() {
    let analyzer = CodeQualityAnalyzer::new();
    let cfg = create_simple_cfg("test_function", 0x1000, 5, 7, 2);
    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();

    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    let metrics = &analysis.function_metrics[0];

    // Verify Halstead metrics are calculated
    assert!(metrics.halstead_metrics.distinct_operators > 0);
    assert!(metrics.halstead_metrics.distinct_operands > 0);
    assert!(metrics.halstead_metrics.total_operators > 0);
    assert!(metrics.halstead_metrics.total_operands > 0);
    assert_eq!(
        metrics.halstead_metrics.vocabulary,
        metrics.halstead_metrics.distinct_operators + metrics.halstead_metrics.distinct_operands
    );
    assert_eq!(
        metrics.halstead_metrics.length,
        metrics.halstead_metrics.total_operators + metrics.halstead_metrics.total_operands
    );

    // Verify calculated metrics
    assert!(metrics.halstead_metrics.volume > 0.0);
    assert!(metrics.halstead_metrics.difficulty > 0.0);
    assert!(metrics.halstead_metrics.effort > 0.0);
    assert!(metrics.halstead_metrics.time_to_program > 0.0);
    assert!(metrics.halstead_metrics.delivered_bugs >= 0.0);
}

#[test]
fn test_empty_function_analysis() {
    let analyzer = CodeQualityAnalyzer::new();

    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "empty_function".to_string(),
        basic_blocks: vec![create_basic_block(0, 0x1000, vec![], BlockType::Entry)],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![0],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 1,
            cognitive_complexity: 0,
            nesting_depth: 0,
            basic_block_count: 1,
            edge_count: 0,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    let metrics = &analysis.function_metrics[0];

    assert_eq!(metrics.halstead_metrics.distinct_operators, 0);
    assert_eq!(metrics.halstead_metrics.distinct_operands, 0);
    assert_eq!(metrics.halstead_metrics.total_operators, 0);
    assert_eq!(metrics.halstead_metrics.total_operands, 0);
    assert_eq!(metrics.halstead_metrics.vocabulary, 0);
    assert_eq!(metrics.halstead_metrics.length, 0);
    assert_eq!(metrics.halstead_metrics.volume, 0.0);
}

#[test]
fn test_complex_function_analysis() {
    let analyzer = CodeQualityAnalyzer::new();
    let cfg = create_complex_cfg("complex_function", 0x2000);
    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();

    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    let metrics = &analysis.function_metrics[0];

    assert_eq!(metrics.function_name, "complex_function");
    assert_eq!(metrics.function_address, 0x2000);
    assert_eq!(metrics.cyclomatic_complexity, 15);
    assert_eq!(metrics.cognitive_complexity, 18);
    assert_eq!(metrics.nesting_depth, 3);
    assert!(metrics.technical_debt_minutes > 0);
    assert!(metrics.halstead_metrics.volume > 0.0);
}

#[test]
fn test_maintainability_index() {
    let analyzer = CodeQualityAnalyzer::new();

    // Test with a simple function (high maintainability)
    let simple_cfg = create_simple_cfg("simple_func", 0x1000, 3, 4, 1);
    let cfg_analysis = create_control_flow_analysis(vec![simple_cfg]);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    let simple_metrics = &analysis.function_metrics[0];

    assert!(simple_metrics.maintainability_index > 50.0);
    assert!(simple_metrics.maintainability_index <= 100.0);

    // Test with a complex function (lower maintainability)
    let complex_cfg = create_complex_cfg("complex_func", 0x2000);
    let cfg_analysis = create_control_flow_analysis(vec![complex_cfg]);
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    let complex_metrics = &analysis.function_metrics[0];

    assert!(complex_metrics.maintainability_index >= 0.0);
    assert!(complex_metrics.maintainability_index < simple_metrics.maintainability_index);
}

#[test]
fn test_technical_debt_estimation() {
    let analyzer = CodeQualityAnalyzer::new();
    let symbol_table = create_empty_symbol_table();

    // Test with a simple function (no debt)
    let simple_cfg = create_simple_cfg("simple_func", 0x1000, 5, 10, 2);
    let cfg_analysis = create_control_flow_analysis(vec![simple_cfg]);
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    assert_eq!(analysis.function_metrics[0].technical_debt_minutes, 0);

    // Test with a complex function (high debt)
    let complex_cfg = create_simple_cfg("complex_func", 0x2000, 15, 20, 6);
    let cfg_analysis = create_control_flow_analysis(vec![complex_cfg]);
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();
    assert!(analysis.function_metrics[0].technical_debt_minutes > 0);
}

#[test]
fn test_parameter_count_estimation() {
    let analyzer = CodeQualityAnalyzer::new();

    // Create a function with parameter register usage
    let instructions = vec![
        create_instruction(
            0x1000,
            "push",
            "rbp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            0x1001,
            "mov",
            "rbp, rsp",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            0x1002,
            "mov",
            "rax, rdi",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
        create_instruction(
            0x1003,
            "add",
            "rax, rsi",
            InstructionType::Arithmetic,
            FlowControl::Fall,
        ),
        create_instruction(
            0x1004,
            "mov",
            "rbx, rdx",
            InstructionType::Memory,
            FlowControl::Fall,
        ),
    ];

    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "param_func".to_string(),
        basic_blocks: vec![create_basic_block(
            0,
            0x1000,
            instructions,
            BlockType::Entry,
        )],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![0],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 1,
            cognitive_complexity: 0,
            nesting_depth: 0,
            basic_block_count: 1,
            edge_count: 0,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert_eq!(analysis.function_metrics[0].parameter_count, 3); // rdi, rsi, rdx used
}

#[test]
fn test_overall_metrics_calculation() {
    let analyzer = CodeQualityAnalyzer::new();

    let cfgs = vec![
        create_simple_cfg("func1", 0x1000, 5, 6, 2),
        create_complex_cfg("func2", 0x2000),
        create_simple_cfg("func3", 0x3000, 8, 10, 3),
    ];

    let cfg_analysis = create_control_flow_analysis(cfgs);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert_eq!(analysis.overall_metrics.total_functions, 3);
    assert!(analysis.overall_metrics.average_complexity > 0.0);
    assert!(analysis.overall_metrics.average_function_length > 0.0);
    assert!(analysis.overall_metrics.total_code_volume > 0.0);
    assert_eq!(
        analysis.overall_metrics.most_complex_function,
        Some("func2".to_string())
    );
    assert_eq!(analysis.overall_metrics.highest_complexity, 15);
}

#[test]
fn test_quality_report_generation() {
    let analyzer = CodeQualityAnalyzer::new();

    // Create a function with multiple quality issues
    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "problematic_func".to_string(),
        basic_blocks: {
            let mut blocks = vec![];
            let mut instructions = vec![];
            // Create a long function with many instructions
            for i in 0..150 {
                instructions.push(create_instruction(
                    0x1000 + i,
                    if i % 10 == 0 { "cmp" } else { "mov" },
                    "rax, rbx",
                    if i % 10 == 0 {
                        InstructionType::Conditional
                    } else {
                        InstructionType::Memory
                    },
                    FlowControl::Fall,
                ));
            }
            blocks.push(create_basic_block(
                0,
                0x1000,
                instructions,
                BlockType::Normal,
            ));
            blocks
        },
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![0],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 25,
            cognitive_complexity: 30,
            nesting_depth: 6,
            basic_block_count: 1,
            edge_count: 0,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    // Check quality issues
    assert!(!analysis.quality_report.quality_issues.is_empty());

    // Check for specific issue types
    let has_complexity_issue = analysis
        .quality_report
        .quality_issues
        .iter()
        .any(|i| matches!(i.issue_type, QualityIssueType::HighComplexity));
    assert!(has_complexity_issue);

    let has_length_issue = analysis
        .quality_report
        .quality_issues
        .iter()
        .any(|i| matches!(i.issue_type, QualityIssueType::LongFunction));
    assert!(has_length_issue);

    let has_nesting_issue = analysis
        .quality_report
        .quality_issues
        .iter()
        .any(|i| matches!(i.issue_type, QualityIssueType::DeepNesting));
    assert!(has_nesting_issue);

    // Check recommendations
    assert!(!analysis.quality_report.recommendations.is_empty());

    // Check technical debt
    assert!(analysis.quality_report.technical_debt_hours > 0.0);

    // Check code health
    assert!(matches!(
        analysis.quality_report.code_health,
        CodeHealth::Critical | CodeHealth::Poor
    ));
}

#[test]
fn test_code_health_classification() {
    let analyzer = CodeQualityAnalyzer::new();
    let symbol_table = create_empty_symbol_table();

    // Test with excellent code
    let excellent_cfg = create_simple_cfg("excellent", 0x1000, 3, 4, 1);
    let cfg_analysis = create_control_flow_analysis(vec![excellent_cfg]);
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert!(analysis.quality_report.overall_quality_score >= 75.0);
    assert!(matches!(
        analysis.quality_report.code_health,
        CodeHealth::Excellent | CodeHealth::Good
    ));
}

#[test]
fn test_multiple_return_paths() {
    let analyzer = CodeQualityAnalyzer::new();

    // Create a function with multiple return paths
    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "multi_return".to_string(),
        basic_blocks: vec![
            create_basic_block(0, 0x1000, vec![], BlockType::Entry),
            create_basic_block(1, 0x1010, vec![], BlockType::Exit),
            create_basic_block(2, 0x1020, vec![], BlockType::Exit),
            create_basic_block(3, 0x1030, vec![], BlockType::Exit),
            create_basic_block(4, 0x1040, vec![], BlockType::Exit),
            create_basic_block(5, 0x1050, vec![], BlockType::Exit),
            create_basic_block(6, 0x1060, vec![], BlockType::Exit),
        ],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![1, 2, 3, 4, 5, 6], // 6 return paths
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 6,
            cognitive_complexity: 8,
            nesting_depth: 2,
            basic_block_count: 7,
            edge_count: 6,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert_eq!(analysis.function_metrics[0].return_paths, 6);

    // Should have a "too many returns" issue
    let has_return_issue = analysis
        .quality_report
        .quality_issues
        .iter()
        .any(|i| matches!(i.issue_type, QualityIssueType::TooManyReturns));
    assert!(has_return_issue);
}

#[test]
fn test_god_function_detection() {
    let analyzer = CodeQualityAnalyzer::new();

    // Create a "god function" with high complexity and length
    let mut instructions = vec![];
    for i in 0..120 {
        instructions.push(create_instruction(
            0x1000 + i,
            if i % 5 == 0 { "cmp" } else { "mov" },
            "rax, rbx",
            if i % 5 == 0 {
                InstructionType::Conditional
            } else {
                InstructionType::Memory
            },
            FlowControl::Fall,
        ));
    }

    let cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "god_function".to_string(),
        basic_blocks: vec![create_basic_block(
            0,
            0x1000,
            instructions,
            BlockType::Normal,
        )],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![0],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 25,
            cognitive_complexity: 30,
            nesting_depth: 4,
            basic_block_count: 1,
            edge_count: 0,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    let cfg_analysis = create_control_flow_analysis(vec![cfg]);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    let has_god_function_issue = analysis
        .quality_report
        .quality_issues
        .iter()
        .any(|i| matches!(i.issue_type, QualityIssueType::GodFunction));
    assert!(has_god_function_issue);
}

#[test]
fn test_empty_analysis() {
    let analyzer = CodeQualityAnalyzer::new();
    let cfg_analysis = create_control_flow_analysis(vec![]);
    let symbol_table = create_empty_symbol_table();

    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert_eq!(analysis.function_metrics.len(), 0);
    assert_eq!(analysis.overall_metrics.total_functions, 0);
    assert_eq!(analysis.overall_metrics.average_complexity, 0.0);
    assert_eq!(analysis.quality_report.overall_quality_score, 100.0); // No code = perfect score
    assert!(analysis.quality_report.quality_issues.is_empty());
}

#[test]
fn test_issue_severity_classification() {
    // Test that severity levels are properly assigned
    let critical_issue = QualityIssue {
        issue_type: QualityIssueType::GodFunction,
        severity: IssueSeverity::Critical,
        function_name: "test".to_string(),
        description: "Test".to_string(),
        recommendation: "Test".to_string(),
        debt_minutes: 100,
    };

    assert!(matches!(critical_issue.severity, IssueSeverity::Critical));

    let major_issue = QualityIssue {
        issue_type: QualityIssueType::HighComplexity,
        severity: IssueSeverity::Major,
        function_name: "test".to_string(),
        description: "Test".to_string(),
        recommendation: "Test".to_string(),
        debt_minutes: 50,
    };

    assert!(matches!(major_issue.severity, IssueSeverity::Major));
}

#[test]
fn test_serialization_deserialization() {
    // Test that all structures can be serialized and deserialized
    let metrics = FunctionMetrics {
        function_name: "test_func".to_string(),
        function_address: 0x1000,
        cyclomatic_complexity: 5,
        cognitive_complexity: 6,
        nesting_depth: 2,
        function_length: 20,
        basic_block_count: 3,
        parameter_count: 2,
        return_paths: 1,
        halstead_metrics: HalsteadMetrics {
            distinct_operators: 5,
            distinct_operands: 10,
            total_operators: 20,
            total_operands: 30,
            vocabulary: 15,
            length: 50,
            volume: 195.0,
            difficulty: 7.5,
            effort: 1462.5,
            time_to_program: 81.25,
            delivered_bugs: 0.065,
        },
        maintainability_index: 75.0,
        technical_debt_minutes: 0,
    };

    let json = serde_json::to_string(&metrics).unwrap();
    let deserialized: FunctionMetrics = serde_json::from_str(&json).unwrap();

    assert_eq!(metrics.function_name, deserialized.function_name);
    assert_eq!(
        metrics.cyclomatic_complexity,
        deserialized.cyclomatic_complexity
    );
    assert_eq!(
        metrics.halstead_metrics.volume,
        deserialized.halstead_metrics.volume
    );
}

#[test]
fn test_analyze_code_quality_function() {
    use std::path::Path;

    // Create test data
    let cfgs = vec![create_simple_cfg("test_func", 0x1000, 5, 7, 2)];
    let cfg_analysis = create_control_flow_analysis(cfgs);
    let symbol_table = create_empty_symbol_table();

    let result = analyze_code_quality(Path::new("/test/path"), &symbol_table, &cfg_analysis);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert_eq!(analysis.function_metrics.len(), 1);
    assert_eq!(analysis.function_metrics[0].function_name, "test_func");
}

#[test]
fn test_analysis_stats() {
    let analyzer = CodeQualityAnalyzer::new();
    let cfgs = vec![
        create_simple_cfg("func1", 0x1000, 5, 6, 2),
        create_complex_cfg("func2", 0x2000),
    ];

    let cfg_analysis = create_control_flow_analysis(cfgs);
    let symbol_table = create_empty_symbol_table();
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    assert_eq!(analysis.analysis_stats.functions_analyzed, 2);
    assert!(analysis.analysis_stats.instructions_analyzed > 0);
    // Duration is u64, so it's always >= 0
}

#[test]
fn test_edge_case_scores() {
    let analyzer = CodeQualityAnalyzer::new();
    let symbol_table = create_empty_symbol_table();

    // Test with zero complexity
    let zero_cfg = ControlFlowGraph {
        function_address: 0x1000,
        function_name: "zero_complexity".to_string(),
        basic_blocks: vec![create_basic_block(0, 0x1000, vec![], BlockType::Entry)],
        edges: vec![],
        entry_block: 0,
        exit_blocks: vec![0],
        loops: vec![],
        complexity: ControlFlowMetrics {
            cyclomatic_complexity: 0,
            cognitive_complexity: 0,
            nesting_depth: 0,
            basic_block_count: 1,
            edge_count: 0,
            loop_count: 0,
            unreachable_blocks: vec![],
        },
    };

    let cfg_analysis = create_control_flow_analysis(vec![zero_cfg]);
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    // Should still have valid scores
    assert!(analysis.quality_report.overall_quality_score >= 0.0);
    assert!(analysis.quality_report.overall_quality_score <= 100.0);
    assert!(analysis.quality_report.complexity_score >= 0.0);
    assert!(analysis.quality_report.complexity_score <= 100.0);
}

#[test]
fn test_recommendations() {
    let analyzer = CodeQualityAnalyzer::new();
    let symbol_table = create_empty_symbol_table();

    // Test with high complexity function
    let high_complexity_cfg = create_simple_cfg("high_complexity", 0x1000, 15, 20, 3);
    let cfg_analysis = create_control_flow_analysis(vec![high_complexity_cfg]);
    let analysis = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

    // Should have recommendations for high complexity
    assert!(!analysis.quality_report.recommendations.is_empty());
    let has_complexity_recommendation = analysis
        .quality_report
        .recommendations
        .iter()
        .any(|r| r.contains("complex"));
    assert!(has_complexity_recommendation);
}
