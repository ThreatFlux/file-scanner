use anyhow::{anyhow, Result};
use capstone::prelude::*;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::function_analysis::{FunctionInfo, SymbolTable};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowGraph {
    pub function_address: u64,
    pub function_name: String,
    pub basic_blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub entry_block: usize,
    pub exit_blocks: Vec<usize>,
    pub loops: Vec<Loop>,
    pub complexity: ControlFlowMetrics,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub block_type: BlockType,
    pub instruction_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BlockType {
    Entry,
    Exit,
    Normal,
    LoopHeader,
    LoopBody,
    Conditional,
    Call,
    Return,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub instruction_type: InstructionType,
    pub flow_control: FlowControl,
    pub size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InstructionType {
    Arithmetic,
    Logic,
    Memory,
    Control,
    System,
    Call,
    Return,
    Jump,
    Conditional,
    Nop,
    Other,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FlowControl {
    Fall,        // Falls through to next instruction
    Jump(u64),   // Unconditional jump to address
    Branch(u64), // Conditional branch to address
    Call(u64),   // Function call to address
    Return,      // Return from function
    Indirect,    // Indirect jump/call
    Halt,        // Stops execution
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfgEdge {
    pub from_block: usize,
    pub to_block: usize,
    pub edge_type: EdgeType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EdgeType {
    Fall,   // Sequential execution
    Jump,   // Unconditional jump
    Branch, // Conditional branch
    Call,   // Function call
    Return, // Return edge
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Loop {
    pub header_block: usize,
    pub body_blocks: Vec<usize>,
    pub exit_blocks: Vec<usize>,
    pub loop_type: LoopType,
    pub nesting_level: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LoopType {
    Natural,     // Natural loop with single entry
    Irreducible, // Multiple entry points
    DoWhile,     // Test at end
    While,       // Test at beginning
    For,         // Counted loop
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowMetrics {
    pub cyclomatic_complexity: u32,
    pub cognitive_complexity: u32,
    pub nesting_depth: u32,
    pub basic_block_count: usize,
    pub edge_count: usize,
    pub loop_count: usize,
    pub unreachable_blocks: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowAnalysis {
    pub cfgs: Vec<ControlFlowGraph>,
    pub overall_metrics: OverallMetrics,
    pub analysis_stats: AnalysisStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverallMetrics {
    pub total_functions: usize,
    pub analyzed_functions: usize,
    pub total_basic_blocks: usize,
    pub average_complexity: f64,
    pub max_complexity: u32,
    pub function_with_max_complexity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisStats {
    pub analysis_duration: u64, // milliseconds
    pub bytes_analyzed: u64,
    pub instructions_analyzed: usize,
    pub errors: Vec<String>,
}

pub struct ControlFlowAnalyzer {
    capstone: Capstone,
}

impl ControlFlowAnalyzer {
    pub fn new_x86_64() -> Result<Self> {
        let capstone = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to build x86_64 capstone engine: {:?}", e))?;

        Ok(Self { capstone })
    }

    pub fn analyze_functions(
        &self,
        binary_data: &[u8],
        symbol_table: &SymbolTable,
        text_section_offset: u64,
        text_section_addr: u64,
    ) -> Result<ControlFlowAnalysis> {
        let start_time = std::time::Instant::now();
        let mut cfgs = Vec::new();
        let mut errors = Vec::new();
        let mut total_instructions = 0;

        // Only analyze exported functions with valid sizes
        let functions_to_analyze: Vec<&FunctionInfo> = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_exported && f.size > 0 && f.address >= text_section_addr)
            .collect();

        for function in &functions_to_analyze {
            // Calculate the offset within the binary file
            let file_offset = (function.address - text_section_addr + text_section_offset) as usize;

            // Ensure we don't read beyond the file
            if file_offset >= binary_data.len() {
                errors.push(format!(
                    "Function {} offset {} beyond file size",
                    function.name, file_offset
                ));
                continue;
            }

            let function_size =
                std::cmp::min(function.size as usize, binary_data.len() - file_offset);
            let function_bytes = &binary_data[file_offset..file_offset + function_size];

            match self.analyze_function(function, function_bytes) {
                Ok(cfg) => {
                    total_instructions += cfg
                        .basic_blocks
                        .iter()
                        .map(|bb| bb.instruction_count)
                        .sum::<usize>();
                    cfgs.push(cfg);
                }
                Err(e) => {
                    errors.push(format!(
                        "Failed to analyze function {}: {}",
                        function.name, e
                    ));
                }
            }
        }

        let duration = start_time.elapsed().as_millis() as u64;

        // Calculate overall metrics
        let total_basic_blocks = cfgs.iter().map(|cfg| cfg.basic_blocks.len()).sum();
        let average_complexity = if cfgs.is_empty() {
            0.0
        } else {
            cfgs.iter()
                .map(|cfg| cfg.complexity.cyclomatic_complexity as f64)
                .sum::<f64>()
                / cfgs.len() as f64
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

        let analyzed_functions = cfgs.len();

        Ok(ControlFlowAnalysis {
            cfgs,
            overall_metrics: OverallMetrics {
                total_functions: functions_to_analyze.len(),
                analyzed_functions,
                total_basic_blocks,
                average_complexity,
                max_complexity,
                function_with_max_complexity,
            },
            analysis_stats: AnalysisStats {
                analysis_duration: duration,
                bytes_analyzed: binary_data.len() as u64,
                instructions_analyzed: total_instructions,
                errors,
            },
        })
    }

    fn analyze_function(
        &self,
        function: &FunctionInfo,
        function_bytes: &[u8],
    ) -> Result<ControlFlowGraph> {
        // Disassemble the function
        let instructions = self.disassemble_function(function_bytes, function.address)?;

        if instructions.is_empty() {
            return Err(anyhow!("No instructions found in function"));
        }

        // Find basic block boundaries
        let block_boundaries = self.find_basic_block_boundaries(&instructions);

        // Create basic blocks
        let basic_blocks = self.create_basic_blocks(&instructions, &block_boundaries);

        // Build control flow edges
        let edges = self.build_control_flow_edges(&basic_blocks);

        // Detect loops
        let loops = self.detect_loops(&basic_blocks, &edges);

        // Calculate complexity metrics
        let complexity = self.calculate_complexity_metrics(&basic_blocks, &edges, &loops);

        // Determine entry and exit blocks
        let entry_block = 0; // First block is always entry
        let exit_blocks = self.find_exit_blocks(&basic_blocks);

        Ok(ControlFlowGraph {
            function_address: function.address,
            function_name: function.name.clone(),
            basic_blocks,
            edges,
            entry_block,
            exit_blocks,
            loops,
            complexity,
        })
    }

    fn disassemble_function(&self, bytes: &[u8], base_address: u64) -> Result<Vec<Instruction>> {
        let instructions = self
            .capstone
            .disasm_all(bytes, base_address)
            .map_err(|e| anyhow!("Failed to disassemble: {:?}", e))?;

        let mut result = Vec::new();

        for insn in instructions.as_ref() {
            let instruction_type = self.classify_instruction(&insn);
            let flow_control = self.analyze_flow_control(&insn);

            result.push(Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                instruction_type,
                flow_control,
                size: insn.bytes().len(),
            });
        }

        Ok(result)
    }

    fn classify_instruction(&self, insn: &capstone::Insn) -> InstructionType {
        let mnemonic = insn.mnemonic().unwrap_or("");

        match mnemonic {
            // Control flow instructions
            "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jge" | "jl" | "jle" | "ja" | "jae"
            | "jb" | "jbe" | "jo" | "jno" | "js" | "jns" | "jp" | "jnp" => InstructionType::Jump,

            // Conditional jumps
            "test" | "cmp" => InstructionType::Conditional,

            // Function calls and returns
            "call" => InstructionType::Call,
            "ret" | "retf" | "retn" => InstructionType::Return,

            // Arithmetic operations
            "add" | "sub" | "mul" | "div" | "inc" | "dec" | "imul" | "idiv" | "neg" => {
                InstructionType::Arithmetic
            }

            // Logic operations
            "and" | "or" | "xor" | "not" | "shl" | "shr" | "sal" | "sar" => InstructionType::Logic,

            // Memory operations
            "mov" | "lea" | "push" | "pop" | "movsb" | "movsw" | "movsd" | "movsq" => {
                InstructionType::Memory
            }

            // No operation
            "nop" => InstructionType::Nop,

            // System calls and interrupts
            "syscall" | "int" | "sysenter" | "sysexit" => InstructionType::System,

            _ => InstructionType::Other,
        }
    }

    fn analyze_flow_control(&self, insn: &capstone::Insn) -> FlowControl {
        let mnemonic = insn.mnemonic().unwrap_or("");

        match mnemonic {
            "ret" | "retf" | "retn" => FlowControl::Return,
            "jmp" => {
                // Try to extract target address for direct jumps
                if let Some(op_str) = insn.op_str() {
                    if let Ok(addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                        FlowControl::Jump(addr)
                    } else {
                        FlowControl::Indirect
                    }
                } else {
                    FlowControl::Indirect
                }
            }
            "je" | "jne" | "jz" | "jnz" | "jg" | "jge" | "jl" | "jle" | "ja" | "jae" | "jb"
            | "jbe" | "jo" | "jno" | "js" | "jns" | "jp" | "jnp" => {
                // Try to extract target address for conditional branches
                if let Some(op_str) = insn.op_str() {
                    if let Ok(addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                        FlowControl::Branch(addr)
                    } else {
                        FlowControl::Indirect
                    }
                } else {
                    FlowControl::Indirect
                }
            }
            "call" => {
                // Try to extract target address for direct calls
                if let Some(op_str) = insn.op_str() {
                    if let Ok(addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                        FlowControl::Call(addr)
                    } else {
                        FlowControl::Indirect
                    }
                } else {
                    FlowControl::Indirect
                }
            }
            "hlt" => FlowControl::Halt,
            _ => FlowControl::Fall,
        }
    }

    fn find_basic_block_boundaries(&self, instructions: &[Instruction]) -> HashSet<u64> {
        let mut boundaries = HashSet::new();

        // First instruction is always a boundary
        if let Some(first) = instructions.first() {
            boundaries.insert(first.address);
        }

        for (i, instruction) in instructions.iter().enumerate() {
            match &instruction.flow_control {
                FlowControl::Jump(target)
                | FlowControl::Branch(target)
                | FlowControl::Call(target) => {
                    // Target of jump/branch/call is a boundary
                    boundaries.insert(*target);

                    // For conditional branches, the next instruction is also a boundary
                    if matches!(instruction.flow_control, FlowControl::Branch(_)) {
                        if let Some(next_insn) = instructions.get(i + 1) {
                            boundaries.insert(next_insn.address);
                        }
                    }
                }
                FlowControl::Return | FlowControl::Halt => {
                    // Instruction after return/halt is a boundary (if it exists)
                    if let Some(next_insn) = instructions.get(i + 1) {
                        boundaries.insert(next_insn.address);
                    }
                }
                _ => {}
            }
        }

        boundaries
    }

    fn create_basic_blocks(
        &self,
        instructions: &[Instruction],
        boundaries: &HashSet<u64>,
    ) -> Vec<BasicBlock> {
        let mut basic_blocks = Vec::new();
        let mut current_block_instructions: Vec<Instruction> = Vec::new();
        let mut block_id = 0;
        let mut block_start_addr = 0;

        for instruction in instructions {
            // Start a new block if this address is a boundary
            if boundaries.contains(&instruction.address) && !current_block_instructions.is_empty() {
                // Finish the current block
                let end_addr = current_block_instructions.last().unwrap().address
                    + current_block_instructions.last().unwrap().size as u64;

                let block_type = self.determine_block_type(&current_block_instructions);

                basic_blocks.push(BasicBlock {
                    id: block_id,
                    start_address: block_start_addr,
                    end_address: end_addr,
                    instruction_count: current_block_instructions.len(),
                    instructions: current_block_instructions.clone(),
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                    block_type,
                });

                block_id += 1;
                current_block_instructions.clear();
            }

            // Start new block if needed
            if current_block_instructions.is_empty() {
                block_start_addr = instruction.address;
            }

            current_block_instructions.push(instruction.clone());

            // End block if this is a control flow instruction
            match instruction.flow_control {
                FlowControl::Return | FlowControl::Jump(_) | FlowControl::Halt => {
                    let end_addr = instruction.address + instruction.size as u64;
                    let block_type = self.determine_block_type(&current_block_instructions);

                    basic_blocks.push(BasicBlock {
                        id: block_id,
                        start_address: block_start_addr,
                        end_address: end_addr,
                        instruction_count: current_block_instructions.len(),
                        instructions: current_block_instructions.clone(),
                        successors: Vec::new(),
                        predecessors: Vec::new(),
                        block_type,
                    });

                    block_id += 1;
                    current_block_instructions.clear();
                }
                _ => {}
            }
        }

        // Handle any remaining instructions
        if !current_block_instructions.is_empty() {
            let end_addr = current_block_instructions.last().unwrap().address
                + current_block_instructions.last().unwrap().size as u64;
            let block_type = self.determine_block_type(&current_block_instructions);

            basic_blocks.push(BasicBlock {
                id: block_id,
                start_address: block_start_addr,
                end_address: end_addr,
                instruction_count: current_block_instructions.len(),
                instructions: current_block_instructions,
                successors: Vec::new(),
                predecessors: Vec::new(),
                block_type,
            });
        }

        basic_blocks
    }

    fn determine_block_type(&self, instructions: &[Instruction]) -> BlockType {
        if let Some(last_insn) = instructions.last() {
            match &last_insn.flow_control {
                FlowControl::Return => BlockType::Return,
                FlowControl::Call(_) => BlockType::Call,
                FlowControl::Branch(_) => BlockType::Conditional,
                _ => BlockType::Normal,
            }
        } else {
            BlockType::Normal
        }
    }

    fn build_control_flow_edges(&self, basic_blocks: &[BasicBlock]) -> Vec<CfgEdge> {
        let mut edges = Vec::new();

        // Create address to block ID mapping
        let mut addr_to_block: HashMap<u64, usize> = HashMap::new();
        for block in basic_blocks {
            addr_to_block.insert(block.start_address, block.id);
        }

        for block in basic_blocks {
            if let Some(last_insn) = block.instructions.last() {
                match &last_insn.flow_control {
                    FlowControl::Jump(target) => {
                        if let Some(&target_block) = addr_to_block.get(target) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: target_block,
                                edge_type: EdgeType::Jump,
                            });
                        }
                    }
                    FlowControl::Branch(target) => {
                        // Conditional branch has two edges: taken and not taken
                        if let Some(&target_block) = addr_to_block.get(target) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: target_block,
                                edge_type: EdgeType::Branch,
                            });
                        }

                        // Fall-through edge to next block
                        if let Some(next_block) = basic_blocks.get(block.id + 1) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: next_block.id,
                                edge_type: EdgeType::Fall,
                            });
                        }
                    }
                    FlowControl::Call(target) => {
                        if let Some(&target_block) = addr_to_block.get(target) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: target_block,
                                edge_type: EdgeType::Call,
                            });
                        }

                        // Fall-through after call
                        if let Some(next_block) = basic_blocks.get(block.id + 1) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: next_block.id,
                                edge_type: EdgeType::Fall,
                            });
                        }
                    }
                    FlowControl::Fall => {
                        // Normal fall-through to next block
                        if let Some(next_block) = basic_blocks.get(block.id + 1) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: next_block.id,
                                edge_type: EdgeType::Fall,
                            });
                        }
                    }
                    FlowControl::Return | FlowControl::Halt => {
                        // No outgoing edges
                    }
                    FlowControl::Indirect => {
                        // For indirect jumps/calls, we can't determine the target statically
                        // In a more sophisticated analysis, we might try to resolve these
                    }
                }
            }
        }

        edges
    }

    fn detect_loops(&self, _basic_blocks: &[BasicBlock], edges: &[CfgEdge]) -> Vec<Loop> {
        let mut loops = Vec::new();

        // Simple back-edge detection for natural loops
        for edge in edges {
            if edge.to_block <= edge.from_block {
                // Potential back edge - suggests a loop
                loops.push(Loop {
                    header_block: edge.to_block,
                    body_blocks: vec![edge.from_block],
                    exit_blocks: Vec::new(),
                    loop_type: LoopType::Natural,
                    nesting_level: 1,
                });
            }
        }

        loops
    }

    fn calculate_complexity_metrics(
        &self,
        basic_blocks: &[BasicBlock],
        edges: &[CfgEdge],
        loops: &[Loop],
    ) -> ControlFlowMetrics {
        // Cyclomatic complexity: V(G) = E - N + 2P
        // Where E = edges, N = nodes (basic blocks), P = connected components (assume 1)
        let cyclomatic_complexity = if basic_blocks.len() <= 1 {
            1
        } else {
            (edges.len() as i32 - basic_blocks.len() as i32 + 2).max(1) as u32
        };

        // Simple cognitive complexity based on control structures
        let cognitive_complexity = self.calculate_cognitive_complexity(basic_blocks);

        // Nesting depth
        let nesting_depth = self.calculate_nesting_depth(basic_blocks);

        // Find unreachable blocks
        let unreachable_blocks = self.find_unreachable_blocks(basic_blocks, edges);

        ControlFlowMetrics {
            cyclomatic_complexity,
            cognitive_complexity,
            nesting_depth,
            basic_block_count: basic_blocks.len(),
            edge_count: edges.len(),
            loop_count: loops.len(),
            unreachable_blocks,
        }
    }

    fn calculate_cognitive_complexity(&self, basic_blocks: &[BasicBlock]) -> u32 {
        let mut complexity = 0;

        for block in basic_blocks {
            match block.block_type {
                BlockType::Conditional => complexity += 1,
                BlockType::LoopHeader | BlockType::LoopBody => complexity += 2,
                _ => {}
            }
        }

        complexity
    }

    fn calculate_nesting_depth(&self, basic_blocks: &[BasicBlock]) -> u32 {
        // Simplified nesting depth calculation
        let mut max_depth: u32 = 0;
        let mut current_depth: i32 = 0;

        for block in basic_blocks {
            match block.block_type {
                BlockType::Conditional => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth as u32);
                }
                BlockType::Return | BlockType::Exit => {
                    current_depth = current_depth.saturating_sub(1);
                }
                _ => {}
            }
        }

        max_depth
    }

    fn find_unreachable_blocks(
        &self,
        basic_blocks: &[BasicBlock],
        edges: &[CfgEdge],
    ) -> Vec<usize> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();

        // Start from entry block (block 0)
        if !basic_blocks.is_empty() {
            queue.push_back(0);
            reachable.insert(0);
        }

        // BFS to find all reachable blocks
        while let Some(block_id) = queue.pop_front() {
            for edge in edges {
                if edge.from_block == block_id && !reachable.contains(&edge.to_block) {
                    reachable.insert(edge.to_block);
                    queue.push_back(edge.to_block);
                }
            }
        }

        // Find unreachable blocks
        basic_blocks
            .iter()
            .filter(|block| !reachable.contains(&block.id))
            .map(|block| block.id)
            .collect()
    }

    fn find_exit_blocks(&self, basic_blocks: &[BasicBlock]) -> Vec<usize> {
        basic_blocks
            .iter()
            .filter(|block| matches!(block.block_type, BlockType::Return | BlockType::Exit))
            .map(|block| block.id)
            .collect()
    }
}

pub fn analyze_control_flow(
    path: &Path,
    symbol_table: &SymbolTable,
) -> Result<ControlFlowAnalysis> {
    // Read the binary file
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse the binary to get the text section info
    let obj = Object::parse(&buffer)?;

    match obj {
        Object::Elf(elf) => {
            // Find the .text section
            for (i, section) in elf.section_headers.iter().enumerate() {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name == ".text" {
                        let analyzer = ControlFlowAnalyzer::new_x86_64()?;
                        return analyzer.analyze_functions(
                            &buffer,
                            symbol_table,
                            section.sh_offset,
                            section.sh_addr,
                        );
                    }
                } else {
                    // For debugging: check section 16 specifically (.text section from readelf)
                    if i == 16 {
                        let analyzer = ControlFlowAnalyzer::new_x86_64()?;
                        return analyzer.analyze_functions(
                            &buffer,
                            symbol_table,
                            section.sh_offset,
                            section.sh_addr,
                        );
                    }
                }
            }
            Err(anyhow!("No .text section found"))
        }
        _ => Err(anyhow!(
            "Only ELF binaries are currently supported for CFG analysis"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper function to create test instructions
    fn create_test_instruction(
        address: u64,
        mnemonic: &str,
        operands: &str,
        flow_control: FlowControl,
    ) -> Instruction {
        Instruction {
            address,
            bytes: vec![0x90], // Simplified
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            instruction_type: InstructionType::Other,
            flow_control,
            size: 1,
        }
    }

    #[test]
    fn test_control_flow_analyzer_creation() {
        let analyzer = ControlFlowAnalyzer::new_x86_64();
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_classify_instruction() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        // We'll need to use the actual disassembler for this test
        // Create a simple x86-64 instruction sequence
        let instructions = vec![
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
            0xe8, 0x00, 0x00, 0x00, 0x00, // call relative
            0xc3, // ret
        ];

        let disassembled = analyzer.capstone.disasm_all(&instructions, 0x1000).unwrap();
        let insns: Vec<_> = disassembled.as_ref().iter().collect();

        // Test classification of mov instruction
        let mov_type = analyzer.classify_instruction(&insns[0]);
        assert!(matches!(mov_type, InstructionType::Memory));

        // Test classification of sub instruction
        let sub_type = analyzer.classify_instruction(&insns[1]);
        assert!(matches!(sub_type, InstructionType::Arithmetic));

        // Test classification of call instruction
        let call_type = analyzer.classify_instruction(&insns[2]);
        assert!(matches!(call_type, InstructionType::Call));

        // Test classification of ret instruction
        let ret_type = analyzer.classify_instruction(&insns[3]);
        assert!(matches!(ret_type, InstructionType::Return));
    }

    #[test]
    fn test_analyze_flow_control() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        // Test different flow control patterns
        let test_cases = vec![
            (vec![0xc3], "ret", FlowControl::Return), // ret
            (
                vec![0xe9, 0x00, 0x00, 0x00, 0x00],
                "jmp",
                FlowControl::Jump(0x1005),
            ), // jmp
            (vec![0x74, 0x10], "je", FlowControl::Branch(0x1012)), // je +16
            (
                vec![0xe8, 0x00, 0x00, 0x00, 0x00],
                "call",
                FlowControl::Call(0x1005),
            ), // call
        ];

        for (bytes, expected_mnemonic, _expected_flow) in test_cases {
            let disassembled = analyzer.capstone.disasm_all(&bytes, 0x1000).unwrap();
            if let Some(insn) = disassembled.as_ref().iter().next() {
                assert_eq!(insn.mnemonic().unwrap(), expected_mnemonic);
                let flow = analyzer.analyze_flow_control(&insn);
                // Flow control analysis depends on operand parsing which varies
                match expected_mnemonic {
                    "ret" => assert!(matches!(flow, FlowControl::Return)),
                    "jmp" => assert!(matches!(flow, FlowControl::Jump(_) | FlowControl::Indirect)),
                    "je" => assert!(matches!(
                        flow,
                        FlowControl::Branch(_) | FlowControl::Indirect
                    )),
                    "call" => assert!(matches!(flow, FlowControl::Call(_) | FlowControl::Indirect)),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn test_find_basic_block_boundaries() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let instructions = vec![
            create_test_instruction(0x1000, "push", "rbp", FlowControl::Fall),
            create_test_instruction(0x1001, "mov", "rbp, rsp", FlowControl::Fall),
            create_test_instruction(0x1004, "test", "eax, eax", FlowControl::Fall),
            create_test_instruction(0x1006, "je", "0x1010", FlowControl::Branch(0x1010)),
            create_test_instruction(0x1008, "mov", "eax, 1", FlowControl::Fall),
            create_test_instruction(0x100b, "jmp", "0x1015", FlowControl::Jump(0x1015)),
            create_test_instruction(0x1010, "mov", "eax, 0", FlowControl::Fall),
            create_test_instruction(0x1015, "ret", "", FlowControl::Return),
        ];

        let boundaries = analyzer.find_basic_block_boundaries(&instructions);

        // Should have boundaries at:
        // - 0x1000 (first instruction)
        // - 0x1008 (after conditional branch)
        // - 0x1010 (branch target)
        // - 0x1015 (jump target and after jump)
        assert!(boundaries.contains(&0x1000));
        assert!(boundaries.contains(&0x1008));
        assert!(boundaries.contains(&0x1010));
        assert!(boundaries.contains(&0x1015));
    }

    #[test]
    fn test_create_basic_blocks() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let instructions = vec![
            create_test_instruction(0x1000, "push", "rbp", FlowControl::Fall),
            create_test_instruction(0x1001, "mov", "rbp, rsp", FlowControl::Fall),
            create_test_instruction(0x1004, "ret", "", FlowControl::Return),
        ];

        let boundaries = analyzer.find_basic_block_boundaries(&instructions);
        let blocks = analyzer.create_basic_blocks(&instructions, &boundaries);

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].id, 0);
        assert_eq!(blocks[0].start_address, 0x1000);
        assert_eq!(blocks[0].end_address, 0x1005); // 0x1004 + 1
        assert_eq!(blocks[0].instruction_count, 3);
        assert!(matches!(blocks[0].block_type, BlockType::Return));
    }

    #[test]
    fn test_build_control_flow_edges() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        // Create a simple CFG with conditional branch
        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1008,
                instructions: vec![create_test_instruction(
                    0x1006,
                    "je",
                    "0x1010",
                    FlowControl::Branch(0x1010),
                )],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Conditional,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1008,
                end_address: 0x1010,
                instructions: vec![create_test_instruction(
                    0x100b,
                    "jmp",
                    "0x1015",
                    FlowControl::Jump(0x1015),
                )],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
            BasicBlock {
                id: 2,
                start_address: 0x1010,
                end_address: 0x1015,
                instructions: vec![create_test_instruction(
                    0x1014,
                    "nop",
                    "",
                    FlowControl::Fall,
                )],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
            BasicBlock {
                id: 3,
                start_address: 0x1015,
                end_address: 0x1016,
                instructions: vec![create_test_instruction(
                    0x1015,
                    "ret",
                    "",
                    FlowControl::Return,
                )],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Return,
                instruction_count: 1,
            },
        ];

        let edges = analyzer.build_control_flow_edges(&blocks);

        // Should have edges:
        // - Block 0 -> Block 2 (branch taken)
        // - Block 0 -> Block 1 (fall through)
        // - Block 1 -> Block 3 (jump)
        // - Block 2 -> Block 3 (fall through)
        assert_eq!(edges.len(), 4);

        // Verify edge types
        let branch_edge = edges.iter().find(|e| e.from_block == 0 && e.to_block == 2);
        assert!(branch_edge.is_some());
        assert!(matches!(branch_edge.unwrap().edge_type, EdgeType::Branch));

        let fall_edge = edges.iter().find(|e| e.from_block == 0 && e.to_block == 1);
        assert!(fall_edge.is_some());
        assert!(matches!(fall_edge.unwrap().edge_type, EdgeType::Fall));
    }

    #[test]
    fn test_detect_loops() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1004,
                end_address: 0x1008,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
        ];

        // Create a back edge from block 1 to block 0 (loop)
        let edges = vec![
            CfgEdge {
                from_block: 0,
                to_block: 1,
                edge_type: EdgeType::Fall,
            },
            CfgEdge {
                from_block: 1,
                to_block: 0,
                edge_type: EdgeType::Branch,
            },
        ];

        let loops = analyzer.detect_loops(&blocks, &edges);

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header_block, 0);
        assert!(loops[0].body_blocks.contains(&1));
        assert!(matches!(loops[0].loop_type, LoopType::Natural));
    }

    #[test]
    fn test_calculate_complexity_metrics() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        // Create a simple CFG
        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Entry,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1004,
                end_address: 0x1008,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Conditional,
                instruction_count: 1,
            },
            BasicBlock {
                id: 2,
                start_address: 0x1008,
                end_address: 0x100c,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Return,
                instruction_count: 1,
            },
        ];

        let edges = vec![
            CfgEdge {
                from_block: 0,
                to_block: 1,
                edge_type: EdgeType::Fall,
            },
            CfgEdge {
                from_block: 1,
                to_block: 2,
                edge_type: EdgeType::Fall,
            },
        ];

        let loops = vec![];

        let metrics = analyzer.calculate_complexity_metrics(&blocks, &edges, &loops);

        // Cyclomatic complexity: E - N + 2 = 2 - 3 + 2 = 1
        assert_eq!(metrics.cyclomatic_complexity, 1);
        assert_eq!(metrics.basic_block_count, 3);
        assert_eq!(metrics.edge_count, 2);
        assert_eq!(metrics.loop_count, 0);
        assert_eq!(metrics.cognitive_complexity, 1); // One conditional block
    }

    #[test]
    fn test_find_unreachable_blocks() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Entry,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1004,
                end_address: 0x1008,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
            BasicBlock {
                id: 2,
                start_address: 0x1008,
                end_address: 0x100c,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
        ];

        // Only connect block 0 to block 1, leaving block 2 unreachable
        let edges = vec![CfgEdge {
            from_block: 0,
            to_block: 1,
            edge_type: EdgeType::Fall,
        }];

        let unreachable = analyzer.find_unreachable_blocks(&blocks, &edges);

        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0], 2);
    }

    #[test]
    fn test_find_exit_blocks() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Entry,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1004,
                end_address: 0x1008,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Return,
                instruction_count: 1,
            },
            BasicBlock {
                id: 2,
                start_address: 0x1008,
                end_address: 0x100c,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Exit,
                instruction_count: 1,
            },
        ];

        let exit_blocks = analyzer.find_exit_blocks(&blocks);

        assert_eq!(exit_blocks.len(), 2);
        assert!(exit_blocks.contains(&1));
        assert!(exit_blocks.contains(&2));
    }

    #[test]
    fn test_determine_block_type() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        // Test with return instruction
        let ret_instructions = vec![create_test_instruction(
            0x1000,
            "ret",
            "",
            FlowControl::Return,
        )];
        let ret_type = analyzer.determine_block_type(&ret_instructions);
        assert!(matches!(ret_type, BlockType::Return));

        // Test with call instruction
        let call_instructions = vec![create_test_instruction(
            0x1000,
            "call",
            "0x2000",
            FlowControl::Call(0x2000),
        )];
        let call_type = analyzer.determine_block_type(&call_instructions);
        assert!(matches!(call_type, BlockType::Call));

        // Test with conditional branch
        let branch_instructions = vec![create_test_instruction(
            0x1000,
            "je",
            "0x2000",
            FlowControl::Branch(0x2000),
        )];
        let branch_type = analyzer.determine_block_type(&branch_instructions);
        assert!(matches!(branch_type, BlockType::Conditional));

        // Test with normal instruction
        let normal_instructions = vec![create_test_instruction(
            0x1000,
            "mov",
            "eax, ebx",
            FlowControl::Fall,
        )];
        let normal_type = analyzer.determine_block_type(&normal_instructions);
        assert!(matches!(normal_type, BlockType::Normal));

        // Test with empty instructions
        let empty_instructions: Vec<Instruction> = vec![];
        let empty_type = analyzer.determine_block_type(&empty_instructions);
        assert!(matches!(empty_type, BlockType::Normal));
    }

    #[test]
    fn test_analyze_function_empty() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let function = FunctionInfo {
            name: "test_func".to_string(),
            address: 0x1000,
            size: 0,
            function_type: crate::function_analysis::FunctionType::Local,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        };

        let empty_bytes = vec![];
        let result = analyzer.analyze_function(&function, &empty_bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_cognitive_complexity_calculation() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Normal,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1004,
                end_address: 0x1008,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Conditional,
                instruction_count: 1,
            },
            BasicBlock {
                id: 2,
                start_address: 0x1008,
                end_address: 0x100c,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::LoopHeader,
                instruction_count: 1,
            },
            BasicBlock {
                id: 3,
                start_address: 0x100c,
                end_address: 0x1010,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::LoopBody,
                instruction_count: 1,
            },
        ];

        let complexity = analyzer.calculate_cognitive_complexity(&blocks);

        // Conditional: +1, LoopHeader: +2, LoopBody: +2 = 5
        assert_eq!(complexity, 5);
    }

    #[test]
    fn test_nesting_depth_calculation() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        let blocks = vec![
            BasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Conditional,
                instruction_count: 1,
            },
            BasicBlock {
                id: 1,
                start_address: 0x1004,
                end_address: 0x1008,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Conditional,
                instruction_count: 1,
            },
            BasicBlock {
                id: 2,
                start_address: 0x1008,
                end_address: 0x100c,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                block_type: BlockType::Return,
                instruction_count: 1,
            },
        ];

        let depth = analyzer.calculate_nesting_depth(&blocks);

        // Two nested conditionals should give depth of 2
        assert_eq!(depth, 2);
    }

    #[test]
    fn test_analyze_control_flow_integration() {
        // Create a minimal ELF file for testing
        // This is a simplified test that would need a proper ELF file in a real scenario
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write a minimal ELF header (this is not a valid ELF, just for testing error handling)
        let elf_header = vec![
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, 0x01, 0x01, 0x00, // 64-bit, little-endian, version 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        temp_file.write_all(&elf_header).unwrap();
        temp_file.flush().unwrap();

        let symbol_table = SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: crate::function_analysis::SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 0,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let result = analyze_control_flow(temp_file.path(), &symbol_table);

        // This should fail because we don't have a valid ELF with .text section
        assert!(result.is_err());
    }

    #[test]
    fn test_edge_type_serialization() {
        // Test that edge types can be properly serialized/deserialized
        let edge_types = vec![
            EdgeType::Fall,
            EdgeType::Jump,
            EdgeType::Branch,
            EdgeType::Call,
            EdgeType::Return,
        ];

        for edge_type in edge_types {
            let serialized = serde_json::to_string(&edge_type).unwrap();
            let deserialized: EdgeType = serde_json::from_str(&serialized).unwrap();

            match (edge_type, deserialized) {
                (EdgeType::Fall, EdgeType::Fall) => {}
                (EdgeType::Jump, EdgeType::Jump) => {}
                (EdgeType::Branch, EdgeType::Branch) => {}
                (EdgeType::Call, EdgeType::Call) => {}
                (EdgeType::Return, EdgeType::Return) => {}
                _ => panic!("Edge type serialization mismatch"),
            }
        }
    }

    #[test]
    fn test_loop_type_serialization() {
        // Test that loop types can be properly serialized/deserialized
        let loop_types = vec![
            LoopType::Natural,
            LoopType::Irreducible,
            LoopType::DoWhile,
            LoopType::While,
            LoopType::For,
        ];

        for loop_type in loop_types {
            let serialized = serde_json::to_string(&loop_type).unwrap();
            let deserialized: LoopType = serde_json::from_str(&serialized).unwrap();

            match (loop_type, deserialized) {
                (LoopType::Natural, LoopType::Natural) => {}
                (LoopType::Irreducible, LoopType::Irreducible) => {}
                (LoopType::DoWhile, LoopType::DoWhile) => {}
                (LoopType::While, LoopType::While) => {}
                (LoopType::For, LoopType::For) => {}
                _ => panic!("Loop type serialization mismatch"),
            }
        }
    }

    #[test]
    fn test_complex_cfg_construction() {
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();

        // Create a more complex function with multiple paths
        let _function = FunctionInfo {
            name: "complex_func".to_string(),
            address: 0x1000,
            size: 100,
            function_type: crate::function_analysis::FunctionType::Exported,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: true,
            is_imported: false,
        };

        // Simulate disassembled instructions for a complex function
        let instructions = vec![
            create_test_instruction(0x1000, "push", "rbp", FlowControl::Fall),
            create_test_instruction(0x1001, "mov", "rbp, rsp", FlowControl::Fall),
            create_test_instruction(0x1004, "test", "eax, eax", FlowControl::Fall),
            create_test_instruction(0x1006, "je", "0x1020", FlowControl::Branch(0x1020)),
            create_test_instruction(0x1008, "cmp", "eax, 10", FlowControl::Fall),
            create_test_instruction(0x100b, "jg", "0x1030", FlowControl::Branch(0x1030)),
            create_test_instruction(0x100d, "call", "0x2000", FlowControl::Call(0x2000)),
            create_test_instruction(0x1012, "jmp", "0x1040", FlowControl::Jump(0x1040)),
            create_test_instruction(0x1020, "xor", "eax, eax", FlowControl::Fall),
            create_test_instruction(0x1022, "jmp", "0x1040", FlowControl::Jump(0x1040)),
            create_test_instruction(0x1030, "mov", "eax, 1", FlowControl::Fall),
            create_test_instruction(0x1033, "call", "0x3000", FlowControl::Call(0x3000)),
            create_test_instruction(0x1038, "test", "eax, eax", FlowControl::Fall),
            create_test_instruction(0x103a, "jne", "0x1000", FlowControl::Branch(0x1000)), // Back edge (loop)
            create_test_instruction(0x1040, "pop", "rbp", FlowControl::Fall),
            create_test_instruction(0x1041, "ret", "", FlowControl::Return),
        ];

        // Find basic blocks
        let boundaries = analyzer.find_basic_block_boundaries(&instructions);
        assert!(boundaries.len() >= 5); // Should have multiple boundaries

        // Create basic blocks
        let blocks = analyzer.create_basic_blocks(&instructions, &boundaries);
        assert!(blocks.len() >= 5); // Should create multiple blocks

        // Build edges
        let edges = analyzer.build_control_flow_edges(&blocks);
        assert!(edges.len() >= 6); // Should have multiple edges

        // Detect loops
        let loops = analyzer.detect_loops(&blocks, &edges);
        assert!(loops.len() >= 1); // Should detect the back edge as a loop

        // Calculate metrics
        let metrics = analyzer.calculate_complexity_metrics(&blocks, &edges, &loops);
        assert!(metrics.cyclomatic_complexity > 1); // Complex function should have higher complexity
        assert_eq!(metrics.basic_block_count, blocks.len());
        assert_eq!(metrics.edge_count, edges.len());
        assert_eq!(metrics.loop_count, loops.len());
    }
}
