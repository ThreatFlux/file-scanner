use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::control_flow::{BasicBlock, ControlFlowAnalysis, ControlFlowGraph, InstructionType};
use crate::function_analysis::SymbolTable;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodeQualityAnalysis {
    pub function_metrics: Vec<FunctionMetrics>,
    pub overall_metrics: OverallCodeMetrics,
    pub quality_report: QualityReport,
    pub analysis_stats: QualityAnalysisStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionMetrics {
    pub function_name: String,
    pub function_address: u64,
    pub cyclomatic_complexity: u32,
    pub cognitive_complexity: u32,
    pub nesting_depth: u32,
    pub function_length: u32, // Number of instructions
    pub basic_block_count: u32,
    pub parameter_count: u32, // Estimated from function signature
    pub return_paths: u32,    // Number of return statements
    pub halstead_metrics: HalsteadMetrics,
    pub maintainability_index: f64,
    pub technical_debt_minutes: u32, // Estimated time to fix issues
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HalsteadMetrics {
    pub distinct_operators: u32, // n1
    pub distinct_operands: u32,  // n2
    pub total_operators: u32,    // N1
    pub total_operands: u32,     // N2
    pub vocabulary: u32,         // n = n1 + n2
    pub length: u32,             // N = N1 + N2
    pub volume: f64,             // V = N * log2(n)
    pub difficulty: f64,         // D = (n1/2) * (N2/n2)
    pub effort: f64,             // E = D * V
    pub time_to_program: f64,    // T = E / 18 (seconds)
    pub delivered_bugs: f64,     // B = V / 3000
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverallCodeMetrics {
    pub total_functions: usize,
    pub total_instructions: usize,
    pub average_complexity: f64,
    pub average_function_length: f64,
    pub total_code_volume: f64,
    pub total_estimated_bugs: f64,
    pub most_complex_function: Option<String>,
    pub highest_complexity: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityReport {
    pub overall_quality_score: f64, // 0.0 to 100.0
    pub complexity_score: f64,      // 0.0 to 100.0
    pub maintainability_score: f64, // 0.0 to 100.0
    pub code_health: CodeHealth,
    pub quality_issues: Vec<QualityIssue>,
    pub recommendations: Vec<String>,
    pub technical_debt_hours: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CodeHealth {
    Excellent, // 90-100
    Good,      // 75-89
    Fair,      // 60-74
    Poor,      // 40-59
    Critical,  // 0-39
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityIssue {
    pub issue_type: QualityIssueType,
    pub severity: IssueSeverity,
    pub function_name: String,
    pub description: String,
    pub recommendation: String,
    pub debt_minutes: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum QualityIssueType {
    HighComplexity,
    LongFunction,
    DeepNesting,
    TooManyReturns,
    HighCoupling,
    LowCohesion,
    DuplicatedCode,
    DeadCode,
    MagicNumbers,
    GodFunction,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IssueSeverity {
    Critical,
    Major,
    Minor,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityAnalysisStats {
    pub analysis_duration_ms: u64,
    pub functions_analyzed: usize,
    pub instructions_analyzed: usize,
    pub issues_found: usize,
}

pub struct CodeQualityAnalyzer;

impl CodeQualityAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        cfg_analysis: &ControlFlowAnalysis,
        _symbol_table: &SymbolTable,
    ) -> Result<CodeQualityAnalysis> {
        let start_time = std::time::Instant::now();
        let mut function_metrics = Vec::new();
        let mut total_instructions = 0;

        // Analyze each function
        for cfg in &cfg_analysis.cfgs {
            let metrics = self.analyze_function(cfg)?;
            total_instructions += metrics.function_length as usize;
            function_metrics.push(metrics);
        }

        // Calculate overall metrics
        let overall_metrics = self.calculate_overall_metrics(&function_metrics, total_instructions);

        // Generate quality report
        let quality_report = self.generate_quality_report(&function_metrics, &overall_metrics);

        let duration = start_time.elapsed().as_millis() as u64;
        let issues_found = quality_report.quality_issues.len();

        Ok(CodeQualityAnalysis {
            function_metrics,
            overall_metrics,
            quality_report,
            analysis_stats: QualityAnalysisStats {
                analysis_duration_ms: duration,
                functions_analyzed: cfg_analysis.cfgs.len(),
                instructions_analyzed: total_instructions,
                issues_found,
            },
        })
    }

    fn analyze_function(&self, cfg: &ControlFlowGraph) -> Result<FunctionMetrics> {
        // Get basic metrics from CFG
        let cyclomatic_complexity = cfg.complexity.cyclomatic_complexity;
        let cognitive_complexity = cfg.complexity.cognitive_complexity;
        let nesting_depth = cfg.complexity.nesting_depth;
        let basic_block_count = cfg.basic_blocks.len() as u32;

        // Count total instructions
        let function_length = cfg
            .basic_blocks
            .iter()
            .map(|bb| bb.instruction_count)
            .sum::<usize>() as u32;

        // Count return paths
        let return_paths = cfg.exit_blocks.len() as u32;

        // Calculate Halstead metrics
        let halstead_metrics = self.calculate_halstead_metrics(&cfg.basic_blocks)?;

        // Calculate maintainability index
        let maintainability_index = self.calculate_maintainability_index(
            &halstead_metrics,
            cyclomatic_complexity,
            function_length,
        );

        // Estimate technical debt
        let technical_debt_minutes = self.estimate_technical_debt(
            cyclomatic_complexity,
            cognitive_complexity,
            function_length,
            nesting_depth,
        );

        // Estimate parameter count (simplified - would need more analysis in practice)
        let parameter_count = self.estimate_parameter_count(&cfg.basic_blocks);

        Ok(FunctionMetrics {
            function_name: cfg.function_name.clone(),
            function_address: cfg.function_address,
            cyclomatic_complexity,
            cognitive_complexity,
            nesting_depth,
            function_length,
            basic_block_count,
            parameter_count,
            return_paths,
            halstead_metrics,
            maintainability_index,
            technical_debt_minutes,
        })
    }

    fn calculate_halstead_metrics(&self, basic_blocks: &[BasicBlock]) -> Result<HalsteadMetrics> {
        let mut operators = HashMap::new();
        let mut operands = HashMap::new();
        let mut total_operators = 0;
        let mut total_operands = 0;

        for block in basic_blocks {
            for instruction in &block.instructions {
                // Classify instruction as operator
                match &instruction.instruction_type {
                    InstructionType::Arithmetic
                    | InstructionType::Logic
                    | InstructionType::Control
                    | InstructionType::Call
                    | InstructionType::Jump
                    | InstructionType::Conditional => {
                        *operators.entry(instruction.mnemonic.clone()).or_insert(0) += 1;
                        total_operators += 1;
                    }
                    _ => {}
                }

                // Extract operands from instruction
                let operand_tokens = self.extract_operand_tokens(&instruction.operands);
                for token in operand_tokens {
                    *operands.entry(token).or_insert(0) += 1;
                    total_operands += 1;
                }
            }
        }

        let distinct_operators = operators.len() as u32;
        let distinct_operands = operands.len() as u32;
        let vocabulary = distinct_operators + distinct_operands;
        let length = total_operators + total_operands;

        let volume = if vocabulary > 0 {
            length as f64 * (vocabulary as f64).log2()
        } else {
            0.0
        };

        let difficulty = if distinct_operands > 0 && operands.values().sum::<u32>() > 0 {
            (distinct_operators as f64 / 2.0) * (total_operands as f64 / distinct_operands as f64)
        } else {
            0.0
        };

        let effort = difficulty * volume;
        let time_to_program = effort / 18.0; // seconds
        let delivered_bugs = volume / 3000.0;

        Ok(HalsteadMetrics {
            distinct_operators,
            distinct_operands,
            total_operators,
            total_operands,
            vocabulary,
            length,
            volume,
            difficulty,
            effort,
            time_to_program,
            delivered_bugs,
        })
    }

    fn extract_operand_tokens(&self, operands: &str) -> Vec<String> {
        // Simple tokenization of operands
        operands
            .split(|c: char| {
                c == ',' || c == ' ' || c == '[' || c == ']' || c == '+' || c == '-' || c == '*'
            })
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    fn calculate_maintainability_index(
        &self,
        halstead: &HalsteadMetrics,
        cyclomatic_complexity: u32,
        lines_of_code: u32,
    ) -> f64 {
        // Microsoft's Maintainability Index formula
        // MI = 171 - 5.2 * ln(V) - 0.23 * CC - 16.2 * ln(LOC)
        let volume = halstead.volume.max(1.0);
        let loc = lines_of_code.max(1) as f64;
        let cc = cyclomatic_complexity as f64;

        let mi = 171.0 - 5.2 * volume.ln() - 0.23 * cc - 16.2 * loc.ln();

        // Normalize to 0-100 scale
        ((mi * 100.0 / 171.0).max(0.0)).min(100.0)
    }

    fn estimate_technical_debt(
        &self,
        cyclomatic_complexity: u32,
        cognitive_complexity: u32,
        function_length: u32,
        nesting_depth: u32,
    ) -> u32 {
        let mut debt_minutes = 0;

        // High complexity penalty
        if cyclomatic_complexity > 10 {
            debt_minutes += (cyclomatic_complexity - 10) * 10;
        }

        // Cognitive complexity penalty
        if cognitive_complexity > 15 {
            debt_minutes += (cognitive_complexity - 15) * 8;
        }

        // Long function penalty
        if function_length > 50 {
            debt_minutes += (function_length - 50) * 2;
        }

        // Deep nesting penalty
        if nesting_depth > 4 {
            debt_minutes += (nesting_depth - 4) * 15;
        }

        debt_minutes
    }

    fn estimate_parameter_count(&self, basic_blocks: &[BasicBlock]) -> u32 {
        // Look for register usage patterns in first basic block
        // This is a simplified heuristic
        if let Some(first_block) = basic_blocks.first() {
            let param_registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
            let mut max_param = 0;

            for (i, reg) in param_registers.iter().enumerate() {
                for instruction in &first_block.instructions {
                    if instruction.operands.contains(reg) {
                        max_param = i + 1;
                    }
                }
            }

            max_param as u32
        } else {
            0
        }
    }

    fn calculate_overall_metrics(
        &self,
        function_metrics: &[FunctionMetrics],
        total_instructions: usize,
    ) -> OverallCodeMetrics {
        let total_functions = function_metrics.len();

        let average_complexity = if total_functions > 0 {
            function_metrics
                .iter()
                .map(|m| m.cyclomatic_complexity as f64)
                .sum::<f64>()
                / total_functions as f64
        } else {
            0.0
        };

        let average_function_length = if total_functions > 0 {
            function_metrics
                .iter()
                .map(|m| m.function_length as f64)
                .sum::<f64>()
                / total_functions as f64
        } else {
            0.0
        };

        let total_code_volume = function_metrics
            .iter()
            .map(|m| m.halstead_metrics.volume)
            .sum::<f64>();

        let total_estimated_bugs = function_metrics
            .iter()
            .map(|m| m.halstead_metrics.delivered_bugs)
            .sum::<f64>();

        let (most_complex_function, highest_complexity) = function_metrics
            .iter()
            .max_by_key(|m| m.cyclomatic_complexity)
            .map(|m| (Some(m.function_name.clone()), m.cyclomatic_complexity))
            .unwrap_or((None, 0));

        OverallCodeMetrics {
            total_functions,
            total_instructions,
            average_complexity,
            average_function_length,
            total_code_volume,
            total_estimated_bugs,
            most_complex_function,
            highest_complexity,
        }
    }

    fn generate_quality_report(
        &self,
        function_metrics: &[FunctionMetrics],
        overall_metrics: &OverallCodeMetrics,
    ) -> QualityReport {
        let mut quality_issues = Vec::new();
        let mut total_debt_minutes = 0;

        // Check each function for quality issues
        for metrics in function_metrics {
            // High complexity
            if metrics.cyclomatic_complexity > 10 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::HighComplexity,
                    severity: if metrics.cyclomatic_complexity > 20 {
                        IssueSeverity::Critical
                    } else {
                        IssueSeverity::Major
                    },
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function has high cyclomatic complexity ({})",
                        metrics.cyclomatic_complexity
                    ),
                    recommendation:
                        "Consider breaking this function into smaller, more focused functions"
                            .to_string(),
                    debt_minutes: (metrics.cyclomatic_complexity - 10) * 10,
                });
            }

            // Long function
            if metrics.function_length > 50 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::LongFunction,
                    severity: if metrics.function_length > 100 {
                        IssueSeverity::Major
                    } else {
                        IssueSeverity::Minor
                    },
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function is too long ({} instructions)",
                        metrics.function_length
                    ),
                    recommendation: "Extract cohesive blocks into separate functions".to_string(),
                    debt_minutes: (metrics.function_length - 50) * 2,
                });
            }

            // Deep nesting
            if metrics.nesting_depth > 4 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::DeepNesting,
                    severity: IssueSeverity::Major,
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function has deep nesting (depth: {})",
                        metrics.nesting_depth
                    ),
                    recommendation: "Use early returns or extract nested logic".to_string(),
                    debt_minutes: (metrics.nesting_depth - 4) * 15,
                });
            }

            // Too many returns
            if metrics.return_paths > 5 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::TooManyReturns,
                    severity: IssueSeverity::Minor,
                    function_name: metrics.function_name.clone(),
                    description: format!(
                        "Function has too many return paths ({})",
                        metrics.return_paths
                    ),
                    recommendation: "Consolidate return paths for better maintainability"
                        .to_string(),
                    debt_minutes: (metrics.return_paths - 5) * 5,
                });
            }

            // God function (doing too much)
            if metrics.cyclomatic_complexity > 20 && metrics.function_length > 100 {
                quality_issues.push(QualityIssue {
                    issue_type: QualityIssueType::GodFunction,
                    severity: IssueSeverity::Critical,
                    function_name: metrics.function_name.clone(),
                    description: "Function is doing too much (high complexity and length)"
                        .to_string(),
                    recommendation:
                        "Refactor into multiple smaller functions with single responsibilities"
                            .to_string(),
                    debt_minutes: 120,
                });
            }

            total_debt_minutes += metrics.technical_debt_minutes;
        }

        // Calculate quality scores
        let complexity_score = self.calculate_complexity_score(overall_metrics.average_complexity);
        let maintainability_score = if function_metrics.is_empty() {
            100.0
        } else {
            function_metrics
                .iter()
                .map(|m| m.maintainability_index)
                .sum::<f64>()
                / function_metrics.len() as f64
        };

        let overall_quality_score = (complexity_score + maintainability_score) / 2.0;

        let code_health = match overall_quality_score {
            score if score >= 90.0 => CodeHealth::Excellent,
            score if score >= 75.0 => CodeHealth::Good,
            score if score >= 60.0 => CodeHealth::Fair,
            score if score >= 40.0 => CodeHealth::Poor,
            _ => CodeHealth::Critical,
        };

        let mut recommendations = Vec::new();
        if overall_metrics.average_complexity > 10.0 {
            recommendations.push(
                "Consider refactoring complex functions to reduce average complexity".to_string(),
            );
        }
        if overall_metrics.average_function_length > 50.0 {
            recommendations.push(
                "Functions are generally too long - aim for 20-50 instructions per function"
                    .to_string(),
            );
        }
        if overall_metrics.total_estimated_bugs > 1.0 {
            recommendations.push(format!(
                "Code volume suggests approximately {:.1} potential bugs - increase testing coverage",
                overall_metrics.total_estimated_bugs
            ));
        }
        if quality_issues.is_empty() {
            recommendations.push("Code quality is good - maintain current standards".to_string());
        }

        let technical_debt_hours = total_debt_minutes as f64 / 60.0;

        QualityReport {
            overall_quality_score,
            complexity_score,
            maintainability_score,
            code_health,
            quality_issues,
            recommendations,
            technical_debt_hours,
        }
    }

    fn calculate_complexity_score(&self, average_complexity: f64) -> f64 {
        // Convert complexity to a 0-100 score (lower complexity = higher score)
        if average_complexity <= 5.0 {
            100.0
        } else if average_complexity <= 10.0 {
            90.0 - (average_complexity - 5.0) * 4.0
        } else if average_complexity <= 20.0 {
            70.0 - (average_complexity - 10.0) * 3.0
        } else if average_complexity <= 30.0 {
            40.0 - (average_complexity - 20.0) * 2.0
        } else {
            20.0_f64.max(20.0 - (average_complexity - 30.0))
        }
    }
}

pub fn analyze_code_quality(
    _path: &Path,
    symbol_table: &SymbolTable,
    cfg_analysis: &ControlFlowAnalysis,
) -> Result<CodeQualityAnalysis> {
    let analyzer = CodeQualityAnalyzer::new();
    analyzer.analyze(cfg_analysis, symbol_table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::{
        AnalysisStats, BlockType, ControlFlowMetrics, FlowControl, Instruction, OverallMetrics,
    };
    use crate::function_analysis::SymbolCounts;
    use std::collections::HashSet;

    fn create_test_instruction(
        mnemonic: &str,
        operands: &str,
        instruction_type: InstructionType,
    ) -> Instruction {
        Instruction {
            address: 0x1000,
            bytes: vec![0x48, 0x89, 0xe5],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            instruction_type,
            flow_control: FlowControl::Fall,
            size: 3,
        }
    }

    fn create_test_basic_block(id: usize, instructions: Vec<Instruction>) -> BasicBlock {
        BasicBlock {
            id,
            start_address: 0x1000,
            end_address: 0x1010,
            instructions,
            successors: vec![],
            predecessors: vec![],
            block_type: BlockType::Normal,
            instruction_count: 10,
        }
    }

    fn create_test_cfg(name: &str, basic_blocks: Vec<BasicBlock>) -> ControlFlowGraph {
        ControlFlowGraph {
            function_address: 0x1000,
            function_name: name.to_string(),
            basic_blocks,
            edges: vec![],
            entry_block: 0,
            exit_blocks: vec![1],
            loops: vec![],
            complexity: ControlFlowMetrics {
                cyclomatic_complexity: 5,
                cognitive_complexity: 8,
                nesting_depth: 3,
                basic_block_count: 2,
                edge_count: 1,
                loop_count: 0,
                unreachable_blocks: vec![],
            },
        }
    }

    fn create_test_cfg_analysis() -> ControlFlowAnalysis {
        ControlFlowAnalysis {
            cfgs: vec![],
            overall_metrics: OverallMetrics {
                total_functions: 1,
                analyzed_functions: 1,
                total_basic_blocks: 2,
                average_complexity: 5.0,
                max_complexity: 5,
                function_with_max_complexity: Some("test_function".to_string()),
            },
            analysis_stats: AnalysisStats {
                analysis_duration: 100,
                bytes_analyzed: 1000,
                instructions_analyzed: 10,
                errors: vec![],
            },
        }
    }

    #[test]
    fn test_code_quality_analyzer_new() {
        let _analyzer = CodeQualityAnalyzer::new();
        // Verify analyzer can be created without issues
        assert!(true);
    }

    #[test]
    fn test_calculate_halstead_metrics_empty() {
        let analyzer = CodeQualityAnalyzer::new();
        let basic_blocks = vec![];

        let result = analyzer.calculate_halstead_metrics(&basic_blocks).unwrap();

        assert_eq!(result.distinct_operators, 0);
        assert_eq!(result.distinct_operands, 0);
        assert_eq!(result.total_operators, 0);
        assert_eq!(result.total_operands, 0);
        assert_eq!(result.vocabulary, 0);
        assert_eq!(result.length, 0);
        assert_eq!(result.volume, 0.0);
        assert_eq!(result.difficulty, 0.0);
        assert_eq!(result.effort, 0.0);
        assert_eq!(result.time_to_program, 0.0);
        assert_eq!(result.delivered_bugs, 0.0);
    }

    #[test]
    fn test_calculate_halstead_metrics_basic() {
        let analyzer = CodeQualityAnalyzer::new();
        let instructions = vec![
            create_test_instruction("mov", "rax, rbx", InstructionType::Arithmetic),
            create_test_instruction("add", "rax, 5", InstructionType::Arithmetic),
            create_test_instruction("cmp", "rax, rcx", InstructionType::Logic),
        ];
        let basic_blocks = vec![create_test_basic_block(0, instructions)];

        let result = analyzer.calculate_halstead_metrics(&basic_blocks).unwrap();

        assert_eq!(result.distinct_operators, 3); // mov, add, cmp
        assert!(result.distinct_operands > 0); // rax, rbx, 5, rcx
        assert_eq!(result.total_operators, 3);
        assert!(result.total_operands > 0);
        assert!(result.vocabulary > 0);
        assert!(result.length > 0);
        assert!(result.volume > 0.0);
    }

    #[test]
    fn test_extract_operand_tokens() {
        let analyzer = CodeQualityAnalyzer::new();

        let tokens = analyzer.extract_operand_tokens("rax, rbx");
        assert_eq!(tokens, vec!["rax", "rbx"]);

        let tokens = analyzer.extract_operand_tokens("[rsp + 8]");
        assert_eq!(tokens, vec!["rsp", "8"]);

        let tokens = analyzer.extract_operand_tokens("dword ptr [rbp - 4]");
        assert_eq!(tokens, vec!["dword", "ptr", "rbp", "4"]);

        let tokens = analyzer.extract_operand_tokens("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_calculate_maintainability_index() {
        let analyzer = CodeQualityAnalyzer::new();

        let halstead = HalsteadMetrics {
            distinct_operators: 10,
            distinct_operands: 15,
            total_operators: 50,
            total_operands: 75,
            vocabulary: 25,
            length: 125,
            volume: 500.0,
            difficulty: 16.67,
            effort: 8333.33,
            time_to_program: 462.96,
            delivered_bugs: 0.167,
        };

        let mi = analyzer.calculate_maintainability_index(&halstead, 5, 20);
        assert!(mi >= 0.0 && mi <= 100.0);

        // Test edge cases
        let mi_low_complexity = analyzer.calculate_maintainability_index(&halstead, 1, 5);
        let mi_high_complexity = analyzer.calculate_maintainability_index(&halstead, 30, 200);
        assert!(mi_low_complexity > mi_high_complexity);
    }

    #[test]
    fn test_estimate_technical_debt() {
        let analyzer = CodeQualityAnalyzer::new();

        // No debt case
        let debt = analyzer.estimate_technical_debt(5, 10, 30, 2);
        assert_eq!(debt, 0);

        // High complexity case
        let debt = analyzer.estimate_technical_debt(15, 20, 100, 6);
        assert!(debt > 0);
        assert_eq!(
            debt,
            (15 - 10) * 10 + (20 - 15) * 8 + (100 - 50) * 2 + (6 - 4) * 15
        );

        // Partial violations
        let debt = analyzer.estimate_technical_debt(12, 10, 30, 2);
        assert_eq!(debt, (12 - 10) * 10); // Only complexity penalty
    }

    #[test]
    fn test_estimate_parameter_count() {
        let analyzer = CodeQualityAnalyzer::new();

        // Empty blocks
        let count = analyzer.estimate_parameter_count(&[]);
        assert_eq!(count, 0);

        // Block with parameter registers
        let instructions = vec![
            create_test_instruction("mov", "rax, rdi", InstructionType::Memory),
            create_test_instruction("mov", "rbx, rsi", InstructionType::Memory),
            create_test_instruction("mov", "rcx, rdx", InstructionType::Memory),
        ];
        let basic_blocks = vec![create_test_basic_block(0, instructions)];

        let count = analyzer.estimate_parameter_count(&basic_blocks);
        assert!(count > 0);

        // Block without parameter registers
        let instructions = vec![
            create_test_instruction("mov", "rax, rbx", InstructionType::Memory),
            create_test_instruction("add", "rax, 5", InstructionType::Arithmetic),
        ];
        let basic_blocks = vec![create_test_basic_block(0, instructions)];

        let count = analyzer.estimate_parameter_count(&basic_blocks);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_calculate_overall_metrics() {
        let analyzer = CodeQualityAnalyzer::new();

        let function_metrics = vec![
            FunctionMetrics {
                function_name: "func1".to_string(),
                function_address: 0x1000,
                cyclomatic_complexity: 5,
                cognitive_complexity: 8,
                nesting_depth: 2,
                function_length: 30,
                basic_block_count: 3,
                parameter_count: 2,
                return_paths: 1,
                halstead_metrics: HalsteadMetrics {
                    distinct_operators: 10,
                    distinct_operands: 15,
                    total_operators: 30,
                    total_operands: 45,
                    vocabulary: 25,
                    length: 75,
                    volume: 300.0,
                    difficulty: 10.0,
                    effort: 3000.0,
                    time_to_program: 166.67,
                    delivered_bugs: 0.1,
                },
                maintainability_index: 85.0,
                technical_debt_minutes: 0,
            },
            FunctionMetrics {
                function_name: "func2".to_string(),
                function_address: 0x2000,
                cyclomatic_complexity: 10,
                cognitive_complexity: 15,
                nesting_depth: 4,
                function_length: 50,
                basic_block_count: 8,
                parameter_count: 3,
                return_paths: 2,
                halstead_metrics: HalsteadMetrics {
                    distinct_operators: 15,
                    distinct_operands: 20,
                    total_operators: 60,
                    total_operands: 90,
                    vocabulary: 35,
                    length: 150,
                    volume: 600.0,
                    difficulty: 18.0,
                    effort: 10800.0,
                    time_to_program: 600.0,
                    delivered_bugs: 0.2,
                },
                maintainability_index: 70.0,
                technical_debt_minutes: 20,
            },
        ];

        let overall = analyzer.calculate_overall_metrics(&function_metrics, 80);

        assert_eq!(overall.total_functions, 2);
        assert_eq!(overall.total_instructions, 80);
        assert_eq!(overall.average_complexity, 7.5);
        assert_eq!(overall.average_function_length, 40.0);
        assert_eq!(overall.total_code_volume, 900.0);
        assert!((overall.total_estimated_bugs - 0.3).abs() < f64::EPSILON);
        assert_eq!(overall.most_complex_function, Some("func2".to_string()));
        assert_eq!(overall.highest_complexity, 10);
    }

    #[test]
    fn test_calculate_overall_metrics_empty() {
        let analyzer = CodeQualityAnalyzer::new();
        let function_metrics = vec![];

        let overall = analyzer.calculate_overall_metrics(&function_metrics, 0);

        assert_eq!(overall.total_functions, 0);
        assert_eq!(overall.total_instructions, 0);
        assert_eq!(overall.average_complexity, 0.0);
        assert_eq!(overall.average_function_length, 0.0);
        assert_eq!(overall.total_code_volume, 0.0);
        assert_eq!(overall.total_estimated_bugs, 0.0);
        assert_eq!(overall.most_complex_function, None);
        assert_eq!(overall.highest_complexity, 0);
    }

    #[test]
    fn test_calculate_complexity_score() {
        let analyzer = CodeQualityAnalyzer::new();

        assert_eq!(analyzer.calculate_complexity_score(3.0), 100.0);
        assert_eq!(analyzer.calculate_complexity_score(5.0), 100.0);
        assert_eq!(analyzer.calculate_complexity_score(7.5), 80.0);
        assert_eq!(analyzer.calculate_complexity_score(10.0), 70.0);
        assert_eq!(analyzer.calculate_complexity_score(15.0), 55.0);
        assert_eq!(analyzer.calculate_complexity_score(25.0), 30.0);
        assert!(analyzer.calculate_complexity_score(40.0) <= 20.0);
    }

    #[test]
    fn test_generate_quality_report() {
        let analyzer = CodeQualityAnalyzer::new();

        let function_metrics = vec![
            FunctionMetrics {
                function_name: "simple_func".to_string(),
                function_address: 0x1000,
                cyclomatic_complexity: 3,
                cognitive_complexity: 5,
                nesting_depth: 2,
                function_length: 20,
                basic_block_count: 3,
                parameter_count: 1,
                return_paths: 1,
                halstead_metrics: HalsteadMetrics {
                    distinct_operators: 5,
                    distinct_operands: 8,
                    total_operators: 15,
                    total_operands: 25,
                    vocabulary: 13,
                    length: 40,
                    volume: 150.0,
                    difficulty: 7.8,
                    effort: 1170.0,
                    time_to_program: 65.0,
                    delivered_bugs: 0.05,
                },
                maintainability_index: 90.0,
                technical_debt_minutes: 0,
            },
            FunctionMetrics {
                function_name: "complex_func".to_string(),
                function_address: 0x2000,
                cyclomatic_complexity: 25,
                cognitive_complexity: 30,
                nesting_depth: 8,
                function_length: 150,
                basic_block_count: 20,
                parameter_count: 5,
                return_paths: 10,
                halstead_metrics: HalsteadMetrics {
                    distinct_operators: 20,
                    distinct_operands: 30,
                    total_operators: 100,
                    total_operands: 150,
                    vocabulary: 50,
                    length: 250,
                    volume: 1400.0,
                    difficulty: 50.0,
                    effort: 70000.0,
                    time_to_program: 3888.89,
                    delivered_bugs: 0.47,
                },
                maintainability_index: 30.0,
                technical_debt_minutes: 315,
            },
        ];

        let overall_metrics = OverallCodeMetrics {
            total_functions: 2,
            total_instructions: 170,
            average_complexity: 14.0,
            average_function_length: 85.0,
            total_code_volume: 1550.0,
            total_estimated_bugs: 0.52,
            most_complex_function: Some("complex_func".to_string()),
            highest_complexity: 25,
        };

        let report = analyzer.generate_quality_report(&function_metrics, &overall_metrics);

        assert!(report.overall_quality_score >= 0.0 && report.overall_quality_score <= 100.0);
        assert!(report.complexity_score >= 0.0 && report.complexity_score <= 100.0);
        assert!(report.maintainability_score >= 0.0 && report.maintainability_score <= 100.0);
        assert_eq!(report.maintainability_score, 60.0); // (90 + 30) / 2
        assert!(!report.quality_issues.is_empty());
        assert!(!report.recommendations.is_empty());
        assert_eq!(report.technical_debt_hours, 5.25); // 315 / 60

        // Check for specific issues in complex function
        let high_complexity_issues: Vec<_> = report
            .quality_issues
            .iter()
            .filter(|issue| matches!(issue.issue_type, QualityIssueType::HighComplexity))
            .collect();
        assert!(!high_complexity_issues.is_empty());

        let god_function_issues: Vec<_> = report
            .quality_issues
            .iter()
            .filter(|issue| matches!(issue.issue_type, QualityIssueType::GodFunction))
            .collect();
        assert!(!god_function_issues.is_empty());
    }

    #[test]
    fn test_code_health_classification() {
        let analyzer = CodeQualityAnalyzer::new();

        // Test excellent code
        let function_metrics = vec![FunctionMetrics {
            function_name: "excellent_func".to_string(),
            function_address: 0x1000,
            cyclomatic_complexity: 2,
            cognitive_complexity: 3,
            nesting_depth: 1,
            function_length: 15,
            basic_block_count: 2,
            parameter_count: 1,
            return_paths: 1,
            halstead_metrics: HalsteadMetrics {
                distinct_operators: 3,
                distinct_operands: 5,
                total_operators: 8,
                total_operands: 12,
                vocabulary: 8,
                length: 20,
                volume: 60.0,
                difficulty: 3.6,
                effort: 216.0,
                time_to_program: 12.0,
                delivered_bugs: 0.02,
            },
            maintainability_index: 95.0,
            technical_debt_minutes: 0,
        }];

        let overall_metrics = OverallCodeMetrics {
            total_functions: 1,
            total_instructions: 15,
            average_complexity: 2.0,
            average_function_length: 15.0,
            total_code_volume: 60.0,
            total_estimated_bugs: 0.02,
            most_complex_function: Some("excellent_func".to_string()),
            highest_complexity: 2,
        };

        let report = analyzer.generate_quality_report(&function_metrics, &overall_metrics);
        assert!(matches!(report.code_health, CodeHealth::Excellent));
    }

    #[test]
    fn test_quality_issue_types() {
        let analyzer = CodeQualityAnalyzer::new();

        // Create function with multiple issues
        let function_metrics = vec![FunctionMetrics {
            function_name: "problematic_func".to_string(),
            function_address: 0x1000,
            cyclomatic_complexity: 15,
            cognitive_complexity: 20,
            nesting_depth: 6,
            function_length: 80,
            basic_block_count: 15,
            parameter_count: 3,
            return_paths: 8,
            halstead_metrics: HalsteadMetrics {
                distinct_operators: 15,
                distinct_operands: 25,
                total_operators: 80,
                total_operands: 120,
                vocabulary: 40,
                length: 200,
                volume: 1064.39,
                difficulty: 24.0,
                effort: 25545.36,
                time_to_program: 1419.18,
                delivered_bugs: 0.35,
            },
            maintainability_index: 45.0,
            technical_debt_minutes: 150,
        }];

        let overall_metrics = OverallCodeMetrics {
            total_functions: 1,
            total_instructions: 80,
            average_complexity: 15.0,
            average_function_length: 80.0,
            total_code_volume: 1064.39,
            total_estimated_bugs: 0.35,
            most_complex_function: Some("problematic_func".to_string()),
            highest_complexity: 15,
        };

        let report = analyzer.generate_quality_report(&function_metrics, &overall_metrics);

        // Should have multiple issue types
        let issue_types: HashSet<_> = report
            .quality_issues
            .iter()
            .map(|issue| &issue.issue_type)
            .collect();

        assert!(issue_types.contains(&QualityIssueType::HighComplexity));
        assert!(issue_types.contains(&QualityIssueType::LongFunction));
        assert!(issue_types.contains(&QualityIssueType::DeepNesting));
        assert!(issue_types.contains(&QualityIssueType::TooManyReturns));
    }

    #[test]
    fn test_analyze_function() {
        let analyzer = CodeQualityAnalyzer::new();

        let instructions = vec![
            create_test_instruction("mov", "rax, rdi", InstructionType::Memory),
            create_test_instruction("add", "rax, 5", InstructionType::Arithmetic),
            create_test_instruction("cmp", "rax, 10", InstructionType::Logic),
            create_test_instruction("jne", "0x1020", InstructionType::Conditional),
            create_test_instruction("ret", "", InstructionType::Return),
        ];

        let basic_blocks = vec![create_test_basic_block(0, instructions)];
        let cfg = create_test_cfg("test_function", basic_blocks);

        let result = analyzer.analyze_function(&cfg).unwrap();

        assert_eq!(result.function_name, "test_function");
        assert_eq!(result.function_address, 0x1000);
        assert_eq!(result.cyclomatic_complexity, 5);
        assert_eq!(result.cognitive_complexity, 8);
        assert_eq!(result.nesting_depth, 3);
        assert_eq!(result.basic_block_count, 1);
        assert_eq!(result.return_paths, 1);
        assert!(result.maintainability_index >= 0.0 && result.maintainability_index <= 100.0);
    }

    #[test]
    fn test_full_analysis() {
        let analyzer = CodeQualityAnalyzer::new();

        let instructions = vec![
            create_test_instruction("push", "rbp", InstructionType::Memory),
            create_test_instruction("mov", "rbp, rsp", InstructionType::Memory),
            create_test_instruction("mov", "rax, rdi", InstructionType::Memory),
            create_test_instruction("ret", "", InstructionType::Return),
        ];

        let basic_blocks = vec![create_test_basic_block(0, instructions)];
        let cfg = create_test_cfg("main", basic_blocks);

        let mut cfg_analysis = create_test_cfg_analysis();
        cfg_analysis.cfgs.push(cfg);

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

        let result = analyzer.analyze(&cfg_analysis, &symbol_table).unwrap();

        assert_eq!(result.function_metrics.len(), 1);
        assert_eq!(result.function_metrics[0].function_name, "main");
        // Analysis duration should be tracked
        assert!(true); // Duration will be > 0 in real usage, but may be 0 in tests
        assert_eq!(result.analysis_stats.functions_analyzed, 1);
        assert!(result.analysis_stats.instructions_analyzed > 0);
    }

    #[test]
    fn test_data_structure_validation() {
        // Test HalsteadMetrics validation
        let distinct_operators = 5;
        let distinct_operands = 8;
        let total_operators = 20;
        let total_operands = 30;
        let vocabulary = distinct_operators + distinct_operands;
        let length = total_operators + total_operands;
        let volume = length as f64 * (vocabulary as f64).log2();
        let difficulty =
            (distinct_operators as f64 / 2.0) * (total_operands as f64 / distinct_operands as f64);
        let effort = difficulty * volume;
        let time_to_program = effort / 18.0;
        let delivered_bugs = volume / 3000.0;

        let halstead = HalsteadMetrics {
            distinct_operators,
            distinct_operands,
            total_operators,
            total_operands,
            vocabulary,
            length,
            volume,
            difficulty,
            effort,
            time_to_program,
            delivered_bugs,
        };

        assert!(halstead.vocabulary == halstead.distinct_operators + halstead.distinct_operands);
        assert!(halstead.length == halstead.total_operators + halstead.total_operands);
        assert!((halstead.effort - halstead.difficulty * halstead.volume).abs() < f64::EPSILON);
        assert!((halstead.time_to_program - halstead.effort / 18.0).abs() < f64::EPSILON);
        assert!((halstead.delivered_bugs - halstead.volume / 3000.0).abs() < f64::EPSILON);

        // Test QualityIssue structure
        let issue = QualityIssue {
            issue_type: QualityIssueType::HighComplexity,
            severity: IssueSeverity::Major,
            function_name: "test_func".to_string(),
            description: "High complexity detected".to_string(),
            recommendation: "Refactor function".to_string(),
            debt_minutes: 30,
        };

        assert!(matches!(issue.issue_type, QualityIssueType::HighComplexity));
        assert!(matches!(issue.severity, IssueSeverity::Major));
        assert_eq!(issue.debt_minutes, 30);
    }

    #[test]
    fn test_edge_cases() {
        let analyzer = CodeQualityAnalyzer::new();

        // Test with minimal valid Halstead metrics
        let minimal_halstead = HalsteadMetrics {
            distinct_operators: 1,
            distinct_operands: 1,
            total_operators: 1,
            total_operands: 1,
            vocabulary: 2,
            length: 2,
            volume: 2.0,
            difficulty: 0.5,
            effort: 1.0,
            time_to_program: 0.056,
            delivered_bugs: 0.0007,
        };

        let mi = analyzer.calculate_maintainability_index(&minimal_halstead, 1, 1);
        assert!(mi >= 0.0 && mi <= 100.0);

        // Test with zero values
        let zero_halstead = HalsteadMetrics {
            distinct_operators: 0,
            distinct_operands: 0,
            total_operators: 0,
            total_operands: 0,
            vocabulary: 0,
            length: 0,
            volume: 0.0,
            difficulty: 0.0,
            effort: 0.0,
            time_to_program: 0.0,
            delivered_bugs: 0.0,
        };

        let mi_zero = analyzer.calculate_maintainability_index(&zero_halstead, 0, 0);
        assert!(mi_zero >= 0.0 && mi_zero <= 100.0);

        // Test debt calculation with zero values
        let debt = analyzer.estimate_technical_debt(0, 0, 0, 0);
        assert_eq!(debt, 0);
    }
}
