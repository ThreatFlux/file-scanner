use anyhow::Result;
use rmcp::{
    handler::server::wrapper::Json,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    schemars, tool, ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{
    behavioral_analysis::{analyze_behavior, BehavioralAnalysis},
    binary_parser::{parse_binary, BinaryInfo},
    code_metrics::{analyze_code_quality, CodeQualityAnalysis},
    control_flow::{analyze_control_flow, ControlFlowAnalysis},
    dependency_analysis::{analyze_dependencies, DependencyAnalysisResult},
    disassembly::{disassemble_binary, DisassemblyResult},
    entropy_analysis::{analyze_entropy, EntropyAnalysis},
    function_analysis::{analyze_symbols, SymbolTable},
    hash::{calculate_all_hashes, Hashes},
    hexdump::{format_hex_dump_text, generate_hex_dump, HexDumpOptions},
    metadata::FileMetadata,
    signature::verify_signature,
    strings::extract_strings,
    threat_detection::{analyze_threats, ThreatAnalysis},
    vulnerability_detection::{analyze_vulnerabilities, VulnerabilityDetectionResult},
};

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileAnalysisRequest {
    #[schemars(description = "Path to the file to analyze")]
    pub file_path: String,

    // Analysis options
    #[schemars(description = "Include file metadata (size, timestamps, permissions)")]
    pub metadata: Option<bool>,
    #[schemars(description = "Include cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)")]
    pub hashes: Option<bool>,
    #[schemars(description = "Extract strings from the file")]
    pub strings: Option<bool>,
    #[schemars(description = "Minimum string length (default: 4)")]
    pub min_string_length: Option<usize>,
    #[schemars(description = "Generate hex dump")]
    pub hex_dump: Option<bool>,
    #[schemars(description = "Hex dump size in bytes (default: 256)")]
    pub hex_dump_size: Option<usize>,
    #[schemars(description = "Hex dump offset from start")]
    pub hex_dump_offset: Option<u64>,
    #[schemars(description = "Analyze binary format (PE/ELF/Mach-O)")]
    pub binary_info: Option<bool>,
    #[schemars(description = "Verify digital signatures")]
    pub signatures: Option<bool>,
    #[schemars(description = "Analyze function symbols")]
    pub symbols: Option<bool>,
    #[schemars(description = "Analyze control flow")]
    pub control_flow: Option<bool>,
    #[schemars(description = "Detect vulnerabilities")]
    pub vulnerabilities: Option<bool>,
    #[schemars(description = "Analyze code quality metrics")]
    pub code_quality: Option<bool>,
    #[schemars(description = "Analyze dependencies")]
    pub dependencies: Option<bool>,
    #[schemars(description = "Analyze entropy patterns")]
    pub entropy: Option<bool>,
    #[schemars(description = "Disassemble code")]
    pub disassembly: Option<bool>,
    #[schemars(description = "Detect threats and malware")]
    pub threats: Option<bool>,
    #[schemars(description = "Analyze behavioral patterns")]
    pub behavioral: Option<bool>,
    #[schemars(description = "Extract YARA rule indicators")]
    pub yara_indicators: Option<bool>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileAnalysisResult {
    pub file_path: String,
    #[schemars(skip)]
    pub metadata: Option<FileMetadata>,
    #[schemars(skip)]
    pub hashes: Option<Hashes>,
    pub strings: Option<Vec<String>>,
    pub hex_dump: Option<String>,
    #[schemars(skip)]
    pub binary_info: Option<BinaryInfo>,
    pub signatures: Option<serde_json::Value>,
    #[schemars(skip)]
    pub symbols: Option<SymbolTable>,
    #[schemars(skip)]
    pub control_flow: Option<ControlFlowAnalysis>,
    #[schemars(skip)]
    pub vulnerabilities: Option<VulnerabilityDetectionResult>,
    #[schemars(skip)]
    pub code_quality: Option<CodeQualityAnalysis>,
    #[schemars(skip)]
    pub dependencies: Option<DependencyAnalysisResult>,
    #[schemars(skip)]
    pub entropy: Option<EntropyAnalysis>,
    #[schemars(skip)]
    pub disassembly: Option<DisassemblyResult>,
    #[schemars(skip)]
    pub threats: Option<ThreatAnalysis>,
    #[schemars(skip)]
    pub behavioral: Option<BehavioralAnalysis>,
    pub yara_indicators: Option<YaraIndicators>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraIndicators {
    pub sha256: String,
    pub md5: String,
    pub file_size: u64,
    pub magic_bytes: String,
    pub entropy: f64,
    pub unique_strings: Vec<String>,
    pub imports: Vec<String>,
    pub sections: Vec<String>,
    pub is_packed: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LlmFileAnalysisRequest {
    #[schemars(description = "Path to the file to analyze")]
    pub file_path: String,

    #[schemars(description = "Token limit for the response (default: 25000)")]
    pub token_limit: Option<usize>,

    #[schemars(description = "Minimum string length to extract (default: 6)")]
    pub min_string_length: Option<usize>,

    #[schemars(description = "Maximum number of strings to return (default: 50)")]
    pub max_strings: Option<usize>,

    #[schemars(description = "Maximum number of imports to return (default: 30)")]
    pub max_imports: Option<usize>,

    #[schemars(description = "Maximum number of opcodes to return (default: 10)")]
    pub max_opcodes: Option<usize>,

    #[schemars(description = "Size of hex patterns to extract (default: 32)")]
    pub hex_pattern_size: Option<usize>,

    #[schemars(description = "Generate YARA rule suggestion (default: true)")]
    pub suggest_yara_rule: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LlmFileAnalysisResult {
    pub md5: String,
    pub file_size: u64,
    pub key_strings: Vec<String>,
    pub hex_patterns: Vec<String>,
    pub imports: Vec<String>,
    pub opcodes: Vec<String>,
    pub entropy: Option<f64>,
    pub yara_rule_suggestion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileScannerMcp;

#[tool(tool_box)]
impl FileScannerMcp {
    #[tool(
        description = "Comprehensive file analysis tool - use flags to control which analyses to perform (metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, yara_indicators)"
    )]
    pub async fn analyze_file(
        &self,
        #[tool(aggr)] request: FileAnalysisRequest,
    ) -> Result<Json<FileAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let mut result = FileAnalysisResult {
            file_path: request.file_path.clone(),
            metadata: None,
            hashes: None,
            strings: None,
            hex_dump: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        // Metadata
        if request.metadata.unwrap_or(false) {
            let mut metadata = FileMetadata::new(&path).map_err(|e| e.to_string())?;
            metadata.extract_basic_info().map_err(|e| e.to_string())?;
            metadata
                .calculate_hashes()
                .await
                .map_err(|e| e.to_string())?;
            result.metadata = Some(metadata);
        }

        // Hashes
        if request.hashes.unwrap_or(false) {
            let hashes = calculate_all_hashes(&path)
                .await
                .map_err(|e| e.to_string())?;
            result.hashes = Some(hashes);
        }

        // Strings
        if request.strings.unwrap_or(false) {
            let min_len = request.min_string_length.unwrap_or(4);
            let strings = extract_strings(&path, min_len).map_err(|e| e.to_string())?;
            let all_strings = [strings.ascii_strings, strings.unicode_strings].concat();
            result.strings = Some(all_strings);
        }

        // Hex dump
        if request.hex_dump.unwrap_or(false) {
            let size = request.hex_dump_size.unwrap_or(256);
            let hex_options = HexDumpOptions {
                offset: request.hex_dump_offset.unwrap_or(0),
                length: Some(size),
                bytes_per_line: 16,
                max_lines: None,
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
            result.hex_dump = Some(format_hex_dump_text(&hex_dump));
        }

        // Binary info
        if request.binary_info.unwrap_or(false) {
            if let Ok(binary_info) = parse_binary(&path) {
                result.binary_info = Some(binary_info);
            }
        }

        // Signatures
        if request.signatures.unwrap_or(false) {
            let sig_result = verify_signature(&path);
            // Convert the result to a JSON-serializable format
            let sig_json = match sig_result {
                Ok(info) => serde_json::json!({
                    "status": "success",
                    "is_signed": info.is_signed,
                    "signature_type": info.signature_type,
                    "signer": info.signer,
                    "timestamp": info.timestamp,
                    "verification_status": info.verification_status,
                    "certificate_chain": info.certificate_chain,
                }),
                Err(e) => serde_json::json!({
                    "status": "error",
                    "error": e.to_string()
                }),
            };
            result.signatures = Some(sig_json);
        }

        // Symbols
        if request.symbols.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                result.symbols = Some(symbols);
            }
        }

        // Control flow
        if request.control_flow.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    result.control_flow = Some(control_flow);
                }
            }
        }

        // Vulnerabilities
        if request.vulnerabilities.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(vulns) = analyze_vulnerabilities(&path, &symbols, &control_flow) {
                        result.vulnerabilities = Some(vulns);
                    }
                }
            }
        }

        // Code quality
        if request.code_quality.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(quality) = analyze_code_quality(&path, &symbols, &control_flow) {
                        result.code_quality = Some(quality);
                    }
                }
            }
        }

        // Dependencies
        if request.dependencies.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                let strings = extract_strings(&path, 4).ok();
                if let Ok(deps) = analyze_dependencies(&path, &symbols, strings.as_ref()) {
                    result.dependencies = Some(deps);
                }
            }
        }

        // Entropy
        if request.entropy.unwrap_or(false) {
            if let Ok(entropy) = analyze_entropy(&path) {
                result.entropy = Some(entropy);
            }
        }

        // Disassembly
        if request.disassembly.unwrap_or(false) {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(disassembly) = disassemble_binary(&path, &symbols) {
                    result.disassembly = Some(disassembly);
                }
            }
        }

        // Threats
        if request.threats.unwrap_or(false) {
            if let Ok(threats) = analyze_threats(&path) {
                result.threats = Some(threats);
            }
        }

        // Behavioral
        if request.behavioral.unwrap_or(false) {
            let strings = extract_strings(&path, 4).ok();
            let symbols = analyze_symbols(&path).ok();
            let disassembly = if let Some(ref syms) = symbols {
                disassemble_binary(&path, syms).ok()
            } else {
                None
            };

            if let Ok(behavioral) = analyze_behavior(
                &path,
                strings.as_ref(),
                symbols.as_ref(),
                disassembly.as_ref(),
            ) {
                result.behavioral = Some(behavioral);
            }
        }

        // YARA indicators
        if request.yara_indicators.unwrap_or(false) {
            let file_metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            let file_size = file_metadata.len();

            // Get hashes if not already calculated
            let hashes = match &result.hashes {
                Some(_) => result.hashes.take().unwrap(),
                None => calculate_all_hashes(&path)
                    .await
                    .map_err(|e| e.to_string())?,
            };

            // Get magic bytes
            let hex_options = HexDumpOptions {
                offset: 0,
                length: Some(8),
                bytes_per_line: 8,
                max_lines: Some(1),
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| e.to_string())?;
            let magic_bytes = hex_dump
                .lines
                .first()
                .map(|line| {
                    line.raw_bytes
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();

            // Get entropy if not already calculated
            let entropy_analysis = if let Some(e) = result.entropy.clone() {
                e
            } else {
                analyze_entropy(&path).map_err(|e| e.to_string())?
            };

            // Extract unique strings
            let strings = extract_strings(&path, 8).map_err(|e| e.to_string())?;
            let mut unique_strings: Vec<String> = strings
                .interesting_strings
                .iter()
                .filter(|s| s.value.len() >= 8 && s.value.len() <= 50)
                .map(|s| s.value.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .take(20)
                .collect();
            unique_strings.sort();

            // Get imports and sections
            let (imports, sections) = if let Some(ref bi) = result.binary_info {
                (
                    bi.imports.clone(),
                    bi.sections.iter().map(|s| s.name.clone()).collect(),
                )
            } else if let Ok(bi) = parse_binary(&path) {
                (
                    bi.imports.clone(),
                    bi.sections.iter().map(|s| s.name.clone()).collect(),
                )
            } else {
                (vec![], vec![])
            };

            result.yara_indicators = Some(YaraIndicators {
                sha256: hashes.sha256,
                md5: hashes.md5,
                file_size,
                magic_bytes,
                entropy: entropy_analysis.overall_entropy,
                unique_strings,
                imports,
                sections,
                is_packed: entropy_analysis.packed_indicators.likely_packed
                    || entropy_analysis.overall_entropy > 7.0,
            });
        }

        Ok(Json(result))
    }

    #[tool(
        description = "LLM-optimized file analysis for YARA rule generation - returns focused, token-limited output with key indicators"
    )]
    pub async fn llm_analyze_file(
        &self,
        #[tool(aggr)] request: LlmFileAnalysisRequest,
    ) -> Result<Json<LlmFileAnalysisResult>, String> {
        use crate::{
            binary_parser::parse_binary, entropy_analysis::analyze_entropy,
            strings::extract_strings,
        };

        let path = PathBuf::from(&request.file_path);
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get file metadata for MD5 hash
        let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let file_size = metadata.len();

        // Calculate MD5 hash only
        let md5_hash = crate::hash::calculate_md5(&path)
            .await
            .map_err(|e| e.to_string())?;

        // Extract strings with focus on interesting patterns
        let min_string_len = request.min_string_length.unwrap_or(6);
        let strings = extract_strings(&path, min_string_len).map_err(|e| e.to_string())?;

        // Filter and prioritize strings for YARA rules
        let key_strings = self.extract_key_strings(&strings, request.max_strings.unwrap_or(50));

        // Get hex patterns from file header/footer
        let hex_patterns =
            self.extract_hex_patterns(&path, request.hex_pattern_size.unwrap_or(32))?;

        // Parse binary for imports
        let imports = if let Ok(binary_info) = parse_binary(&path) {
            binary_info
                .imports
                .into_iter()
                .take(request.max_imports.unwrap_or(30))
                .collect()
        } else {
            vec![]
        };

        // Get interesting opcodes/byte sequences
        let opcodes = self.extract_key_opcodes(&path, request.max_opcodes.unwrap_or(10))?;

        // Calculate entropy for packing detection
        let entropy = analyze_entropy(&path).ok().map(|e| e.overall_entropy);

        // Build focused result
        let mut result = LlmFileAnalysisResult {
            md5: md5_hash,
            file_size,
            key_strings,
            hex_patterns,
            imports,
            opcodes,
            entropy,
            yara_rule_suggestion: None,
        };

        // Generate YARA rule suggestion if requested
        if request.suggest_yara_rule.unwrap_or(true) {
            result.yara_rule_suggestion =
                Some(self.generate_yara_rule_suggestion(&result, &request.file_path));
        }

        // Ensure we're within token limit
        let serialized = serde_json::to_string(&result).unwrap_or_default();
        let token_limit = request.token_limit.unwrap_or(25000);

        if serialized.len() > token_limit {
            // Trim results to fit token limit
            result = self.trim_results_to_token_limit(result, token_limit);
        }

        Ok(Json(result))
    }

    fn extract_key_strings(
        &self,
        strings: &crate::strings::ExtractedStrings,
        max_count: usize,
    ) -> Vec<String> {
        let mut key_strings = Vec::new();

        // Prioritize interesting strings
        for s in &strings.interesting_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if s.value.len() >= 8 && s.value.len() <= 100 {
                key_strings.push(s.value.clone());
            }
        }

        // Add unique ASCII strings
        let mut seen = std::collections::HashSet::new();
        for s in &strings.ascii_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if s.len() >= 8 && s.len() <= 100 && seen.insert(s) {
                key_strings.push(s.clone());
            }
        }

        key_strings
    }

    fn extract_hex_patterns(
        &self,
        path: &PathBuf,
        pattern_size: usize,
    ) -> Result<Vec<String>, String> {
        use crate::hexdump::{generate_hex_dump, HexDumpOptions};

        let mut patterns = Vec::new();

        // Get file header pattern
        let header_options = HexDumpOptions {
            offset: 0,
            length: Some(pattern_size),
            bytes_per_line: pattern_size,
            max_lines: Some(1),
        };

        if let Ok(header_dump) = generate_hex_dump(path, header_options) {
            if let Some(line) = header_dump.lines.first() {
                let hex_pattern = line
                    .raw_bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                patterns.push(hex_pattern);
            }
        }

        // Get file footer pattern if file is large enough
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > pattern_size as u64 {
                let footer_options = HexDumpOptions {
                    offset: metadata.len() - pattern_size as u64,
                    length: Some(pattern_size),
                    bytes_per_line: pattern_size,
                    max_lines: Some(1),
                };

                if let Ok(footer_dump) = generate_hex_dump(path, footer_options) {
                    if let Some(line) = footer_dump.lines.first() {
                        let hex_pattern = line
                            .raw_bytes
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        patterns.push(hex_pattern);
                    }
                }
            }
        }

        Ok(patterns)
    }

    fn extract_key_opcodes(&self, path: &Path, max_count: usize) -> Result<Vec<String>, String> {
        use crate::hexdump::{generate_hex_dump, HexDumpOptions};

        let mut opcodes = Vec::new();

        // Look for common opcode patterns in code sections
        let options = HexDumpOptions {
            offset: 0x1000, // Common code section offset
            length: Some(256),
            bytes_per_line: 16,
            max_lines: Some(16),
        };

        if let Ok(dump) = generate_hex_dump(path, options) {
            for line in dump.lines.iter().take(max_count) {
                // Look for interesting opcode sequences
                let bytes = &line.raw_bytes;
                for window in bytes.windows(4) {
                    // Common interesting patterns
                    if (window[0] == 0xE8 || window[0] == 0xE9) || // CALL/JMP
                       (window[0] == 0xFF && (window[1] & 0xF0) == 0x10) || // Indirect calls
                       (window[0] == 0x48 && window[1] == 0x8B) || // MOV patterns
                       (window[0] == 0x55 && window[1] == 0x48)
                    {
                        // Function prologue
                        let pattern = window
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !opcodes.contains(&pattern) {
                            opcodes.push(pattern);
                        }
                    }
                }
            }
        }

        Ok(opcodes.into_iter().take(max_count).collect())
    }

    fn generate_yara_rule_suggestion(
        &self,
        analysis: &LlmFileAnalysisResult,
        file_name: &str,
    ) -> String {
        let rule_name = file_name
            .replace("/", "_")
            .replace(".", "_")
            .replace("-", "_");
        let mut conditions = Vec::new();

        // Add file size condition
        conditions.push(format!("filesize == {}", analysis.file_size));

        // Add entropy condition if packed
        if let Some(entropy) = analysis.entropy {
            if entropy > 7.0 {
                conditions.push(format!("math.entropy(0, filesize) > {:.1}", entropy - 0.5));
            }
        }

        // Build string conditions
        let string_count = analysis.key_strings.len().min(5);
        if string_count > 0 {
            conditions.push(format!("{} of ($s*)", string_count.div_ceil(2)));
        }

        // Add hex pattern conditions
        if !analysis.hex_patterns.is_empty() {
            conditions.push("$header at 0".to_string());
        }

        // Build the rule
        let mut rule = format!("rule {} {{\n", rule_name);
        rule.push_str("    meta:\n");
        rule.push_str(&format!("        md5 = \"{}\"\n", analysis.md5));
        rule.push_str(&format!("        filesize = {}\n", analysis.file_size));

        rule.push_str("    strings:\n");

        // Add hex patterns
        if let Some(header) = analysis.hex_patterns.first() {
            rule.push_str(&format!("        $header = {{ {} }}\n", header));
        }

        // Add key strings
        for (i, s) in analysis.key_strings.iter().take(10).enumerate() {
            let escaped = s.replace("\\", "\\\\").replace("\"", "\\\"");
            rule.push_str(&format!("        $s{} = \"{}\"\n", i + 1, escaped));
        }

        // Add condition
        rule.push_str("    condition:\n");
        rule.push_str(&format!("        {}\n", conditions.join(" and ")));
        rule.push_str("}\n");

        rule
    }

    fn trim_results_to_token_limit(
        &self,
        mut result: LlmFileAnalysisResult,
        token_limit: usize,
    ) -> LlmFileAnalysisResult {
        // Progressively trim results until we fit within token limit
        loop {
            let serialized = serde_json::to_string(&result).unwrap_or_default();
            if serialized.len() <= token_limit {
                break;
            }

            // Trim strategies in order of preference
            if result.key_strings.len() > 20 {
                result.key_strings.truncate(result.key_strings.len() - 5);
            } else if result.imports.len() > 10 {
                result.imports.truncate(result.imports.len() - 5);
            } else if result.opcodes.len() > 5 {
                result.opcodes.truncate(result.opcodes.len() - 2);
            } else if result.key_strings.len() > 5 {
                result.key_strings.truncate(result.key_strings.len() - 1);
            } else {
                // Last resort: remove YARA suggestion
                result.yara_rule_suggestion = None;
                break;
            }
        }

        result
    }
}

#[tool(tool_box)]
impl ServerHandler for FileScannerMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            server_info: Implementation {
                name: "file-scanner".into(),
                version: "0.1.0".into(),
            },
            instructions: Some("A comprehensive file scanner with a single analyze_file tool that supports multiple analysis types via flags: metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, and yara_indicators.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf), std::io::Error> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file.bin");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    fn create_test_elf_file() -> Result<(TempDir, std::path::PathBuf), std::io::Error> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_elf");
        let mut elf_data = vec![
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, 0x01, 0x01, 0x00, // 64-bit, little-endian, version 1
        ];
        // Add some padding to make it a minimal valid ELF-like file
        elf_data.extend(vec![0u8; 56]); // Pad to 64 bytes

        let mut file = fs::File::create(&file_path)?;
        file.write_all(&elf_data)?;
        Ok((temp_dir, file_path))
    }

    #[test]
    fn test_file_analysis_request_serialization() {
        let request = FileAnalysisRequest {
            file_path: "/test/file.bin".to_string(),
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(true),
            min_string_length: Some(8),
            hex_dump: Some(true),
            hex_dump_size: Some(512),
            hex_dump_offset: Some(0),
            binary_info: Some(true),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(true),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(true),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.file_path, request.file_path);
        assert_eq!(deserialized.metadata, request.metadata);
        assert_eq!(deserialized.hashes, request.hashes);
        assert_eq!(deserialized.min_string_length, request.min_string_length);
    }

    #[test]
    fn test_llm_file_analysis_request_serialization() {
        let request = LlmFileAnalysisRequest {
            file_path: "/test/file.bin".to_string(),
            token_limit: Some(20000),
            min_string_length: Some(6),
            max_strings: Some(40),
            max_imports: Some(25),
            max_opcodes: Some(8),
            hex_pattern_size: Some(24),
            suggest_yara_rule: Some(true),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: LlmFileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.file_path, request.file_path);
        assert_eq!(deserialized.token_limit, request.token_limit);
        assert_eq!(deserialized.max_strings, request.max_strings);
    }

    #[test]
    fn test_yara_indicators_serialization() {
        let indicators = YaraIndicators {
            sha256: "abc123".to_string(),
            md5: "def456".to_string(),
            file_size: 1024,
            magic_bytes: "4D 5A".to_string(),
            entropy: 6.5,
            unique_strings: vec!["test".to_string(), "example".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            sections: vec![".text".to_string(), ".data".to_string()],
            is_packed: false,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&indicators).unwrap();
        let deserialized: YaraIndicators = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sha256, indicators.sha256);
        assert_eq!(deserialized.file_size, indicators.file_size);
        assert_eq!(deserialized.unique_strings, indicators.unique_strings);
    }

    #[tokio::test]
    async fn test_analyze_file_nonexistent() {
        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: "/nonexistent/file.bin".to_string(),
            metadata: Some(true),
            hashes: None,
            strings: None,
            min_string_length: None,
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_err());
        match result {
            Err(error_msg) => assert!(error_msg.contains("does not exist")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_analyze_file_basic_metadata() {
        let test_content = b"Hello, World! This is test content for analysis.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            metadata: Some(true),
            hashes: None,
            strings: None,
            min_string_length: None,
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.metadata.is_some());
        assert!(analysis.hashes.is_none());
        assert!(analysis.strings.is_none());
    }

    #[tokio::test]
    async fn test_analyze_file_hashes() {
        let test_content = b"Test content for hash calculation";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            metadata: None,
            hashes: Some(true),
            strings: None,
            min_string_length: None,
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.hashes.is_some());
        let hashes = analysis.hashes.unwrap();
        assert!(!hashes.md5.is_empty());
        assert!(!hashes.sha256.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_file_strings() {
        let test_content =
            b"Hello World! This is a test string for extraction. Another string here.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            metadata: None,
            hashes: None,
            strings: Some(true),
            min_string_length: Some(4),
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.strings.is_some());
        let strings = analysis.strings.unwrap();
        assert!(!strings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_file_hex_dump() {
        let test_content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            metadata: None,
            hashes: None,
            strings: None,
            min_string_length: None,
            hex_dump: Some(true),
            hex_dump_size: Some(64),
            hex_dump_offset: Some(0),
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.hex_dump.is_some());
        let hex_dump = analysis.hex_dump.unwrap();
        assert!(hex_dump.contains("41 42 43")); // ABC in hex
    }

    #[tokio::test]
    async fn test_analyze_file_combined_analysis() {
        let test_content = b"Combined analysis test with various features enabled.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(true),
            min_string_length: Some(6),
            hex_dump: Some(true),
            hex_dump_size: Some(32),
            hex_dump_offset: Some(0),
            binary_info: Some(true), // Will fail but shouldn't error
            signatures: Some(true),  // Will show no signature
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: Some(true),
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.metadata.is_some());
        assert!(analysis.hashes.is_some());
        assert!(analysis.strings.is_some());
        assert!(analysis.hex_dump.is_some());
        assert!(analysis.signatures.is_some());
        assert!(analysis.entropy.is_some());
    }

    #[tokio::test]
    async fn test_llm_analyze_file_nonexistent() {
        let mcp = FileScannerMcp;
        let request = LlmFileAnalysisRequest {
            file_path: "/nonexistent/file.bin".to_string(),
            token_limit: None,
            min_string_length: None,
            max_strings: None,
            max_imports: None,
            max_opcodes: None,
            hex_pattern_size: None,
            suggest_yara_rule: None,
        };

        let result = mcp.llm_analyze_file(request).await;
        assert!(result.is_err());
        match result {
            Err(error_msg) => assert!(error_msg.contains("does not exist")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_llm_analyze_file_basic() {
        let test_content = b"LLM analysis test content with interesting patterns and strings.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = LlmFileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            token_limit: Some(10000),
            min_string_length: Some(6),
            max_strings: Some(20),
            max_imports: Some(10),
            max_opcodes: Some(5),
            hex_pattern_size: Some(16),
            suggest_yara_rule: Some(true),
        };

        let result = mcp.llm_analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(!analysis.md5.is_empty());
        assert!(analysis.file_size > 0);
        assert!(analysis.yara_rule_suggestion.is_some());
        let yara_rule = analysis.yara_rule_suggestion.unwrap();
        assert!(yara_rule.contains("rule"));
        assert!(yara_rule.contains("filesize"));
    }

    #[test]
    fn test_extract_key_strings() {
        let mcp = FileScannerMcp;

        // Create mock extracted strings
        let extracted_strings = crate::strings::ExtractedStrings {
            total_count: 10,
            unique_count: 8,
            ascii_strings: vec![
                "short".to_string(),
                "this is a longer string for testing".to_string(),
                "medium length string".to_string(),
                "another test string here".to_string(),
            ],
            unicode_strings: vec![],
            interesting_strings: vec![
                crate::strings::InterestingString {
                    category: "URL".to_string(),
                    value: "https://example.com/malware".to_string(),
                    offset: 100,
                },
                crate::strings::InterestingString {
                    category: "File Path".to_string(),
                    value: "/usr/bin/suspicious".to_string(),
                    offset: 200,
                },
            ],
        };

        let key_strings = mcp.extract_key_strings(&extracted_strings, 5);

        assert!(!key_strings.is_empty());
        assert!(key_strings.len() <= 5);

        // Should prioritize interesting strings
        assert!(key_strings.contains(&"https://example.com/malware".to_string()));
        assert!(key_strings.contains(&"/usr/bin/suspicious".to_string()));
    }

    #[test]
    fn test_extract_hex_patterns() {
        let test_content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let result = mcp.extract_hex_patterns(&file_path, 16);

        assert!(result.is_ok());
        let patterns = result.unwrap();
        assert!(!patterns.is_empty());

        // Should contain header pattern
        let header_pattern = &patterns[0];
        assert!(header_pattern.contains("41 42 43")); // ABC in hex
    }

    #[test]
    fn test_extract_key_opcodes() {
        let test_content = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL instruction
            0x48, 0x8B, 0x05, 0x00, // MOV instruction
            0x55, 0x48, 0x89, 0xE5, // Function prologue
            0xFF, 0x15, 0x00, 0x00, // Indirect call
        ];
        let (_temp_dir, file_path) = create_test_file(&test_content).unwrap();

        let mcp = FileScannerMcp;
        let result = mcp.extract_key_opcodes(&file_path, 5);

        // This test might not find opcodes since it looks at offset 0x1000
        // But it should not error
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_yara_rule_suggestion() {
        let mcp = FileScannerMcp;

        let analysis = LlmFileAnalysisResult {
            md5: "abc123def456".to_string(),
            file_size: 1024,
            key_strings: vec![
                "suspicious_function".to_string(),
                "malware_string".to_string(),
                "http://evil.com".to_string(),
            ],
            hex_patterns: vec!["4D 5A 90 00".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            opcodes: vec!["E8 00 00 00".to_string()],
            entropy: Some(7.2),
            yara_rule_suggestion: None,
        };

        let yara_rule = mcp.generate_yara_rule_suggestion(&analysis, "test_malware.exe");

        assert!(yara_rule.contains("rule test_malware_exe"));
        assert!(yara_rule.contains("md5 = \"abc123def456\""));
        assert!(yara_rule.contains("filesize = 1024"));
        assert!(yara_rule.contains("$header = { 4D 5A 90 00 }"));
        assert!(yara_rule.contains("$s1 = \"suspicious_function\""));
        assert!(yara_rule.contains("filesize == 1024"));
        assert!(yara_rule.contains("math.entropy"));
    }

    #[test]
    fn test_trim_results_to_token_limit() {
        let mcp = FileScannerMcp;

        let result = LlmFileAnalysisResult {
            md5: "abc123".to_string(),
            file_size: 1024,
            key_strings: (0..50).map(|i| format!("string_{}", i)).collect(),
            hex_patterns: vec!["4D 5A".to_string()],
            imports: (0..40).map(|i| format!("import_{}.dll", i)).collect(),
            opcodes: (0..20).map(|i| format!("opcode_{:02X}", i)).collect(),
            entropy: Some(6.5),
            yara_rule_suggestion: Some("very long yara rule here".to_string()),
        };

        let trimmed = mcp.trim_results_to_token_limit(result, 500);

        // Should have fewer strings/imports/opcodes
        assert!(trimmed.key_strings.len() < 50);
        assert!(trimmed.imports.len() < 40);
        assert!(trimmed.opcodes.len() < 20);
    }

    #[test]
    fn test_server_handler_get_info() {
        let mcp = FileScannerMcp;
        let info = mcp.get_info();

        assert_eq!(info.server_info.name, "file-scanner");
        assert_eq!(info.server_info.version, "0.1.0");
        assert!(info.instructions.is_some());
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn test_file_analysis_result_defaults() {
        let result = FileAnalysisResult {
            file_path: "test.bin".to_string(),
            metadata: None,
            hashes: None,
            strings: None,
            hex_dump: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        assert_eq!(result.file_path, "test.bin");
        assert!(result.metadata.is_none());
        assert!(result.hashes.is_none());
        assert!(result.yara_indicators.is_none());
    }

    #[test]
    fn test_llm_file_analysis_result_serialization() {
        let result = LlmFileAnalysisResult {
            md5: "abc123".to_string(),
            file_size: 2048,
            key_strings: vec!["test".to_string()],
            hex_patterns: vec!["4D 5A".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            opcodes: vec!["E8 00".to_string()],
            entropy: Some(6.8),
            yara_rule_suggestion: Some("rule test {}".to_string()),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: LlmFileAnalysisResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.md5, result.md5);
        assert_eq!(deserialized.file_size, result.file_size);
        assert_eq!(deserialized.entropy, result.entropy);
    }
}
