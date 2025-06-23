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
    java_analysis::{analyze_class_file, analyze_java_archive, JavaAnalysisResult},
    metadata::FileMetadata,
    npm_analysis::{analyze_npm_package, NpmPackageAnalysis},
    python_analysis::{analyze_python_package, PythonPackageAnalysis},
    signature::verify_signature,
    strings::extract_strings,
    threat_detection::{analyze_threats, ThreatAnalysis},
    vulnerability_detection::{analyze_vulnerabilities, VulnerabilityDetectionResult},
};

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileAnalysisRequest {
    #[schemars(description = "Path to the file to analyze")]
    pub file_path: String,

    // Convenience flag
    #[schemars(description = "Enable all analysis options (overrides individual flags)")]
    pub all: Option<bool>,

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
    #[schemars(
        description = "Hex dump size in bytes (default: 256, or entire file up to 100MB when 'all' is true)"
    )]
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

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraScanRequest {
    #[schemars(description = "Path to the file or directory to scan")]
    pub path: String,

    #[schemars(description = "YARA rule content to use for scanning")]
    pub yara_rule: String,

    #[schemars(description = "If true, recursively scan directories (default: true)")]
    pub recursive: Option<bool>,

    #[schemars(description = "Maximum file size to scan in bytes (default: 100MB)")]
    pub max_file_size: Option<u64>,

    #[schemars(description = "Include detailed match information (default: true)")]
    pub detailed_matches: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraScanResult {
    pub total_files_scanned: usize,
    pub total_matches: usize,
    pub scan_duration_ms: u64,
    pub matches: Vec<YaraFileMatch>,
    pub errors: Vec<YaraScanError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraFileMatch {
    pub file_path: String,
    pub file_size: u64,
    pub matches: Vec<YaraRuleMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraRuleMatch {
    pub rule_identifier: String,
    pub tags: Vec<String>,
    pub metadata: std::collections::HashMap<String, String>,
    pub strings: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraScanError {
    pub file_path: String,
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JavaAnalysisRequest {
    #[schemars(description = "Path to the Java file to analyze (JAR/WAR/EAR/APK/AAR/CLASS)")]
    pub file_path: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NpmAnalysisRequest {
    #[schemars(
        description = "Path to npm package (can be .tgz file or directory with package.json)"
    )]
    pub package_path: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PythonAnalysisRequest {
    #[schemars(
        description = "Path to Python package (can be .whl, .tar.gz, .zip file or directory with setup.py/pyproject.toml)"
    )]
    pub package_path: String,
}

#[derive(Debug, Clone)]
pub struct FileScannerMcp;

#[tool(tool_box)]
impl FileScannerMcp {
    #[tool(
        description = "Comprehensive file analysis tool - use 'all' flag to enable all analyses, or individual flags to control specific analyses (metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, yara_indicators)"
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

        // Check if 'all' flag is set
        let all = request.all.unwrap_or(false);

        // Cache extracted strings to avoid multiple expensive extractions
        let mut cached_strings: Option<crate::strings::ExtractedStrings> = None;

        // Preemptively extract strings if any analysis that needs them is requested
        let needs_strings = request.strings.unwrap_or(false)
            || request.dependencies.unwrap_or(false)
            || request.behavioral.unwrap_or(false)
            || request.yara_indicators.unwrap_or(false)
            || all;

        if needs_strings && cached_strings.is_none() {
            let min_len = request.min_string_length.unwrap_or(4);
            if let Ok(strings) = extract_strings(&path, min_len) {
                cached_strings = Some(strings);
            }
        }

        // Metadata
        if request.metadata.unwrap_or(false) || all {
            let mut metadata = FileMetadata::new(&path).map_err(|e| e.to_string())?;
            metadata.extract_basic_info().map_err(|e| e.to_string())?;
            metadata
                .calculate_hashes()
                .await
                .map_err(|e| e.to_string())?;
            result.metadata = Some(metadata);
        }

        // Hashes
        if request.hashes.unwrap_or(false) || all {
            let hashes = calculate_all_hashes(&path)
                .await
                .map_err(|e| e.to_string())?;
            result.hashes = Some(hashes);
        }

        // Strings (use cached version)
        if request.strings.unwrap_or(false) || all {
            if let Some(ref strings) = cached_strings {
                let all_strings = [
                    strings.ascii_strings.clone(),
                    strings.unicode_strings.clone(),
                ]
                .concat();
                result.strings = Some(all_strings);
            }
        }

        // Hex dump
        if request.hex_dump.unwrap_or(false) || all {
            // When 'all' is selected, show the ENTIRE file (with a reasonable safety limit)
            let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let max_allowed = 100 * 1024 * 1024; // 100MB safety limit

            let default_size = if all {
                // Show entire file up to safety limit
                std::cmp::min(file_size as usize, max_allowed)
            } else {
                256
            };

            let size = request.hex_dump_size.unwrap_or(default_size);
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
        if request.binary_info.unwrap_or(false) || all {
            if let Ok(binary_info) = parse_binary(&path) {
                result.binary_info = Some(binary_info);
            }
        }

        // Signatures
        if request.signatures.unwrap_or(false) || all {
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
        if request.symbols.unwrap_or(false) || all {
            if let Ok(symbols) = analyze_symbols(&path) {
                result.symbols = Some(symbols);
            }
        }

        // Control flow
        if request.control_flow.unwrap_or(false) || all {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    result.control_flow = Some(control_flow);
                }
            }
        }

        // Vulnerabilities
        if request.vulnerabilities.unwrap_or(false) || all {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(vulns) = analyze_vulnerabilities(&path, &symbols, &control_flow) {
                        result.vulnerabilities = Some(vulns);
                    }
                }
            }
        }

        // Code quality
        if request.code_quality.unwrap_or(false) || all {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(quality) = analyze_code_quality(&path, &symbols, &control_flow) {
                        result.code_quality = Some(quality);
                    }
                }
            }
        }

        // Dependencies
        if request.dependencies.unwrap_or(false) || all {
            if let Ok(symbols) = analyze_symbols(&path) {
                // Use cached strings if available, otherwise extract with min length 4
                if let Ok(deps) = analyze_dependencies(&path, &symbols, cached_strings.as_ref()) {
                    result.dependencies = Some(deps);
                }
            }
        }

        // Entropy
        if request.entropy.unwrap_or(false) || all {
            if let Ok(entropy) = analyze_entropy(&path) {
                result.entropy = Some(entropy);
            }
        }

        // Disassembly
        if request.disassembly.unwrap_or(false) || all {
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(disassembly) = disassemble_binary(&path, &symbols) {
                    result.disassembly = Some(disassembly);
                }
            }
        }

        // Threats
        if request.threats.unwrap_or(false) || all {
            if let Ok(threats) = analyze_threats(&path) {
                result.threats = Some(threats);
            }
        }

        // Behavioral
        if request.behavioral.unwrap_or(false) || all {
            let symbols = analyze_symbols(&path).ok();
            let disassembly = if let Some(ref syms) = symbols {
                disassemble_binary(&path, syms).ok()
            } else {
                None
            };

            if let Ok(behavioral) = analyze_behavior(
                &path,
                cached_strings.as_ref(),
                symbols.as_ref(),
                disassembly.as_ref(),
            ) {
                result.behavioral = Some(behavioral);
            }
        }

        // YARA indicators
        if request.yara_indicators.unwrap_or(false) || all {
            let file_metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            let file_size = file_metadata.len();

            // Get hashes if not already calculated
            let hashes = match &result.hashes {
                Some(h) => h.clone(),
                None => {
                    let h = calculate_all_hashes(&path)
                        .await
                        .map_err(|e| e.to_string())?;
                    if result.hashes.is_none() {
                        result.hashes = Some(h.clone());
                    }
                    h
                }
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

            // Extract unique strings (use cached if available, otherwise extract with min length 8)
            let strings = if let Some(ref cached) = cached_strings {
                cached
            } else {
                // Fallback: extract strings with min length 8 if not cached
                cached_strings = Some(extract_strings(&path, 8).map_err(|e| e.to_string())?);
                cached_strings.as_ref().unwrap()
            };
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

    #[tool(
        description = "Scan files with custom YARA rules - supports single files or directories with recursive scanning"
    )]
    pub async fn yara_scan_file(
        &self,
        #[tool(aggr)] request: YaraScanRequest,
    ) -> Result<Json<YaraScanResult>, String> {
        use crate::threat_detection::scan_with_custom_rule;
        use std::time::Instant;

        let start_time = Instant::now();
        let path = PathBuf::from(&request.path);

        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.path));
        }

        let recursive = request.recursive.unwrap_or(true);
        let max_file_size = request.max_file_size.unwrap_or(100 * 1024 * 1024); // 100MB default
        let detailed_matches = request.detailed_matches.unwrap_or(true);

        // Scan files
        let scan_result = scan_with_custom_rule(
            &path,
            &request.yara_rule,
            recursive,
            max_file_size,
            detailed_matches,
        )
        .await
        .map_err(|e| e.to_string())?;

        let duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(YaraScanResult {
            total_files_scanned: scan_result.total_files_scanned,
            total_matches: scan_result.total_matches,
            scan_duration_ms: duration_ms,
            matches: scan_result.matches,
            errors: scan_result.errors,
        }))
    }

    #[tool(
        description = "Analyze Java archives (JAR/WAR/EAR/APK/AAR) and class files - provides detailed Java/Android specific analysis including manifests, certificates, classes, and security assessment"
    )]
    pub async fn analyze_java_file(
        &self,
        #[tool(aggr)] request: JavaAnalysisRequest,
    ) -> Result<Json<JavaAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Determine if it's a Java archive or class file
        let is_class_file = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase() == "class")
            .unwrap_or(false);

        let analysis_result = if is_class_file {
            analyze_class_file(&path).map_err(|e| e.to_string())?
        } else {
            analyze_java_archive(&path).map_err(|e| e.to_string())?
        };

        Ok(Json(analysis_result))
    }

    #[tool(
        description = "Analyze npm packages for vulnerabilities and malicious code - detects typosquatting, supply chain attacks, malware patterns, and known vulnerabilities. Works with .tgz files or directories containing package.json"
    )]
    pub async fn analyze_npm_package(
        &self,
        #[tool(aggr)] request: NpmAnalysisRequest,
    ) -> Result<Json<NpmPackageAnalysis>, String> {
        let path = PathBuf::from(&request.package_path);

        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.package_path));
        }

        let analysis_result = analyze_npm_package(&path).map_err(|e| e.to_string())?;

        Ok(Json(analysis_result))
    }

    #[tool(
        description = "Analyze Python packages for vulnerabilities and malicious code - detects typosquatting, supply chain attacks, malware patterns, and known vulnerabilities. Works with .whl, .tar.gz, .zip files or directories containing setup.py/pyproject.toml"
    )]
    pub async fn analyze_python_package(
        &self,
        #[tool(aggr)] request: PythonAnalysisRequest,
    ) -> Result<Json<PythonPackageAnalysis>, String> {
        let path = PathBuf::from(&request.package_path);

        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.package_path));
        }

        let analysis_result = analyze_python_package(&path).map_err(|e| e.to_string())?;

        Ok(Json(analysis_result))
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
            instructions: Some("A comprehensive file scanner with analyze_file, llm_analyze_file, yara_scan_file, analyze_java_file, analyze_npm_package, and analyze_python_package tools. The analyze_file tool supports multiple analysis types via flags: metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, behavioral, and yara_indicators. The yara_scan_file tool allows scanning files or directories with custom YARA rules. The analyze_java_file tool provides specialized analysis for Java archives (JAR/WAR/EAR/APK/AAR) and class files. The analyze_npm_package tool analyzes npm packages for vulnerabilities, malicious code, typosquatting, and supply chain attacks. The analyze_python_package tool provides similar analysis for Python packages including .whl, .tar.gz, and source distributions.".into()),
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

    #[allow(dead_code)]
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
            all: Some(false),
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
        assert_eq!(deserialized.all, request.all);
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
            all: None,
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
            all: None,
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
            all: None,
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
            all: None,
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
            all: None,
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
            all: None,
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

    #[tokio::test]
    async fn test_analyze_file_all_flag_enables_everything() {
        let test_content = b"Test content for all flag verification";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(true),
            // Set all individual flags to false to verify 'all' overrides them
            metadata: Some(false),
            hashes: Some(false),
            strings: Some(false),
            min_string_length: Some(6),
            hex_dump: Some(false),
            hex_dump_size: Some(32),
            hex_dump_offset: Some(0),
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;

        // Verify that 'all: true' enables all analysis types despite individual flags being false
        assert!(
            response.metadata.is_some(),
            "metadata should be present with all=true"
        );
        assert!(
            response.hashes.is_some(),
            "hashes should be present with all=true"
        );
        assert!(
            response.strings.is_some(),
            "strings should be present with all=true"
        );
        assert!(
            response.hex_dump.is_some(),
            "hex_dump should be present with all=true"
        );
        assert!(
            response.entropy.is_some(),
            "entropy should be present with all=true"
        );
        assert!(
            response.yara_indicators.is_some(),
            "yara_indicators should be present with all=true"
        );
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_false_respects_individual_flags() {
        let test_content = b"Test content for individual flag verification";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(false),
            strings: Some(true),
            min_string_length: Some(4),
            hex_dump: Some(false),
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;

        // Verify only the explicitly enabled analyses are present
        assert!(
            response.metadata.is_some(),
            "metadata should be present when explicitly enabled"
        );
        assert!(
            response.hashes.is_none(),
            "hashes should be absent when explicitly disabled"
        );
        assert!(
            response.strings.is_some(),
            "strings should be present when explicitly enabled"
        );
        assert!(
            response.hex_dump.is_none(),
            "hex_dump should be absent when explicitly disabled"
        );
        assert!(
            response.entropy.is_none(),
            "entropy should be absent when explicitly disabled"
        );
        assert!(
            response.yara_indicators.is_none(),
            "yara_indicators should be absent when explicitly disabled"
        );
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_none_uses_individual_flags() {
        let test_content = b"Test content for default behavior verification";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: None, // Default behavior
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(false),
            min_string_length: None,
            hex_dump: Some(false),
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;

        // Verify behavior matches individual flags when 'all' is None
        assert!(
            response.metadata.is_some(),
            "metadata should be present when enabled"
        );
        assert!(
            response.hashes.is_some(),
            "hashes should be present when enabled"
        );
        assert!(
            response.strings.is_none(),
            "strings should be absent when disabled"
        );
        assert!(
            response.hex_dump.is_none(),
            "hex_dump should be absent when disabled"
        );
        assert!(
            response.entropy.is_none(),
            "entropy should be absent when disabled"
        );
    }

    #[test]
    fn test_file_analysis_request_serialization_with_all_flag() {
        // Test with all flag set to true
        let request_all_true = FileAnalysisRequest {
            file_path: "/test/file.bin".to_string(),
            all: Some(true),
            metadata: Some(false),
            hashes: Some(false),
            strings: Some(false),
            min_string_length: Some(8),
            hex_dump: Some(false),
            hex_dump_size: Some(512),
            hex_dump_offset: Some(0),
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
        };

        let json = serde_json::to_string(&request_all_true).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.all, Some(true));
        assert_eq!(deserialized.file_path, request_all_true.file_path);

        // Test with all flag set to false
        let request_all_false = FileAnalysisRequest {
            file_path: "/test/file2.bin".to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(true),
            min_string_length: Some(4),
            hex_dump: Some(true),
            hex_dump_size: Some(256),
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

        let json = serde_json::to_string(&request_all_false).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.all, Some(false));
        assert_eq!(deserialized.metadata, Some(true));
        assert_eq!(deserialized.entropy, Some(true));

        // Test with all flag as None (default)
        let request_all_none = FileAnalysisRequest {
            file_path: "/test/file3.bin".to_string(),
            all: None,
            metadata: Some(true),
            hashes: Some(false),
            strings: Some(true),
            min_string_length: Some(6),
            hex_dump: Some(false),
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
        };

        let json = serde_json::to_string(&request_all_none).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.all, None);
        assert_eq!(deserialized.metadata, Some(true));
        assert_eq!(deserialized.hashes, Some(false));
        assert_eq!(deserialized.strings, Some(true));
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_comprehensive_verification() {
        let test_content = b"Comprehensive test content with various features for all flag testing";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp;

        // Test 1: Verify 'all: true' enables more analyses than individual flags
        let request_all = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(true),
            metadata: None,
            hashes: None,
            strings: None,
            min_string_length: Some(4),
            hex_dump: None,
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

        let result_all = mcp.analyze_file(request_all).await;
        assert!(result_all.is_ok());
        let response_all = result_all.unwrap().0;

        // Test 2: Compare with selective analysis
        let request_selective = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(true),
            strings: None,
            min_string_length: Some(4),
            hex_dump: None,
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

        let result_selective = mcp.analyze_file(request_selective).await;
        assert!(result_selective.is_ok());
        let response_selective = result_selective.unwrap().0;

        // Verify 'all: true' provides more complete analysis
        assert!(response_all.metadata.is_some() && response_selective.metadata.is_some());
        assert!(response_all.hashes.is_some() && response_selective.hashes.is_some());

        // These should be present with 'all: true' but not with selective analysis
        assert!(response_all.strings.is_some());
        assert!(response_selective.strings.is_none());

        assert!(response_all.hex_dump.is_some());
        assert!(response_selective.hex_dump.is_none());

        assert!(response_all.entropy.is_some());
        assert!(response_selective.entropy.is_none());

        assert!(response_all.yara_indicators.is_some());
        assert!(response_selective.yara_indicators.is_none());
    }
}
