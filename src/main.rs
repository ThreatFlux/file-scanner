#![allow(dead_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod archive_analysis;
mod behavioral_analysis;
mod binary_parser;
mod cache;
mod call_graph;
mod code_metrics;
mod control_flow;
mod dependency_analysis;
mod disassembly;
mod entropy_analysis;
mod function_analysis;
mod hash;
mod hexdump;
mod java_analysis;
mod mcp;
mod mcp_server;
mod mcp_transport;
mod metadata;
mod npm_analysis;
mod npm_vuln_db;
mod ole_vba_analysis;
mod pdf_analysis;
mod python_analysis;
mod python_vuln_db;
mod rar_analysis;
pub mod repository_integrity;
mod script_analysis;
mod sevenz_analysis;
mod signature;
mod string_tracker_compat;
mod strings;
pub mod taint_tracking;
mod tar_analysis;
mod threat_detection;
pub mod typosquatting_detection;
mod vulnerability_detection;

use behavioral_analysis::analyze_behavior;
use code_metrics::analyze_code_quality;
use control_flow::analyze_control_flow;
use dependency_analysis::analyze_dependencies;
use disassembly::disassemble_binary;
use entropy_analysis::analyze_entropy;
use function_analysis::analyze_symbols;
use hexdump::{extract_footer_hex, extract_header_hex, generate_hex_dump, HexDumpOptions};
use java_analysis::{analyze_class_file, analyze_java_archive};
use mcp_server::YaraIndicators;
use mcp_transport::McpTransportServer;
use metadata::FileMetadata;
use npm_analysis::analyze_npm_package;
use python_analysis::analyze_python_package;
use threat_detection::analyze_threats;
use vulnerability_detection::analyze_vulnerabilities;

#[derive(Parser, Debug)]
#[command(name = "file-scanner")]
#[command(about = "A native static file scanner that provides comprehensive file metadata", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(help = "Path to the file to scan (used when not in MCP mode)")]
    file_path: Option<PathBuf>,

    #[arg(short, long, help = "Output format (json, yaml, pretty)")]
    format: Option<String>,

    #[arg(short = 'a', long, help = "Enable all analysis options")]
    all: bool,

    #[arg(short, long, help = "Extract strings from file")]
    strings: bool,

    #[arg(long, help = "Minimum string length to extract")]
    min_string_len: Option<usize>,

    #[arg(short, long, help = "Verify digital signatures")]
    verify_signatures: bool,

    #[arg(long, help = "Include hex dump of file header/footer")]
    hex_dump: bool,

    #[arg(long, help = "Bytes to dump from start of file", default_value = "512")]
    hex_dump_size: usize,

    #[arg(long, help = "Hex dump offset (0 for header, negative for footer)")]
    hex_dump_offset: Option<i64>,

    #[arg(long, help = "Analyze function symbols and symbol tables")]
    symbols: bool,

    #[arg(long, help = "Analyze control flow graphs and patterns")]
    control_flow: bool,

    #[arg(long, help = "Detect security vulnerabilities")]
    vulnerabilities: bool,

    #[arg(long, help = "Analyze code quality metrics")]
    code_quality: bool,

    #[arg(long, help = "Analyze library dependencies and imports")]
    dependencies: bool,

    #[arg(long, help = "Analyze entropy patterns and packing detection")]
    entropy: bool,

    #[arg(long, help = "Disassemble binary code")]
    disassembly: bool,

    #[arg(long, help = "Detect threats and malware patterns")]
    threats: bool,

    #[arg(long, help = "Analyze behavioral patterns")]
    behavioral: bool,

    #[arg(long, help = "Extract YARA rule indicators")]
    yara_indicators: bool,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Run as MCP server with stdio transport
    McpStdio,
    /// Run as MCP server with HTTP transport
    McpHttp {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    /// Run as MCP server with SSE transport
    McpSse {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    /// Analyze file with LLM-optimized output
    LlmAnalyze {
        #[arg(help = "Path to the file to analyze")]
        file_path: PathBuf,
        #[arg(long, help = "Token limit for response", default_value = "25000")]
        token_limit: usize,
        #[arg(long, help = "Minimum string length", default_value = "6")]
        min_string_length: usize,
        #[arg(long, help = "Maximum strings to return", default_value = "50")]
        max_strings: usize,
        #[arg(long, help = "Maximum imports to return", default_value = "30")]
        max_imports: usize,
        #[arg(long, help = "Generate YARA rule suggestion")]
        suggest_yara_rule: bool,
    },
    /// Scan files with YARA rules
    YaraScan {
        #[arg(help = "Path to file or directory to scan")]
        path: PathBuf,
        #[arg(short, long, help = "YARA rule file or inline rule")]
        rule: String,
        #[arg(short = 'R', long, help = "Recursively scan directories")]
        recursive: bool,
        #[arg(long, help = "Maximum file size to scan in MB", default_value = "100")]
        max_file_size_mb: u64,
        #[arg(long, help = "Show detailed match information")]
        detailed: bool,
    },
    /// Analyze NPM package for security issues
    AnalyzeNpm {
        #[arg(help = "Path to NPM package or package.json")]
        package_path: PathBuf,
    },
    /// Analyze Python package for security issues
    AnalyzePython {
        #[arg(help = "Path to Python package (.whl, .tar.gz, .zip)")]
        package_path: PathBuf,
    },
    /// Analyze Java/Android file
    AnalyzeJava {
        #[arg(help = "Path to JAR/WAR/EAR/APK/AAR or class file")]
        file_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle commands
    match args.command {
        Some(Commands::McpStdio) => {
            let server = McpTransportServer::new();
            return server.run_stdio().await;
        }
        Some(Commands::McpHttp { port }) => {
            let server = McpTransportServer::new();
            return server.run_http(port).await;
        }
        Some(Commands::McpSse { port }) => {
            let server = McpTransportServer::new();
            return server.run_sse(port).await;
        }
        Some(Commands::LlmAnalyze {
            file_path,
            token_limit,
            min_string_length,
            max_strings,
            max_imports,
            suggest_yara_rule,
        }) => {
            return handle_llm_analyze(
                file_path,
                token_limit,
                min_string_length,
                max_strings,
                max_imports,
                suggest_yara_rule,
            )
            .await;
        }
        Some(Commands::YaraScan {
            path,
            rule,
            recursive,
            max_file_size_mb,
            detailed,
        }) => {
            return handle_yara_scan(path, rule, recursive, max_file_size_mb, detailed).await;
        }
        Some(Commands::AnalyzeNpm { package_path }) => {
            return handle_npm_analysis(package_path).await;
        }
        Some(Commands::AnalyzePython { package_path }) => {
            return handle_python_analysis(package_path).await;
        }
        Some(Commands::AnalyzeJava { file_path }) => {
            return handle_java_analysis(file_path).await;
        }
        None => {
            // Continue with regular file scanning
        }
    }

    // Regular file scanning mode
    let file_path = args
        .file_path
        .ok_or_else(|| anyhow::anyhow!("File path is required for scanning mode"))?;

    if !file_path.exists() {
        anyhow::bail!("File not found: {:?}", file_path);
    }

    let mut metadata = FileMetadata::new(&file_path)?;

    metadata.extract_basic_info()?;

    metadata.calculate_hashes().await?;

    if let Ok(binary_info) = binary_parser::parse_binary(&file_path) {
        metadata.binary_info = Some(binary_info);
    }

    // Handle --all flag
    let strings_enabled = args.all || args.strings;
    let signatures_enabled = args.all || args.verify_signatures;
    let hex_dump_enabled = args.all || args.hex_dump;
    let symbols_enabled = args.all || args.symbols;
    let control_flow_enabled = args.all || args.control_flow;
    let vulnerabilities_enabled = args.all || args.vulnerabilities;
    let code_quality_enabled = args.all || args.code_quality;
    let dependencies_enabled = args.all || args.dependencies;
    let entropy_enabled = args.all || args.entropy;
    let disassembly_enabled = args.all || args.disassembly;
    let threats_enabled = args.all || args.threats;
    let behavioral_enabled = args.all || args.behavioral;
    let yara_indicators_enabled = args.all || args.yara_indicators;

    if strings_enabled {
        let min_len = args.min_string_len.unwrap_or(4);
        metadata.extracted_strings = Some(strings::extract_strings(&file_path, min_len)?);
    }

    if signatures_enabled {
        metadata.signature_info = signature::verify_signature(&file_path).ok();
    }

    if hex_dump_enabled {
        let hex_size = if args.all && args.hex_dump_size == 512 {
            // When --all is used, show more hex dump
            std::cmp::min(metadata.size as usize, 100 * 1024 * 1024) // Up to 100MB
        } else {
            args.hex_dump_size
        };

        let hex_result = if let Some(offset) = args.hex_dump_offset {
            if offset < 0 {
                extract_footer_hex(&file_path, hex_size)
            } else {
                let options = HexDumpOptions {
                    offset: offset as u64,
                    length: Some(hex_size),
                    bytes_per_line: 16,
                    max_lines: None,
                };
                generate_hex_dump(&file_path, options)
            }
        } else {
            extract_header_hex(&file_path, hex_size)
        };

        metadata.hex_dump = hex_result.ok();
    }

    // Add new analysis features
    if symbols_enabled {
        if let Ok(symbols) = analyze_symbols(&file_path) {
            metadata.symbol_analysis = Some(symbols);
        }
    }

    if control_flow_enabled {
        if let Ok(symbols) = analyze_symbols(&file_path) {
            if let Ok(control_flow) = analyze_control_flow(&file_path, &symbols) {
                metadata.control_flow_analysis = Some(control_flow);
            }
        }
    }

    if vulnerabilities_enabled {
        if let Ok(symbols) = analyze_symbols(&file_path) {
            if let Ok(control_flow) = analyze_control_flow(&file_path, &symbols) {
                if let Ok(vulnerabilities) =
                    analyze_vulnerabilities(&file_path, &symbols, &control_flow)
                {
                    metadata.vulnerability_analysis = Some(vulnerabilities);
                }
            }
        }
    }

    if code_quality_enabled {
        if let Ok(symbols) = analyze_symbols(&file_path) {
            if let Ok(control_flow) = analyze_control_flow(&file_path, &symbols) {
                if let Ok(code_quality) = analyze_code_quality(&file_path, &symbols, &control_flow)
                {
                    metadata.code_quality_analysis = Some(code_quality);
                }
            }
        }
    }

    if dependencies_enabled {
        if let Ok(symbols) = analyze_symbols(&file_path) {
            let strings = metadata.extracted_strings.as_ref();
            if let Ok(dependencies) = analyze_dependencies(&file_path, &symbols, strings) {
                metadata.dependency_analysis = Some(dependencies);
            }
        }
    }

    if entropy_enabled {
        if let Ok(entropy) = analyze_entropy(&file_path) {
            metadata.entropy_analysis = Some(entropy);
        }
    }

    if disassembly_enabled {
        if let Ok(symbols) = analyze_symbols(&file_path) {
            if let Ok(disassembly) = disassemble_binary(&file_path, &symbols) {
                metadata.disassembly = Some(disassembly);
            }
        }
    }

    if threats_enabled {
        if let Ok(threats) = analyze_threats(&file_path) {
            metadata.threat_analysis = Some(threats);
        }
    }

    if behavioral_enabled {
        let symbols = analyze_symbols(&file_path).ok();
        let disassembly = if let Some(ref syms) = symbols {
            disassemble_binary(&file_path, syms).ok()
        } else {
            None
        };
        let strings = metadata.extracted_strings.as_ref();

        if let Ok(behavioral) =
            analyze_behavior(&file_path, strings, symbols.as_ref(), disassembly.as_ref())
        {
            metadata.behavioral_analysis = Some(behavioral);
        }
    }

    if yara_indicators_enabled {
        // Extract YARA indicators
        if let (Some(hashes), Some(binary_info)) = (&metadata.hashes, &metadata.binary_info) {
            // Get magic bytes from hex dump or file header
            let magic_bytes = if let Some(ref hex_dump) = metadata.hex_dump {
                hex_dump
                    .lines
                    .first()
                    .map(|line| {
                        line.raw_bytes
                            .iter()
                            .take(16)
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let indicators = YaraIndicators {
                sha256: hashes.sha256.clone(),
                md5: hashes.md5.clone(),
                file_size: metadata.size,
                magic_bytes,
                entropy: metadata
                    .entropy_analysis
                    .as_ref()
                    .map(|e| e.overall_entropy)
                    .unwrap_or(0.0),
                unique_strings: metadata
                    .extracted_strings
                    .as_ref()
                    .map(|s| {
                        s.interesting_strings
                            .iter()
                            .take(20)
                            .map(|is| is.value.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
                imports: binary_info.imports.iter().take(20).cloned().collect(),
                sections: binary_info
                    .sections
                    .iter()
                    .map(|s| s.name.clone())
                    .collect(),
                is_packed: metadata
                    .entropy_analysis
                    .as_ref()
                    .map(|e| e.overall_entropy > 7.0) // High entropy indicates packing
                    .unwrap_or(false),
            };
            metadata.yara_indicators = Some(indicators);
        }
    }

    match args.format.as_deref() {
        Some("json") => {
            println!("{}", serde_json::to_string(&metadata)?);
        }
        Some("yaml") => {
            println!("{}", serde_yaml::to_string(&metadata)?);
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
    }

    Ok(())
}

// TODO: Temporarily disabled during refactoring
async fn handle_llm_analyze(
    _file_path: PathBuf,
    _token_limit: usize,
    _min_string_length: usize,
    _max_strings: usize,
    _max_imports: usize,
    _suggest_yara_rule: bool,
) -> Result<()> {
    println!("LLM analysis temporarily disabled during refactoring");
    Ok(())
}

// TODO: Temporarily disabled during refactoring
async fn handle_yara_scan(
    _path: PathBuf,
    _rule: String,
    _recursive: bool,
    _max_file_size_mb: u64,
    _detailed: bool,
) -> Result<()> {
    println!("YARA scanning temporarily disabled during refactoring");
    Ok(())
}

async fn handle_npm_analysis(package_path: PathBuf) -> Result<()> {
    let result = analyze_npm_package(&package_path)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn handle_python_analysis(package_path: PathBuf) -> Result<()> {
    let result = analyze_python_package(&package_path)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn handle_java_analysis(file_path: PathBuf) -> Result<()> {
    // Check if it's a JAR/WAR/EAR or a class file
    let extension = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase());

    let result = match extension.as_deref() {
        Some("jar") | Some("war") | Some("ear") | Some("apk") | Some("aar") => {
            analyze_java_archive(&file_path)?
        }
        Some("class") => analyze_class_file(&file_path)?,
        _ => {
            // Try to detect based on content
            if let Ok(result) = analyze_java_archive(&file_path) {
                result
            } else {
                analyze_class_file(&file_path)?
            }
        }
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
