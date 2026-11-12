#![allow(
    dead_code,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::only_used_in_recursion,
    clippy::ref_option,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unnecessary_debug_formatting,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::wildcard_enum_match_arm
)]

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
mod mcp_server;
mod mcp_transport;
mod metadata;
mod npm_analysis;
mod npm_vuln_db;
mod ole_vba_analysis;
mod package_scan;
mod pdf_analysis;
mod python_analysis;
mod python_vuln_db;
mod rar_analysis;
mod script_analysis;
mod sevenz_analysis;
mod signature;
mod string_tracker_compat;
mod strings;
pub mod taint_tracking;
mod tar_analysis;
mod threat_detection;
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
use mcp_server::{
    analyze_file_llm, yara_scan_files, LlmFileAnalysisRequest, YaraIndicators, YaraScanRequest,
};
use mcp_transport::McpTransportServer;
use metadata::FileMetadata;
use npm_analysis::analyze_npm_package;
use python_analysis::analyze_python_package;
use threat_detection::analyze_threats;
use vulnerability_detection::analyze_vulnerabilities;

#[derive(Parser, Debug)]
#[command(name = "file-scanner")]
#[command(version)]
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

    #[arg(
        long,
        allow_negative_numbers = true,
        help = "Hex dump offset (0 for header, negative for footer)"
    )]
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

/// Which files the MCP tools may read (all three mcp-* subcommands).
#[derive(clap::Args, Debug)]
struct ScopeArgs {
    /// Directory the tools may read; repeatable. When any is set, every tool path
    /// must resolve (symlinks and `..` included) to a location under one of them.
    /// Without this option the environment variable FILE_SCANNER_ALLOWED_ROOTS
    /// (`:`-separated) is used; with neither, every readable path is allowed.
    #[arg(long = "allow-root", value_name = "DIR")]
    allow_root: Vec<PathBuf>,
    /// Directory for cached results (private, mode 0700). Default: the user's cache
    /// directory; environment variable FILE_SCANNER_CACHE_DIR
    #[arg(long = "cache-dir", value_name = "DIR")]
    cache_dir: Option<PathBuf>,
    /// Turn result caching off: nothing is stored or served from a cache
    #[arg(long = "no-cache")]
    no_cache: bool,
}

/// Network settings of mcp-http and mcp-sse.
#[derive(clap::Args, Debug)]
struct HttpArgs {
    /// Port to listen on (0 picks a free one)
    #[arg(short, long, default_value_t = mcp_transport::http::DEFAULT_PORT)]
    port: u16,
    /// Address to bind. The default accepts local connections only; use 0.0.0.0 for
    /// all interfaces together with --auth-token and --allow-root
    #[arg(long, default_value = mcp_transport::http::DEFAULT_HOST)]
    host: String,
    /// Extra Host header value to accept besides localhost, 127.0.0.1 and ::1
    /// (`name` or `name:port`); repeatable
    #[arg(long = "allowed-host", value_name = "HOST")]
    allowed_host: Vec<String>,
    /// Extra browser Origin to accept besides loopback ones
    /// (`scheme://host[:port|:*]`); repeatable
    #[arg(long = "allowed-origin", value_name = "ORIGIN")]
    allowed_origin: Vec<String>,
    /// Bearer token every request except /health must present
    /// (`Authorization: Bearer <token>`). Prefer the environment variable: command
    /// lines are visible to other users
    #[arg(
        long = "auth-token",
        env = "FILE_SCANNER_AUTH_TOKEN",
        hide_env_values = true,
        value_name = "TOKEN"
    )]
    auth_token: Option<String>,
}

impl HttpArgs {
    fn into_config(self) -> mcp_transport::HttpConfig {
        mcp_transport::HttpConfig {
            host: self.host,
            port: self.port,
            allowed_hosts: self.allowed_host,
            allowed_origins: self.allowed_origin,
            auth_token: self.auth_token,
            ..mcp_transport::HttpConfig::default()
        }
    }
}

/// The server state for the command line: `--allow-root` wins over the environment.
fn mcp_server_for(scope: ScopeArgs) -> McpTransportServer {
    let mut config = mcp_server::StateConfig::from_env();
    if !scope.allow_root.is_empty() {
        config.allow_roots = scope.allow_root;
    }
    if let Some(dir) = scope.cache_dir {
        config.cache_dir = dir;
    }
    config.cache_enabled = !scope.no_cache;
    McpTransportServer::with_config(config)
}

#[derive(Subcommand, Debug)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Run as MCP server with stdio transport
    McpStdio {
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Run as MCP server with Streamable HTTP transport (endpoint /mcp)
    McpHttp {
        #[command(flatten)]
        http: HttpArgs,
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Deprecated alias of mcp-http (the old SSE transport is gone)
    McpSse {
        #[command(flatten)]
        http: HttpArgs,
        #[command(flatten)]
        scope: ScopeArgs,
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
        #[arg(
            short,
            long,
            help = "YARA rule file, directory of .yar/.yara files, or inline rule"
        )]
        rule: String,
        #[arg(short = 'R', long, help = "Recursively scan directories")]
        recursive: bool,
        #[arg(long, help = "Maximum file size to scan in MB", default_value = "100")]
        max_file_size_mb: u64,
        #[arg(long, help = "Show detailed match information")]
        detailed: bool,
        #[arg(long, help = "Most files to examine (default: no limit)")]
        max_files: Option<usize>,
        #[arg(
            long,
            help = "Stop the scan after this many seconds (default: no limit)"
        )]
        timeout: Option<u64>,
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

fn main() -> Result<()> {
    // An explicit runtime instead of `#[tokio::main]`: dropping a runtime waits
    // for running `spawn_blocking` closures, which would keep a stdio server
    // alive for minutes after its client left. Bound that wait.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(run());
    runtime.shutdown_timeout(std::time::Duration::from_millis(100));
    outcome
}

async fn run() -> Result<()> {
    let args = Args::parse();

    // Handle commands
    match args.command {
        Some(Commands::McpStdio { scope }) => {
            return mcp_server_for(scope).run_stdio().await;
        }
        Some(Commands::McpHttp { http, scope }) => {
            return mcp_server_for(scope).run_http(http.into_config()).await;
        }
        Some(Commands::McpSse { http, scope }) => {
            return mcp_server_for(scope).run_sse(http.into_config()).await;
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
            max_files,
            timeout,
        }) => {
            return handle_yara_scan(
                path,
                rule,
                recursive,
                max_file_size_mb,
                detailed,
                (max_files, timeout),
            )
            .await;
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
        anyhow::bail!("File not found: {}", file_path.display());
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
                            .map(|b| format!("{b:02X}"))
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
                    .map_or(0.0, |e| e.overall_entropy),
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
                    .is_some_and(|e| e.overall_entropy > 7.0),
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

async fn handle_llm_analyze(
    file_path: PathBuf,
    token_limit: usize,
    min_string_length: usize,
    max_strings: usize,
    max_imports: usize,
    suggest_yara_rule: bool,
) -> Result<()> {
    let result = analyze_file_llm(LlmFileAnalysisRequest {
        file_path: file_path.to_string_lossy().into_owned(),
        token_limit: Some(token_limit),
        min_string_length: Some(min_string_length),
        max_strings: Some(max_strings),
        max_imports: Some(max_imports),
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: Some(suggest_yara_rule),
    })
    .await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

async fn handle_yara_scan(
    path: PathBuf,
    rule: String,
    recursive: bool,
    max_file_size_mb: u64,
    detailed: bool,
    (max_files, timeout_seconds): (Option<usize>, Option<u64>),
) -> Result<()> {
    // A rule file or directory goes in as `rule_path`, so diagnostics name the
    // file and a directory of rules works; anything else is rule text.
    let rule_path = PathBuf::from(&rule);
    let (yara_rule, rule_path) = if rule_path.exists() {
        (
            String::new(),
            Some(rule_path.to_string_lossy().into_owned()),
        )
    } else {
        (rule, None)
    };
    let max_file_size = max_file_size_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("maximum file size is too large"))?;
    let result = yara_scan_files(YaraScanRequest {
        path: path.to_string_lossy().into_owned(),
        yara_rule,
        rule_path,
        recursive: Some(recursive),
        max_file_size: Some(max_file_size),
        detailed_matches: Some(detailed),
        max_files,
        timeout_seconds,
    })
    .await?;
    println!("{}", serde_json::to_string(&result)?);
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
        .map(str::to_lowercase);

    let result = match extension.as_deref() {
        Some("jar" | "war" | "ear" | "apk" | "aar") => analyze_java_archive(&file_path)?,
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
