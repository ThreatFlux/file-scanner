use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Script analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    pub script_type: ScriptType,
    pub metadata: ScriptMetadata,
    pub security_analysis: ScriptSecurityAnalysis,
    pub suspicious_indicators: SuspiciousScriptIndicators,
    pub commands: Vec<String>,
    pub functions: Vec<String>,
    pub imports: Vec<String>,
    pub obfuscation_indicators: ObfuscationIndicators,
}

/// Types of scripts supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScriptType {
    PowerShell,
    Python,
    JavaScript,
    Batch,
    Shell,
    VBScript,
    Unknown,
}

/// Script metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMetadata {
    pub language: String,
    pub line_count: usize,
    pub character_count: usize,
    pub encoding: String,
    pub has_shebang: bool,
    pub interpreter_path: Option<String>,
    pub language_version: Option<String>,
}

/// Security analysis for scripts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSecurityAnalysis {
    pub overall_risk: RiskLevel,
    pub malicious_patterns: Vec<String>,
    pub network_activity: Vec<String>,
    pub file_operations: Vec<String>,
    pub registry_operations: Vec<String>,
    pub process_operations: Vec<String>,
    pub privilege_escalation: Vec<String>,
    pub data_exfiltration: Vec<String>,
}

/// Risk levels for scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Suspicious indicators in scripts
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuspiciousScriptIndicators {
    pub risk_score: u32,
    pub has_suspicious_functions: bool,
    pub has_network_access: bool,
    pub has_file_manipulation: bool,
    pub has_registry_access: bool,
    pub has_process_injection: bool,
    pub has_encryption: bool,
    pub has_base64_encoding: bool,
    pub suspicious_patterns: Vec<String>,
}

/// Obfuscation detection indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationIndicators {
    pub is_obfuscated: bool,
    pub obfuscation_techniques: Vec<String>,
    pub entropy_score: f64,
    pub string_concatenation_count: usize,
    pub variable_substitution_count: usize,
    pub base64_strings: Vec<String>,
}

impl Default for ObfuscationIndicators {
    fn default() -> Self {
        Self {
            is_obfuscated: false,
            obfuscation_techniques: Vec::new(),
            entropy_score: 0.0,
            string_concatenation_count: 0,
            variable_substitution_count: 0,
            base64_strings: Vec::new(),
        }
    }
}

/// Analyze a `PowerShell` script file.
///
/// Refuses input that is recognizably another language (a Python or shell script is not
/// labelled PowerShell): the error names the language found and points to `analyze_script`.
pub fn analyze_powershell<P: AsRef<Path>>(path: P) -> Result<ScriptAnalysis> {
    let path = path.as_ref();
    let content = fs::read_to_string(path).context("Failed to read PowerShell script")?;

    match detect_script_type(path, &content) {
        (ScriptType::PowerShell, _) => {}
        (ScriptType::Unknown, _) => {
            if !is_powershell_script(path) {
                anyhow::bail!(
                    "{} does not look like PowerShell (no .ps1/.psm1/.psd1 extension and no \
                     PowerShell syntax). Use analyze_script, which detects the language.",
                    path.display()
                );
            }
        }
        (other, _) => anyhow::bail!(
            "{} is a {} script, not PowerShell. Use analyze_script, which detects the language.",
            path.display(),
            language_name(&other)
        ),
    }
    Ok(powershell_summary(&content))
}

/// The `PowerShell` summary of script text already read.
fn powershell_summary(content: &str) -> ScriptAnalysis {
    let metadata = analyze_powershell_metadata(content);
    let (commands, functions, imports) = extract_powershell_elements(content);
    let suspicious_indicators = analyze_powershell_security(content);
    let obfuscation = detect_powershell_obfuscation(content);

    let security_analysis = ScriptSecurityAnalysis {
        overall_risk: determine_script_risk(&suspicious_indicators),
        malicious_patterns: extract_malicious_patterns(content, ScriptType::PowerShell),
        network_activity: extract_network_patterns(content, ScriptType::PowerShell),
        file_operations: extract_file_operations(content, ScriptType::PowerShell),
        registry_operations: extract_registry_operations(content),
        process_operations: extract_process_operations(content, ScriptType::PowerShell),
        privilege_escalation: extract_privilege_escalation(content, ScriptType::PowerShell),
        data_exfiltration: extract_data_exfiltration(content, ScriptType::PowerShell),
    };

    ScriptAnalysis {
        script_type: ScriptType::PowerShell,
        metadata,
        security_analysis,
        suspicious_indicators,
        commands,
        functions,
        imports,
        obfuscation_indicators: obfuscation,
    }
}

/// Analyze `PowerShell` script metadata
fn analyze_powershell_metadata(content: &str) -> ScriptMetadata {
    let lines: Vec<&str> = content.lines().collect();
    let line_count = if content.is_empty() { 0 } else { lines.len() };
    let character_count = content.len();

    // Check for shebang (uncommon in PowerShell but possible)
    let has_shebang = content.starts_with("#!");
    let interpreter_path = if has_shebang {
        lines
            .first()
            .map(|line| line.trim_start_matches("#!").trim().to_string())
    } else {
        None
    };

    // Try to detect PowerShell version from comments or requires statements
    let language_version = detect_powershell_version(content);

    ScriptMetadata {
        language: "PowerShell".to_string(),
        line_count,
        character_count,
        encoding: "UTF-8".to_string(), // Assume UTF-8 for now
        has_shebang,
        interpreter_path,
        language_version,
    }
}

/// Detect `PowerShell` version from script content
fn detect_powershell_version(content: &str) -> Option<String> {
    // Look for #Requires statements
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("#Requires") && line.contains("-Version") {
            if let Some(version_part) = line.split("-Version").nth(1) {
                let version = version_part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !version.is_empty() {
                    return Some(version);
                }
            }
        }
    }
    None
}

/// Extract `PowerShell` commands, functions, and imports
fn extract_powershell_elements(content: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut commands = Vec::new();
    let mut functions = Vec::new();
    let mut imports = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') {
            continue;
        }

        // Extract function definitions (case insensitive)
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("function ") {
            if let Some(func_name) = extract_function_name(line) {
                functions.push(func_name);
            }
        }

        // Extract imports/modules
        if line.starts_with("Import-Module") || line.starts_with("using") {
            imports.push(line.to_string());
        }

        // Extract common PowerShell commands
        let powershell_commands = [
            "Invoke-Expression",
            "Invoke-Command",
            "Invoke-RestMethod",
            "Invoke-WebRequest",
            "Start-Process",
            "Get-Process",
            "Stop-Process",
            "Get-Service",
            "Start-Service",
            "Get-WmiObject",
            "Get-CimInstance",
            "New-Object",
            "Add-Type",
            "Set-ExecutionPolicy",
            "Get-Content",
            "Set-Content",
            "Out-File",
            "Copy-Item",
            "Move-Item",
            "Remove-Item",
            "Get-ChildItem",
            "Test-Path",
            "New-Item",
            "Get-Location",
            "Set-Location",
            "Get-Registry",
            "Set-Registry",
            "New-Registry",
            "Remove-Registry",
        ];

        for &cmd in &powershell_commands {
            if line.contains(cmd) {
                commands.push(cmd.to_string());
            }
        }
    }

    // Remove duplicates and sort
    commands.sort();
    commands.dedup();
    functions.sort();
    functions.dedup();
    imports.sort();
    imports.dedup();

    (commands, functions, imports)
}

/// Extract function name from `PowerShell` function definition
fn extract_function_name(line: &str) -> Option<String> {
    let line = line.trim();
    let line_lower = line.to_lowercase();

    // Find function keyword case-insensitively
    if let Some(function_pos) = line_lower.find("function ") {
        let after_function = &line[function_pos + 9..]; // "function " is 9 chars
        if let Some(end) = after_function.find(|c: char| c.is_whitespace() || c == '(' || c == '{')
        {
            Some(after_function[..end].trim().to_string())
        } else {
            Some(after_function.trim().to_string())
        }
    } else {
        None
    }
}

/// Analyze `PowerShell` security indicators
fn analyze_powershell_security(content: &str) -> SuspiciousScriptIndicators {
    let mut indicators = SuspiciousScriptIndicators::default();

    // Suspicious PowerShell functions
    let suspicious_functions = [
        "Invoke-Expression",
        "Invoke-Command",
        "DownloadString",
        "DownloadFile",
        "EncodedCommand",
        "WindowsIdentity",
        "Impersonate",
        "CreateProcess",
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "OpenProcess",
        "ReflectivePEInjection",
        "Invoke-Shellcode",
        "Invoke-DllInjection",
        "Add-Type",
        "System.Reflection.Assembly",
        "Load",
        "LoadFrom",
        "FromBase64String",
        "Convert",
        "System.Text.Encoding",
    ];

    // Network-related patterns
    let network_patterns = [
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "Net.WebClient",
        "DownloadString",
        "DownloadData",
        "System.Net.Sockets",
        "TcpClient",
        "UdpClient",
        "HttpWebRequest",
        "WebRequest",
        "FtpWebRequest",
    ];

    // File manipulation patterns
    let file_patterns = [
        "Get-Content",
        "Set-Content",
        "Out-File",
        "Add-Content",
        "Copy-Item",
        "Move-Item",
        "Remove-Item",
        "New-Item",
        "Rename-Item",
        "Clear-Content",
        "System.IO.File",
        "System.IO.Directory",
        "WriteAllText",
        "ReadAllText",
    ];

    // Registry access patterns
    let registry_patterns = [
        "Get-ItemProperty",
        "Set-ItemProperty",
        "New-ItemProperty",
        "Remove-ItemProperty",
        "HKLM:",
        "HKCU:",
        "HKCR:",
        "Registry::",
        "Microsoft.Win32.Registry",
    ];

    // Process manipulation patterns
    let process_patterns = [
        "Start-Process",
        "Get-Process",
        "Stop-Process",
        "Wait-Process",
        "System.Diagnostics.Process",
        "ProcessStartInfo",
        "CreateProcess",
    ];

    let content_lower = content.to_lowercase();

    // Check for suspicious functions
    for &pattern in &suspicious_functions {
        if content_lower.contains(&pattern.to_lowercase()) {
            indicators.has_suspicious_functions = true;
            indicators.suspicious_patterns.push(pattern.to_string());
            indicators.risk_score += 15;
        }
    }

    // Check for network activity
    for &pattern in &network_patterns {
        if content_lower.contains(&pattern.to_lowercase()) {
            indicators.has_network_access = true;
            indicators.risk_score += 10;
        }
    }

    // Check for file manipulation
    for &pattern in &file_patterns {
        if content_lower.contains(&pattern.to_lowercase()) {
            indicators.has_file_manipulation = true;
            indicators.risk_score += 5;
        }
    }

    // Check for registry access
    for &pattern in &registry_patterns {
        if content_lower.contains(&pattern.to_lowercase()) {
            indicators.has_registry_access = true;
            indicators.risk_score += 10;
        }
    }

    // Check for process manipulation
    for &pattern in &process_patterns {
        if content_lower.contains(&pattern.to_lowercase()) {
            indicators.has_process_injection = true;
            indicators.risk_score += 12;
        }
    }

    // Check for encoding/encryption
    if content_lower.contains("base64") || content_lower.contains("frombase64string") {
        indicators.has_base64_encoding = true;
        indicators.risk_score += 8;
    }

    if content_lower.contains("encrypt")
        || content_lower.contains("decrypt")
        || content_lower.contains("cipher")
        || content_lower.contains("aes")
    {
        indicators.has_encryption = true;
        indicators.risk_score += 12;
    }

    indicators
}

/// Detect `PowerShell` obfuscation techniques
fn detect_powershell_obfuscation(content: &str) -> ObfuscationIndicators {
    let mut indicators = ObfuscationIndicators {
        entropy_score: calculate_entropy(content),
        ..Default::default()
    };

    // Detect obfuscation techniques
    let mut techniques = Vec::new();

    // String concatenation obfuscation - look for various patterns
    let concat_count = content.matches('+').count(); // Count all + signs
    indicators.string_concatenation_count = concat_count;
    if concat_count > 5 {
        techniques.push("String concatenation".to_string());
    }

    // Variable substitution
    let var_subst_count = content.matches("${").count();
    indicators.variable_substitution_count = var_subst_count;
    if var_subst_count > 5 {
        techniques.push("Variable substitution".to_string());
    }

    // Base64 strings detection - look for quoted base64 strings
    if let Ok(base64_regex) = regex::Regex::new(r#"["'][A-Za-z0-9+/]{16,}={0,2}["']"#) {
        for capture in base64_regex.find_iter(content) {
            indicators.base64_strings.push(capture.as_str().to_string());
        }
    }
    // Also look for FromBase64String patterns
    if content.contains("FromBase64String") || content.contains("base64") {
        indicators
            .base64_strings
            .push("Base64 pattern detected".to_string());
    }
    if !indicators.base64_strings.is_empty() {
        techniques.push("Base64 encoding".to_string());
    }

    // Character replacement obfuscation
    if content.contains("-replace") && content.matches("-replace").count() > 3 {
        techniques.push("Character replacement".to_string());
    }

    // PowerShell-specific obfuscation
    if content.contains("-join") || content.contains("[char]") {
        techniques.push("Character array obfuscation".to_string());
    }

    // Determine if obfuscated
    indicators.is_obfuscated = !techniques.is_empty() || indicators.entropy_score > 4.5;
    indicators.obfuscation_techniques = techniques;

    indicators
}

/// Calculate entropy of content
fn calculate_entropy(content: &str) -> f64 {
    let mut freq = std::collections::HashMap::new();
    let len = content.len() as f64;

    for c in content.chars() {
        *freq.entry(c).or_insert(0.0) += 1.0;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count / len;
        entropy = p.mul_add(-p.log2(), entropy);
    }

    entropy
}

/// Extract malicious patterns from script content
fn extract_malicious_patterns(content: &str, script_type: ScriptType) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    if script_type == ScriptType::PowerShell {
        let malicious_patterns = [
            "invoke-expression",
            "downloadstring",
            "encodedcommand",
            "bypass",
            "unrestricted",
            "hidden",
            "windowstyle",
            "noprofile",
            "noninteractive",
            "reflectivepeinjection",
            "invoke-shellcode",
            "invoke-mimikatz",
        ];

        for &pattern in &malicious_patterns {
            if content_lower.contains(pattern) {
                patterns.push(pattern.to_string());
            }
        }
    } else {
        // Add patterns for other script types later
    }

    patterns
}

/// Extract network activity patterns
fn extract_network_patterns(content: &str, script_type: ScriptType) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    if script_type == ScriptType::PowerShell {
        let network_patterns = [
            "invoke-webrequest",
            "invoke-restmethod",
            "net.webclient",
            "downloadstring",
            "downloadfile",
            "system.net.sockets",
            "tcpclient",
            "udpclient",
            "httpwebrequest",
        ];

        for &pattern in &network_patterns {
            if content_lower.contains(pattern) {
                patterns.push(pattern.to_string());
            }
        }
    }

    patterns
}

/// Extract file operation patterns
fn extract_file_operations(content: &str, script_type: ScriptType) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    if script_type == ScriptType::PowerShell {
        let file_patterns = [
            "get-content",
            "set-content",
            "out-file",
            "copy-item",
            "move-item",
            "remove-item",
            "new-item",
            "system.io.file",
        ];

        for &pattern in &file_patterns {
            if content_lower.contains(pattern) {
                patterns.push(pattern.to_string());
            }
        }
    }

    patterns
}

/// Extract registry operation patterns
fn extract_registry_operations(content: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    let registry_patterns = [
        "get-itemproperty",
        "set-itemproperty",
        "new-itemproperty",
        "remove-itemproperty",
        "hklm:",
        "hkcu:",
        "registry::",
    ];

    for &pattern in &registry_patterns {
        if content_lower.contains(pattern) {
            patterns.push(pattern.to_string());
        }
    }

    patterns
}

/// Extract process operation patterns
fn extract_process_operations(content: &str, script_type: ScriptType) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    if script_type == ScriptType::PowerShell {
        let process_patterns = [
            "start-process",
            "get-process",
            "stop-process",
            "system.diagnostics.process",
            "createprocess",
        ];

        for &pattern in &process_patterns {
            if content_lower.contains(pattern) {
                patterns.push(pattern.to_string());
            }
        }
    }

    patterns
}

/// Extract privilege escalation patterns
fn extract_privilege_escalation(content: &str, script_type: ScriptType) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    if script_type == ScriptType::PowerShell {
        let privilege_patterns = [
            "runas",
            "elevation",
            "administrator",
            "uac",
            "bypass",
            "windowsidentity",
            "impersonate",
            "token",
            "privilege",
        ];

        for &pattern in &privilege_patterns {
            if content_lower.contains(pattern) {
                patterns.push(pattern.to_string());
            }
        }
    }

    patterns
}

/// Extract data exfiltration patterns
fn extract_data_exfiltration(content: &str, script_type: ScriptType) -> Vec<String> {
    let mut patterns = Vec::new();
    let content_lower = content.to_lowercase();

    if script_type == ScriptType::PowerShell {
        let exfil_patterns = [
            "invoke-webrequest",
            "post",
            "upload",
            "ftp",
            "email",
            "smtp",
            "sendmail",
            "compress",
            "archive",
            "zip",
        ];

        for &pattern in &exfil_patterns {
            if content_lower.contains(pattern) {
                patterns.push(pattern.to_string());
            }
        }
    }

    patterns
}

/// Determine overall risk level based on indicators
const fn determine_script_risk(indicators: &SuspiciousScriptIndicators) -> RiskLevel {
    if indicators.risk_score > 80 {
        RiskLevel::Critical
    } else if indicators.risk_score > 50 {
        RiskLevel::High
    } else if indicators.risk_score > 20 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Check if a file is a `PowerShell` script
pub fn is_powershell_script<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    // Check file extension
    if let Some(ext) = path.extension() {
        if let Some(ext_str) = ext.to_str() {
            return matches!(ext_str.to_lowercase().as_str(), "ps1" | "psm1" | "psd1");
        }
    }

    // Check file content for PowerShell indicators
    if let Ok(content) = fs::read_to_string(path) {
        let first_lines = content
            .lines()
            .take(10)
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();

        return first_lines.contains("powershell")
            || first_lines.contains("param(")
            || first_lines.contains("function ")
            || first_lines.contains("$_")
            || first_lines.contains("get-")
            || first_lines.contains("set-")
            || first_lines.contains("invoke-");
    }

    false
}

// ---------------------------------------------------------------------------
// analyze_script: language detection plus per-language pattern tables
// ---------------------------------------------------------------------------

/// Most bytes of a script that are read and scanned.
pub const MAX_SCRIPT_BYTES: usize = 8 * 1024 * 1024;
/// Most findings kept in a report (the true count is in `findings_total`).
pub const MAX_SCRIPT_FINDINGS: usize = 2000;
/// Longest `matched` text kept for one finding, in characters.
const MAX_MATCH_CHARS: usize = 160;

/// One pattern hit: where it is and the text that matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptFinding {
    /// `download_execute`, `dynamic_execution`, `encoded_payload`, `persistence`,
    /// `credential_access`, `defense_evasion`, `remote_shell`, `command_execution`,
    /// `obfuscation` or `privilege_escalation`.
    pub category: String,
    /// Short rule name, stable across versions.
    pub rule: String,
    pub severity: RiskLevel,
    /// 1-based line number.
    pub line: usize,
    /// The text the pattern matched (cut to 160 characters).
    pub matched: String,
    pub description: String,
}

/// What `analyze_script` returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptReport {
    pub script_type: ScriptType,
    pub language: String,
    /// How the language was decided: `override`, `shebang`, `extension` or `content`.
    pub detected_by: String,
    pub bytes_read: usize,
    /// True when the file is bigger than [`MAX_SCRIPT_BYTES`] and the rest was not scanned.
    pub truncated_input: bool,
    pub line_count: usize,
    pub risk_score: u32,
    pub overall_risk: RiskLevel,
    pub category_counts: std::collections::BTreeMap<String, usize>,
    /// Number of pattern hits found (before the cap on `findings`).
    pub findings_total: usize,
    pub findings: Vec<ScriptFinding>,
    /// The PowerShell-specific summary (commands, functions, obfuscation), PowerShell only.
    pub powershell: Option<ScriptAnalysis>,
}

#[derive(Clone, Copy)]
enum Sev {
    Low,
    Med,
    High,
    Crit,
}

impl Sev {
    const fn level(self) -> RiskLevel {
        match self {
            Self::Low => RiskLevel::Low,
            Self::Med => RiskLevel::Medium,
            Self::High => RiskLevel::High,
            Self::Crit => RiskLevel::Critical,
        }
    }
    const fn points(self) -> u32 {
        match self {
            Self::Low => 2,
            Self::Med => 8,
            Self::High => 20,
            Self::Crit => 35,
        }
    }
}

/// (category, rule, severity, pattern, description)
type RuleDef = (&'static str, &'static str, Sev, &'static str, &'static str);

struct CompiledRule {
    category: &'static str,
    rule: &'static str,
    severity: Sev,
    regex: regex::Regex,
    description: &'static str,
}

fn compile_rules(defs: &[RuleDef], case_insensitive: bool) -> Vec<CompiledRule> {
    defs.iter()
        .map(|&(category, rule, severity, pattern, description)| {
            let pattern = if case_insensitive {
                format!("(?i){pattern}")
            } else {
                pattern.to_string()
            };
            CompiledRule {
                category,
                rule,
                severity,
                regex: regex::Regex::new(&pattern).unwrap_or_else(|error| {
                    panic!("built-in rule {rule} does not compile: {error}")
                }),
                description,
            }
        })
        .collect()
}

const SHELL_RULES: &[RuleDef] = &[
    (
        "download_execute",
        "curl_pipe_shell",
        Sev::Crit,
        r"(?i)\b(curl|wget|fetch)\b[^\n|;]*\|\s*(sudo\s+(-\w+\s+)*)?(ba|z|da|k)?sh\b",
        "downloads a script and pipes it straight into a shell",
    ),
    (
        "download_execute",
        "shell_from_download",
        Sev::Crit,
        r"(?i)(\b(ba|z|da)?sh|\bsource|\s\.)\s+(-\w+\s+)*<\(\s*(curl|wget)\b",
        "runs a downloaded script through process substitution",
    ),
    (
        "download_execute",
        "download_then_run",
        Sev::High,
        r"(?i)\b(curl|wget)\b.*(&&|;)\s*(chmod\s+\S*(\+x|[0-7]*[1357]\b)|(ba)?sh\s+\S|\./\S)",
        "downloads a file and then makes it executable or runs it",
    ),
    (
        "dynamic_execution",
        "eval_decoded",
        Sev::Crit,
        r"(?i)\b(base64|openssl\s+base64|xxd)\b[^\n|]*(-d|--decode|-D|-r)\b[^\n|]*\|\s*(ba|z|da)?sh\b|\beval\b.*\$\(.*(base64\s+(-d|--decode)|xxd\s+-r)",
        "decodes data and runs it as shell code",
    ),
    (
        "dynamic_execution",
        "eval",
        Sev::Med,
        r#"\beval\s+["'$`(]"#,
        "eval of a built string or substitution",
    ),
    (
        "encoded_payload",
        "base64_decode",
        Sev::Med,
        r"(?i)\bbase64\s+(-d|-D|--decode)\b",
        "decodes base64 data",
    ),
    (
        "encoded_payload",
        "hex_decode",
        Sev::Low,
        r#"(?i)\bxxd\s+-r|printf\s+['"]?(\\x[0-9a-f]{2}){6,}"#,
        "decodes or writes hex-escaped bytes",
    ),
    (
        "remote_shell",
        "dev_tcp",
        Sev::Crit,
        r"/dev/(tcp|udp)/",
        "opens a network socket through /dev/tcp (reverse shell idiom)",
    ),
    (
        "remote_shell",
        "netcat_exec",
        Sev::High,
        r"(?i)\b(nc|ncat|netcat)\b.*\s-[a-z]*e\s|\bmkfifo\b.*\b(nc|ncat|netcat)\b",
        "netcat with command execution or a FIFO relay",
    ),
    (
        "persistence",
        "cron",
        Sev::High,
        r"(?i)\bcrontab\b|/etc/cron\.|/var/spool/cron",
        "installs or edits a cron job",
    ),
    (
        "persistence",
        "shell_profile",
        Sev::Med,
        r"(?i)>>?\s*\S*(\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/profile)\b",
        "appends to a shell start-up file",
    ),
    (
        "persistence",
        "systemd",
        Sev::High,
        r"(?i)\bsystemctl\s+(enable|daemon-reload)\b|/etc/systemd/system/|\.config/systemd/user",
        "installs a systemd unit",
    ),
    (
        "persistence",
        "launchd",
        Sev::High,
        r"(?i)\blaunchctl\s+(load|bootstrap|submit)\b|/Library/Launch(Agents|Daemons)",
        "installs a launchd job",
    ),
    (
        "persistence",
        "ssh_authorized_keys",
        Sev::High,
        r"(?i)authorized_keys",
        "touches SSH authorized_keys",
    ),
    (
        "persistence",
        "rc_local",
        Sev::Med,
        r"(?i)/etc/rc\.local|/etc/init\.d/",
        "writes to an init script",
    ),
    (
        "credential_access",
        "shadow_file",
        Sev::High,
        r"/etc/shadow",
        "reads the password hash file",
    ),
    (
        "credential_access",
        "ssh_private_key",
        Sev::High,
        r"(?i)\.ssh/(id_[a-z0-9_]+|identity)\b",
        "reads an SSH private key",
    ),
    (
        "credential_access",
        "cloud_credentials",
        Sev::High,
        r"(?i)\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json|\.netrc|\.npmrc",
        "reads cloud or registry credentials",
    ),
    (
        "credential_access",
        "keychain",
        Sev::High,
        r"(?i)\bsecurity\s+(find-(generic|internet)-password|dump-keychain)",
        "reads the macOS keychain",
    ),
    (
        "credential_access",
        "browser_store",
        Sev::High,
        r"(?i)Login Data|logins\.json|key[34]\.db|cookies\.sqlite",
        "reads browser credential or cookie stores",
    ),
    (
        "privilege_escalation",
        "sudoers",
        Sev::High,
        r"NOPASSWD|/etc/sudoers|\bchmod\s+(u\+s|[0-7]?4[0-7]{3})\b",
        "changes sudo rules or sets a setuid bit",
    ),
    (
        "defense_evasion",
        "history_wipe",
        Sev::Med,
        r"(?i)\bhistory\s+-c|HISTFILE=/dev/null|unset\s+HISTFILE|\bshred\b.*(\.bash_history|/var/log)|\brm\s+(-\w+\s+)*\S*(\.bash_history|/var/log/\S*)",
        "erases shell history or logs",
    ),
    (
        "defense_evasion",
        "disable_firewall",
        Sev::High,
        r"(?i)\biptables\s+-F|\bufw\s+disable|\bsetenforce\s+0",
        "turns off the firewall or SELinux",
    ),
];

const POWERSHELL_RULES: &[RuleDef] = &[
    (
        "download_execute",
        "iex_download",
        Sev::Crit,
        r"\b(iex|invoke-expression)\b.*(downloadstring|downloaddata|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|net\.webclient|webclient)|(downloadstring|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|webclient).*\|\s*(iex|invoke-expression)\b",
        "downloads code and runs it with Invoke-Expression",
    ),
    (
        "download_execute",
        "webclient_download",
        Sev::High,
        r"net\.webclient.*\.download(string|file|data)|\bstart-bitstransfer\b|\bbitsadmin\b|\bcertutil\b.*-urlcache",
        "downloads from the network (WebClient, BITS or certutil)",
    ),
    (
        "download_execute",
        "download_to_file",
        Sev::Med,
        r"\b(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b[^|\n]*\s-(outfile|o)\b",
        "downloads to a file",
    ),
    (
        "dynamic_execution",
        "invoke_expression",
        Sev::Med,
        r"\b(invoke-expression|iex)\b(\s|\()",
        "Invoke-Expression runs a string as code",
    ),
    (
        "dynamic_execution",
        "scriptblock_create",
        Sev::High,
        r"\[scriptblock\]::create|invoke-command\b.*-scriptblock",
        "builds and runs a script block from a string",
    ),
    (
        "dynamic_execution",
        "native_interop",
        Sev::High,
        r"\badd-type\b.*-(memberdefinition|typedefinition)|dllimport|virtualalloc|writeprocessmemory|createremotethread",
        "compiles or calls native code (shellcode loader idiom)",
    ),
    (
        "dynamic_execution",
        "assembly_load",
        Sev::High,
        r"\[(system\.)?reflection\.assembly\]::load",
        "loads a .NET assembly from memory",
    ),
    (
        "encoded_payload",
        "encoded_command",
        Sev::High,
        r"\s-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{16,}",
        "runs a base64 encoded command",
    ),
    (
        "encoded_payload",
        "frombase64",
        Sev::Med,
        r"frombase64string",
        "decodes base64 data",
    ),
    (
        "encoded_payload",
        "compressed_payload",
        Sev::Med,
        r"gzipstream|deflatestream|io\.compression",
        "decompresses an embedded payload",
    ),
    (
        "encoded_payload",
        "char_array",
        Sev::Med,
        r"(\[char\]\s*\d+\s*[,+-]?\s*){4,}|-join\s*\(?\s*\(?\s*\d+(\s*,\s*\d+){5,}",
        "builds text from character codes",
    ),
    (
        "encoded_payload",
        "xor_decode",
        Sev::Med,
        r"\s-bxor\s",
        "XOR decoding loop",
    ),
    (
        "persistence",
        "scheduled_task",
        Sev::High,
        r"\bschtasks(\.exe)?\s+/create|register-scheduledtask|new-scheduledtask",
        "creates a scheduled task",
    ),
    (
        "persistence",
        "run_key",
        Sev::High,
        r"currentversion\\run(once)?\b|\\start menu\\programs\\startup",
        "writes a Run key or Startup folder entry",
    ),
    (
        "persistence",
        "service",
        Sev::High,
        r"\bnew-service\b|\bsc(\.exe)?\s+create\b",
        "creates a service",
    ),
    (
        "persistence",
        "wmi_subscription",
        Sev::High,
        r"__eventfilter|commandlineeventconsumer|register-wmievent|set-wmiinstance",
        "creates a WMI event subscription",
    ),
    (
        "persistence",
        "profile_edit",
        Sev::Med,
        r"(add-content|out-file|set-content)\s+\$profile|\$profile\b.*(add-content|out-file)",
        "edits the PowerShell profile",
    ),
    (
        "credential_access",
        "mimikatz",
        Sev::Crit,
        r"mimikatz|sekurlsa|lsadump",
        "credential dumping tool",
    ),
    (
        "credential_access",
        "lsass_or_hive",
        Sev::Crit,
        r"\blsass(\.exe)?\b|comsvcs\.dll.*minidump|\breg(\.exe)?\s+save\s+hklm\\(sam|security|system)",
        "dumps LSASS or registry hives",
    ),
    (
        "credential_access",
        "credential_store",
        Sev::High,
        r"ntds\.dit|ntdsutil|vaultcmd|cmdkey\s+/list|passwordvault|credential(manager|vault)",
        "reads Windows credential stores",
    ),
    (
        "credential_access",
        "prompt_credential",
        Sev::Med,
        r"\bget-credential\b|\.getnetworkcredential\(\)",
        "asks for or unwraps credentials",
    ),
    (
        "credential_access",
        "browser_store",
        Sev::High,
        r"login data|logins\.json|key4\.db|chrome\\user data|cookies\.sqlite",
        "reads browser credential or cookie stores",
    ),
    (
        "defense_evasion",
        "amsi_bypass",
        Sev::High,
        r"amsiutils|amsiinitfailed|amsicontext|\[ref\]\.assembly\.gettype",
        "tampers with AMSI",
    ),
    (
        "defense_evasion",
        "defender_tamper",
        Sev::High,
        r"(set|add)-mppreference\b.*(-disable|-exclusion)",
        "disables or excludes Defender",
    ),
    (
        "defense_evasion",
        "execution_policy_bypass",
        Sev::Med,
        r"\s-(executionpolicy|ep)\s+bypass|\s-w(indowstyle)?\s+hidden",
        "bypasses the execution policy or hides the window",
    ),
    (
        "defense_evasion",
        "clear_logs",
        Sev::High,
        r"clear-eventlog|remove-eventlog|\bwevtutil(\.exe)?\s+cl\b",
        "clears event logs",
    ),
];

const JAVASCRIPT_RULES: &[RuleDef] = &[
    (
        "download_execute",
        "eval_download",
        Sev::Crit,
        r"\b(eval|Function)\s*\(.*(fetch\s*\(|XMLHttpRequest|responseText|\.text\(\)|https?\.get|axios|request\s*\(|atob\s*\()",
        "evaluates data that was just fetched or decoded",
    ),
    (
        "download_execute",
        "spawn_download",
        Sev::High,
        r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\(.*\b(curl|wget|powershell|cmd(\.exe)?\s+/c|/bin/(ba)?sh|bash\s+-c)\b",
        "spawns a shell or downloader",
    ),
    (
        "download_execute",
        "wsh_http",
        Sev::High,
        r"(?i)MSXML2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream|new\s+ActiveXObject\s*\(\s*.WScript\.Shell",
        "Windows Script Host download or shell object",
    ),
    (
        "dynamic_execution",
        "eval",
        Sev::Med,
        r"\beval\s*\(",
        "eval of a string",
    ),
    (
        "dynamic_execution",
        "function_constructor",
        Sev::Med,
        r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*[^)]*\)\s*\(\s*\)",
        "builds a function from a string",
    ),
    (
        "dynamic_execution",
        "timer_string",
        Sev::Med,
        r#"\b(setTimeout|setInterval)\s*\(\s*["'`]"#,
        "timer that evaluates a string",
    ),
    (
        "dynamic_execution",
        "vm_run",
        Sev::Med,
        r"\bvm\.(runIn(This|New)Context|Script)\b",
        "runs code through the vm module",
    ),
    (
        "dynamic_execution",
        "document_write_decoded",
        Sev::High,
        r"document\.write\s*\(\s*(unescape|atob)",
        "writes decoded markup into the page",
    ),
    (
        "command_execution",
        "child_process",
        Sev::Med,
        r#"child_process\s*\.\s*(exec|execSync|spawn|spawnSync|execFile)\b|require\s*\(\s*["']child_process["']\s*\)"#,
        "runs operating-system commands",
    ),
    (
        "encoded_payload",
        "atob",
        Sev::Med,
        r"\batob\s*\(|Buffer\.from\([^)]*['\x22](base64|hex)['\x22]",
        "decodes base64 or hex data",
    ),
    (
        "encoded_payload",
        "char_codes",
        Sev::High,
        r"String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){4,}",
        "builds text from a run of character codes",
    ),
    (
        "encoded_payload",
        "escape_runs",
        Sev::Med,
        r"(\\x[0-9a-fA-F]{2}){8,}|(\\u[0-9a-fA-F]{4}){6,}|\bunescape\s*\(|decodeURIComponent\s*\(\s*escape",
        "long escape sequences or unescape",
    ),
    (
        "encoded_payload",
        "inflate",
        Sev::Med,
        r"zlib\.(inflate|gunzip|unzip)(Sync)?\s*\(",
        "decompresses an embedded payload",
    ),
    (
        "persistence",
        "run_key",
        Sev::High,
        r"(?i)CurrentVersion\\{1,2}Run|\bschtasks\b",
        "writes a Run key or scheduled task",
    ),
    (
        "persistence",
        "unix_startup",
        Sev::High,
        r"(?i)\bcrontab\b|LaunchAgents|LaunchDaemons|systemctl\s+enable|/etc/systemd/|authorized_keys",
        "installs a cron, launchd, systemd or SSH key entry",
    ),
    (
        "persistence",
        "shell_profile",
        Sev::Med,
        r"\.bashrc|\.zshrc|\.bash_profile|\.profile\b",
        "touches a shell start-up file",
    ),
    (
        "credential_access",
        "secret_files",
        Sev::High,
        r"\.ssh/|id_rsa|\.aws/credentials|\.npmrc|\.netrc|\.docker/config\.json|\.kube/config|/etc/shadow",
        "reads key or credential files",
    ),
    (
        "credential_access",
        "browser_store",
        Sev::High,
        r"Login Data|logins\.json|key4\.db|Local State",
        "reads browser credential stores",
    ),
    (
        "credential_access",
        "env_secrets",
        Sev::Med,
        r"process\.env\.[A-Z_]*(TOKEN|SECRET|PASSWORD|API_?KEY)|document\.cookie",
        "reads secrets from the environment or cookies",
    ),
];

const PYTHON_RULES: &[RuleDef] = &[
    (
        "download_execute",
        "exec_download",
        Sev::Crit,
        r"\b(exec|eval)\s*\(.*(urlopen|requests\.(get|post)|urllib\.request|httpx\.|\.content\b|\.text\b)",
        "runs code that was just downloaded",
    ),
    (
        "download_execute",
        "shell_download",
        Sev::High,
        r"\b(os\.system|subprocess\.\w+|popen|check_output)\s*\(.*\b(curl|wget)\b|\b(curl|wget)\b[^\n\x22']*\|\s*(ba)?sh",
        "shells out to curl or wget",
    ),
    (
        "download_execute",
        "urlretrieve",
        Sev::Med,
        r"\burlretrieve\s*\(",
        "downloads a file",
    ),
    (
        "dynamic_execution",
        "exec",
        Sev::Med,
        r"\bexec\s*\(",
        "exec of a string",
    ),
    (
        "dynamic_execution",
        "eval",
        Sev::Med,
        r"\beval\s*\(",
        "eval of a string",
    ),
    (
        "dynamic_execution",
        "compile_exec",
        Sev::High,
        r#"\bcompile\s*\(.*["']exec["']"#,
        "compiles a string for exec",
    ),
    (
        "dynamic_execution",
        "dynamic_import",
        Sev::Med,
        r"__import__\s*\(",
        "imports a module by computed name",
    ),
    (
        "dynamic_execution",
        "marshal_pickle",
        Sev::High,
        r"\bmarshal\.loads\b|\b(c?[Pp]ickle|dill)\.loads?\b",
        "loads serialized code or objects (runs code on load)",
    ),
    (
        "dynamic_execution",
        "native_code",
        Sev::High,
        r"ctypes\.(windll|CDLL|cdll)|VirtualAlloc|CFUNCTYPE|WriteProcessMemory",
        "calls native code (shellcode loader idiom)",
    ),
    (
        "command_execution",
        "process",
        Sev::Med,
        r"\bos\.system\s*\(|subprocess\.(Popen|call|run|check_output|check_call)\s*\(|\bos\.popen\s*\(|\bshell\s*=\s*True|\bos\.exec[lv]p?e?\s*\(",
        "runs operating-system commands",
    ),
    (
        "remote_shell",
        "socket_shell",
        Sev::High,
        r"\bos\.dup2\s*\(|\bpty\.spawn\s*\(",
        "wires a socket to a shell (reverse shell idiom)",
    ),
    (
        "encoded_payload",
        "base64",
        Sev::Med,
        r"\b(b64decode|urlsafe_b64decode|b32decode|a85decode|b85decode|decodebytes)\s*\(",
        "decodes base64 data",
    ),
    (
        "encoded_payload",
        "decompress",
        Sev::Med,
        r"\b(zlib|bz2|lzma|gzip)\.decompress\s*\(",
        "decompresses an embedded payload",
    ),
    (
        "encoded_payload",
        "hex_rot",
        Sev::Med,
        r#"\bbinascii\.(unhexlify|a2b_\w+)|\bbytes\.fromhex|codecs\.decode\([^)]*["'](rot_?13|hex|base64|zlib|uu)["']"#,
        "decodes hex or rot13 data",
    ),
    (
        "encoded_payload",
        "chr_chain",
        Sev::Med,
        r"(\bchr\s*\(\s*\d+\s*\)\s*\+\s*){3,}",
        "builds text from character codes",
    ),
    (
        "persistence",
        "unix_startup",
        Sev::High,
        r"(?i)\bcrontab\b|LaunchAgents|LaunchDaemons|systemctl|/etc/rc\.local|authorized_keys|\.pth\b",
        "installs a cron, launchd, systemd or SSH key entry",
    ),
    (
        "persistence",
        "shell_profile",
        Sev::Med,
        r"\.bashrc|\.zshrc|\.bash_profile|\.profile\b",
        "touches a shell start-up file",
    ),
    (
        "persistence",
        "windows_startup",
        Sev::High,
        r"(?i)CurrentVersion\\{1,2}Run|\bschtasks\b|\bwinreg\b",
        "writes a Run key or scheduled task",
    ),
    (
        "credential_access",
        "secret_files",
        Sev::High,
        r"\.ssh/id_|\.aws/credentials|/etc/shadow|\.netrc|\.pypirc|\.npmrc|\.docker/config\.json|\.kube/config",
        "reads key or credential files",
    ),
    (
        "credential_access",
        "browser_store",
        Sev::High,
        r"Login Data|logins\.json|key4\.db|Cookies\.sqlite|keyring\.get_password",
        "reads browser or keyring credentials",
    ),
    (
        "credential_access",
        "env_secrets",
        Sev::Med,
        r#"os\.environ(\.get\(|\[)\s*["'][A-Z_]*(TOKEN|SECRET|PASSWORD|API_?KEY)"#,
        "reads secrets from the environment",
    ),
];

const BATCH_RULES: &[RuleDef] = &[
    (
        "download_execute",
        "powershell_download",
        Sev::Crit,
        r"\bpowershell(\.exe)?\b[^\n]*(downloadstring|downloadfile|\biwr\b|invoke-webrequest|\birm\b|invoke-restmethod|bitstransfer|webclient)",
        "calls PowerShell to download",
    ),
    (
        "download_execute",
        "certutil_bitsadmin",
        Sev::High,
        r"\bcertutil(\.exe)?\b[^\n]*-urlcache|\bbitsadmin(\.exe)?\b[^\n]*/transfer",
        "downloads with certutil or bitsadmin",
    ),
    (
        "download_execute",
        "lolbin_url",
        Sev::High,
        r"\b(mshta|regsvr32|rundll32|wmic)(\.exe)?\b[^\n]*https?://",
        "runs a system binary against a remote URL",
    ),
    (
        "download_execute",
        "curl_output",
        Sev::Med,
        r"\bcurl(\.exe)?\b[^\n]*\s(-o|--output|-O)\b",
        "downloads to a file",
    ),
    (
        "dynamic_execution",
        "powershell_iex",
        Sev::High,
        r"\bpowershell(\.exe)?\b[^\n]*\b(iex|invoke-expression)\b",
        "calls PowerShell Invoke-Expression",
    ),
    (
        "dynamic_execution",
        "call_variable",
        Sev::Med,
        r"\bcall\s+%[^%]+%|\bfor\s+/f[^\n]*\bdo\s+(call|%)",
        "runs a command built in a variable",
    ),
    (
        "encoded_payload",
        "powershell_encoded",
        Sev::High,
        r"\bpowershell(\.exe)?\b[^\n]*\s-(e|ec|enc|encodedcommand)\s+\S{16,}",
        "calls PowerShell with a base64 encoded command",
    ),
    (
        "encoded_payload",
        "certutil_decode",
        Sev::High,
        r"\bcertutil(\.exe)?\b[^\n]*-decode(hex)?\b",
        "decodes a payload with certutil",
    ),
    (
        "obfuscation",
        "substring_variables",
        Sev::Med,
        r"(%[a-z0-9_]+:~-?\d+(,-?\d+)?%.*){3,}",
        "command assembled from variable substrings",
    ),
    (
        "persistence",
        "schtasks",
        Sev::High,
        r"\bschtasks(\.exe)?\b[^\n]*/create",
        "creates a scheduled task",
    ),
    (
        "persistence",
        "run_key",
        Sev::High,
        r"\breg(\.exe)?\s+add\b[^\n]*currentversion\\run|\\start menu\\programs\\startup",
        "writes a Run key or Startup folder entry",
    ),
    (
        "persistence",
        "service_or_user",
        Sev::High,
        r"\bsc(\.exe)?\s+create\b|\bnet\s+user\b[^\n]*/add",
        "creates a service or a user account",
    ),
    (
        "privilege_escalation",
        "admin_group",
        Sev::Crit,
        r"\bnet\s+localgroup\s+administrators\b[^\n]*/add",
        "adds an account to Administrators",
    ),
    (
        "credential_access",
        "hive_dump",
        Sev::Crit,
        r"\breg(\.exe)?\s+save\s+hklm\\(sam|security|system)|mimikatz|sekurlsa",
        "dumps registry hives or runs a credential tool",
    ),
    (
        "credential_access",
        "credential_stores",
        Sev::High,
        r"ntds\.dit|ntdsutil|\blsass\b|\bcmdkey\s+/list|\bvaultcmd\b|netsh\s+wlan\s+(show|export)\s+profile[^\n]*key\s*=\s*clear",
        "reads Windows credential stores or Wi-Fi keys",
    ),
    (
        "defense_evasion",
        "disable_security",
        Sev::High,
        r"netsh\s+advfirewall\s+set\s+\S+\s+state\s+off|netsh\s+firewall\s+set\s+opmode\s+disable|\b(sc|net)(\.exe)?\s+(stop|config)\s+\S*(windefend|wscsvc|sense|mpssvc)|set-mppreference|add-mppreference",
        "turns off the firewall or Defender",
    ),
    (
        "defense_evasion",
        "ransomware_prep",
        Sev::Crit,
        r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\n]*(recoveryenabled\s+no|ignoreallfailures)",
        "deletes shadow copies or disables recovery",
    ),
    (
        "defense_evasion",
        "clear_logs",
        Sev::High,
        r"\bwevtutil(\.exe)?\s+cl\b|taskkill[^\n]*/im\s+\S*(msmpeng|mbam|avast|defender)",
        "clears logs or kills security tools",
    ),
    (
        "defense_evasion",
        "powershell_hidden",
        Sev::Med,
        r"\bpowershell(\.exe)?\b[^\n]*(-w(indowstyle)?\s+hidden|-nop\b|-ep\s+bypass|-executionpolicy\s+bypass)",
        "hidden window or execution policy bypass",
    ),
];

const VBSCRIPT_RULES: &[RuleDef] = &[
    (
        "download_execute",
        "powershell_download",
        Sev::Crit,
        r"powershell[^\n]*(downloadstring|downloadfile|\biex\b|invoke-expression|\s-enc)",
        "calls PowerShell to download or run an encoded command",
    ),
    (
        "download_execute",
        "adodb_stream",
        Sev::High,
        r"adodb\.stream|urldownloadtofile",
        "saves downloaded bytes to disk",
    ),
    (
        "download_execute",
        "http_client",
        Sev::Med,
        r"msxml2\.(server)?xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest",
        "makes HTTP requests",
    ),
    (
        "command_execution",
        "run_command",
        Sev::High,
        r"\.run\b.*(powershell|cmd(\.exe)?\s*/c|mshta|wscript|cscript|regsvr32|rundll32)|shell\.application.*shellexecute",
        "starts another program",
    ),
    (
        "command_execution",
        "exec",
        Sev::Med,
        r"\.exec\s*\(|createobject\s*\(\s*.wscript\.shell",
        "creates a shell object or runs a command",
    ),
    (
        "dynamic_execution",
        "execute_global",
        Sev::High,
        r"\bexecuteglobal\b|msscriptcontrol\.scriptcontrol",
        "runs a string as VBScript",
    ),
    (
        "dynamic_execution",
        "execute_eval",
        Sev::Med,
        r#"(^|[^.\w])execute\b\s*[("\w]|(^|[^.\w])eval\b\s*\("#,
        "Execute or Eval of a string",
    ),
    (
        "dynamic_execution",
        "script_moniker",
        Sev::Crit,
        r#"getobject\s*\(\s*["']script:"#,
        "runs a remote scriptlet",
    ),
    (
        "encoded_payload",
        "chr_chain",
        Sev::Med,
        r"(\bchr[bw]?\s*\(\s*(&h)?[0-9a-f]+\s*\)\s*&\s*){3,}|\bstrreverse\s*\(",
        "builds text from character codes or reversed strings",
    ),
    (
        "encoded_payload",
        "base64_xml",
        Sev::High,
        r"\.nodetypedvalue|bin\.base64|dt:dt",
        "decodes base64 with MSXML",
    ),
    (
        "persistence",
        "run_key",
        Sev::High,
        r"currentversion\\run|\bschtasks\b|\\startup\\|win32_startupcommand|__eventfilter|commandlineeventconsumer",
        "writes a Run key, task, Startup entry or WMI subscription",
    ),
    (
        "persistence",
        "regwrite",
        Sev::Med,
        r"\.regwrite\b|\.createshortcut\b",
        "writes the registry or a shortcut",
    ),
    (
        "credential_access",
        "credential_stores",
        Sev::High,
        r"login data|logins\.json|cookies\.sqlite|\blsass\b|mimikatz|\bcmdkey\b|\bvaultcmd\b|reg\s+save\s+hklm\\sam",
        "reads credential stores",
    ),
    (
        "defense_evasion",
        "hidden_window",
        Sev::Med,
        r"\.run\s*\(?[^\n]*,\s*0\s*[,)]|on\s+error\s+resume\s+next",
        "hidden window or error suppression",
    ),
];

static SHELL_COMPILED: std::sync::LazyLock<Vec<CompiledRule>> =
    std::sync::LazyLock::new(|| compile_rules(SHELL_RULES, false));
static POWERSHELL_COMPILED: std::sync::LazyLock<Vec<CompiledRule>> =
    std::sync::LazyLock::new(|| compile_rules(POWERSHELL_RULES, true));
static JAVASCRIPT_COMPILED: std::sync::LazyLock<Vec<CompiledRule>> =
    std::sync::LazyLock::new(|| compile_rules(JAVASCRIPT_RULES, false));
static PYTHON_COMPILED: std::sync::LazyLock<Vec<CompiledRule>> =
    std::sync::LazyLock::new(|| compile_rules(PYTHON_RULES, false));
static BATCH_COMPILED: std::sync::LazyLock<Vec<CompiledRule>> =
    std::sync::LazyLock::new(|| compile_rules(BATCH_RULES, true));
static VBSCRIPT_COMPILED: std::sync::LazyLock<Vec<CompiledRule>> =
    std::sync::LazyLock::new(|| compile_rules(VBSCRIPT_RULES, true));

fn rules_for(script_type: &ScriptType) -> &'static [CompiledRule] {
    match script_type {
        ScriptType::Shell => &SHELL_COMPILED,
        ScriptType::PowerShell => &POWERSHELL_COMPILED,
        ScriptType::JavaScript => &JAVASCRIPT_COMPILED,
        ScriptType::Python => &PYTHON_COMPILED,
        ScriptType::Batch => &BATCH_COMPILED,
        ScriptType::VBScript => &VBSCRIPT_COMPILED,
        ScriptType::Unknown => &[],
    }
}

/// Display name of a script type.
pub const fn language_name(script_type: &ScriptType) -> &'static str {
    match script_type {
        ScriptType::PowerShell => "PowerShell",
        ScriptType::Python => "Python",
        ScriptType::JavaScript => "JavaScript",
        ScriptType::Batch => "Batch",
        ScriptType::Shell => "Shell",
        ScriptType::VBScript => "VBScript",
        ScriptType::Unknown => "Unknown",
    }
}

/// Parse a language name or common alias (`sh`, `bash`, `ps1`, `js`, `py`, `bat`, `vbs`).
pub fn parse_script_language(name: &str) -> Option<ScriptType> {
    match name.trim().to_ascii_lowercase().as_str() {
        "powershell" | "pwsh" | "ps1" | "ps" => Some(ScriptType::PowerShell),
        "python" | "py" | "python3" => Some(ScriptType::Python),
        "javascript" | "js" | "node" | "jscript" => Some(ScriptType::JavaScript),
        "batch" | "bat" | "cmd" => Some(ScriptType::Batch),
        "shell" | "sh" | "bash" | "zsh" | "ksh" | "dash" => Some(ScriptType::Shell),
        "vbscript" | "vbs" | "vba" => Some(ScriptType::VBScript),
        _ => None,
    }
}

fn type_from_shebang(content: &str) -> Option<ScriptType> {
    let first = content.lines().next()?;
    let line = first.strip_prefix("#!")?.trim();
    // `#!/usr/bin/env -S bash -e` and `#!/bin/bash` both end in the interpreter.
    let mut tokens = line.split_whitespace();
    let mut program = tokens.next()?;
    if program.ends_with("/env") || program == "env" {
        program = tokens.find(|token| !token.starts_with('-'))?;
    }
    let name = program
        .rsplit('/')
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    if name.starts_with("python") {
        Some(ScriptType::Python)
    } else if name == "pwsh" || name == "powershell" {
        Some(ScriptType::PowerShell)
    } else if matches!(name.as_str(), "node" | "nodejs" | "deno" | "bun") {
        Some(ScriptType::JavaScript)
    } else if matches!(
        name.as_str(),
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "fish" | "busybox"
    ) {
        Some(ScriptType::Shell)
    } else {
        None
    }
}

fn type_from_extension(path: &Path) -> Option<ScriptType> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "ps1" | "psm1" | "psd1" => Some(ScriptType::PowerShell),
        "py" | "pyw" | "pyi" => Some(ScriptType::Python),
        "js" | "mjs" | "cjs" | "jse" => Some(ScriptType::JavaScript),
        "bat" | "cmd" => Some(ScriptType::Batch),
        "sh" | "bash" | "zsh" | "ksh" | "command" => Some(ScriptType::Shell),
        "vbs" | "vbe" => Some(ScriptType::VBScript),
        _ => None,
    }
}

/// Extensions of source files that are not scripts in any of the six languages.
fn has_source_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "c" | "h"
                    | "cc"
                    | "cpp"
                    | "cxx"
                    | "hpp"
                    | "hh"
                    | "go"
                    | "rs"
                    | "java"
                    | "kt"
                    | "swift"
                    | "cs"
                    | "m"
                    | "mm"
                    | "scala"
                    | "zig"
                    | "dart"
                    | "ts"
                    | "tsx"
                    | "jsx"
                    | "php"
                    | "rb"
                    | "pl"
                    | "lua"
            )
        })
}

/// Per-language "this line looks like it" patterns, used when neither a shebang nor
/// an extension decides.
static CONTENT_HINTS: std::sync::LazyLock<Vec<(ScriptType, regex::Regex)>> =
    std::sync::LazyLock::new(|| {
        let hints: &[(ScriptType, &str)] = &[
            (
                ScriptType::PowerShell,
                r"(?i)^\s*param\s*\(|^\s*function\s+[\w]+-[\w-]+|\$[a-z_]\w*\s*=|\b(get|set|new|invoke|write|out|import|add|start|remove|select|where|foreach)-[a-z]\w+|\$_\b|\$env:|\|\s*(where|foreach)-object",
            ),
            (
                ScriptType::Python,
                r"^\s*(import\s+[\w.]+(\s*,\s*[\w.]+)*\s*$|from\s+[\w.]+\s+import\s|def\s+\w+\s*\(.*\)\s*(->.*)?:|class\s+\w+.*:\s*$|if\s+__name__\s*==)",
            ),
            (
                ScriptType::JavaScript,
                r#"^\s*(const|let|var)\s+[\w$]+\s*=|\bfunction\s*[\w$]*\s*\(|\brequire\s*\(|=>\s*[{(]|console\.(log|error)|module\.exports|^\s*import\s+.*\s+from\s+['"]"#,
            ),
            (
                ScriptType::Shell,
                r"^\s*(if\s+\[\[?\s|fi\s*$|done\s*$|esac\s*$|then\s*$|echo\s|export\s+\w+=|set\s+-[euxo]|\w+=\$\(|\[\[\s)",
            ),
            (
                ScriptType::Batch,
                r"(?i)^\s*@?echo\s+(off|on)\b|^\s*set\s+(/\w\s+)?\x22?\w+=|^\s*goto\s+\S+|^\s*:\w+\s*$|%~?[0-9a-z_]+%|^\s*(rem|::)(\s|$)|^\s*if\s+(not\s+)?(exist|errorlevel|defined)\b",
            ),
            (
                ScriptType::VBScript,
                r"(?i)^\s*(dim\s+\w+|set\s+\w+\s*=\s*(createobject|getobject)|on\s+error\s+resume\s+next|end\s+(sub|function|if)\b|wscript\.\w+|option\s+explicit|(sub|function)\s+\w+)",
            ),
        ];
        hints
            .iter()
            .map(|(kind, pattern)| {
                (
                    kind.clone(),
                    regex::Regex::new(pattern).expect("built-in language hint compiles"),
                )
            })
            .collect()
    });

fn type_from_content(content: &str) -> ScriptType {
    let mut scores = vec![0usize; CONTENT_HINTS.len()];
    for line in content.lines().take(300) {
        for (slot, (_, regex)) in scores.iter_mut().zip(CONTENT_HINTS.iter()) {
            if regex.is_match(line) {
                *slot += 1;
            }
        }
    }
    let best = scores.iter().copied().max().unwrap_or(0);
    if best == 0 {
        return ScriptType::Unknown;
    }
    let leaders: Vec<usize> = scores
        .iter()
        .enumerate()
        .filter(|(_, score)| **score == best)
        .map(|(index, _)| index)
        .collect();
    // A single matching line is only trusted when nothing else matched.
    if best == 1 && scores.iter().filter(|score| **score > 0).count() > 1 {
        return ScriptType::Unknown;
    }
    // Ties go to the shell family first (the order of CONTENT_HINTS puts PowerShell first,
    // which is the wrong default for a tie), so prefer the lowest-risk-of-mislabel order.
    let order = [
        ScriptType::Shell,
        ScriptType::Python,
        ScriptType::JavaScript,
        ScriptType::PowerShell,
        ScriptType::Batch,
        ScriptType::VBScript,
    ];
    for kind in order {
        if leaders.iter().any(|&index| CONTENT_HINTS[index].0 == kind) {
            return kind;
        }
    }
    ScriptType::Unknown
}

/// Decide the language of a script: shebang, then extension, then content.
/// Returns the type and how it was decided (`shebang`, `extension`, `content`, `unknown`).
pub fn detect_script_type(path: &Path, content: &str) -> (ScriptType, &'static str) {
    if let Some(kind) = type_from_shebang(content) {
        return (kind, "shebang");
    }
    if let Some(kind) = type_from_extension(path) {
        return (kind, "extension");
    }
    if has_source_extension(path) {
        // Source code in a compiled language is not a script; guessing a script language
        // from its content would label it wrongly.
        return (ScriptType::Unknown, "unknown");
    }
    match type_from_content(content) {
        ScriptType::Unknown => (ScriptType::Unknown, "unknown"),
        kind => (kind, "content"),
    }
}

/// Read a script as text, bounded. Handles UTF-8 (with or without BOM) and UTF-16 BOMs;
/// refuses binary files.
fn read_script_text(path: &Path) -> Result<(String, usize, bool)> {
    use std::io::Read;
    let file =
        fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut raw = Vec::new();
    file.take(MAX_SCRIPT_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let truncated = raw.len() > MAX_SCRIPT_BYTES;
    raw.truncate(MAX_SCRIPT_BYTES);
    let bytes_read = raw.len();

    let text = if raw.starts_with(&[0xFF, 0xFE]) || raw.starts_with(&[0xFE, 0xFF]) {
        let little = raw[0] == 0xFF;
        let units: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                if little {
                    u16::from_le_bytes(*pair)
                } else {
                    u16::from_be_bytes(*pair)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let body = raw.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&raw);
        if body.iter().take(4096).any(|&byte| byte == 0) {
            anyhow::bail!(
                "{} is binary (it contains NUL bytes), not a text script. \
                 Use analyze_file for an overview of what it is.",
                path.display()
            );
        }
        String::from_utf8_lossy(body).into_owned()
    };
    Ok((text, bytes_read, truncated))
}

fn is_comment_line(script_type: &ScriptType, trimmed: &str) -> bool {
    match script_type {
        ScriptType::Shell | ScriptType::Python | ScriptType::PowerShell => {
            trimmed.starts_with('#') && !trimmed.starts_with("#!")
        }
        ScriptType::JavaScript => trimmed.starts_with("//"),
        ScriptType::Batch => {
            trimmed.starts_with("::")
                || trimmed
                    .get(..4)
                    .is_some_and(|head| head.eq_ignore_ascii_case("rem "))
                || trimmed.eq_ignore_ascii_case("rem")
        }
        ScriptType::VBScript => {
            trimmed.starts_with('\'')
                || trimmed
                    .get(..4)
                    .is_some_and(|head| head.eq_ignore_ascii_case("rem "))
        }
        ScriptType::Unknown => false,
    }
}

fn cut_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut out: String = text.chars().take(max).collect();
        out.push_str("...");
        out
    }
}

type RuleScan = (
    Vec<ScriptFinding>,
    usize,
    u32,
    std::collections::BTreeMap<String, usize>,
);

fn scan_with_rules(script_type: &ScriptType, content: &str) -> RuleScan {
    let rules = rules_for(script_type);
    let mut findings = Vec::new();
    let mut category_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut total = 0usize;
    let mut score = 0u32;
    let mut per_rule: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_comment_line(script_type, trimmed) {
            continue;
        }
        for rule in rules {
            let Some(found) = rule.regex.find(line) else {
                continue;
            };
            total += 1;
            *category_counts
                .entry(rule.category.to_string())
                .or_insert(0) += 1;
            // Only the first three hits of a rule add to the score.
            let seen = per_rule.entry(rule.rule).or_insert(0);
            if *seen < 3 {
                score += rule.severity.points();
            }
            *seen += 1;
            if findings.len() < MAX_SCRIPT_FINDINGS {
                findings.push(ScriptFinding {
                    category: rule.category.to_string(),
                    rule: rule.rule.to_string(),
                    severity: rule.severity.level(),
                    line: index + 1,
                    matched: cut_chars(found.as_str().trim(), MAX_MATCH_CHARS),
                    description: rule.description.to_string(),
                });
            }
        }
    }
    (findings, total, score.min(100), category_counts)
}

fn risk_for(score: u32, findings: &[ScriptFinding]) -> RiskLevel {
    let by_score = if score >= 60 {
        RiskLevel::Critical
    } else if score >= 35 {
        RiskLevel::High
    } else if score >= 10 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };
    // One critical pattern (download-and-run, credential dumping) is never "medium".
    if findings.iter().any(|f| f.severity == RiskLevel::Critical)
        && matches!(by_score, RiskLevel::Low | RiskLevel::Medium)
    {
        RiskLevel::High
    } else {
        by_score
    }
}

/// Decide the language of the script at `path` without scanning it: `language` wins when
/// given, then shebang, extension and content. Returns the type and how it was decided.
/// Errors when the file is not text or no language fits.
pub fn resolve_script_language(
    path: &Path,
    language: Option<ScriptType>,
) -> Result<(ScriptType, &'static str)> {
    let (content, _, _) = read_script_text(path)?;
    let (script_type, detected_by) = match language {
        Some(kind) => (kind, "override"),
        None => detect_script_type(path, &content),
    };
    if script_type == ScriptType::Unknown {
        anyhow::bail!(unknown_language_message(path));
    }
    Ok((script_type, detected_by))
}

fn unknown_language_message(path: &Path) -> String {
    format!(
        "Could not tell which language {} is written in (no shebang, no known script \
         extension, and the content matched no language). Pass language as one of: shell, \
         powershell, javascript, python, batch, vbscript. If it is not a script, use \
         analyze_file.",
        path.display()
    )
}

/// Analyze one script: detect its language (`language` overrides detection), apply that
/// language's pattern table and report each hit with its line number and matching text.
pub fn analyze_script<P: AsRef<Path>>(
    path: P,
    language: Option<ScriptType>,
) -> Result<ScriptReport> {
    let path = path.as_ref();
    let (content, bytes_read, truncated_input) = read_script_text(path)?;
    let (script_type, detected_by) = match language {
        Some(kind) => (kind, "override"),
        None => detect_script_type(path, &content),
    };
    if script_type == ScriptType::Unknown {
        anyhow::bail!(unknown_language_message(path));
    }
    let (findings, findings_total, risk_score, category_counts) =
        scan_with_rules(&script_type, &content);
    let powershell = (script_type == ScriptType::PowerShell).then(|| powershell_summary(&content));
    let line_count = if content.is_empty() {
        0
    } else {
        content.lines().count()
    };
    Ok(ScriptReport {
        overall_risk: risk_for(risk_score, &findings),
        language: language_name(&script_type).to_string(),
        script_type,
        detected_by: detected_by.to_string(),
        bytes_read,
        truncated_input,
        line_count,
        risk_score,
        category_counts,
        findings_total,
        findings,
        powershell,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_powershell_detection() {
        let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
        let content = "Get-Process | Where-Object {$_.Name -eq 'notepad'}";
        std::fs::write(temp_file.path(), content).unwrap();

        assert!(is_powershell_script(temp_file.path()));
    }

    #[test]
    fn test_powershell_analysis() {
        let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
        let content = r#"
function Test-Function {
    param($param1)
    Get-Process | Stop-Process
    Invoke-WebRequest -Uri "http://example.com"
}
"#;
        std::fs::write(temp_file.path(), content).unwrap();

        let analysis = analyze_powershell(temp_file.path()).unwrap();
        assert_eq!(analysis.script_type, ScriptType::PowerShell);
        assert!(!analysis.functions.is_empty());
        assert!(analysis.suspicious_indicators.has_network_access);
    }
}
