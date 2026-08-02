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

/// Analyze a `PowerShell` script file
pub fn analyze_powershell<P: AsRef<Path>>(path: P) -> Result<ScriptAnalysis> {
    let path = path.as_ref();
    let content = fs::read_to_string(path).context("Failed to read PowerShell script")?;

    let metadata = analyze_powershell_metadata(&content);
    let (commands, functions, imports) = extract_powershell_elements(&content);
    let suspicious_indicators = analyze_powershell_security(&content);
    let obfuscation = detect_powershell_obfuscation(&content);

    let security_analysis = ScriptSecurityAnalysis {
        overall_risk: determine_script_risk(&suspicious_indicators),
        malicious_patterns: extract_malicious_patterns(&content, ScriptType::PowerShell),
        network_activity: extract_network_patterns(&content, ScriptType::PowerShell),
        file_operations: extract_file_operations(&content, ScriptType::PowerShell),
        registry_operations: extract_registry_operations(&content),
        process_operations: extract_process_operations(&content, ScriptType::PowerShell),
        privilege_escalation: extract_privilege_escalation(&content, ScriptType::PowerShell),
        data_exfiltration: extract_data_exfiltration(&content, ScriptType::PowerShell),
    };

    Ok(ScriptAnalysis {
        script_type: ScriptType::PowerShell,
        metadata,
        security_analysis,
        suspicious_indicators,
        commands,
        functions,
        imports,
        obfuscation_indicators: obfuscation,
    })
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
