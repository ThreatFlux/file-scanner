use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::disassembly::DisassemblyResult;
use crate::function_analysis::SymbolTable;
use crate::strings::ExtractedStrings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    pub anti_analysis: Vec<AntiAnalysisTechnique>,
    pub persistence: Vec<PersistenceMechanism>,
    pub network_behavior: Vec<NetworkPattern>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub process_operations: Vec<ProcessOperation>,
    pub evasion_score: f32,
    pub suspicious_behaviors: Vec<SuspiciousBehavior>,
    pub recommendations: Vec<String>,
    /// How much of the file's strings the string-based detectors saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string_coverage: Option<StringCoverage>,
}

/// A string a detector matched, and where it sits in the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEvidence {
    /// The string (first 160 characters).
    pub value: String,
    /// Offset of its first occurrence in the file, when the file could be searched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// How much of a file the string-based detectors examined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringCoverage {
    /// Distinct strings examined (ASCII and UTF-16).
    pub strings_examined: usize,
    pub bytes_examined: u64,
    pub file_size: u64,
    /// False when the file or its strings exceeded the examination bounds.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisTechnique {
    pub technique_type: AntiAnalysisType,
    pub indicators: Vec<String>,
    /// The strings that matched, with offsets (first 10).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<StringEvidence>,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AntiAnalysisType {
    AntiDebug,
    AntiVM,
    AntiSandbox,
    AntiDisassembly,
    Obfuscation,
    TimeDelays,
    EnvironmentChecks,
    ProcessHollowing,
    CodeInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMechanism {
    pub mechanism_type: PersistenceType,
    pub target_locations: Vec<String>,
    /// The strings that matched, with offsets (first 10).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<StringEvidence>,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceType {
    RegistryKeys,
    ServiceInstallation,
    ScheduledTasks,
    StartupFolders,
    DLLHijacking,
    ProcessInjection,
    BootkitRootkit,
    WMIEventSubscription,
    BrowserExtension,
    OfficeAddins,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    pub pattern_type: NetworkPatternType,
    pub indicators: Vec<String>,
    /// The URLs, addresses and other strings that matched, with offsets (first 10).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<StringEvidence>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub suspicious_level: SuspicionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPatternType {
    CommandAndControl,
    DataExfiltration,
    DomainGeneration,
    TorUsage,
    P2PCommunication,
    HTTPSBypass,
    DNSTunneling,
    IRCCommunication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuspicionLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation_type: FileOpType,
    pub targets: Vec<String>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum FileOpType {
    FileCreation,
    FileDeletion,
    FileModification,
    FileEncryption,
    FileCopying,
    FileHiding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation_type: RegistryOpType,
    pub keys: Vec<String>,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOpType {
    KeyCreation,
    KeyDeletion,
    ValueModification,
    PermissionChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperation {
    pub operation_type: ProcessOpType,
    pub targets: Vec<String>,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProcessOpType {
    ProcessCreation,
    ProcessTermination,
    ProcessInjection,
    ProcessHollowing,
    ThreadCreation,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousBehavior {
    pub behavior_type: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Most file bytes read to find strings.
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// Most string bytes kept for the detectors.
const MAX_CORPUS_STRING_BYTES: usize = 32 * 1024 * 1024;
/// Most distinct strings kept for the detectors.
const MAX_CORPUS_STRINGS: usize = 2_000_000;
/// Shortest string examined.
const MIN_STRING_LEN: usize = 4;
/// Pieces of evidence kept per finding.
const MAX_EVIDENCE: usize = 10;
/// Longest evidence string shown.
const MAX_EVIDENCE_CHARS: usize = 160;

/// Run the behavioral detectors.
///
/// The strings the caller passes are capped (`extract_strings` keeps the
/// first 1,000 of each kind), so when `path` is a readable file its strings
/// are extracted again here, all of them up to a byte bound, and merged with
/// the ones passed in. What the detectors saw is reported in
/// `string_coverage`.
pub fn analyze_behavior(
    path: &Path,
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
    disassembly: Option<&DisassemblyResult>,
) -> Result<BehavioralAnalysis> {
    let corpus = build_corpus(path, strings);
    let strings = corpus.strings.as_ref();

    let mut anti_analysis = detect_anti_analysis(strings, symbols, disassembly);
    let mut persistence = detect_persistence_mechanisms(strings, symbols);
    let mut network_behavior = detect_network_patterns(strings, symbols);
    let file_operations = detect_file_operations(strings, symbols);
    let registry_operations = detect_registry_operations(strings);
    let process_operations = detect_process_operations(strings, symbols);

    if let Some(bytes) = &corpus.file_bytes {
        for technique in &mut anti_analysis {
            locate_evidence(&mut technique.evidence, bytes);
        }
        for mechanism in &mut persistence {
            locate_evidence(&mut mechanism.evidence, bytes);
        }
        for pattern in &mut network_behavior {
            locate_evidence(&mut pattern.evidence, bytes);
        }
    }

    let suspicious_behaviors = identify_suspicious_behaviors(
        &anti_analysis,
        &persistence,
        &network_behavior,
        &file_operations,
        &process_operations,
    );

    let evasion_score = calculate_evasion_score(&anti_analysis, &suspicious_behaviors);
    let recommendations = generate_behavioral_recommendations(
        &anti_analysis,
        &persistence,
        &network_behavior,
        &suspicious_behaviors,
        evasion_score,
    );

    Ok(BehavioralAnalysis {
        anti_analysis,
        persistence,
        network_behavior,
        file_operations,
        registry_operations,
        process_operations,
        evasion_score,
        suspicious_behaviors,
        recommendations,
        string_coverage: corpus.coverage,
    })
}

/// Every string the detectors look at.
struct Corpus {
    strings: Option<ExtractedStrings>,
    coverage: Option<StringCoverage>,
    /// The file's bytes (up to the read bound), kept to find offsets.
    file_bytes: Option<Vec<u8>>,
}

fn build_corpus(path: &Path, provided: Option<&ExtractedStrings>) -> Corpus {
    build_corpus_bounded(
        path,
        provided,
        MAX_SCAN_BYTES,
        MAX_CORPUS_STRING_BYTES,
        MAX_CORPUS_STRINGS,
    )
}

fn build_corpus_bounded(
    path: &Path,
    provided: Option<&ExtractedStrings>,
    max_scan_bytes: u64,
    max_string_bytes: usize,
    max_strings: usize,
) -> Corpus {
    use regex::bytes::Regex;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::io::Read;

    let mut ascii: Vec<String> = Vec::new();
    let mut unicode: Vec<String> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut string_bytes = 0usize;
    let mut bounded = false;

    let fingerprint = |kind: u8, text: &str| {
        let mut hasher = DefaultHasher::new();
        kind.hash(&mut hasher);
        text.hash(&mut hasher);
        hasher.finish()
    };

    if let Some(provided) = provided {
        for text in &provided.ascii_strings {
            if seen.insert(fingerprint(0, text)) {
                string_bytes += text.len();
                ascii.push(text.clone());
            }
        }
        for text in &provided.unicode_strings {
            if seen.insert(fingerprint(1, text)) {
                string_bytes += text.len();
                unicode.push(text.clone());
            }
        }
    }

    // Read the file (bounded) and extract all of its strings.
    let mut file_bytes = None;
    let mut file_size = 0u64;
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.is_file() {
            file_size = metadata.len();
            let mut buffer = Vec::new();
            let read = std::fs::File::open(path)
                .and_then(|file| file.take(max_scan_bytes).read_to_end(&mut buffer));
            if read.is_ok() {
                bounded = file_size > max_scan_bytes;
                let ascii_regex = Regex::new(&format!(r"[\x20-\x7E]{{{MIN_STRING_LEN},}}")).ok();
                let utf16_regex =
                    Regex::new(&format!(r"(?:[\x20-\x7E]\x00){{{MIN_STRING_LEN},}}")).ok();
                if let Some(regex) = &ascii_regex {
                    for found in regex.find_iter(&buffer) {
                        let Ok(text) = std::str::from_utf8(found.as_bytes()) else {
                            continue;
                        };
                        if string_bytes >= max_string_bytes
                            || ascii.len() + unicode.len() >= max_strings
                        {
                            bounded = true;
                            break;
                        }
                        if seen.insert(fingerprint(0, text)) {
                            string_bytes += text.len();
                            ascii.push(text.to_string());
                        }
                    }
                }
                if let Some(regex) = &utf16_regex {
                    for found in regex.find_iter(&buffer) {
                        if string_bytes >= max_string_bytes
                            || ascii.len() + unicode.len() >= max_strings
                        {
                            bounded = true;
                            break;
                        }
                        let text: String = found
                            .as_bytes()
                            .iter()
                            .step_by(2)
                            .map(|&byte| char::from(byte))
                            .collect();
                        if seen.insert(fingerprint(1, &text)) {
                            string_bytes += text.len();
                            unicode.push(text);
                        }
                    }
                }
                file_bytes = Some(buffer);
            }
        }
    }

    if provided.is_none() && file_bytes.is_none() {
        return Corpus {
            strings: None,
            coverage: None,
            file_bytes: None,
        };
    }

    let coverage = StringCoverage {
        strings_examined: ascii.len() + unicode.len(),
        bytes_examined: file_bytes.as_ref().map_or(0, |b| b.len() as u64),
        file_size,
        complete: !bounded,
    };
    Corpus {
        strings: Some(ExtractedStrings {
            total_count: ascii.len() + unicode.len(),
            unique_count: ascii.len() + unicode.len(),
            ascii_strings: ascii,
            unicode_strings: unicode,
            interesting_strings: Vec::new(),
        }),
        coverage: Some(coverage),
        file_bytes,
    }
}

/// Fill in each piece of evidence's offset: where its string first occurs in
/// the file, as ASCII or as UTF-16LE.
fn locate_evidence(evidence: &mut [StringEvidence], file: &[u8]) {
    use regex::bytes::Regex;
    for item in evidence.iter_mut() {
        let literal = regex::escape(&item.value);
        let ascii = Regex::new(&format!("(?-u:{literal})"))
            .ok()
            .and_then(|regex| regex.find(file).map(|found| found.start()));
        let position = ascii.or_else(|| {
            let wide: String = item
                .value
                .bytes()
                .map(|b| format!(r"\x{b:02X}\x00"))
                .collect();
            Regex::new(&format!("(?-u:{wide})"))
                .ok()
                .and_then(|regex| regex.find(file).map(|found| found.start()))
        });
        item.offset = position.map(|p| p as u64);
    }
}

/// Add the string that matched to a finding's evidence (distinct, capped).
/// A string longer than the display limit (compilers pack a Go or Rust
/// binary's literals into one giant run) is shown as a window around `needle`.
fn push_evidence(evidence: &mut Vec<StringEvidence>, hit: &str, needle: &str) {
    if evidence.len() >= MAX_EVIDENCE {
        return;
    }
    let value = evidence_window(hit, hit.find(needle).unwrap_or(0), needle.len());
    if !evidence.iter().any(|e| e.value == value) {
        evidence.push(StringEvidence {
            value,
            offset: None,
        });
    }
}

/// At most `MAX_EVIDENCE_CHARS` characters of `text`, centred on the
/// `len` bytes at byte offset `at` when the text is longer.
fn evidence_window(text: &str, at: usize, len: usize) -> String {
    let total = text.chars().count();
    if total <= MAX_EVIDENCE_CHARS {
        return text.to_string();
    }
    let hit_start = text[..at.min(text.len())].chars().count();
    let hit_chars = text
        .get(at..(at + len).min(text.len()))
        .map_or(0, |t| t.chars().count());
    let spare = MAX_EVIDENCE_CHARS.saturating_sub(hit_chars) / 2;
    let start = hit_start.saturating_sub(spare);
    text.chars().skip(start).take(MAX_EVIDENCE_CHARS).collect()
}

/// Whether `text` holds `needle`. A short alphanumeric needle ("Xen", "GET",
/// "PEB") must stand alone, not sit inside a longer word, or it would match
/// ordinary text in any large binary.
fn has_indicator(text: &str, needle: &str) -> bool {
    let standalone = needle.len() <= 6 && needle.bytes().all(|b| b.is_ascii_alphanumeric());
    if !standalone {
        return text.contains(needle);
    }
    let bytes = text.as_bytes();
    text.match_indices(needle).any(|(start, found)| {
        let before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let end = start + found.len();
        let after = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        before && after
    })
}

/// The first string holding `needle`: ASCII strings, then (when
/// `include_unicode`) UTF-16 ones.
fn first_containing<'a>(
    strings: &'a ExtractedStrings,
    needle: &str,
    include_unicode: bool,
) -> Option<&'a str> {
    strings
        .ascii_strings
        .iter()
        .find(|s| has_indicator(s, needle))
        .or_else(|| {
            if include_unicode {
                strings
                    .unicode_strings
                    .iter()
                    .find(|s| has_indicator(s, needle))
            } else {
                None
            }
        })
        .map(String::as_str)
}

fn detect_anti_analysis(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
    disassembly: Option<&DisassemblyResult>,
) -> Vec<AntiAnalysisTechnique> {
    let mut techniques = Vec::new();

    // Anti-debugging detection
    let debug_indicators = vec![
        ("IsDebuggerPresent", "Windows API for debugger detection"),
        ("CheckRemoteDebuggerPresent", "Remote debugger detection"),
        ("NtQueryInformationProcess", "Process information query"),
        ("OutputDebugString", "Debug output detection"),
        ("NtSetInformationThread", "Thread hiding from debugger"),
        ("ZwSetInformationThread", "Thread hiding alternate"),
        ("PEB", "Process Environment Block access"),
        ("BeingDebugged", "Direct PEB flag check"),
        ("NtGlobalFlag", "Global flag debugging check"),
        ("RDTSC", "Timing-based anti-debug"),
        ("GetTickCount", "Timing checks"),
        ("QueryPerformanceCounter", "High-precision timing"),
    ];

    let mut found_indicators = Vec::new();
    let mut debug_evidence = Vec::new();

    // Check strings
    if let Some(strings) = strings {
        for (indicator, _desc) in &debug_indicators {
            if let Some(hit) = first_containing(strings, indicator, true) {
                found_indicators.push(indicator.to_string());
                push_evidence(&mut debug_evidence, hit, indicator);
            }
        }
    }

    // Check symbols
    if let Some(symbols) = symbols {
        for (indicator, _) in &debug_indicators {
            if symbols.functions.iter().any(|f| f.name.contains(indicator))
                && !found_indicators.contains(&indicator.to_string())
            {
                found_indicators.push(indicator.to_string());
            }
        }
    }

    // Timing and PEB words alone turn up in ordinary programs: one of them is
    // not a debugger check, a real anti-debug API (or two weak signs) is.
    const WEAK_DEBUG: [&str; 4] = ["PEB", "RDTSC", "GetTickCount", "QueryPerformanceCounter"];
    let strong_debug = found_indicators
        .iter()
        .any(|i| !WEAK_DEBUG.contains(&i.as_str()));
    if strong_debug || found_indicators.len() >= 2 {
        techniques.push(AntiAnalysisTechnique {
            evidence: debug_evidence,
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: found_indicators,
            confidence: 0.85,
            description: "Debugger detection techniques found".to_string(),
        });
    }

    // Anti-VM detection
    let vm_indicators = vec![
        ("VMware", "VMware detection"),
        ("VirtualBox", "VirtualBox detection"),
        ("QEMU", "QEMU detection"),
        ("Xen", "Xen hypervisor detection"),
        ("Hyper-V", "Hyper-V detection"),
        ("vmci", "VMware driver"),
        ("vboxdrv", "VirtualBox driver"),
        ("vpc.exe", "Virtual PC detection"),
        ("VMToolsd", "VMware tools"),
        ("VBoxService", "VirtualBox service"),
        ("HARDWARE\\ACPI\\DSDT\\VBOX", "VirtualBox registry key"),
        ("HARDWARE\\ACPI\\DSDT\\VMW", "VMware registry key"),
        ("SystemBiosVersion", "BIOS version check"),
        ("VideoBiosVersion", "Video BIOS check"),
        ("CPUID", "CPU feature detection"),
        ("hypervisor", "Hypervisor bit check"),
    ];

    let mut vm_found = Vec::new();
    let mut vm_evidence = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &vm_indicators {
            if let Some(hit) = first_containing(strings, indicator, true) {
                vm_found.push(indicator.to_string());
                push_evidence(&mut vm_evidence, hit, indicator);
            }
        }
    }

    if !vm_found.is_empty() {
        techniques.push(AntiAnalysisTechnique {
            evidence: vm_evidence,
            technique_type: AntiAnalysisType::AntiVM,
            indicators: vm_found,
            confidence: 0.80,
            description: "Virtual machine detection attempts".to_string(),
        });
    }

    // Anti-sandbox detection
    let sandbox_indicators = vec![
        ("SbieDll", "Sandboxie detection"),
        ("SxIn", "360 Sandbox detection"),
        ("Sf2", "Avast Sandbox"),
        ("cmdvrt", "COMODO Sandbox"),
        ("sample", "Common sandbox filename"),
        ("malware", "Common sandbox filename"),
        ("virus", "Common sandbox filename"),
        ("sandbox", "Sandbox environment string"),
        ("GetUserName", "Username checking"),
        ("GetComputerName", "Computer name checking"),
        ("Sleep", "Delay execution"),
        ("NtDelayExecution", "Kernel delay execution"),
        ("GetCursorPos", "User activity check"),
        ("GetLastInputInfo", "User input timing"),
        ("mouse_event", "Simulated mouse check"),
        ("CreateToolhelp32Snapshot", "Process enumeration"),
    ];

    let mut sandbox_found = Vec::new();
    let mut sandbox_evidence = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &sandbox_indicators {
            if let Some(hit) = first_containing(strings, indicator, false) {
                sandbox_found.push(indicator.to_string());
                push_evidence(&mut sandbox_evidence, hit, indicator);
            }
        }
    }

    if sandbox_found.len() >= 3 {
        techniques.push(AntiAnalysisTechnique {
            evidence: sandbox_evidence,
            technique_type: AntiAnalysisType::AntiSandbox,
            indicators: sandbox_found,
            confidence: 0.75,
            description: "Sandbox evasion techniques detected".to_string(),
        });
    }

    // Code obfuscation detection
    if let Some(disassembly) = disassembly {
        let suspicious_patterns = &disassembly.analysis.suspicious_patterns;
        let obfuscation_indicators = [
            ("NopSled", "NOP sled obfuscation"),
            ("IndirectJumps", "Control flow obfuscation"),
            ("SelfModifying", "Self-modifying code"),
            ("ReturnOriented", "ROP chain obfuscation"),
        ];

        for pattern in suspicious_patterns {
            if let Some(desc) = obfuscation_indicators
                .iter()
                .find(|(name, _)| format!("{:?}", pattern.pattern_type).contains(name))
                .map(|(_, desc)| desc)
            {
                techniques.push(AntiAnalysisTechnique {
                    evidence: Vec::new(),
                    technique_type: AntiAnalysisType::Obfuscation,
                    indicators: vec![format!("{:?}", pattern.pattern_type)],
                    confidence: 0.70,
                    description: desc.to_string(),
                });
            }
        }
    }

    techniques
}

fn detect_persistence_mechanisms(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<PersistenceMechanism> {
    let mut mechanisms = Vec::new();

    // Registry persistence
    let registry_persistence = vec![
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            PersistenceType::RegistryKeys,
            "Startup registry key",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            PersistenceType::RegistryKeys,
            "Run once registry key",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            PersistenceType::RegistryKeys,
            "Run services key",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
            PersistenceType::RegistryKeys,
            "Shell folders manipulation",
        ),
        (
            "SOFTWARE\\Classes\\",
            PersistenceType::RegistryKeys,
            "File association hijacking",
        ),
        (
            "SYSTEM\\CurrentControlSet\\Services",
            PersistenceType::ServiceInstallation,
            "Service installation",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            PersistenceType::RegistryKeys,
            "Winlogon manipulation",
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
            PersistenceType::RegistryKeys,
            "Policy modification",
        ),
    ];

    if let Some(strings) = strings {
        for (key, pers_type, desc) in registry_persistence {
            if let Some(hit) = first_containing(strings, key, true) {
                let mut evidence = Vec::new();
                push_evidence(&mut evidence, hit, key);
                mechanisms.push(PersistenceMechanism {
                    evidence,
                    mechanism_type: pers_type,
                    target_locations: vec![key.to_string()],
                    severity: Severity::High,
                    description: desc.to_string(),
                });
            }
        }
    }

    // Service creation APIs
    let service_apis = vec![
        ("CreateService", "Service creation API"),
        ("OpenSCManager", "Service manager access"),
        ("StartService", "Service startup"),
        ("ChangeServiceConfig", "Service configuration change"),
        ("RegisterServiceCtrlHandler", "Service control handler"),
    ];

    let mut service_indicators = Vec::new();

    if let Some(symbols) = symbols {
        for (api, _) in &service_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                service_indicators.push(api.to_string());
            }
        }
    }

    if service_indicators.len() >= 2 {
        mechanisms.push(PersistenceMechanism {
            evidence: Vec::new(),
            mechanism_type: PersistenceType::ServiceInstallation,
            target_locations: service_indicators,
            severity: Severity::High,
            description: "Windows service installation capability".to_string(),
        });
    }

    // Scheduled task indicators
    let task_indicators = vec![
        ("schtasks", "Scheduled task command"),
        ("Task Scheduler", "Task scheduler reference"),
        ("ITaskScheduler", "Task scheduler interface"),
        ("\\Tasks\\", "Tasks folder path"),
        ("at.exe", "AT command scheduler"),
    ];

    if let Some(strings) = strings {
        let mut found_tasks = Vec::new();
        let mut task_evidence = Vec::new();
        for (indicator, _) in &task_indicators {
            if let Some(hit) = first_containing(strings, indicator, false) {
                found_tasks.push(indicator.to_string());
                push_evidence(&mut task_evidence, hit, indicator);
            }
        }

        if !found_tasks.is_empty() {
            mechanisms.push(PersistenceMechanism {
                evidence: task_evidence,
                mechanism_type: PersistenceType::ScheduledTasks,
                target_locations: found_tasks,
                severity: Severity::Medium,
                description: "Scheduled task persistence".to_string(),
            });
        }
    }

    // DLL hijacking indicators
    let dll_hijack_indicators = vec![
        ("LoadLibrary", "Dynamic library loading"),
        ("SetDllDirectory", "DLL directory manipulation"),
        ("AddDllDirectory", "DLL directory addition"),
        (".dll", "DLL file references"),
        ("System32", "System directory access"),
        ("SysWOW64", "32-bit system directory"),
    ];

    let mut dll_indicators = Vec::new();
    let mut dll_evidence = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &dll_hijack_indicators {
            if let Some(hit) = first_containing(strings, indicator, false) {
                dll_indicators.push(indicator.to_string());
                push_evidence(&mut dll_evidence, hit, indicator);
            }
        }
    }

    if dll_indicators.len() >= 3 {
        mechanisms.push(PersistenceMechanism {
            evidence: dll_evidence,
            mechanism_type: PersistenceType::DLLHijacking,
            target_locations: dll_indicators,
            severity: Severity::High,
            description: "DLL hijacking capability".to_string(),
        });
    }

    mechanisms
}

fn onion_address_regex() -> &'static regex::Regex {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b")
            .expect("onion address pattern")
    });
    &RE
}

fn ip_regex() -> &'static regex::Regex {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        )
        .expect("IP address pattern")
    });
    &RE
}

fn ip_url_regex() -> &'static regex::Regex {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\b(?:https?|wss?|ftp|tcp)://(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        )
        .expect("IP URL pattern")
    });
    &RE
}

fn detect_network_patterns(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<NetworkPattern> {
    let mut patterns = Vec::new();

    // C&C indicators
    let cc_indicators = vec![
        ("http://", "HTTP communication"),
        ("https://", "HTTPS communication"),
        ("ftp://", "FTP protocol"),
        ("tcp://", "TCP protocol"),
        ("ws://", "WebSocket protocol"),
        ("wss://", "Secure WebSocket"),
        (".onion", "Tor hidden service"),
        ("tor2web", "Tor gateway"),
        ("user-agent", "HTTP user agent"),
        ("POST", "HTTP POST method"),
        ("GET", "HTTP GET method"),
        ("Content-Type", "HTTP content type"),
        ("application/json", "JSON data format"),
        ("base64", "Base64 encoding"),
    ];

    let mut found_cc = Vec::new();
    let mut cc_evidence = Vec::new();
    let mut protocols = HashSet::new();
    let mut schemes = 0usize;
    let mut markers = 0usize;
    let mut strong = false;

    if let Some(strings) = strings {
        for (indicator, _) in &cc_indicators {
            if let Some(hit) = first_containing(strings, indicator, false) {
                found_cc.push(indicator.to_string());
                push_evidence(&mut cc_evidence, hit, indicator);

                // Extract protocol
                if indicator.ends_with("://") {
                    protocols.insert(indicator.trim_end_matches("://").to_string());
                    schemes += 1;
                }
                match *indicator {
                    "tor2web" => strong = true,
                    "user-agent" | "POST" | "GET" | "Content-Type" | "application/json"
                    | "base64" => markers += 1,
                    _ => {}
                }
            }
        }

        // A URL whose host is a raw IP address is how implants usually name
        // their server; an IP address on its own is only a string.
        let ip_url = ip_url_regex();
        let ip_literal = ip_regex();
        let mut raw_ip_url = false;
        let mut ip_seen = false;
        for s in &strings.ascii_strings {
            if !raw_ip_url {
                if let Some(found) = ip_url.find(s) {
                    raw_ip_url = true;
                    push_evidence(&mut cc_evidence, s, found.as_str());
                }
            }
            if !ip_seen {
                if let Some(found) = ip_literal.find(s) {
                    ip_seen = true;
                    push_evidence(&mut cc_evidence, s, found.as_str());
                }
            }
            if raw_ip_url && ip_seen {
                break;
            }
        }
        if ip_seen || raw_ip_url {
            found_cc.push("IP address found".to_string());
        }
        if raw_ip_url {
            found_cc.push("URL with a raw IP address".to_string());
            strong = true;
        }
        // The bare text ".onion" sits in the networking libraries of ordinary
        // programs; a complete onion address is a destination.
        let onion = onion_address_regex();
        if let Some((s, found)) = strings
            .ascii_strings
            .iter()
            .find_map(|s| onion.find(s).map(|found| (s, found)))
        {
            strong = true;
            push_evidence(&mut cc_evidence, s, found.as_str());
        }

        // Command-and-control needs more than a URL scheme: ordinary programs
        // carry "https://" in their help text. The level says how much more.
        let level = if strong && (markers >= 1 || raw_ip_url) {
            SuspicionLevel::High
        } else if strong || (schemes >= 1 && markers >= 2) {
            SuspicionLevel::Medium
        } else {
            SuspicionLevel::Low
        };

        if !found_cc.is_empty() {
            patterns.push(NetworkPattern {
                evidence: cc_evidence,
                pattern_type: NetworkPatternType::CommandAndControl,
                indicators: found_cc,
                protocols: protocols.clone().into_iter().collect(),
                ports: vec![],
                suspicious_level: level,
            });
        }
    }

    // Network APIs
    let network_apis = vec![
        ("socket", "Socket creation"),
        ("connect", "Network connection"),
        ("send", "Data sending"),
        ("recv", "Data receiving"),
        ("WSAStartup", "Winsock initialization"),
        ("InternetOpen", "WinINet initialization"),
        ("InternetConnect", "Internet connection"),
        ("HttpSendRequest", "HTTP request"),
        ("URLDownloadToFile", "File download"),
        ("WinHttpOpen", "WinHTTP initialization"),
        ("getaddrinfo", "DNS resolution"),
        ("gethostbyname", "DNS lookup"),
    ];

    let mut found_apis = Vec::new();

    if let Some(symbols) = symbols {
        for (api, _) in &network_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                found_apis.push(api.to_string());
            }
        }
    }

    // Common ports
    let port_indicators = vec![
        (":80", 80, "HTTP"),
        (":443", 443, "HTTPS"),
        (":8080", 8080, "HTTP alternate"),
        (":8443", 8443, "HTTPS alternate"),
        (":21", 21, "FTP"),
        (":22", 22, "SSH"),
        (":23", 23, "Telnet"),
        (":25", 25, "SMTP"),
        (":3389", 3389, "RDP"),
        (":445", 445, "SMB"),
        (":1433", 1433, "MSSQL"),
        (":3306", 3306, "MySQL"),
        (":6667", 6667, "IRC"),
        (":9001", 9001, "Tor"),
    ];

    let mut found_ports = Vec::new();
    let mut port_numbers = Vec::new();

    if let Some(strings) = strings {
        for (indicator, port, desc) in &port_indicators {
            if strings.ascii_strings.iter().any(|s| s.contains(indicator)) {
                found_ports.push(format!("{port} ({desc})"));
                port_numbers.push(*port);
            }
        }
    }

    if !found_apis.is_empty() {
        let suspicious_level = if found_apis.len() >= 4 {
            SuspicionLevel::High
        } else {
            SuspicionLevel::Medium
        };

        patterns.push(NetworkPattern {
            evidence: Vec::new(),
            pattern_type: NetworkPatternType::DataExfiltration,
            indicators: found_apis,
            protocols: vec!["TCP".to_string()],
            ports: port_numbers,
            suspicious_level,
        });
    }

    // Tor indicators
    let tor_indicators = vec![
        (".onion", "Tor hidden service"),
        ("tor.exe", "Tor executable"),
        ("Tor Browser", "Tor browser"),
        ("9050", "Tor SOCKS port"),
        ("9051", "Tor control port"),
        ("torrc", "Tor configuration"),
    ];

    let mut tor_found = Vec::new();
    let mut tor_evidence = Vec::new();

    if let Some(strings) = strings {
        for (indicator, _) in &tor_indicators {
            if let Some(hit) = first_containing(strings, indicator, false) {
                tor_found.push(indicator.to_string());
                push_evidence(&mut tor_evidence, hit, indicator);
            }
        }
    }

    let onion_address = strings.is_some_and(|strings| {
        strings
            .ascii_strings
            .iter()
            .any(|s| onion_address_regex().is_match(s))
    });
    let tor_high = tor_found.len() >= 2 || onion_address;
    if !tor_found.is_empty() {
        patterns.push(NetworkPattern {
            evidence: tor_evidence,
            pattern_type: NetworkPatternType::TorUsage,
            indicators: tor_found,
            protocols: vec!["Tor".to_string()],
            ports: vec![9050, 9051],
            // The bare text ".onion" alone is in ordinary networking code.
            suspicious_level: if tor_high {
                SuspicionLevel::High
            } else {
                SuspicionLevel::Medium
            },
        });
    }

    patterns
}

fn detect_file_operations(
    strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<FileOperation> {
    let mut operations = Vec::new();

    // File manipulation APIs
    let file_apis = vec![
        ("CreateFile", FileOpType::FileCreation),
        ("DeleteFile", FileOpType::FileDeletion),
        ("MoveFile", FileOpType::FileModification),
        ("CopyFile", FileOpType::FileCopying),
        ("WriteFile", FileOpType::FileModification),
        ("SetFileAttributes", FileOpType::FileHiding),
        ("FindFirstFile", FileOpType::FileModification),
        ("GetTempPath", FileOpType::FileCreation),
    ];

    let mut found_ops = HashMap::new();

    if let Some(symbols) = symbols {
        for (api, op_type) in &file_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                found_ops
                    .entry(op_type.clone())
                    .or_insert_with(Vec::new)
                    .push(api.to_string());
            }
        }
    }

    // File extensions of interest
    let suspicious_extensions = vec![
        (".exe", "Executable files"),
        (".dll", "Library files"),
        (".sys", "System drivers"),
        (".bat", "Batch scripts"),
        (".cmd", "Command scripts"),
        (".ps1", "PowerShell scripts"),
        (".vbs", "VBScript files"),
        (".js", "JavaScript files"),
        (".tmp", "Temporary files"),
        (".log", "Log files"),
        (".dat", "Data files"),
        (".ini", "Configuration files"),
        (".cfg", "Configuration files"),
        (".encrypted", "Encrypted files"),
        (".locked", "Locked files"),
    ];

    let mut target_extensions = Vec::new();

    if let Some(strings) = strings {
        for (ext, _) in &suspicious_extensions {
            if strings.ascii_strings.iter().any(|s| s.ends_with(ext)) {
                target_extensions.push(ext.to_string());
            }
        }
    }

    // Convert found operations to FileOperation structs
    for (op_type, apis) in found_ops {
        let suspicious = matches!(
            op_type,
            FileOpType::FileDeletion | FileOpType::FileEncryption | FileOpType::FileHiding
        );

        operations.push(FileOperation {
            operation_type: op_type,
            targets: apis,
            suspicious,
        });
    }

    // Check for encryption patterns
    let crypto_file_patterns = vec![
        "CryptEncrypt",
        "CryptDecrypt",
        "AES",
        "RSA",
        ".encrypted",
        ".locked",
        "ransom",
    ];

    let mut crypto_indicators = Vec::new();

    if let Some(strings) = strings {
        for pattern in &crypto_file_patterns {
            if strings.ascii_strings.iter().any(|s| s.contains(pattern)) {
                crypto_indicators.push(pattern.to_string());
            }
        }
    }

    if crypto_indicators.len() >= 2 {
        operations.push(FileOperation {
            operation_type: FileOpType::FileEncryption,
            targets: crypto_indicators,
            suspicious: true,
        });
    }

    operations
}

fn detect_registry_operations(strings: Option<&ExtractedStrings>) -> Vec<RegistryOperation> {
    let mut operations = Vec::new();

    if let Some(strings) = strings {
        // Registry APIs
        let registry_apis = vec![
            (
                "RegCreateKey",
                RegistryOpType::KeyCreation,
                "Registry key creation",
            ),
            (
                "RegOpenKey",
                RegistryOpType::ValueModification,
                "Registry key access",
            ),
            (
                "RegSetValue",
                RegistryOpType::ValueModification,
                "Registry value setting",
            ),
            (
                "RegDeleteKey",
                RegistryOpType::KeyDeletion,
                "Registry key deletion",
            ),
            (
                "RegDeleteValue",
                RegistryOpType::KeyDeletion,
                "Registry value deletion",
            ),
            (
                "RegQueryValue",
                RegistryOpType::ValueModification,
                "Registry value query",
            ),
        ];

        for (api, op_type, purpose) in registry_apis {
            if strings.ascii_strings.iter().any(|s| s.contains(api)) {
                operations.push(RegistryOperation {
                    operation_type: op_type,
                    keys: vec![api.to_string()],
                    purpose: purpose.to_string(),
                });
            }
        }

        // Common registry paths
        let registry_paths = vec![
            ("HKEY_LOCAL_MACHINE", "System-wide settings"),
            ("HKEY_CURRENT_USER", "User-specific settings"),
            ("SOFTWARE\\Microsoft", "Microsoft software settings"),
            ("SYSTEM\\CurrentControlSet", "System configuration"),
            ("SOFTWARE\\Classes", "File associations"),
        ];

        for (path, purpose) in registry_paths {
            if strings.ascii_strings.iter().any(|s| s.contains(path))
                || strings.unicode_strings.iter().any(|s| s.contains(path))
            {
                operations.push(RegistryOperation {
                    operation_type: RegistryOpType::ValueModification,
                    keys: vec![path.to_string()],
                    purpose: purpose.to_string(),
                });
            }
        }
    }

    operations
}

fn detect_process_operations(
    _strings: Option<&ExtractedStrings>,
    symbols: Option<&SymbolTable>,
) -> Vec<ProcessOperation> {
    let mut operations = Vec::new();

    // Process manipulation APIs
    let process_apis = vec![
        (
            "CreateProcess",
            ProcessOpType::ProcessCreation,
            vec!["Process creation"],
        ),
        (
            "CreateThread",
            ProcessOpType::ThreadCreation,
            vec!["Thread creation"],
        ),
        (
            "CreateRemoteThread",
            ProcessOpType::ProcessInjection,
            vec!["Remote thread injection"],
        ),
        (
            "OpenProcess",
            ProcessOpType::ProcessInjection,
            vec!["Process handle acquisition"],
        ),
        (
            "TerminateProcess",
            ProcessOpType::ProcessTermination,
            vec!["Process termination"],
        ),
        (
            "WriteProcessMemory",
            ProcessOpType::ProcessInjection,
            vec!["Memory writing"],
        ),
        (
            "ReadProcessMemory",
            ProcessOpType::ProcessInjection,
            vec!["Memory reading"],
        ),
        (
            "VirtualAllocEx",
            ProcessOpType::ProcessInjection,
            vec!["Remote memory allocation"],
        ),
        (
            "SetThreadContext",
            ProcessOpType::ProcessInjection,
            vec!["Thread context manipulation"],
        ),
        (
            "QueueUserAPC",
            ProcessOpType::ProcessInjection,
            vec!["APC injection"],
        ),
        (
            "NtCreateThreadEx",
            ProcessOpType::ProcessInjection,
            vec!["Native thread creation"],
        ),
        (
            "RtlCreateUserThread",
            ProcessOpType::ProcessInjection,
            vec!["User thread creation"],
        ),
    ];

    let mut found_by_type: HashMap<ProcessOpType, Vec<String>> = HashMap::new();

    if let Some(symbols) = symbols {
        for (api, op_type, techniques) in &process_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                found_by_type
                    .entry(op_type.clone())
                    .or_default()
                    .extend(techniques.iter().map(std::string::ToString::to_string));
            }
        }
    }

    // Process hollowing indicators
    let hollowing_apis = vec![
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "CreateProcess",
        "WriteProcessMemory",
        "SetThreadContext",
        "ResumeThread",
    ];

    let mut hollowing_found = 0;

    if let Some(symbols) = symbols {
        for api in &hollowing_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                hollowing_found += 1;
            }
        }
    }

    if hollowing_found >= 4 {
        operations.push(ProcessOperation {
            operation_type: ProcessOpType::ProcessHollowing,
            targets: vec!["Process hollowing capability detected".to_string()],
            techniques: hollowing_apis
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        });
    }

    // Privilege escalation indicators
    let privilege_apis = vec![
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser",
        "DuplicateTokenEx",
        "SetTokenInformation",
    ];

    let mut priv_indicators = Vec::new();

    if let Some(symbols) = symbols {
        for api in &privilege_apis {
            if symbols.functions.iter().any(|f| f.name.contains(api)) {
                priv_indicators.push(api.to_string());
            }
        }
    }

    if priv_indicators.len() >= 2 {
        operations.push(ProcessOperation {
            operation_type: ProcessOpType::PrivilegeEscalation,
            targets: vec!["Token manipulation detected".to_string()],
            techniques: priv_indicators,
        });
    }

    // Convert found operations
    for (op_type, techniques) in found_by_type {
        operations.push(ProcessOperation {
            operation_type: op_type,
            targets: vec![],
            techniques,
        });
    }

    operations
}

fn identify_suspicious_behaviors(
    _anti_analysis: &[AntiAnalysisTechnique],
    persistence: &[PersistenceMechanism],
    network: &[NetworkPattern],
    file_ops: &[FileOperation],
    process_ops: &[ProcessOperation],
) -> Vec<SuspiciousBehavior> {
    let mut behaviors = Vec::new();

    // Check for ransomware behavior
    let has_encryption = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileEncryption));
    let has_file_enum = file_ops
        .iter()
        .any(|op| op.targets.iter().any(|t| t.contains("FindFirstFile")));
    let has_deletion = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileDeletion));

    if has_encryption && (has_file_enum || has_deletion) {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Ransomware".to_string(),
            description: "File encryption with enumeration/deletion patterns".to_string(),
            severity: Severity::Critical,
            evidence: vec![
                "File encryption capability".to_string(),
                "File enumeration/deletion".to_string(),
            ],
        });
    }

    // Check for rootkit behavior
    let has_kernel_apis = process_ops.iter().any(|op| {
        op.techniques
            .iter()
            .any(|t| t.contains("Nt") || t.contains("Zw"))
    });
    let has_process_hiding = process_ops
        .iter()
        .any(|op| matches!(op.operation_type, ProcessOpType::ProcessInjection));
    let has_service_install = persistence
        .iter()
        .any(|p| matches!(p.mechanism_type, PersistenceType::ServiceInstallation));

    if has_kernel_apis && (has_process_hiding || has_service_install) {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Rootkit".to_string(),
            description: "Kernel API usage with hiding/persistence".to_string(),
            severity: Severity::Critical,
            evidence: vec![
                "Native API usage".to_string(),
                "Process manipulation".to_string(),
            ],
        });
    }

    // Check for data theft
    // A pattern rated Low (a URL or an IP address in the strings) is a
    // finding to look at, not network capability.
    let has_network = network
        .iter()
        .any(|n| !matches!(n.suspicious_level, SuspicionLevel::Low));
    let has_file_access = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileCopying));
    let has_credential_apis = process_ops.iter().any(|op| {
        op.techniques
            .iter()
            .any(|t| t.contains("Cred") || t.contains("Token") || t.contains("Password"))
    });

    if has_network && (has_file_access || has_credential_apis) {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "DataTheft".to_string(),
            description: "Network capability with file/credential access".to_string(),
            severity: Severity::High,
            evidence: vec![
                "Network communication".to_string(),
                "File/credential access".to_string(),
            ],
        });
    }

    // Check for backdoor
    let has_cc = network.iter().any(|n| {
        matches!(n.pattern_type, NetworkPatternType::CommandAndControl)
            && !matches!(n.suspicious_level, SuspicionLevel::Low)
    });
    let has_persistence_mech = !persistence.is_empty();
    let has_remote_exec = process_ops
        .iter()
        .any(|op| matches!(op.operation_type, ProcessOpType::ProcessCreation));

    if has_cc && has_persistence_mech && has_remote_exec {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Backdoor".to_string(),
            description: "C&C communication with persistence and execution".to_string(),
            severity: Severity::Critical,
            evidence: vec![
                "Command and control".to_string(),
                "Persistence mechanism".to_string(),
                "Remote execution".to_string(),
            ],
        });
    }

    // Check for dropper/downloader
    let has_download = network.iter().any(|n| {
        n.indicators
            .iter()
            .any(|i| i.contains("URLDownloadToFile") || i.contains("InternetReadFile"))
    });
    let has_file_write = file_ops
        .iter()
        .any(|op| matches!(op.operation_type, FileOpType::FileCreation));
    let has_exec = process_ops
        .iter()
        .any(|op| matches!(op.operation_type, ProcessOpType::ProcessCreation));

    if has_download && has_file_write && has_exec {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "Dropper".to_string(),
            description: "Downloads and executes additional payloads".to_string(),
            severity: Severity::High,
            evidence: vec![
                "Download capability".to_string(),
                "File writing".to_string(),
                "Process execution".to_string(),
            ],
        });
    }

    behaviors
}

fn calculate_evasion_score(
    anti_analysis: &[AntiAnalysisTechnique],
    suspicious_behaviors: &[SuspiciousBehavior],
) -> f32 {
    let mut score = 0.0;

    // Anti-analysis techniques contribute to evasion score
    for technique in anti_analysis {
        score += match technique.technique_type {
            AntiAnalysisType::AntiDebug => 15.0,
            AntiAnalysisType::AntiVM => 15.0,
            AntiAnalysisType::AntiSandbox => 20.0,
            AntiAnalysisType::AntiDisassembly => 10.0,
            AntiAnalysisType::Obfuscation => 20.0,
            AntiAnalysisType::ProcessHollowing => 25.0,
            AntiAnalysisType::CodeInjection => 20.0,
            _ => 10.0,
        };

        // Adjust by confidence
        score *= technique.confidence;
    }

    // Critical behaviors increase evasion score
    for behavior in suspicious_behaviors {
        if matches!(behavior.severity, Severity::Critical) {
            score += 10.0;
        }
    }

    // Cap at 100
    score.min(100.0)
}

fn generate_behavioral_recommendations(
    anti_analysis: &[AntiAnalysisTechnique],
    persistence: &[PersistenceMechanism],
    network: &[NetworkPattern],
    suspicious_behaviors: &[SuspiciousBehavior],
    evasion_score: f32,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    // Evasion score recommendations
    if evasion_score > 70.0 {
        recommendations.push(
            "CRITICAL: Very high evasion score. Use advanced sandbox with anti-evasion bypasses."
                .to_string(),
        );
        recommendations
            .push("Consider manual reverse engineering in isolated environment.".to_string());
    } else if evasion_score > 40.0 {
        recommendations.push(
            "High evasion techniques detected. Extended sandbox analysis recommended.".to_string(),
        );
        recommendations.push("Monitor for delayed execution and environment checks.".to_string());
    }

    // Anti-analysis recommendations
    for technique in anti_analysis {
        match technique.technique_type {
            AntiAnalysisType::AntiDebug => {
                recommendations.push(
                    "Anti-debugging detected. Use kernel-mode debugger or bypass techniques."
                        .to_string(),
                );
            }
            AntiAnalysisType::AntiVM => {
                recommendations.push(
                    "VM detection present. Use bare-metal analysis or VM hiding techniques."
                        .to_string(),
                );
            }
            AntiAnalysisType::AntiSandbox => {
                recommendations.push(
                    "Sandbox evasion detected. Extend analysis time and simulate user activity."
                        .to_string(),
                );
            }
            AntiAnalysisType::ProcessHollowing => {
                recommendations.push(
                    "Process hollowing capability. Monitor child process creation closely."
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    // Persistence recommendations
    if !persistence.is_empty() {
        recommendations
            .push("Persistence mechanisms detected. Check system after reboot.".to_string());

        for mechanism in persistence {
            match mechanism.mechanism_type {
                PersistenceType::RegistryKeys => {
                    recommendations
                        .push("Registry persistence found. Monitor registry changes.".to_string());
                }
                PersistenceType::ServiceInstallation => {
                    recommendations.push(
                        "Service installation capability. Check installed services.".to_string(),
                    );
                }
                PersistenceType::ScheduledTasks => {
                    recommendations
                        .push("Scheduled task persistence. Review task scheduler.".to_string());
                }
                _ => {}
            }
        }
    }

    // Network recommendations
    for pattern in network {
        match pattern.pattern_type {
            NetworkPatternType::CommandAndControl => {
                // Low means ordinary strings (a URL in help text): nothing to act on.
                if !matches!(pattern.suspicious_level, SuspicionLevel::Low) {
                    recommendations.push(
                        "Possible C&C communication strings found. Check the evidence under \
                         network_behavior and monitor traffic to those hosts."
                            .to_string(),
                    );
                    if !pattern.evidence.is_empty() {
                        recommendations.push(
                            "Verify the hosts in that evidence before blocking them at the \
                             firewall."
                                .to_string(),
                        );
                    }
                }
            }
            NetworkPatternType::TorUsage => {
                recommendations
                    .push("Tor usage detected. Sample may use hidden services.".to_string());
            }
            NetworkPatternType::DataExfiltration => {
                recommendations.push(
                    "Data exfiltration capability. Monitor outbound connections.".to_string(),
                );
            }
            _ => {}
        }
    }

    // Behavior-specific recommendations
    for behavior in suspicious_behaviors {
        match behavior.behavior_type.as_str() {
            "Ransomware" => {
                recommendations
                    .push("RANSOMWARE BEHAVIOR DETECTED! Isolate immediately.".to_string());
                recommendations.push("Backup critical files before any execution.".to_string());
                recommendations.push("Monitor file system for encryption activity.".to_string());
            }
            "Rootkit" => {
                recommendations
                    .push("Rootkit behavior detected. Use rootkit detection tools.".to_string());
                recommendations.push("Check for hidden processes and files.".to_string());
            }
            "Backdoor" => {
                recommendations.push(
                    "Backdoor functionality detected. Scan for network listeners.".to_string(),
                );
                recommendations.push("Check all persistence locations.".to_string());
            }
            "DataTheft" => {
                recommendations
                    .push("Data theft capability. Monitor sensitive file access.".to_string());
                recommendations.push("Check for credential dumping attempts.".to_string());
            }
            _ => {}
        }
    }

    if recommendations.is_empty() {
        recommendations.push("No significant behavioral anomalies detected.".to_string());
        recommendations.push("Standard security monitoring recommended.".to_string());
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disassembly::{
        ControlFlowSummary, InstructionAnalysis, OutputFormats, PatternType,
        Severity as DisassemblySeverity, SuspiciousPattern,
    };
    use crate::function_analysis::{FunctionInfo, FunctionType, ImportInfo, SymbolCounts};
    use crate::strings::InterestingString;
    use std::collections::HashMap;

    fn create_test_strings() -> ExtractedStrings {
        ExtractedStrings {
            total_count: 8,
            unique_count: 8,
            ascii_strings: vec![
                "IsDebuggerPresent".to_string(),
                "CreateRemoteThread".to_string(),
                "http://malware.com".to_string(),
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                ".exe".to_string(),
                "RegCreateKey".to_string(),
            ],
            unicode_strings: vec!["VMware".to_string(), "C:\\Windows\\System32".to_string()],
            interesting_strings: vec![InterestingString {
                category: "API".to_string(),
                value: "CreateRemoteThread".to_string(),
                offset: 100,
            }],
        }
    }

    fn create_test_symbols() -> SymbolTable {
        SymbolTable {
            functions: vec![
                FunctionInfo {
                    name: "CreateRemoteThread".to_string(),
                    address: 0x1000,
                    size: 100,
                    function_type: FunctionType::Imported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: false,
                    is_exported: false,
                    is_imported: true,
                },
                FunctionInfo {
                    name: "WriteProcessMemory".to_string(),
                    address: 0x2000,
                    size: 150,
                    function_type: FunctionType::Imported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: false,
                    is_exported: false,
                    is_imported: true,
                },
                FunctionInfo {
                    name: "CreateFile".to_string(),
                    address: 0x3000,
                    size: 200,
                    function_type: FunctionType::Imported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: false,
                    is_exported: false,
                    is_imported: true,
                },
            ],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![
                ImportInfo {
                    name: "kernel32.dll".to_string(),
                    library: Some("kernel32".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "ntdll.dll".to_string(),
                    library: Some("ntdll".to_string()),
                    address: Some(0x2000),
                    ordinal: None,
                    is_delayed: false,
                },
            ],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 3,
                local_functions: 0,
                imported_functions: 3,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        }
    }

    fn create_test_disassembly() -> DisassemblyResult {
        DisassemblyResult {
            architecture: "x86_64".to_string(),
            instructions: vec![],
            analysis: InstructionAnalysis {
                total_instructions: 1,
                instruction_types: HashMap::new(),
                register_usage: HashMap::new(),
                memory_accesses: vec![],
                system_calls: vec![],
                crypto_operations: vec![],
                suspicious_patterns: vec![SuspiciousPattern {
                    pattern_type: PatternType::NopSled,
                    addresses: vec![0x1000],
                    description: "NOP sled detected".to_string(),
                    severity: DisassemblySeverity::Medium,
                }],
                control_flow_summary: ControlFlowSummary {
                    total_jumps: 0,
                    conditional_jumps: 0,
                    unconditional_jumps: 0,
                    function_calls: 0,
                    indirect_calls: 0,
                    returns: 0,
                    interrupts: 0,
                },
            },
            functions: vec![],
            output_formats: OutputFormats {
                assembly: "test".to_string(),
                json_structured: serde_json::json!({}),
                graph_data: crate::disassembly::GraphVisualizationData {
                    nodes: vec![],
                    edges: vec![],
                },
            },
        }
    }

    #[test]
    fn test_evasion_score_calculation() {
        let anti_analysis = vec![AntiAnalysisTechnique {
            evidence: Vec::new(),
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: vec!["IsDebuggerPresent".to_string()],
            confidence: 0.9,
            description: "Test".to_string(),
        }];

        let behaviors = vec![];

        let score = calculate_evasion_score(&anti_analysis, &behaviors);
        assert!(score > 0.0 && score <= 100.0);
    }

    #[test]
    fn test_evasion_score_with_critical_behaviors() {
        let anti_analysis = vec![
            AntiAnalysisTechnique {
                evidence: Vec::new(),
                technique_type: AntiAnalysisType::ProcessHollowing,
                indicators: vec!["NtUnmapViewOfSection".to_string()],
                confidence: 1.0,
                description: "Process hollowing".to_string(),
            },
            AntiAnalysisTechnique {
                evidence: Vec::new(),
                technique_type: AntiAnalysisType::Obfuscation,
                indicators: vec!["Self-modifying code".to_string()],
                confidence: 0.8,
                description: "Code obfuscation".to_string(),
            },
        ];

        let behaviors = vec![
            SuspiciousBehavior {
                behavior_type: "Ransomware".to_string(),
                description: "File encryption detected".to_string(),
                severity: Severity::Critical,
                evidence: vec!["File encryption".to_string()],
            },
            SuspiciousBehavior {
                behavior_type: "Backdoor".to_string(),
                description: "C&C communication".to_string(),
                severity: Severity::Critical,
                evidence: vec!["Network communication".to_string()],
            },
        ];

        let score = calculate_evasion_score(&anti_analysis, &behaviors);
        assert!(score > 40.0);
        assert!(score <= 100.0);
    }

    #[test]
    fn test_evasion_score_caps_at_100() {
        let anti_analysis = vec![
            AntiAnalysisTechnique {
                evidence: Vec::new(),
                technique_type: AntiAnalysisType::ProcessHollowing,
                indicators: vec!["test".to_string()],
                confidence: 1.0,
                description: "test".to_string(),
            };
            10 // Large number to force high score
        ];

        let behaviors = vec![
            SuspiciousBehavior {
                behavior_type: "Critical".to_string(),
                description: "test".to_string(),
                severity: Severity::Critical,
                evidence: vec!["test".to_string()],
            };
            20 // Large number to force high score
        ];

        let score = calculate_evasion_score(&anti_analysis, &behaviors);
        assert_eq!(score, 100.0);
    }

    #[test]
    fn test_detect_anti_analysis_debug_techniques() {
        let strings = create_test_strings();
        let symbols = create_test_symbols();
        let disassembly = create_test_disassembly();

        let techniques = detect_anti_analysis(Some(&strings), Some(&symbols), Some(&disassembly));

        let anti_debug = techniques
            .iter()
            .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiDebug));
        assert!(anti_debug.is_some());

        let anti_debug = anti_debug.unwrap();
        assert!(!anti_debug.indicators.is_empty());
        assert!(anti_debug.confidence > 0.0);
        assert!(anti_debug.description.contains("Debugger"));
    }

    #[test]
    fn test_detect_anti_analysis_vm_techniques() {
        let mut strings = create_test_strings();
        strings.ascii_strings.push("VirtualBox".to_string());
        strings.ascii_strings.push("CPUID".to_string());

        let techniques = detect_anti_analysis(Some(&strings), None, None);

        let anti_vm = techniques
            .iter()
            .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiVM));
        assert!(anti_vm.is_some());

        let anti_vm = anti_vm.unwrap();
        assert!(!anti_vm.indicators.is_empty());
        assert!(anti_vm.confidence > 0.0);
        assert!(anti_vm.indicators.contains(&"VirtualBox".to_string()));
    }

    #[test]
    fn test_detect_anti_analysis_sandbox_techniques() {
        let mut strings = create_test_strings();
        strings.ascii_strings.extend([
            "SbieDll".to_string(),
            "sample".to_string(),
            "sandbox".to_string(),
            "GetCursorPos".to_string(),
        ]);

        let techniques = detect_anti_analysis(Some(&strings), None, None);

        let anti_sandbox = techniques
            .iter()
            .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiSandbox));
        assert!(anti_sandbox.is_some());

        let anti_sandbox = anti_sandbox.unwrap();
        assert!(anti_sandbox.indicators.len() >= 3);
        assert!(anti_sandbox.confidence > 0.0);
    }

    #[test]
    fn test_detect_anti_analysis_obfuscation() {
        let disassembly = create_test_disassembly();

        let techniques = detect_anti_analysis(None, None, Some(&disassembly));

        let obfuscation = techniques
            .iter()
            .find(|t| matches!(t.technique_type, AntiAnalysisType::Obfuscation));
        assert!(obfuscation.is_some());

        let obfuscation = obfuscation.unwrap();
        assert!(!obfuscation.indicators.is_empty());
        assert!(obfuscation.confidence > 0.0);
    }

    #[test]
    fn test_detect_persistence_registry_keys() {
        let strings = create_test_strings();

        let mechanisms = detect_persistence_mechanisms(Some(&strings), None);

        let registry_persistence = mechanisms
            .iter()
            .find(|m| matches!(m.mechanism_type, PersistenceType::RegistryKeys));
        assert!(registry_persistence.is_some());

        let registry_persistence = registry_persistence.unwrap();
        assert!(!registry_persistence.target_locations.is_empty());
        assert!(matches!(registry_persistence.severity, Severity::High));
    }

    #[test]
    fn test_detect_persistence_service_installation() {
        let mut symbols = create_test_symbols();
        symbols.functions.push(FunctionInfo {
            name: "CreateService".to_string(),
            address: 0x3000,
            size: 200,
            function_type: FunctionType::Imported,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        });
        symbols.functions.push(FunctionInfo {
            name: "OpenSCManager".to_string(),
            address: 0x4000,
            size: 150,
            function_type: FunctionType::Imported,
            calling_convention: None,
            parameters: vec![],
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        });

        let mechanisms = detect_persistence_mechanisms(None, Some(&symbols));

        let service_persistence = mechanisms
            .iter()
            .find(|m| matches!(m.mechanism_type, PersistenceType::ServiceInstallation));
        assert!(service_persistence.is_some());

        let service_persistence = service_persistence.unwrap();
        assert!(service_persistence.target_locations.len() >= 2);
        assert!(matches!(service_persistence.severity, Severity::High));
    }

    #[test]
    fn test_detect_persistence_scheduled_tasks() {
        let mut strings = create_test_strings();
        strings
            .ascii_strings
            .extend(["schtasks".to_string(), "Task Scheduler".to_string()]);

        let mechanisms = detect_persistence_mechanisms(Some(&strings), None);

        let task_persistence = mechanisms
            .iter()
            .find(|m| matches!(m.mechanism_type, PersistenceType::ScheduledTasks));
        assert!(task_persistence.is_some());

        let task_persistence = task_persistence.unwrap();
        assert!(!task_persistence.target_locations.is_empty());
        assert!(matches!(task_persistence.severity, Severity::Medium));
    }

    #[test]
    fn test_detect_persistence_dll_hijacking() {
        let mut strings = create_test_strings();
        strings.ascii_strings.extend([
            "LoadLibrary".to_string(),
            "SetDllDirectory".to_string(),
            ".dll".to_string(),
            "System32".to_string(),
        ]);

        let mechanisms = detect_persistence_mechanisms(Some(&strings), None);

        let dll_persistence = mechanisms
            .iter()
            .find(|m| matches!(m.mechanism_type, PersistenceType::DLLHijacking));
        assert!(dll_persistence.is_some());

        let dll_persistence = dll_persistence.unwrap();
        assert!(dll_persistence.target_locations.len() >= 3);
        assert!(matches!(dll_persistence.severity, Severity::High));
    }

    #[test]
    fn test_detect_network_patterns_command_control() {
        let mut strings = create_test_strings();
        strings.ascii_strings.extend([
            "https://malicious.com".to_string(),
            "POST".to_string(),
            "user-agent".to_string(),
            "192.168.1.100".to_string(),
        ]);

        let patterns = detect_network_patterns(Some(&strings), None);

        let cc_pattern = patterns
            .iter()
            .find(|p| matches!(p.pattern_type, NetworkPatternType::CommandAndControl));
        assert!(cc_pattern.is_some());

        let cc_pattern = cc_pattern.unwrap();
        assert!(!cc_pattern.indicators.is_empty());
        assert!(!cc_pattern.protocols.is_empty());
        assert!(matches!(
            cc_pattern.suspicious_level,
            SuspicionLevel::High | SuspicionLevel::Medium
        ));
    }

    #[test]
    fn test_detect_network_patterns_data_exfiltration() {
        let mut symbols = create_test_symbols();
        symbols.functions.extend([
            FunctionInfo {
                name: "socket".to_string(),
                address: 0x5000,
                size: 100,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "send".to_string(),
                address: 0x6000,
                size: 80,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "recv".to_string(),
                address: 0x7000,
                size: 80,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "connect".to_string(),
                address: 0x8000,
                size: 120,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
        ]);

        let patterns = detect_network_patterns(None, Some(&symbols));

        let exfil_pattern = patterns
            .iter()
            .find(|p| matches!(p.pattern_type, NetworkPatternType::DataExfiltration));
        assert!(exfil_pattern.is_some());

        let exfil_pattern = exfil_pattern.unwrap();
        assert!(exfil_pattern.indicators.len() >= 4);
        assert!(matches!(
            exfil_pattern.suspicious_level,
            SuspicionLevel::High
        ));
    }

    #[test]
    fn test_detect_network_patterns_tor_usage() {
        let mut strings = create_test_strings();
        strings.ascii_strings.extend([
            ".onion".to_string(),
            "9050".to_string(),
            "Tor Browser".to_string(),
        ]);

        let patterns = detect_network_patterns(Some(&strings), None);

        let tor_pattern = patterns
            .iter()
            .find(|p| matches!(p.pattern_type, NetworkPatternType::TorUsage));
        assert!(tor_pattern.is_some());

        let tor_pattern = tor_pattern.unwrap();
        assert!(!tor_pattern.indicators.is_empty());
        assert!(tor_pattern.ports.contains(&9050));
        assert!(matches!(tor_pattern.suspicious_level, SuspicionLevel::High));
    }

    #[test]
    fn test_detect_file_operations() {
        let strings = create_test_strings();
        let mut symbols = create_test_symbols();
        symbols.functions.extend([
            FunctionInfo {
                name: "CreateFile".to_string(),
                address: 0x9000,
                size: 200,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "DeleteFile".to_string(),
                address: 0xA000,
                size: 150,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
        ]);

        let operations = detect_file_operations(Some(&strings), Some(&symbols));

        assert!(!operations.is_empty());

        let creation_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, FileOpType::FileCreation));
        assert!(creation_op.is_some());

        let deletion_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, FileOpType::FileDeletion));
        assert!(deletion_op.is_some());
        assert!(deletion_op.unwrap().suspicious);
    }

    #[test]
    fn test_detect_file_operations_encryption() {
        let mut strings = create_test_strings();
        strings.ascii_strings.extend([
            "CryptEncrypt".to_string(),
            "AES".to_string(),
            ".encrypted".to_string(),
        ]);

        let operations = detect_file_operations(Some(&strings), None);

        let encryption_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, FileOpType::FileEncryption));
        assert!(encryption_op.is_some());

        let encryption_op = encryption_op.unwrap();
        assert!(encryption_op.suspicious);
        assert!(encryption_op.targets.len() >= 2);
    }

    #[test]
    fn test_detect_registry_operations() {
        let strings = create_test_strings();

        let operations = detect_registry_operations(Some(&strings));

        assert!(!operations.is_empty());

        let creation_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, RegistryOpType::KeyCreation));
        assert!(creation_op.is_some());

        let modification_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, RegistryOpType::ValueModification));
        assert!(modification_op.is_some());
    }

    #[test]
    fn test_detect_registry_operations_comprehensive() {
        let mut strings = create_test_strings();
        strings.ascii_strings.extend([
            "RegSetValue".to_string(),
            "RegDeleteKey".to_string(),
            "HKEY_LOCAL_MACHINE".to_string(),
            "SYSTEM\\CurrentControlSet".to_string(),
        ]);

        let operations = detect_registry_operations(Some(&strings));

        assert!(operations.len() >= 4);

        let deletion_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, RegistryOpType::KeyDeletion));
        assert!(deletion_op.is_some());
    }

    #[test]
    fn test_detect_process_operations() {
        let symbols = create_test_symbols();

        let operations = detect_process_operations(None, Some(&symbols));

        assert!(!operations.is_empty());

        let injection_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, ProcessOpType::ProcessInjection));
        assert!(injection_op.is_some());

        let injection_op = injection_op.unwrap();
        assert!(!injection_op.techniques.is_empty());
    }

    #[test]
    fn test_detect_process_operations_hollowing() {
        let mut symbols = create_test_symbols();
        symbols.functions.extend([
            FunctionInfo {
                name: "NtUnmapViewOfSection".to_string(),
                address: 0xB000,
                size: 100,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "CreateProcess".to_string(),
                address: 0xC000,
                size: 300,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "SetThreadContext".to_string(),
                address: 0xD000,
                size: 150,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "ResumeThread".to_string(),
                address: 0xE000,
                size: 80,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
        ]);

        let operations = detect_process_operations(None, Some(&symbols));

        let hollowing_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, ProcessOpType::ProcessHollowing));
        assert!(hollowing_op.is_some());

        let hollowing_op = hollowing_op.unwrap();
        assert!(!hollowing_op.techniques.is_empty());
        assert!(hollowing_op
            .techniques
            .contains(&"NtUnmapViewOfSection".to_string()));
    }

    #[test]
    fn test_detect_process_operations_privilege_escalation() {
        let mut symbols = create_test_symbols();
        symbols.functions.extend([
            FunctionInfo {
                name: "AdjustTokenPrivileges".to_string(),
                address: 0xF000,
                size: 200,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
            FunctionInfo {
                name: "OpenProcessToken".to_string(),
                address: 0x10000,
                size: 150,
                function_type: FunctionType::Imported,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            },
        ]);

        let operations = detect_process_operations(None, Some(&symbols));

        let priv_esc_op = operations
            .iter()
            .find(|op| matches!(op.operation_type, ProcessOpType::PrivilegeEscalation));
        assert!(priv_esc_op.is_some());

        let priv_esc_op = priv_esc_op.unwrap();
        assert!(priv_esc_op.techniques.len() >= 2);
    }

    #[test]
    fn test_identify_suspicious_behaviors_ransomware() {
        let anti_analysis = vec![];
        let persistence = vec![];
        let network = vec![];
        let file_ops = vec![
            FileOperation {
                operation_type: FileOpType::FileEncryption,
                targets: vec!["CryptEncrypt".to_string()],
                suspicious: true,
            },
            FileOperation {
                operation_type: FileOpType::FileDeletion,
                targets: vec!["DeleteFile".to_string()],
                suspicious: true,
            },
        ];
        let process_ops = vec![];

        let behaviors = identify_suspicious_behaviors(
            &anti_analysis,
            &persistence,
            &network,
            &file_ops,
            &process_ops,
        );

        let ransomware = behaviors.iter().find(|b| b.behavior_type == "Ransomware");
        assert!(ransomware.is_some());

        let ransomware = ransomware.unwrap();
        assert!(matches!(ransomware.severity, Severity::Critical));
        assert!(!ransomware.evidence.is_empty());
    }

    #[test]
    fn test_identify_suspicious_behaviors_rootkit() {
        let anti_analysis = vec![];
        let persistence = vec![PersistenceMechanism {
            evidence: Vec::new(),
            mechanism_type: PersistenceType::ServiceInstallation,
            target_locations: vec!["CreateService".to_string()],
            severity: Severity::High,
            description: "Service installation".to_string(),
        }];
        let network = vec![];
        let file_ops = vec![];
        let process_ops = vec![ProcessOperation {
            operation_type: ProcessOpType::ProcessInjection,
            targets: vec!["target_process".to_string()],
            techniques: vec!["NtCreateThreadEx".to_string()],
        }];

        let behaviors = identify_suspicious_behaviors(
            &anti_analysis,
            &persistence,
            &network,
            &file_ops,
            &process_ops,
        );

        let rootkit = behaviors.iter().find(|b| b.behavior_type == "Rootkit");
        assert!(rootkit.is_some());

        let rootkit = rootkit.unwrap();
        assert!(matches!(rootkit.severity, Severity::Critical));
    }

    #[test]
    fn test_identify_suspicious_behaviors_backdoor() {
        let anti_analysis = vec![];
        let persistence = vec![PersistenceMechanism {
            evidence: Vec::new(),
            mechanism_type: PersistenceType::RegistryKeys,
            target_locations: vec!["Run key".to_string()],
            severity: Severity::High,
            description: "Registry persistence".to_string(),
        }];
        let network = vec![NetworkPattern {
            evidence: Vec::new(),
            pattern_type: NetworkPatternType::CommandAndControl,
            indicators: vec!["http://evil.com".to_string()],
            protocols: vec!["HTTP".to_string()],
            ports: vec![80],
            suspicious_level: SuspicionLevel::High,
        }];
        let file_ops = vec![];
        let process_ops = vec![ProcessOperation {
            operation_type: ProcessOpType::ProcessCreation,
            targets: vec!["cmd.exe".to_string()],
            techniques: vec!["CreateProcess".to_string()],
        }];

        let behaviors = identify_suspicious_behaviors(
            &anti_analysis,
            &persistence,
            &network,
            &file_ops,
            &process_ops,
        );

        let backdoor = behaviors.iter().find(|b| b.behavior_type == "Backdoor");
        assert!(backdoor.is_some());

        let backdoor = backdoor.unwrap();
        assert!(matches!(backdoor.severity, Severity::Critical));
        assert!(backdoor.evidence.len() >= 3);
    }

    #[test]
    fn test_identify_suspicious_behaviors_data_theft() {
        let anti_analysis = vec![];
        let persistence = vec![];
        let network = vec![NetworkPattern {
            evidence: Vec::new(),
            pattern_type: NetworkPatternType::DataExfiltration,
            indicators: vec!["send".to_string()],
            protocols: vec!["TCP".to_string()],
            ports: vec![443],
            suspicious_level: SuspicionLevel::High,
        }];
        let file_ops = vec![FileOperation {
            operation_type: FileOpType::FileCopying,
            targets: vec!["CopyFile".to_string()],
            suspicious: false,
        }];
        let process_ops = vec![];

        let behaviors = identify_suspicious_behaviors(
            &anti_analysis,
            &persistence,
            &network,
            &file_ops,
            &process_ops,
        );

        let data_theft = behaviors.iter().find(|b| b.behavior_type == "DataTheft");
        assert!(data_theft.is_some());

        let data_theft = data_theft.unwrap();
        assert!(matches!(data_theft.severity, Severity::High));
    }

    #[test]
    fn test_identify_suspicious_behaviors_dropper() {
        let anti_analysis = vec![];
        let persistence = vec![];
        let network = vec![NetworkPattern {
            evidence: Vec::new(),
            pattern_type: NetworkPatternType::DataExfiltration,
            indicators: vec!["URLDownloadToFile".to_string()],
            protocols: vec!["HTTP".to_string()],
            ports: vec![80],
            suspicious_level: SuspicionLevel::Medium,
        }];
        let file_ops = vec![FileOperation {
            operation_type: FileOpType::FileCreation,
            targets: vec!["CreateFile".to_string()],
            suspicious: false,
        }];
        let process_ops = vec![ProcessOperation {
            operation_type: ProcessOpType::ProcessCreation,
            targets: vec!["downloaded.exe".to_string()],
            techniques: vec!["CreateProcess".to_string()],
        }];

        let behaviors = identify_suspicious_behaviors(
            &anti_analysis,
            &persistence,
            &network,
            &file_ops,
            &process_ops,
        );

        let dropper = behaviors.iter().find(|b| b.behavior_type == "Dropper");
        assert!(dropper.is_some());

        let dropper = dropper.unwrap();
        assert!(matches!(dropper.severity, Severity::High));
        assert!(dropper.evidence.len() >= 3);
    }

    #[test]
    fn test_generate_behavioral_recommendations_high_evasion() {
        let anti_analysis = vec![AntiAnalysisTechnique {
            evidence: Vec::new(),
            technique_type: AntiAnalysisType::ProcessHollowing,
            indicators: vec!["hollowing".to_string()],
            confidence: 1.0,
            description: "Process hollowing".to_string(),
        }];
        let persistence = vec![];
        let network = vec![];
        let behaviors = vec![SuspiciousBehavior {
            behavior_type: "Ransomware".to_string(),
            description: "File encryption".to_string(),
            severity: Severity::Critical,
            evidence: vec!["encryption".to_string()],
        }];

        let recommendations = generate_behavioral_recommendations(
            &anti_analysis,
            &persistence,
            &network,
            &behaviors,
            80.0,
        );

        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| r.contains("CRITICAL")));
        assert!(recommendations.iter().any(|r| r.contains("RANSOMWARE")));
        assert!(recommendations
            .iter()
            .any(|r| r.contains("Process hollowing")));
    }

    #[test]
    fn test_generate_behavioral_recommendations_medium_evasion() {
        let anti_analysis = vec![AntiAnalysisTechnique {
            evidence: Vec::new(),
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: vec!["debug".to_string()],
            confidence: 0.8,
            description: "Anti-debugging".to_string(),
        }];
        let persistence = vec![];
        let network = vec![];
        let behaviors = vec![];

        let recommendations = generate_behavioral_recommendations(
            &anti_analysis,
            &persistence,
            &network,
            &behaviors,
            50.0,
        );

        assert!(!recommendations.is_empty());
        assert!(recommendations
            .iter()
            .any(|r| r.contains("Extended sandbox")));
        assert!(recommendations
            .iter()
            .any(|r| r.contains("kernel-mode debugger")));
    }

    #[test]
    fn test_generate_behavioral_recommendations_persistence() {
        let anti_analysis = vec![];
        let persistence = vec![
            PersistenceMechanism {
                evidence: Vec::new(),
                mechanism_type: PersistenceType::RegistryKeys,
                target_locations: vec!["Run".to_string()],
                severity: Severity::High,
                description: "Registry persistence".to_string(),
            },
            PersistenceMechanism {
                evidence: Vec::new(),
                mechanism_type: PersistenceType::ServiceInstallation,
                target_locations: vec!["Service".to_string()],
                severity: Severity::High,
                description: "Service persistence".to_string(),
            },
        ];
        let network = vec![];
        let behaviors = vec![];

        let recommendations = generate_behavioral_recommendations(
            &anti_analysis,
            &persistence,
            &network,
            &behaviors,
            10.0,
        );

        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| r.contains("reboot")));
        assert!(recommendations.iter().any(|r| r.contains("registry")));
        assert!(recommendations.iter().any(|r| r.contains("services")));
    }

    #[test]
    fn test_generate_behavioral_recommendations_network() {
        let anti_analysis = vec![];
        let persistence = vec![];
        let network = vec![
            NetworkPattern {
                evidence: vec![StringEvidence {
                    value: "https://c2.evil.com/beacon".to_string(),
                    offset: Some(1024),
                }],
                pattern_type: NetworkPatternType::CommandAndControl,
                indicators: vec!["c2.evil.com".to_string()],
                protocols: vec!["HTTPS".to_string()],
                ports: vec![443],
                suspicious_level: SuspicionLevel::High,
            },
            NetworkPattern {
                evidence: Vec::new(),
                pattern_type: NetworkPatternType::TorUsage,
                indicators: vec![".onion".to_string()],
                protocols: vec!["Tor".to_string()],
                ports: vec![9050],
                suspicious_level: SuspicionLevel::High,
            },
        ];
        let behaviors = vec![];

        let recommendations = generate_behavioral_recommendations(
            &anti_analysis,
            &persistence,
            &network,
            &behaviors,
            10.0,
        );

        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| r.contains("C&C")));
        assert!(recommendations.iter().any(|r| r.contains("firewall")));
        assert!(recommendations.iter().any(|r| r.contains("Tor")));
    }

    #[test]
    fn test_generate_behavioral_recommendations_no_threats() {
        let anti_analysis = vec![];
        let persistence = vec![];
        let network = vec![];
        let behaviors = vec![];

        let recommendations = generate_behavioral_recommendations(
            &anti_analysis,
            &persistence,
            &network,
            &behaviors,
            5.0,
        );

        assert!(!recommendations.is_empty());
        assert!(recommendations
            .iter()
            .any(|r| r.contains("No significant behavioral anomalies")));
        assert!(recommendations
            .iter()
            .any(|r| r.contains("Standard security monitoring")));
    }

    #[test]
    fn test_analyze_behavior_integration() {
        use std::path::Path;

        let path = Path::new("/test/file");
        let strings = create_test_strings();
        let symbols = create_test_symbols();
        let disassembly = create_test_disassembly();

        let result = analyze_behavior(path, Some(&strings), Some(&symbols), Some(&disassembly));
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(!analysis.anti_analysis.is_empty());
        assert!(!analysis.persistence.is_empty());
        assert!(!analysis.network_behavior.is_empty());
        assert!(!analysis.file_operations.is_empty());
        assert!(!analysis.registry_operations.is_empty());
        assert!(!analysis.process_operations.is_empty());
        assert!(analysis.evasion_score >= 0.0);
        assert!(analysis.evasion_score <= 100.0);
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_data_structure_serialization() {
        let analysis = BehavioralAnalysis {
            string_coverage: None,
            anti_analysis: vec![AntiAnalysisTechnique {
                evidence: Vec::new(),
                technique_type: AntiAnalysisType::AntiDebug,
                indicators: vec!["test".to_string()],
                confidence: 0.8,
                description: "Test technique".to_string(),
            }],
            persistence: vec![PersistenceMechanism {
                evidence: Vec::new(),
                mechanism_type: PersistenceType::RegistryKeys,
                target_locations: vec!["test_key".to_string()],
                severity: Severity::High,
                description: "Test persistence".to_string(),
            }],
            network_behavior: vec![NetworkPattern {
                evidence: Vec::new(),
                pattern_type: NetworkPatternType::CommandAndControl,
                indicators: vec!["test_indicator".to_string()],
                protocols: vec!["HTTP".to_string()],
                ports: vec![80],
                suspicious_level: SuspicionLevel::High,
            }],
            file_operations: vec![FileOperation {
                operation_type: FileOpType::FileCreation,
                targets: vec!["test_file".to_string()],
                suspicious: false,
            }],
            registry_operations: vec![RegistryOperation {
                operation_type: RegistryOpType::KeyCreation,
                keys: vec!["test_key".to_string()],
                purpose: "Test purpose".to_string(),
            }],
            process_operations: vec![ProcessOperation {
                operation_type: ProcessOpType::ProcessCreation,
                targets: vec!["test_process".to_string()],
                techniques: vec!["test_technique".to_string()],
            }],
            evasion_score: 42.5,
            suspicious_behaviors: vec![SuspiciousBehavior {
                behavior_type: "TestBehavior".to_string(),
                description: "Test behavior description".to_string(),
                severity: Severity::Medium,
                evidence: vec!["test_evidence".to_string()],
            }],
            recommendations: vec!["Test recommendation".to_string()],
        };

        // Test JSON serialization
        let json_result = serde_json::to_string(&analysis);
        assert!(json_result.is_ok());

        let deserialized_result: Result<BehavioralAnalysis, _> =
            serde_json::from_str(&json_result.unwrap());
        assert!(deserialized_result.is_ok());

        let deserialized = deserialized_result.unwrap();
        assert_eq!(deserialized.evasion_score, 42.5);
        assert_eq!(deserialized.anti_analysis.len(), 1);
        assert_eq!(deserialized.persistence.len(), 1);
        assert_eq!(deserialized.suspicious_behaviors.len(), 1);
    }

    #[test]
    fn test_enum_variations() {
        // Test all AntiAnalysisType variants
        let anti_types = vec![
            AntiAnalysisType::AntiDebug,
            AntiAnalysisType::AntiVM,
            AntiAnalysisType::AntiSandbox,
            AntiAnalysisType::AntiDisassembly,
            AntiAnalysisType::Obfuscation,
            AntiAnalysisType::TimeDelays,
            AntiAnalysisType::EnvironmentChecks,
            AntiAnalysisType::ProcessHollowing,
            AntiAnalysisType::CodeInjection,
        ];

        for anti_type in anti_types {
            let technique = AntiAnalysisTechnique {
                evidence: Vec::new(),
                technique_type: anti_type,
                indicators: vec!["test".to_string()],
                confidence: 0.8,
                description: "test".to_string(),
            };
            assert!(serde_json::to_string(&technique).is_ok());
        }

        // Test all PersistenceType variants
        let persistence_types = vec![
            PersistenceType::RegistryKeys,
            PersistenceType::ServiceInstallation,
            PersistenceType::ScheduledTasks,
            PersistenceType::StartupFolders,
            PersistenceType::DLLHijacking,
            PersistenceType::ProcessInjection,
            PersistenceType::BootkitRootkit,
            PersistenceType::WMIEventSubscription,
            PersistenceType::BrowserExtension,
            PersistenceType::OfficeAddins,
        ];

        for pers_type in persistence_types {
            let mechanism = PersistenceMechanism {
                evidence: Vec::new(),
                mechanism_type: pers_type,
                target_locations: vec!["test".to_string()],
                severity: Severity::Medium,
                description: "test".to_string(),
            };
            assert!(serde_json::to_string(&mechanism).is_ok());
        }

        // Test all NetworkPatternType variants
        let network_types = vec![
            NetworkPatternType::CommandAndControl,
            NetworkPatternType::DataExfiltration,
            NetworkPatternType::DomainGeneration,
            NetworkPatternType::TorUsage,
            NetworkPatternType::P2PCommunication,
            NetworkPatternType::HTTPSBypass,
            NetworkPatternType::DNSTunneling,
            NetworkPatternType::IRCCommunication,
        ];

        for net_type in network_types {
            let pattern = NetworkPattern {
                evidence: Vec::new(),
                pattern_type: net_type,
                indicators: vec!["test".to_string()],
                protocols: vec!["TCP".to_string()],
                ports: vec![80],
                suspicious_level: SuspicionLevel::Medium,
            };
            assert!(serde_json::to_string(&pattern).is_ok());
        }
    }

    #[test]
    fn test_hash_and_eq_implementations() {
        use std::collections::HashSet;

        // Test FileOpType hash and equality
        let mut file_ops = HashSet::new();
        file_ops.insert(FileOpType::FileCreation);
        file_ops.insert(FileOpType::FileDeletion);
        file_ops.insert(FileOpType::FileCreation); // Duplicate
        assert_eq!(file_ops.len(), 2);

        // Test ProcessOpType hash and equality
        let mut process_ops = HashSet::new();
        process_ops.insert(ProcessOpType::ProcessCreation);
        process_ops.insert(ProcessOpType::ProcessInjection);
        process_ops.insert(ProcessOpType::ProcessCreation); // Duplicate
        assert_eq!(process_ops.len(), 2);
    }

    // ---- all strings, evidence and the C&C rating

    fn file_with(lines: &[String]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, lines.join("\n")).unwrap();
        (dir, path)
    }

    fn filler(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("filler_line_number_{i:05}"))
            .collect()
    }

    fn capped(lines: &[String]) -> ExtractedStrings {
        // What `extract_strings` hands over: the first 1,000 only.
        ExtractedStrings {
            total_count: lines.len(),
            unique_count: lines.len(),
            ascii_strings: lines.iter().take(1000).cloned().collect(),
            unicode_strings: vec![],
            interesting_strings: vec![],
        }
    }

    #[test]
    fn indicators_after_the_first_thousand_strings_are_found() {
        let indicators = [
            "IsDebuggerPresent",
            "VBoxService",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "schtasks /create",
        ];
        let mut early = indicators
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        early.extend(filler(1100));
        let mut late = filler(1100);
        late.extend(indicators.iter().map(ToString::to_string));

        let (_d1, early_path) = file_with(&early);
        let (_d2, late_path) = file_with(&late);
        let early_result =
            analyze_behavior(&early_path, Some(&capped(&early)), None, None).unwrap();
        let late_result = analyze_behavior(&late_path, Some(&capped(&late)), None, None).unwrap();

        for result in [&early_result, &late_result] {
            assert!(
                result
                    .anti_analysis
                    .iter()
                    .any(|t| matches!(t.technique_type, AntiAnalysisType::AntiDebug)),
                "{result:?}"
            );
            assert!(result
                .anti_analysis
                .iter()
                .any(|t| matches!(t.technique_type, AntiAnalysisType::AntiVM)));
            assert!(result
                .persistence
                .iter()
                .any(|p| matches!(p.mechanism_type, PersistenceType::RegistryKeys)));
            assert!(result
                .persistence
                .iter()
                .any(|p| matches!(p.mechanism_type, PersistenceType::ScheduledTasks)));
        }
        assert_eq!(early_result.evasion_score, late_result.evasion_score);
        assert!(late_result.evasion_score > 0.0);
        let coverage = late_result.string_coverage.as_ref().unwrap();
        assert!(coverage.strings_examined >= 1104);
        assert!(coverage.complete);
    }

    #[test]
    fn evidence_names_the_matching_string_and_its_offset() {
        let mut lines = filler(1100);
        lines.push("call IsDebuggerPresent now".to_string());
        let (_dir, path) = file_with(&lines);
        let expected = std::fs::read(&path)
            .unwrap()
            .windows(17)
            .position(|w| w == b"IsDebuggerPresent")
            .unwrap() as u64;
        // Even with no strings passed in, the file is searched.
        let result = analyze_behavior(&path, None, None, None).unwrap();
        let technique = result
            .anti_analysis
            .iter()
            .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiDebug))
            .unwrap();
        assert_eq!(technique.evidence[0].value, "call IsDebuggerPresent now");
        // The offset is where the string starts, 5 bytes before the keyword.
        assert_eq!(technique.evidence[0].offset, Some(expected - 5));
    }

    #[test]
    fn ordinary_urls_are_not_high_suspicion_command_and_control() {
        let lines = vec![
            "Report bugs to https://www.gnu.org/software/coreutils/".to_string(),
            "License GPLv3+: https://gnu.org/licenses/gpl.html".to_string(),
            "see http://www.gnu.org/software/coreutils/ for help".to_string(),
        ];
        let (_dir, path) = file_with(&lines);
        let result = analyze_behavior(&path, None, None, None).unwrap();
        let cc = result
            .network_behavior
            .iter()
            .find(|n| matches!(n.pattern_type, NetworkPatternType::CommandAndControl))
            .unwrap();
        assert!(matches!(cc.suspicious_level, SuspicionLevel::Low), "{cc:?}");
        // The evidence is the URLs themselves, with offsets.
        assert!(cc.evidence.iter().any(|e| e.value.contains("www.gnu.org")));
        assert!(cc.evidence.iter().all(|e| e.offset.is_some()), "{cc:?}");
        assert!(
            !result.recommendations.iter().any(|r| r.contains("C&C")),
            "{:?}",
            result.recommendations
        );
        assert!(!result
            .suspicious_behaviors
            .iter()
            .any(|b| b.behavior_type == "Backdoor" || b.behavior_type == "DataTheft"));
    }

    #[test]
    fn a_raw_ip_url_with_http_markers_is_rated_high_with_the_url_as_evidence() {
        let lines = vec![
            "POST /gate.php HTTP/1.1".to_string(),
            "user-agent: Mozilla/4.0".to_string(),
            "http://203.0.113.45:8080/gate.php".to_string(),
        ];
        let (_dir, path) = file_with(&lines);
        let result = analyze_behavior(&path, None, None, None).unwrap();
        let cc = result
            .network_behavior
            .iter()
            .find(|n| matches!(n.pattern_type, NetworkPatternType::CommandAndControl))
            .unwrap();
        assert!(
            matches!(cc.suspicious_level, SuspicionLevel::High),
            "{cc:?}"
        );
        assert!(cc
            .evidence
            .iter()
            .any(|e| e.value == "http://203.0.113.45:8080/gate.php" && e.offset.is_some()));
        assert!(result.recommendations.iter().any(|r| r.contains("C&C")));
    }

    #[test]
    fn short_words_inside_longer_words_are_not_indicators() {
        let lines = vec![
            "Xenial Xerus release notes".to_string(),
            "GETTING started with the sample documents".to_string(),
            "GetTickCount".to_string(),
        ];
        let (_dir, path) = file_with(&lines);
        let result = analyze_behavior(&path, None, None, None).unwrap();
        assert!(
            result.anti_analysis.is_empty(),
            "{:?}",
            result.anti_analysis
        );
    }

    #[test]
    fn the_corpus_bounds_make_coverage_incomplete() {
        let (_dir, path) = file_with(&[
            "first_string_here".to_string(),
            "second_string_here".to_string(),
            "third_string_here".to_string(),
        ]);
        let size = std::fs::metadata(&path).unwrap().len();
        // Read bound below the file size.
        let corpus = build_corpus_bounded(&path, None, size / 2, usize::MAX, usize::MAX);
        let coverage = corpus.coverage.unwrap();
        assert!(!coverage.complete, "{coverage:?}");
        assert_eq!(coverage.file_size, size);
        // String-byte bound.
        let coverage = build_corpus_bounded(&path, None, size, 10, usize::MAX)
            .coverage
            .unwrap();
        assert!(!coverage.complete && coverage.strings_examined < 3);
        // String-count bound.
        let coverage = build_corpus_bounded(&path, None, size, usize::MAX, 1)
            .coverage
            .unwrap();
        assert!(!coverage.complete && coverage.strings_examined == 1);
        // Generous bounds: complete.
        let coverage = build_corpus_bounded(&path, None, size, usize::MAX, usize::MAX)
            .coverage
            .unwrap();
        assert!(coverage.complete);
    }

    #[test]
    fn a_file_over_the_read_bound_is_reported_as_incomplete_or_complete() {
        let (_dir, path) = file_with(&["IsDebuggerPresent".to_string()]);
        let result = analyze_behavior(&path, None, None, None).unwrap();
        let coverage = result.string_coverage.unwrap();
        assert!(coverage.complete);
        assert_eq!(coverage.file_size, 17);
        // A path that is not a file leaves the passed strings as the only input.
        let result = analyze_behavior(
            std::path::Path::new("/nonexistent/file"),
            Some(&create_test_strings()),
            None,
            None,
        )
        .unwrap();
        assert!(result.string_coverage.is_some());
        assert!(!result.anti_analysis.is_empty());
    }

    #[test]
    fn a_giant_packed_string_is_shown_as_a_window_around_the_match() {
        // Go and Rust binaries keep their literals in one long run.
        let packed = format!(
            "{}https://example.org/path{}",
            "a".repeat(5000),
            "b".repeat(5000)
        );
        let (_dir, path) = file_with(std::slice::from_ref(&packed));
        let result = analyze_behavior(&path, None, None, None).unwrap();
        let cc = result
            .network_behavior
            .iter()
            .find(|n| matches!(n.pattern_type, NetworkPatternType::CommandAndControl))
            .unwrap();
        let shown = &cc.evidence[0];
        assert!(
            shown.value.chars().count() <= MAX_EVIDENCE_CHARS,
            "{}",
            shown.value.len()
        );
        assert!(shown.value.contains("https://"), "{}", shown.value);
        let in_file = std::fs::read(&path).unwrap();
        let at = shown.offset.unwrap() as usize;
        assert_eq!(&in_file[at..at + shown.value.len()], shown.value.as_bytes());
    }

    #[test]
    fn the_bare_text_onion_is_not_command_and_control_but_an_address_is() {
        let (_d1, bare) = file_with(&["resolving .onion names is not supported".to_string()]);
        let result = analyze_behavior(&bare, None, None, None).unwrap();
        assert!(
            result.network_behavior.iter().all(|n| matches!(
                n.suspicious_level,
                SuspicionLevel::Low | SuspicionLevel::Medium
            )),
            "{:?}",
            result.network_behavior
        );
        let (_d2, address) =
            file_with(&["http://expyuzz4wqqyqhjn.onion/gate user-agent".to_string()]);
        let result = analyze_behavior(&address, None, None, None).unwrap();
        let cc = result
            .network_behavior
            .iter()
            .find(|n| matches!(n.pattern_type, NetworkPatternType::CommandAndControl))
            .unwrap();
        assert!(
            matches!(cc.suspicious_level, SuspicionLevel::High),
            "{cc:?}"
        );
    }
}
