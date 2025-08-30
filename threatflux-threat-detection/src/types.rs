//! Core types and data structures for threat detection

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

/// Main threat analysis result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ThreatAnalysis {
    /// Detected matches from all engines
    pub matches: Vec<YaraMatch>,
    /// Overall threat level assessment
    pub threat_level: ThreatLevel,
    /// Threat classifications detected
    pub classifications: Vec<ThreatClassification>,
    /// Threat indicators found
    pub indicators: Vec<ThreatIndicator>,
    /// Scan statistics
    pub scan_stats: ScanStatistics,
    /// Security recommendations
    pub recommendations: Vec<String>,
}

/// Threat severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ThreatLevel {
    None,
    #[default]
    Clean,
    Suspicious,
    Malicious,
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::None => write!(f, "None"),
            ThreatLevel::Clean => write!(f, "Clean"),
            ThreatLevel::Suspicious => write!(f, "Suspicious"),
            ThreatLevel::Malicious => write!(f, "Malicious"),
            ThreatLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Threat classification categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ThreatClassification {
    Trojan,
    Virus,
    Worm,
    Rootkit,
    Adware,
    Spyware,
    Ransomware,
    Apt,
    Pua, // Potentially Unwanted Application
    Banker,
    Downloader,
    Backdoor,
    Exploit,
    Cryptominer,
    InfoStealer,
    Botnet,
    WebShell,
    Keylogger,
    ScreenCapture,
    RemoteAccess,
    Other(String),
}

impl std::fmt::Display for ThreatClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatClassification::Trojan => write!(f, "Trojan"),
            ThreatClassification::Virus => write!(f, "Virus"),
            ThreatClassification::Worm => write!(f, "Worm"),
            ThreatClassification::Rootkit => write!(f, "Rootkit"),
            ThreatClassification::Adware => write!(f, "Adware"),
            ThreatClassification::Spyware => write!(f, "Spyware"),
            ThreatClassification::Ransomware => write!(f, "Ransomware"),
            ThreatClassification::Apt => write!(f, "APT"),
            ThreatClassification::Pua => write!(f, "PUA"),
            ThreatClassification::Banker => write!(f, "Banker"),
            ThreatClassification::Downloader => write!(f, "Downloader"),
            ThreatClassification::Backdoor => write!(f, "Backdoor"),
            ThreatClassification::Exploit => write!(f, "Exploit"),
            ThreatClassification::Cryptominer => write!(f, "Cryptominer"),
            ThreatClassification::InfoStealer => write!(f, "InfoStealer"),
            ThreatClassification::Botnet => write!(f, "Botnet"),
            ThreatClassification::WebShell => write!(f, "WebShell"),
            ThreatClassification::Keylogger => write!(f, "Keylogger"),
            ThreatClassification::ScreenCapture => write!(f, "ScreenCapture"),
            ThreatClassification::RemoteAccess => write!(f, "RemoteAccess"),
            ThreatClassification::Other(s) => write!(f, "{}", s),
        }
    }
}

/// YARA rule match information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct YaraMatch {
    /// Rule identifier/name
    pub rule_identifier: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
    /// String matches within the rule
    pub strings: Vec<StringMatch>,
}

/// String match within a YARA rule
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct StringMatch {
    /// String identifier from the rule
    pub identifier: String,
    /// Offset in the file where match occurred
    pub offset: u64,
    /// Length of the match
    pub length: usize,
    /// Matched string value (if printable)
    pub value: Option<String>,
}

/// Threat indicators
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ThreatIndicator {
    /// Type of indicator
    pub indicator_type: IndicatorType,
    /// Human-readable description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// MITRE ATT&CK technique ID (if applicable)
    pub mitre_technique: Option<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Types of threat indicators
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum IndicatorType {
    KnownMalwareFamily,
    SuspiciousBehavior,
    ExploitTechnique,
    AntiAnalysis,
    NetworkIndicator,
    PersistenceMechanism,
    DataExfiltration,
    CryptoOperation,
    SystemModification,
    ProcessInjection,
    PrivilegeEscalation,
    LateralMovement,
    CommandAndControl,
    DefenseEvasion,
    Discovery,
    Collection,
    Exfiltration,
    Impact,
}

/// Severity levels for indicators
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum Severity {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// Scan statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ScanStatistics {
    /// Total scan duration
    pub scan_duration: Duration,
    /// Number of rules evaluated
    pub rules_evaluated: usize,
    /// Number of patterns matched
    pub patterns_matched: usize,
    /// Total bytes scanned
    pub file_size_scanned: u64,
}

/// Scan target specification
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum ScanTarget {
    /// Scan a file on disk
    File(PathBuf),
    /// Scan data in memory
    Memory { data: Vec<u8>, name: Option<String> },
    /// Scan a directory recursively
    Directory(PathBuf),
}

/// Detection engine trait
#[async_trait::async_trait]
pub trait DetectionEngine: Send + Sync {
    /// Get engine type name
    fn engine_type(&self) -> &str;

    /// Get engine version
    fn version(&self) -> &str;

    /// Scan a target
    async fn scan(&self, target: ScanTarget) -> crate::Result<ThreatAnalysis>;

    /// Scan with a custom rule
    async fn scan_with_custom_rule(
        &self,
        target: ScanTarget,
        rule: &str,
    ) -> crate::Result<ThreatAnalysis>;

    /// Update engine rules
    async fn update_rules(&mut self) -> crate::Result<()>;

    /// Check if engine is available
    fn is_available(&self) -> bool;
}

/// Engine configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct EngineConfig {
    /// Engine-specific configuration
    pub settings: HashMap<String, String>,
    /// Rule sources
    pub rule_sources: Vec<RuleSource>,
    /// Update interval for rules (hours)
    pub update_interval: u64,
}

/// Rule source configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct RuleSource {
    /// Source name/identifier
    pub name: String,
    /// Source URL or path
    pub url: String,
    /// Source type
    pub source_type: RuleSourceType,
    /// Authentication info (if needed)
    pub auth: Option<String>,
}

/// Types of rule sources
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum RuleSourceType {
    /// Git repository
    Git,
    /// HTTP/HTTPS URL
    Http,
    /// Local file system
    Local,
    /// Built-in rules
    Builtin,
}

/// Global scan configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ScanConfig {
    /// Maximum file size to scan
    pub max_file_size: u64,
    /// Scan timeout
    pub scan_timeout: Duration,
    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,
}

/// Rule compilation result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct CompiledRules {
    /// Number of rules compiled
    pub rule_count: usize,
    /// Compilation errors (if any)
    pub errors: Vec<String>,
    /// Warnings (if any)
    pub warnings: Vec<String>,
    /// Rule metadata
    pub metadata: HashMap<String, RuleMetadata>,
}

/// Metadata for individual rules
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct RuleMetadata {
    /// Rule name
    pub name: String,
    /// Rule author
    pub author: Option<String>,
    /// Rule description
    pub description: Option<String>,
    /// Rule version
    pub version: Option<String>,
    /// Last modified date
    pub date: Option<String>,
    /// Rule tags
    pub tags: Vec<String>,
}



impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,       // 100MB
            scan_timeout: Duration::from_secs(300), // 5 minutes
            max_concurrent_scans: 4,
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            settings: HashMap::new(),
            rule_sources: Vec::new(),
            update_interval: 24, // 24 hours
        }
    }
}
