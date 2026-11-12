use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

// Import threatflux-threat-detection for enhanced capabilities
use threatflux_threat_detection::{ThreatDetector, ThreatDetectorConfig};

// YARA-related types for scanning
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraFileMatch {
    pub file_path: String,
    pub file_size: u64,
    /// Rules that matched, at most `max_rules_per_file` of them.
    pub matches: Vec<YaraRuleMatch>,
    /// How many rules matched this file (more than `matches.len()` when the list was cut).
    #[serde(default)]
    pub rules_total: usize,
    /// Every matching rule's name, also past `max_rules_per_file`; used for
    /// the per-rule hit counts and not part of the answer.
    #[serde(skip)]
    #[schemars(skip)]
    pub all_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraRuleMatch {
    pub rule_identifier: String,
    pub tags: Vec<String>,
    pub metadata: std::collections::HashMap<String, String>,
    /// Listed string matches, at most `max_matches_per_rule` of them (none when
    /// detailed matches are off).
    pub strings: Vec<YaraStringMatch>,
    /// Every string match the rule produced, listed or not.
    #[serde(default)]
    pub strings_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    /// Length of the matched bytes in the file.
    pub length: usize,
    /// The matched bytes as text when they are printable UTF-8 (first 64 bytes).
    pub value: Option<String>,
    /// The matched bytes as space-separated upper-case hex when they are not
    /// printable text (first 64 bytes); use it to rebuild a hex pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

/// A file a YARA scan did not scan, with the reason.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraSkippedFile {
    pub file_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraScanError {
    pub file_path: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    pub matches: Vec<YaraMatch>,
    pub threat_level: ThreatLevel,
    pub classifications: Vec<ThreatClassification>,
    pub indicators: Vec<ThreatIndicator>,
    pub scan_stats: ScanStatistics,
    pub recommendations: Vec<String>,
    /// Enhanced analysis from threatflux-threat-detection (if available)
    pub enhanced_analysis: Option<EnhancedAnalysisInfo>,
    /// What each matched rule found in the file: the matched strings (capped)
    /// and their offsets.
    #[serde(default)]
    pub evidence: Vec<RuleEvidence>,
}

/// The strings behind one rule match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvidence {
    pub rule_identifier: String,
    /// Every string match the rule produced, listed or not.
    pub strings_total: usize,
    pub strings: Vec<YaraStringMatch>,
}

/// Information about enhanced analysis from threatflux-threat-detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAnalysisInfo {
    pub enabled: bool,
    pub confidence_score: f32,
    pub analysis_depth: String,
    /// Share of the engine's rules that were evaluated. The engine does not
    /// report this, so it is absent rather than a made-up number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_percentage: Option<f32>,
    pub engines_used: usize,
    /// The engine's own verdict, before it was merged into `threat_level`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_threat_level: Option<String>,
    /// Rules the engine matched. They are reported here, separately: the
    /// engine's rules are generic keyword rules that ordinary programs also
    /// hit, so they reach `matches`, `classifications`, `indicators` and
    /// `threat_level` only when a built-in rule that is not informational
    /// corroborates them (`engine_merged`); even then only its non-keyword
    /// rules and their indicators are added, never its classes.
    #[serde(default)]
    pub engine_matches: Vec<String>,
    /// The classes the engine proposed (not counted unless `engine_merged`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_classifications: Vec<String>,
    /// The indicators the engine proposed, as "Severity: description".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_indicators: Vec<String>,
    /// What the engine's strings matched, with offsets (up to 10 per rule).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_evidence: Vec<RuleEvidence>,
    /// True when the engine's non-keyword rules and indicators were folded into
    /// the top-level result (its classes never are).
    #[serde(default)]
    pub engine_merged: bool,
    /// Why the engine's findings were or were not counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_note: Option<String>,
    /// Why the enhanced engine did not run, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// A class the engine named that has no variant of its own.
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_identifier: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub scan_duration: Duration,
    pub rules_evaluated: usize,
    pub patterns_matched: usize,
    pub file_size_scanned: u64,
}

/// Longest stretch of matched bytes shown for a string match.
const MAX_SHOWN_MATCH_BYTES: usize = 64;
/// String matches kept as evidence per rule in `analyze_threats`.
const EVIDENCE_STRINGS_PER_RULE: usize = 10;
/// Largest file the threat scan reads into memory.
const MAX_THREAT_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// How long the built-in scan of one file may run.
const BUILTIN_SCAN_TIMEOUT: Duration = Duration::from_secs(60);

pub fn analyze_threats(path: &Path) -> Result<ThreatAnalysis> {
    let start_time = Instant::now();

    // Read file
    let size = fs::metadata(path)
        .context("Failed to read file for threat analysis")?
        .len();
    if size > MAX_THREAT_FILE_BYTES {
        anyhow::bail!(
            "The file is {size} bytes, above the {MAX_THREAT_FILE_BYTES}-byte limit of the threat \
             scan (it is read into memory). Scan a smaller file or use yara_scan_file on a part."
        );
    }
    let file_data = fs::read(path).context("Failed to read file for threat analysis")?;
    let file_size = file_data.len() as u64;

    // Scan with the compiled built-in rule set (compiled once per process)
    let rules = builtin_compiled_rules()?;
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(BUILTIN_SCAN_TIMEOUT);
    let scan_results = scanner
        .scan(&file_data)
        .map_err(|e| anyhow::anyhow!("Built-in YARA scan failed: {e}"))?;

    // Every matching rule is a real engine match: tags, metadata and the
    // matched strings all come from the scan, not from the rule text.
    let mut matches = Vec::new();
    let mut evidence = Vec::new();
    let mut threat_classifications = Vec::new();
    let mut indicators = Vec::new();

    let text_file = looks_like_text(&file_data);
    for matching_rule in scan_results.matching_rules() {
        // The built-in rules are few and small: no detail budget applies.
        let (mut budget, mut trimmed) = (usize::MAX, false);
        let mut rule_match = convert_rule_match(
            &matching_rule,
            &file_data,
            true,
            EVIDENCE_STRINGS_PER_RULE,
            &mut budget,
            &mut trimmed,
        );
        // A match on weak evidence is reported, marked, and counts for nothing.
        let weak = weak_evidence_reason(
            &matching_rule,
            &file_data,
            &rule_match.tags,
            text_file,
            rule_match.metadata.get("severity").map(String::as_str) == Some("high"),
        );
        if let Some(reason) = weak {
            rule_match
                .metadata
                .insert(WEAK_EVIDENCE_KEY.to_string(), "weak".to_string());
            rule_match
                .metadata
                .insert("evidence_reason".to_string(), reason.to_string());
        }

        for tag in &rule_match.tags {
            if weak.is_some() {
                break;
            }
            if let Some(classification) = tag_to_classification(tag) {
                if !threat_classifications.contains(&classification) {
                    threat_classifications.push(classification);
                }
            }
        }

        let yara_match = YaraMatch {
            rule_identifier: rule_match.rule_identifier.clone(),
            tags: rule_match.tags.clone(),
            metadata: rule_match.metadata.clone(),
        };
        if weak.is_none() {
            if let Some(indicator) = create_threat_indicator(&yara_match) {
                indicators.push(indicator);
            }
        }
        evidence.push(RuleEvidence {
            rule_identifier: rule_match.rule_identifier,
            strings_total: rule_match.strings_total,
            strings: rule_match.strings,
        });
        matches.push(yara_match);
    }

    let rules_evaluated = rules.iter().count();
    let threat_level = level_for_matches(&matches, &indicators);

    // Generate recommendations
    let recommendations =
        generate_recommendations(&threat_level, &matches, &threat_classifications);

    let scan_stats = ScanStatistics {
        scan_duration: start_time.elapsed(),
        rules_evaluated,
        patterns_matched: matches.len(),
        file_size_scanned: file_size,
    };

    Ok(ThreatAnalysis {
        matches,
        threat_level,
        classifications: threat_classifications,
        indicators,
        scan_stats,
        recommendations,
        enhanced_analysis: None,
        evidence,
    })
}

/// Metadata key set on a built-in match that rests on weak evidence.
const WEAK_EVIDENCE_KEY: &str = "evidence_strength";
/// A matched string shorter than this says nothing on its own.
const MIN_STRONG_STRING_BYTES: usize = 4;

/// Whether the file is text: no NUL byte anywhere in it and valid UTF-8 in
/// its first 64 KiB. A binary part after long leading text is not text.
fn looks_like_text(data: &[u8]) -> bool {
    let head = &data[..data.len().min(64 * 1024)];
    if data.contains(&0) {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        // A multi-byte character cut by the window is not a binary signal.
        Err(e) => e.error_len().is_none() && head.len() < data.len(),
    }
}

/// Why a rule's match is weak evidence, or `None` when it is not: every matched
/// string is under four bytes or a run of one repeated byte (padding), or the
/// rule names a debugger or virtual-machine technique and the file is text
/// (documentation that describes it). Such a match is still reported.
fn weak_evidence_reason(
    rule: &yara_x::Rule<'_, '_>,
    data: &[u8],
    tags: &[String],
    text_file: bool,
    high_severity: bool,
) -> Option<&'static str> {
    if text_file && !high_severity && tags.iter().any(|t| t == "anti_vm" || t == "anti_debug") {
        return Some("a text file that describes the technique in words");
    }
    // The words "bind shell" and "reverse shell" in a text file are
    // documentation; a command line that opens one is not.
    if text_file
        && tags.iter().any(|t| t == "backdoor")
        && rule
            .patterns()
            .filter(|p| p.matches().next().is_some())
            .all(|p| matches!(p.identifier(), "$bind" | "$reverse"))
    {
        return Some("a text file that describes the technique in words");
    }
    let mut any = false;
    for pattern in rule.patterns() {
        for m in pattern.matches() {
            any = true;
            let range = m.range();
            let bytes = &data[range.start.min(data.len())..range.end.min(data.len())];
            let padding = bytes.windows(2).all(|w| w[0] == w[1]);
            if bytes.len() >= MIN_STRONG_STRING_BYTES && !padding {
                return None;
            }
        }
    }
    any.then_some("every matched string is under 4 bytes or a run of one repeated byte")
}

/// The level for a set of matches. Rules that declare `severity = "low"` are
/// informational (a URL or the word "AES" in a binary says little on its
/// own), and so are matches marked as weak evidence: they are reported but do
/// not raise the level.
fn level_for_matches(matches: &[YaraMatch], indicators: &[ThreatIndicator]) -> ThreatLevel {
    let significant: Vec<YaraMatch> = matches
        .iter()
        .filter(|m| {
            m.metadata.get("severity").map(String::as_str) != Some("low")
                && m.metadata.get(WEAK_EVIDENCE_KEY).map(String::as_str) != Some("weak")
        })
        .cloned()
        .collect();
    let significant_indicators: Vec<ThreatIndicator> = indicators
        .iter()
        .filter(|i| !matches!(i.severity, Severity::Low))
        .cloned()
        .collect();
    let level = calculate_threat_level(&significant, &significant_indicators);
    // One matched rule that is not informational is still worth a look.
    if level == ThreatLevel::Clean && !significant.is_empty() {
        ThreatLevel::Suspicious
    } else {
        level
    }
}

/// Enhanced threat analysis using both the built-in YARA rules and
/// threatflux-threat-detection. The engine's matches, indicators,
/// classifications and verdict are merged into the returned analysis.
pub async fn analyze_threats_enhanced(path: &Path) -> Result<ThreatAnalysis> {
    // First run the built-in analysis
    let mut analysis = analyze_threats(path)?;

    match run_enhanced_analysis(path).await {
        Ok((mut info, engine)) => {
            let data = match fs::metadata(path) {
                Ok(m) if m.len() <= 100 * 1024 * 1024 => fs::read(path).ok(),
                _ => None,
            };
            merge_engine_result(&mut analysis, &mut info, &engine, data.as_deref());
            analysis.enhanced_analysis = Some(info);
            analysis.recommendations.push(
                "Enhanced threat analysis completed with additional intelligence.".to_string(),
            );
        }
        Err(e) => {
            analysis.enhanced_analysis = Some(EnhancedAnalysisInfo {
                enabled: false,
                confidence_score: 0.0,
                analysis_depth: "Basic (enhanced analysis failed)".to_string(),
                coverage_percentage: None,
                engines_used: 1, // Only the built-in rules
                engine_threat_level: None,
                engine_matches: Vec::new(),
                engine_classifications: Vec::new(),
                engine_indicators: Vec::new(),
                engine_evidence: Vec::new(),
                engine_merged: false,
                engine_note: None,
                error: Some(format!("{e:#}")),
            });
        }
    }

    Ok(analysis)
}

/// Run the threatflux engines on a file. Returns the summary and the raw result.
async fn run_enhanced_analysis(
    path: &Path,
) -> Result<(
    EnhancedAnalysisInfo,
    threatflux_threat_detection::ThreatAnalysis,
)> {
    let config = ThreatDetectorConfig {
        enable_yara: true,
        enable_clamav: false, // Disabled due to security vulnerability
        enable_patterns: true,
        max_file_size: 100 * 1024 * 1024, // 100MB
        scan_timeout: 300,                // 5 minutes
        max_concurrent_scans: 4,
        rule_sources: Vec::new(),
    };

    let detector = ThreatDetector::with_config(config)
        .await
        .context("Failed to create threatflux threat detector")?;
    let engines_used = detector.engine_count();

    let result = detector
        .scan_file(path)
        .await
        .context("Failed to scan file with threatflux detector")?;

    let confidence_score = if result.indicators.is_empty() {
        0.5 // Default confidence
    } else {
        result.indicators.iter().map(|i| i.confidence).sum::<f32>() / result.indicators.len() as f32
    };

    let analysis_depth = match (result.indicators.len(), result.matches.len()) {
        (i, m) if i >= 5 && m >= 3 => "Comprehensive",
        (i, m) if i >= 2 || m >= 1 => "Standard",
        _ => "Basic",
    }
    .to_string();

    let info = EnhancedAnalysisInfo {
        enabled: true,
        confidence_score,
        analysis_depth,
        coverage_percentage: None,
        engines_used,
        engine_threat_level: Some(result.threat_level.to_string()),
        engine_matches: {
            let mut names: Vec<String> = Vec::new();
            for m in &result.matches {
                if !names.contains(&m.rule_identifier) {
                    names.push(m.rule_identifier.clone());
                }
            }
            names
        },
        engine_classifications: Vec::new(),
        engine_indicators: Vec::new(),
        engine_evidence: Vec::new(),
        engine_merged: false,
        engine_note: None,
        error: None,
    };
    Ok((info, result))
}

fn map_engine_classification(
    classification: &threatflux_threat_detection::ThreatClassification,
) -> ThreatClassification {
    use threatflux_threat_detection::ThreatClassification as E;
    match classification {
        E::Trojan => ThreatClassification::Trojan,
        E::Virus => ThreatClassification::Virus,
        E::Worm => ThreatClassification::Worm,
        E::Rootkit => ThreatClassification::Rootkit,
        E::Adware => ThreatClassification::Adware,
        E::Spyware => ThreatClassification::Spyware,
        E::Ransomware => ThreatClassification::Ransomware,
        E::Apt => ThreatClassification::Apt,
        E::Pua => ThreatClassification::Pua,
        E::Banker => ThreatClassification::Banker,
        E::Downloader => ThreatClassification::Downloader,
        E::Backdoor => ThreatClassification::Backdoor,
        E::Exploit => ThreatClassification::Exploit,
        E::Cryptominer => ThreatClassification::Cryptominer,
        E::InfoStealer => ThreatClassification::InfoStealer,
        E::Botnet => ThreatClassification::Botnet,
        E::WebShell => ThreatClassification::WebShell,
        E::Keylogger => ThreatClassification::Keylogger,
        E::ScreenCapture => ThreatClassification::ScreenCapture,
        E::RemoteAccess => ThreatClassification::RemoteAccess,
        E::Other(name) => ThreatClassification::Other(name.clone()),
    }
}

fn map_engine_indicator_type(kind: &threatflux_threat_detection::IndicatorType) -> IndicatorType {
    use threatflux_threat_detection::IndicatorType as E;
    match kind {
        E::KnownMalwareFamily => IndicatorType::KnownMalwareFamily,
        E::SuspiciousBehavior => IndicatorType::SuspiciousBehavior,
        E::ExploitTechnique => IndicatorType::ExploitTechnique,
        E::AntiAnalysis => IndicatorType::AntiAnalysis,
        E::NetworkIndicator => IndicatorType::NetworkIndicator,
        E::PersistenceMechanism => IndicatorType::PersistenceMechanism,
        E::DataExfiltration => IndicatorType::DataExfiltration,
        E::CryptoOperation => IndicatorType::CryptoOperation,
        E::SystemModification => IndicatorType::SystemModification,
        E::ProcessInjection => IndicatorType::ProcessInjection,
        E::PrivilegeEscalation => IndicatorType::PrivilegeEscalation,
        E::LateralMovement => IndicatorType::LateralMovement,
        E::CommandAndControl => IndicatorType::CommandAndControl,
        E::DefenseEvasion => IndicatorType::DefenseEvasion,
        E::Discovery => IndicatorType::Discovery,
        E::Collection => IndicatorType::Collection,
        E::Exfiltration => IndicatorType::Exfiltration,
        E::Impact => IndicatorType::Impact,
    }
}

fn map_engine_level(level: &threatflux_threat_detection::ThreatLevel) -> ThreatLevel {
    use threatflux_threat_detection::ThreatLevel as E;
    match level {
        E::None | E::Clean => ThreatLevel::Clean,
        E::Suspicious => ThreatLevel::Suspicious,
        E::Malicious => ThreatLevel::Malicious,
        E::Critical => ThreatLevel::Critical,
    }
}

/// Engine rules too generic to count as a detection on their own: they match
/// short words ("rop", "MS") or two-byte sequences that ordinary files hold.
/// They stay in `matches`, but add no indicator, class or verdict.
const GENERIC_ENGINE_RULES: &[&str] = &["Exploit_Detection"];

/// Engine rules built from generic keywords or patterns. Their matches stay
/// in the engine's own report and are not folded into the built-in analysis.
fn is_keyword_engine_rule(rule: &str) -> bool {
    rule.ends_with("_Detection")
        || rule.starts_with("string_pattern_")
        || rule.starts_with("regex_pattern_")
}

fn is_generic_engine_rule(rule: &str) -> bool {
    GENERIC_ENGINE_RULES.contains(&rule)
}

/// Report the engine's detections, and fold them into the built-in analysis
/// only when that analysis corroborates them. `data` is the file's bytes,
/// used to show what each engine string matched.
///
/// The engine's rules are generic keyword rules (socket + "/bin/sh", any
/// base58-looking run, the words "mining" and "difficulty"): /bin/bash, ssh
/// and a README match them. So the engine's matches, classes, indicators and
/// verdict always go into `info` (`engine_*`), while `matches`,
/// `classifications`, `indicators` and the recommendations take them over only
/// when a built-in rule that is not informational already put the file at
/// Suspicious or above. The engine never raises `threat_level` itself.
fn merge_engine_result(
    analysis: &mut ThreatAnalysis,
    info: &mut EnhancedAnalysisInfo,
    engine: &threatflux_threat_detection::ThreatAnalysis,
    data: Option<&[u8]>,
) {
    use threatflux_threat_detection::Severity as E;

    let corroborated = analysis.threat_level >= ThreatLevel::Suspicious;
    let mut specific_rule_matched = false;
    let mut generic_rule_matched = false;
    let mut engine_evidence: Vec<RuleEvidence> = Vec::new();
    let mut engine_rules: Vec<YaraMatch> = Vec::new();
    for engine_match in &engine.matches {
        if is_generic_engine_rule(&engine_match.rule_identifier) {
            generic_rule_matched = true;
        } else {
            specific_rule_matched = true;
        }
        if engine_rules
            .iter()
            .any(|m| m.rule_identifier == engine_match.rule_identifier)
        {
            continue;
        }
        engine_rules.push(YaraMatch {
            rule_identifier: engine_match.rule_identifier.clone(),
            tags: engine_match.tags.clone(),
            metadata: engine_match.metadata.clone(),
        });
        let mut seen: HashSet<(u64, usize)> = HashSet::new();
        let mut strings = Vec::new();
        for s in &engine_match.strings {
            // A value that is only the rule's own name says nothing.
            if s.value.as_deref() == Some(engine_match.rule_identifier.as_str()) {
                continue;
            }
            if !seen.insert((s.offset, s.length)) {
                continue;
            }
            let (mut value, mut hex) = (s.value.clone(), None);
            if let Some(data) = data {
                let start = usize::try_from(s.offset).unwrap_or(usize::MAX);
                if start < data.len() && s.length > 0 {
                    let end = start.saturating_add(s.length).min(data.len());
                    (value, hex) = describe_matched_bytes(&data[start..end]);
                }
            }
            if strings.len() < EVIDENCE_STRINGS_PER_RULE {
                strings.push(YaraStringMatch {
                    identifier: s.identifier.clone(),
                    offset: s.offset,
                    length: s.length,
                    value,
                    hex,
                });
            }
        }
        engine_evidence.push(RuleEvidence {
            rule_identifier: engine_match.rule_identifier.clone(),
            strings_total: engine_match.strings.len(),
            strings,
        });
    }

    let mut engine_classes: Vec<ThreatClassification> = Vec::new();
    for classification in &engine.classifications {
        let mapped = map_engine_classification(classification);
        if generic_rule_matched && !specific_rule_matched && mapped == ThreatClassification::Exploit
        {
            continue;
        }
        if !engine_classes.contains(&mapped) {
            engine_classes.push(mapped);
        }
    }

    let mut engine_indicators: Vec<ThreatIndicator> = Vec::new();
    for indicator in &engine.indicators {
        if GENERIC_ENGINE_RULES
            .iter()
            .any(|rule| indicator.description.contains(rule))
        {
            continue;
        }
        let mut description = indicator.description.clone();
        if let Some(technique) = &indicator.mitre_technique {
            description.push_str(&format!(" (MITRE {technique})"));
        }
        if engine_indicators
            .iter()
            .any(|i| i.description == description)
        {
            continue;
        }
        engine_indicators.push(ThreatIndicator {
            indicator_type: map_engine_indicator_type(&indicator.indicator_type),
            description,
            severity: match indicator.severity {
                E::Low => Severity::Low,
                E::Medium => Severity::Medium,
                E::High => Severity::High,
                E::Critical => Severity::Critical,
            },
            confidence: indicator.confidence,
        });
    }

    info.engine_classifications = engine_classes.iter().map(|c| format!("{c:?}")).collect();
    info.engine_indicators = engine_indicators
        .iter()
        .map(|i| format!("{:?}: {}", i.severity, i.description))
        .collect();
    info.engine_evidence = engine_evidence.clone();
    info.engine_merged = false;
    info.engine_note = Some(if engine_rules.is_empty() {
        "The engine matched no rules.".to_string()
    } else if corroborated {
        "Corroborated by a built-in rule: only non-keyword engine rules and indicators were \
         added; engine classes never are."
            .to_string()
    } else {
        "Only generic keyword rules matched and no built-in rule corroborated them: listed \
         here, not counted in threat_level."
            .to_string()
    });

    if !corroborated {
        return;
    }
    let (matches_before, indicators_before) = (analysis.matches.len(), analysis.indicators.len());
    for (rule, evidence) in engine_rules.into_iter().zip(engine_evidence) {
        if is_keyword_engine_rule(&rule.rule_identifier) {
            continue;
        }
        if analysis
            .matches
            .iter()
            .any(|m| m.rule_identifier == rule.rule_identifier)
        {
            continue;
        }
        analysis.matches.push(rule);
        analysis.evidence.push(evidence);
    }
    // The engine's keyword rules (Backdoor_Detection, Cryptominer_Detection,
    // ...) match ordinary programs, so their classes are not added: a class is
    // reported only when a built-in rule produced it. Their Critical
    // KnownMalwareFamily indicators are left out for the same reason.
    for indicator in engine_indicators {
        if matches!(indicator.indicator_type, IndicatorType::KnownMalwareFamily)
            && indicator.description.starts_with("YARA rule match")
        {
            continue;
        }
        if indicator.description.contains("string_pattern_")
            || indicator.description.contains("regex_pattern_")
            || analysis
                .indicators
                .iter()
                .any(|i| i.description == indicator.description)
        {
            continue;
        }
        analysis.indicators.push(indicator);
    }
    info.engine_merged =
        analysis.matches.len() > matches_before || analysis.indicators.len() > indicators_before;
    analysis.scan_stats.patterns_matched = analysis.matches.len();
    analysis.recommendations = generate_recommendations(
        &analysis.threat_level,
        &analysis.matches,
        &analysis.classifications,
    );
}

/// The built-in rules, compiled once per process.
fn builtin_compiled_rules() -> Result<&'static yara_x::Rules> {
    static RULES: std::sync::OnceLock<std::result::Result<yara_x::Rules, String>> =
        std::sync::OnceLock::new();
    RULES
        .get_or_init(|| compile_rules().map_err(|e| format!("{e:#}")))
        .as_ref()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn compile_rules() -> Result<yara_x::Rules> {
    let sources = builtin_rule_sources();
    compile_rule_sources(&sources).map_err(|e| anyhow::anyhow!(e))
}

/// The built-in rule texts, named for diagnostics.
pub fn builtin_rule_sources() -> Vec<(String, String)> {
    get_builtin_rules()
        .into_iter()
        .enumerate()
        .map(|(i, text)| (format!("builtin rule {}", i + 1), text.to_string()))
        .collect()
}

/// Compile rule sources into one rule set. Each source is `(origin, text)`;
/// the origin names the source in diagnostics. A rule that does not compile
/// returns the compiler's own message (kind, line, column, offending text).
/// `include` is not allowed: a rule that pulls in another file would read
/// outside the paths the caller was allowed to name.
pub fn compile_rule_sources(
    sources: &[(String, String)],
) -> std::result::Result<yara_x::Rules, String> {
    compile_rule_sources_with_warnings(sources).map(|(rules, _)| rules)
}

/// Like [`compile_rule_sources`], also returning the compiler's warnings.
pub fn compile_rule_sources_with_warnings(
    sources: &[(String, String)],
) -> std::result::Result<(yara_x::Rules, Vec<String>), String> {
    let mut compiler = yara_x::Compiler::new();
    compiler.enable_includes(false);
    // Warnings about the server's own rules are not the caller's to act on:
    // keep the ones a source raised only when it is not a built-in source.
    let mut warnings: Vec<String> = Vec::new();
    let builtin_origins: HashSet<String> =
        builtin_rule_sources().into_iter().map(|(o, _)| o).collect();
    for (origin, text) in sources {
        let source = yara_x::SourceCode::from(text.as_str()).with_origin(origin.clone());
        let before = compiler.warnings().len();
        if let Err(error) = compiler.add_source(source) {
            return Err(format!("Failed to compile YARA rule ({origin}): {error}"));
        }
        let is_builtin = builtin_origins.contains(origin);
        for warning in &compiler.warnings()[before..] {
            if !is_builtin && warnings.len() < 10 {
                warnings.push(warning.to_string());
            }
        }
    }
    let rules = compiler.build();
    if rules.iter().count() == 0 {
        return Err(
            "The YARA source defines no rules. Pass at least one `rule name { condition: ... }`."
                .to_string(),
        );
    }
    Ok((rules, warnings))
}

pub fn get_builtin_rules() -> Vec<&'static str> {
    vec![
        // Rule 1: Suspicious API calls
        r#"
rule suspicious_api_calls : suspicious {
    meta:
        description = "Detects suspicious Windows API call patterns"
        author = "File Scanner"
        severity = "medium"
        category = "behavior"
    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "SetWindowsHookEx" ascii
        $api5 = "GetAsyncKeyState" ascii
    condition:
        3 of ($api*)
}"#,
        // Rule 2: Ransomware indicators
        r#"
rule ransomware_indicators : ransomware critical {
    meta:
        description = "Detects potential ransomware indicators"
        severity = "critical"
        category = "ransomware"
    strings:
        $ransom1 = "Your files have been encrypted" ascii wide nocase
        $ransom2 = "Bitcoin" ascii nocase
        $ransom3 = "decrypt your files" ascii wide nocase
        $ransom4 = "pay the ransom" ascii wide nocase
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".crypto" ascii
    condition:
        2 of ($ransom*) or (1 of ($ransom1, $ransom3, $ransom4) and 1 of ($ext*))
}"#,
        // Rule 3: Crypto operations
        r#"
rule crypto_operations : crypto {
    meta:
        description = "Detects cryptographic operations"
        severity = "low"
        category = "crypto"
    strings:
        $aes1 = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        $aes2 = "AES" ascii
        $rsa1 = "RSA" ascii
        $sha1 = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5 }
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
    condition:
        any of ($aes*, $rsa*, $sha*) or $b64
}"#,
        // Rule 4: Anti-analysis techniques
        r#"
rule anti_analysis : anti_vm anti_debug {
    meta:
        description = "Detects anti-analysis and anti-VM techniques"
        category = "evasion"
    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "XenVMMXenVMM" ascii
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "OutputDebugString" ascii
        $dbg3 = "CheckRemoteDebuggerPresent" ascii
        // Linux: reading the tracer's pid next to ptrace or the DMI product
        // names (the way programs spot a debugger or a virtual machine).
        $tracer = "TracerPid" ascii
        $procstatus = "/proc/self/status" ascii
        $ptrace = "ptrace" ascii
        $dmi = "/dmi/id/" ascii
    condition:
        2 of ($vm*) or 2 of ($dbg*) or ($tracer and $procstatus and ($ptrace or $dmi))
}"#,
        // Rule 5: Network communication
        r#"
rule network_communication : network {
    meta:
        description = "Detects network communication patterns"
        severity = "low"
        category = "network"
    strings:
        $http = "http://" ascii
        $https = "https://" ascii
        $socket1 = "socket" ascii
        $socket2 = "connect" ascii
        $socket3 = "send" ascii
        $socket4 = "recv" ascii
    condition:
        ($http or $https) or 3 of ($socket*)
}"#,
        // Rule 6: Persistence mechanisms
        r#"
rule persistence_mechanisms : persistence {
    meta:
        description = "Detects common persistence mechanisms"
        category = "persistence"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide
        $reg2 = "CurrentVersion\\RunOnce" ascii wide
        $svc1 = "CreateService" ascii
        $svc2 = "SERVICE_AUTO_START" ascii
        $task = "schtasks" ascii nocase
    condition:
        2 of ($reg*) or ($svc1 and $svc2) or $task
}"#,
        // Rule 7: Shell code patterns
        r#"
rule shellcode_patterns : shellcode exploit {
    meta:
        description = "Detects common shellcode patterns"
        category = "exploit"
    strings:
        // Compilers pad x86 code with up to 15 NOPs, so a sled is longer than that.
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $get_pc = { E8 00 00 00 00 5? }
        $seh = { 64 A1 00 00 00 00 }
    condition:
        $nop_sled or ($get_pc and $seh)
}"#,
        // Rule 8: Cryptominer patterns
        r#"
rule cryptominer_patterns : cryptominer {
    meta:
        description = "Detects cryptocurrency mining patterns"
        category = "cryptominer"
    strings:
        $str1 = "stratum+tcp://" ascii
        $str2 = "mining.pool" ascii
        $str3 = "monero" ascii nocase
        $str4 = "bitcoin" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        // A wallet-like run alone is common (hex digests, hashes); it counts
        // only next to the words a miner prints about itself.
        $m1 = "mining" ascii nocase fullword
        $m2 = "hashrate" ascii nocase
        $m3 = "xmrig" ascii nocase
        $m4 = "cryptonight" ascii nocase
        $m5 = "wallet" ascii nocase
    condition:
        2 of ($str*) or ($str1 and $wallet) or ($wallet and 2 of ($m*))
}"#,
        // Rule 9: Info stealer patterns
        r#"
rule infostealer_patterns : infostealer {
    meta:
        description = "Detects information stealing patterns"
        category = "infostealer"
    strings:
        $browser1 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $browser2 = "\\Google\\Chrome\\User Data" ascii wide
        $browser3 = "login_data.db" ascii
        $cred1 = "CredEnumerate" ascii
        $cred2 = "CryptUnprotectData" ascii
    condition:
        2 of ($browser*) or 2 of ($cred*)
}"#,
        // Rule 10: Backdoor patterns
        r#"
rule backdoor_patterns : backdoor {
    meta:
        description = "Detects backdoor patterns"
        category = "backdoor"
    strings:
        $cmd = "cmd.exe /c" ascii nocase
        // Classic reverse-shell command lines. A bare "sh -c" is how every
        // program that runs a command (editors, shells, Node.js) starts a shell.
        $shell1 = "bash -i >& /dev/tcp/" ascii
        $shell2 = "nc -e /bin/" ascii
        $bind = "bind shell" ascii nocase
        $reverse = "reverse shell" ascii nocase
    condition:
        $cmd or any of ($shell*) or any of ($bind, $reverse)
}"#,
        // Rule 11: A hard-coded domain that imitates a vendor's update service
        r#"
rule update_lookalike_domain : c2 {
    meta:
        description = "Hard-coded domain imitating a software update service"
        severity = "high"
        category = "command_and_control"
    strings:
        // Where the name stands as a domain, not as code or a path: after a
        // URL scheme, as a whole NUL-terminated string in a binary's string
        // table, or as a Host header. An identifier (`chrome_update.info(`),
        // a member access or an import path never has these around it.
        $url = /:\/\/(msft|msoft|ms|adobe|flash|java|chrome)[-_]?updat(e|er|es)\.(com|net|org|info|biz|xyz|top|ru|cn)/ ascii nocase
        $cstr = /\x00(msft|msoft|ms|adobe|flash|java|chrome)[-_]?updat(e|er|es)\.(com|net|org|info|biz|xyz|top|ru|cn)\x00/ ascii nocase
        $host = /Host: (msft|msoft|ms|adobe|flash|java|chrome)[-_]?updat(e|er|es)\.(com|net|org|info|biz|xyz|top|ru|cn)[\r\n:\x00]/ ascii nocase
    condition:
        any of them
}"#,
        // Rule 12: Programs that announce their own evasion checks
        r#"
rule self_announcing_evasion : anti_debug {
    meta:
        description = "Debugger or sandbox detection next to a ptrace call"
        severity = "high"
        category = "evasion"
    strings:
        // The import as a symbol-table entry (NUL on both sides, `_` on
        // Mach-O); prose that mentions ptrace has no NUL around it.
        $ptrace = /\x00_?ptrace\x00/ ascii
        $announce = /(debugger|sandbox|virtual machine) (environment )?detected/ ascii nocase
    condition:
        $ptrace and $announce
}"#,
        // Rule 13: A hard-coded XOR key
        r#"
rule hardcoded_xor_key : obfuscation {
    meta:
        description = "Hard-coded XOR key constant (payload obfuscation)"
        severity = "high"
        category = "obfuscation"
    strings:
        // A key literal: the name in its constant spellings with a run of
        // digits right after it. Identifiers such as xorKeyStream123 and
        // the standard library's XORKeyStream do not have that shape.
        $key = /XOR_?(Key|KEY)[0-9]{6,}/ ascii
    condition:
        $key
}"#,
    ]
}

pub fn tag_to_classification(tag: &str) -> Option<ThreatClassification> {
    match tag.to_lowercase().as_str() {
        "trojan" => Some(ThreatClassification::Trojan),
        "virus" => Some(ThreatClassification::Virus),
        "worm" => Some(ThreatClassification::Worm),
        "rootkit" => Some(ThreatClassification::Rootkit),
        "adware" => Some(ThreatClassification::Adware),
        "spyware" => Some(ThreatClassification::Spyware),
        "ransomware" => Some(ThreatClassification::Ransomware),
        "apt" => Some(ThreatClassification::Apt),
        "pua" => Some(ThreatClassification::Pua),
        "banker" => Some(ThreatClassification::Banker),
        "downloader" => Some(ThreatClassification::Downloader),
        "backdoor" => Some(ThreatClassification::Backdoor),
        "exploit" => Some(ThreatClassification::Exploit),
        "cryptominer" => Some(ThreatClassification::Cryptominer),
        "infostealer" => Some(ThreatClassification::InfoStealer),
        _ => None,
    }
}

pub fn create_threat_indicator(rule_match: &YaraMatch) -> Option<ThreatIndicator> {
    let description = rule_match
        .metadata
        .get("description")
        .cloned()
        .unwrap_or_else(|| format!("Matched rule: {}", rule_match.rule_identifier));

    let severity = rule_match
        .metadata
        .get("severity")
        .and_then(|s| match s.as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        })
        .unwrap_or(Severity::Medium);

    let indicator_type = if rule_match.tags.contains(&"anti_vm".to_string())
        || rule_match.tags.contains(&"anti_debug".to_string())
    {
        IndicatorType::AntiAnalysis
    } else if rule_match.tags.contains(&"network".to_string()) {
        IndicatorType::NetworkIndicator
    } else if rule_match.tags.contains(&"persistence".to_string()) {
        IndicatorType::PersistenceMechanism
    } else if rule_match.tags.contains(&"exploit".to_string()) {
        IndicatorType::ExploitTechnique
    } else if rule_match.tags.contains(&"crypto".to_string()) {
        IndicatorType::CryptoOperation
    } else if rule_match.metadata.contains_key("family") {
        IndicatorType::KnownMalwareFamily
    } else {
        IndicatorType::SuspiciousBehavior
    };

    Some(ThreatIndicator {
        indicator_type,
        description,
        severity,
        confidence: 0.8, // Default confidence
    })
}

pub fn calculate_threat_level(
    matches: &[YaraMatch],
    indicators: &[ThreatIndicator],
) -> ThreatLevel {
    if matches.is_empty() {
        return ThreatLevel::Clean;
    }

    // Check for critical indicators
    let has_critical = indicators
        .iter()
        .any(|i| matches!(i.severity, Severity::Critical));
    if has_critical {
        return ThreatLevel::Critical;
    }

    // Check for known malware families
    let has_malware_family = indicators
        .iter()
        .any(|i| matches!(i.indicator_type, IndicatorType::KnownMalwareFamily));

    // Check for high severity indicators
    let high_severity_count = indicators
        .iter()
        .filter(|i| matches!(i.severity, Severity::High))
        .count();

    if has_malware_family || high_severity_count >= 2 {
        return ThreatLevel::Malicious;
    }

    // Check for suspicious patterns
    let suspicious_count = matches.len();
    if suspicious_count >= 3 || high_severity_count >= 1 {
        return ThreatLevel::Suspicious;
    }

    ThreatLevel::Clean
}

pub fn generate_recommendations(
    threat_level: &ThreatLevel,
    matches: &[YaraMatch],
    classifications: &[ThreatClassification],
) -> Vec<String> {
    let mut recommendations = Vec::new();

    match threat_level {
        ThreatLevel::Critical => {
            recommendations
                .push("CRITICAL THREAT DETECTED! Isolate this file immediately.".to_string());
            recommendations.push("Do not execute this file under any circumstances.".to_string());
            recommendations.push("Submit to security team for immediate analysis.".to_string());
        }
        ThreatLevel::Malicious => {
            recommendations.push("Malicious file detected. Quarantine recommended.".to_string());
            recommendations.push("Perform deep analysis in isolated environment.".to_string());
            recommendations.push("Check system for related infections.".to_string());
        }
        ThreatLevel::Suspicious => {
            recommendations
                .push("Suspicious patterns detected. Further analysis recommended.".to_string());
            recommendations.push("Execute only in sandboxed environment.".to_string());
            recommendations.push("Monitor behavior if execution is necessary.".to_string());
        }
        ThreatLevel::Clean => {
            recommendations.push("No significant threats detected.".to_string());
            recommendations.push("Standard security practices recommended.".to_string());
        }
    }

    // Add specific recommendations based on classifications
    for classification in classifications {
        match classification {
            ThreatClassification::Ransomware => {
                recommendations.push("Backup critical data immediately.".to_string());
                recommendations.push("Check for encrypted files on system.".to_string());
            }
            ThreatClassification::InfoStealer => {
                recommendations.push("Change all passwords and credentials.".to_string());
                recommendations.push("Monitor for unauthorized access.".to_string());
            }
            ThreatClassification::Backdoor => {
                recommendations.push("Scan for network connections.".to_string());
                recommendations.push("Check for unauthorized remote access.".to_string());
            }
            ThreatClassification::Cryptominer => {
                recommendations.push("Monitor CPU and GPU usage.".to_string());
                recommendations.push("Check for unauthorized mining pools.".to_string());
            }
            _ => {}
        }
    }

    // Add recommendations based on specific matches
    for match_result in matches {
        if match_result.tags.contains(&"anti_analysis".to_string()) {
            recommendations
                .push("File uses anti-analysis techniques. Use advanced sandbox.".to_string());
        }
        if match_result.tags.contains(&"persistence".to_string()) {
            recommendations.push("Check system startup locations for persistence.".to_string());
        }
    }

    recommendations
}

// Custom YARA scanning support

/// Limits for a directory or file scan. `Default` gives the values the MCP
/// tool uses when an argument is left out.
#[derive(Debug, Clone)]
pub struct YaraScanOptions {
    pub recursive: bool,
    /// Files larger than this are listed as skipped.
    pub max_file_size: u64,
    /// List string matches (off: only counts).
    pub detailed_matches: bool,
    /// Most files examined; the walk stops there and `files_not_scanned` is a
    /// lower bound.
    pub max_files: usize,
    /// Most string matches listed per rule per file.
    pub max_matches_per_rule: usize,
    /// Most matching rules listed per file.
    pub max_rules_per_file: usize,
    /// Wall-clock budget for the whole scan.
    pub timeout: Duration,
    /// Vets each entry the walk meets before it is counted or opened (the
    /// caller's path policy). `None`: no vetting.
    pub entry_check: Option<EntryCheck>,
}

/// What an [`EntryCheck`] is called with: the entry's path, its own file type
/// (a link is not followed) and whether it is a symlink. `Err` carries the
/// refusal text.
pub type EntryCheckFn =
    dyn Fn(&Path, std::fs::FileType, bool) -> std::result::Result<(), String> + Send + Sync;

/// A shareable entry check for [`YaraScanOptions::entry_check`].
#[derive(Clone)]
pub struct EntryCheck(pub std::sync::Arc<EntryCheckFn>);

impl std::fmt::Debug for EntryCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryCheck")
    }
}

impl Default for YaraScanOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            max_file_size: 100 * 1024 * 1024,
            detailed_matches: true,
            max_files: DEFAULT_MAX_FILES,
            max_matches_per_rule: DEFAULT_MAX_MATCHES_PER_RULE,
            max_rules_per_file: DEFAULT_MAX_RULES_PER_FILE,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            entry_check: None,
        }
    }
}

/// Default for `YaraScanOptions::max_files`.
pub const DEFAULT_MAX_FILES: usize = 10_000;
/// Default for `YaraScanOptions::max_matches_per_rule`.
pub const DEFAULT_MAX_MATCHES_PER_RULE: usize = 10;
/// Default for `YaraScanOptions::max_rules_per_file`.
pub const DEFAULT_MAX_RULES_PER_FILE: usize = 100;
/// Default for `YaraScanOptions::timeout`, in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 60;
/// Skipped files named individually in a result; the rest are only counted.
const MAX_SKIPPED_LISTED: usize = 100;
/// Scan worker threads (each holds one file in memory at a time).
const MAX_SCAN_WORKERS: usize = 4;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomYaraScanResult {
    pub total_files_scanned: usize,
    /// Rule matches over all files (one rule matching one file counts once).
    pub total_matches: usize,
    pub files_matched: usize,
    pub matches: Vec<YaraFileMatch>,
    pub errors: Vec<YaraScanError>,
    /// Files not scanned because they were too large or unreadable (the first
    /// `MAX_SKIPPED_LISTED`; see `skipped_total`).
    pub skipped: Vec<YaraSkippedFile>,
    pub skipped_total: usize,
    /// Files left unscanned because `max_files` or the time budget was hit.
    pub files_not_scanned: usize,
    /// The walk stopped early (`max_files` or the time budget), so
    /// `files_not_scanned` is only a lower bound.
    #[serde(default)]
    pub more_files_not_counted: bool,
    /// The time budget ran out while walking the tree.
    #[serde(default)]
    pub walk_timed_out: bool,
    /// Files whose match detail (strings, tags, metadata, rules past the
    /// first few) was dropped because the scan had kept `MAX_DETAIL_BYTES`
    /// of detail already. Their rule counts are still exact.
    #[serde(default)]
    pub detail_trimmed_files: usize,
    pub timed_out: bool,
    /// Set when the entry check refused an entry that makes the whole scan
    /// unacceptable (a symlink leaving the allowed folders); the walk stopped
    /// there and the other members of this result are partial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// How many files each rule matched, most hits first.
    pub rule_hits: Vec<RuleHitCount>,
    /// Compiler warnings about the rules (first 10).
    pub rule_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuleHitCount {
    pub rule: String,
    pub files: usize,
}

/// Scan `path` with rule text, with the default limits except for the four
/// arguments. Kept for callers that do not need the options.
pub async fn scan_with_custom_rule(
    path: &Path,
    yara_rule: &str,
    recursive: bool,
    max_file_size: u64,
    detailed_matches: bool,
) -> Result<CustomYaraScanResult> {
    let rules = compile_rule_sources(&[("yara_rule".to_string(), yara_rule.to_string())])
        .map_err(|e| anyhow::anyhow!(e))?;
    let options = YaraScanOptions {
        recursive,
        max_file_size,
        detailed_matches,
        ..YaraScanOptions::default()
    };
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || scan_path_with_rules(&path, &rules, &options))
        .await
        .map_err(|e| anyhow::anyhow!("YARA scan task failed: {e}"))
}

/// How much match detail one scan keeps in memory (estimated bytes). Past it
/// further matching files keep only their path, size, rule count and the
/// first few rule names.
const MAX_DETAIL_BYTES: usize = 24 * 1024 * 1024;
/// Rules still listed for a file whose detail was dropped.
const TRIMMED_RULES_PER_FILE: usize = 3;

/// Most detail one file may build (estimated bytes), so several files
/// scanned together reserve a small part of the shared budget each.
const MAX_FILE_DETAIL_BYTES: usize = 2 * 1024 * 1024;

/// Take up to `want` bytes from what is left of the shared detail budget
/// (`reserved` counts what files hold now) and return how many were taken.
fn reserve_detail(reserved: &std::sync::atomic::AtomicUsize, want: usize) -> usize {
    use std::sync::atomic::Ordering;
    let mut held = reserved.load(Ordering::SeqCst);
    loop {
        let taken = want.min(MAX_DETAIL_BYTES.saturating_sub(held));
        match reserved.compare_exchange_weak(held, held + taken, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return taken,
            Err(now) => held = now,
        }
    }
}

/// A rough size of what one file's match keeps in memory.
fn estimate_match_bytes(file_match: &YaraFileMatch) -> usize {
    let rules: usize = file_match
        .matches
        .iter()
        .map(|rule| {
            let strings: usize = rule
                .strings
                .iter()
                .map(|s| {
                    s.identifier.len()
                        + s.value.as_ref().map_or(0, String::len)
                        + s.hex.as_ref().map_or(0, String::len)
                        + 80
                })
                .sum();
            let meta: usize = rule
                .metadata
                .iter()
                .map(|(k, v)| k.len() + v.len() + 64)
                .sum();
            let tags: usize = rule.tags.iter().map(|t| t.len() + 24).sum();
            rule.rule_identifier.len() + 128 + strings + meta + tags
        })
        .sum();
    file_match.file_path.len() + 96 + rules
}

/// One compiled rule set, scanned over a file or a directory tree by a few
/// worker threads; the rules are shared, not copied per file.
pub fn scan_path_with_rules(
    path: &Path,
    rules: &yara_x::Rules,
    options: &YaraScanOptions,
) -> CustomYaraScanResult {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    let deadline = Instant::now() + options.timeout;
    let mut candidates = collect_files_to_scan(path, options, deadline);

    let mut result = CustomYaraScanResult {
        skipped: candidates.skipped,
        skipped_total: candidates.skipped_total,
        files_not_scanned: candidates.not_examined,
        more_files_not_counted: candidates.more_files,
        walk_timed_out: candidates.walk_timed_out,
        timed_out: candidates.walk_timed_out,
        refused: candidates.refused.take(),
        ..CustomYaraScanResult::default()
    };
    if result.refused.is_some() {
        return result;
    }

    let files = candidates.files;
    let next = AtomicUsize::new(0);
    let timed_out = AtomicBool::new(false);
    let outcomes: Mutex<Vec<(usize, FileOutcome)>> = Mutex::new(Vec::new());
    let hits: Mutex<HashMap<String, usize>> = Mutex::new(HashMap::new());
    let detail_bytes = AtomicUsize::new(0);
    let trimmed_files = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(1, MAX_SCAN_WORKERS)
        .min(files.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut scanner = yara_x::Scanner::new(rules);
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(file) = files.get(index) else { break };
                    let now = Instant::now();
                    if now >= deadline {
                        timed_out.store(true, Ordering::SeqCst);
                        outcomes
                            .lock()
                            .expect("outcome list lock")
                            .push((index, FileOutcome::NotScanned));
                        continue;
                    }
                    scanner.set_timeout(deadline - now);
                    // Each file reserves its allowance (at most
                    // MAX_FILE_DETAIL_BYTES) from the shared detail budget
                    // before it is scanned, so workers running together can
                    // not overshoot it, and gives back what it did not use.
                    let allowance = reserve_detail(&detail_bytes, MAX_FILE_DETAIL_BYTES);
                    let (mut outcome, trimmed) =
                        scan_one_file(&mut scanner, file, options, allowance);
                    let used = match &outcome {
                        FileOutcome::Scanned(Some(file_match)) => estimate_match_bytes(file_match),
                        _ => 0,
                    };
                    detail_bytes.fetch_sub(allowance.saturating_sub(used), Ordering::SeqCst);
                    if let FileOutcome::Scanned(Some(file_match)) = &mut outcome {
                        {
                            let mut hits = hits.lock().expect("rule hit lock");
                            for rule in file_match.all_rules.drain(..) {
                                *hits.entry(rule).or_default() += 1;
                            }
                        }
                        if trimmed {
                            trimmed_files.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    if matches!(outcome, FileOutcome::TimedOut) {
                        timed_out.store(true, Ordering::SeqCst);
                    }
                    outcomes
                        .lock()
                        .expect("outcome list lock")
                        .push((index, outcome));
                }
            });
        }
    });

    let mut outcomes = outcomes.into_inner().expect("outcome list lock");
    outcomes.sort_by_key(|(index, _)| *index);
    let hits = hits.into_inner().expect("rule hit lock");
    result.detail_trimmed_files = trimmed_files.load(Ordering::SeqCst);
    for (index, outcome) in outcomes {
        let file = &files[index];
        match outcome {
            FileOutcome::Scanned(file_match) => {
                result.total_files_scanned += 1;
                if let Some(file_match) = file_match {
                    result.files_matched += 1;
                    result.total_matches += file_match.rules_total;
                    result.matches.push(file_match);
                }
            }
            FileOutcome::Error(error) => {
                result.errors.push(YaraScanError {
                    file_path: file.display().to_string(),
                    error,
                });
            }
            FileOutcome::TimedOut => {
                result.errors.push(YaraScanError {
                    file_path: file.display().to_string(),
                    error: format!(
                        "scan timed out (the scan budget is {} s). Simplify the rule, scan a \
                         smaller file or raise timeout_seconds",
                        options.timeout.as_secs()
                    ),
                });
            }
            FileOutcome::NotScanned => result.files_not_scanned += 1,
        }
    }
    result.timed_out |= timed_out.load(Ordering::SeqCst);

    let mut rule_hits: Vec<RuleHitCount> = hits
        .into_iter()
        .map(|(rule, files)| RuleHitCount { rule, files })
        .collect();
    rule_hits.sort_by(|a, b| b.files.cmp(&a.files).then_with(|| a.rule.cmp(&b.rule)));
    result.rule_hits = rule_hits;
    result
}

enum FileOutcome {
    /// Scanned; `Some` when at least one rule matched.
    Scanned(Option<YaraFileMatch>),
    Error(String),
    TimedOut,
    /// The time budget ran out before this file started.
    NotScanned,
}

/// The outcome, and whether the file's detail was cut to fit `allowance`.
fn scan_one_file(
    scanner: &mut yara_x::Scanner<'_>,
    path: &Path,
    options: &YaraScanOptions,
    allowance: usize,
) -> (FileOutcome, bool) {
    match scan_single_file(scanner, path, options, allowance) {
        Ok(Some((found, trimmed))) => (FileOutcome::Scanned(Some(found)), trimmed),
        Ok(None) => (FileOutcome::Scanned(None), false),
        Err(ScanFailure::Timeout) => (FileOutcome::TimedOut, false),
        Err(ScanFailure::Other(message)) => (FileOutcome::Error(message), false),
    }
}

/// The files a scan will visit, and what was left out.
struct Candidates {
    files: Vec<PathBuf>,
    skipped: Vec<YaraSkippedFile>,
    skipped_total: usize,
    /// Files known to be left out (at least one when the walk stopped early).
    not_examined: usize,
    /// The walk stopped before the end, so more files may exist.
    more_files: bool,
    walk_timed_out: bool,
    /// Regular files taken or skipped by size so far (toward `max_files`).
    examined: usize,
    /// An entry the check refused for the whole scan.
    refused: Option<String>,
}

/// Walk the tree lazily: stop at the first regular file beyond `max_files`
/// (the rest is not counted) or at the deadline, never follow
/// symlinks (a link to a file outside the tree is not part of the tree).
fn collect_files_to_scan(path: &Path, options: &YaraScanOptions, deadline: Instant) -> Candidates {
    let mut candidates = Candidates {
        files: Vec::new(),
        skipped: Vec::new(),
        skipped_total: 0,
        not_examined: 0,
        more_files: false,
        walk_timed_out: false,
        examined: 0,
        refused: None,
    };

    if path.is_file() {
        // The caller named this file, so a symlink to it is followed.
        let size = fs::metadata(path).ok().map(|m| m.len());
        candidates.consider(path.to_path_buf(), size, options);
    } else if path.is_dir() {
        let walker = WalkDir::new(path)
            .follow_links(false)
            .max_depth(if options.recursive { usize::MAX } else { 1 })
            .sort_by_file_name();
        for entry in walker {
            if Instant::now() >= deadline {
                candidates.walk_timed_out = true;
                candidates.more_files = true;
                candidates.not_examined += 1;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    let file = error
                        .path()
                        .map_or_else(String::new, |p| p.display().to_string());
                    candidates.skip(file, format!("could not be read while walking: {error}"));
                    continue;
                }
            };
            if entry.depth() > 0 {
                if let Some(check) = &options.entry_check {
                    if let Err(reason) =
                        (check.0)(entry.path(), entry.file_type(), entry.path_is_symlink())
                    {
                        if entry.path_is_symlink() {
                            // A link that leaves the allowed folders refuses the call.
                            candidates.refused = Some(reason);
                            break;
                        }
                        // A FIFO, socket or device is never opened. It is only
                        // skipped, so the refusal's advice to remove it is dropped.
                        let reason = reason
                            .strip_suffix(" Remove it or pass a directory without special files.")
                            .map_or(reason.clone(), |r| {
                                format!("{r} It is skipped, not opened.")
                            });
                        candidates.skip(entry.path().display().to_string(), reason);
                        continue;
                    }
                }
            }
            // `file_type` does not follow symlinks, so a link is skipped.
            if entry.file_type().is_file() {
                let size = entry.metadata().ok().map(|m| m.len());
                if !candidates.consider(entry.path().to_path_buf(), size, options) {
                    break;
                }
            } else if entry.path_is_symlink() && entry.depth() > 0 {
                // (A symlink given as `path` was resolved and is scanned below it.)
                candidates.skip(
                    entry.path().display().to_string(),
                    "symbolic link (not followed)".to_string(),
                );
            }
        }
    }
    candidates
}

impl Candidates {
    fn skip(&mut self, file_path: String, reason: String) {
        self.skipped_total += 1;
        if self.skipped.len() < MAX_SKIPPED_LISTED {
            self.skipped.push(YaraSkippedFile { file_path, reason });
        }
    }

    /// Take a file for scanning (or skip it). False once `max_files` files
    /// were taken and one more was seen: the walk can stop there.
    fn consider(&mut self, file: PathBuf, size: Option<u64>, options: &YaraScanOptions) -> bool {
        if self.examined >= options.max_files {
            self.not_examined += 1;
            self.more_files = true;
            return false;
        }
        match size {
            Some(size) if size > options.max_file_size => self.skip(
                file.display().to_string(),
                format!(
                    "larger than max_file_size ({size} bytes > {} bytes)",
                    options.max_file_size
                ),
            ),
            Some(_) => self.files.push(file),
            None => self.skip(
                file.display().to_string(),
                "could not read the file's size (unreadable)".to_string(),
            ),
        }
        self.examined += 1;
        true
    }
}

#[derive(Debug)]
enum ScanFailure {
    Timeout,
    Other(String),
}

/// Scan one file. `allowance` is how many estimated bytes of match detail
/// (see `estimate_match_bytes`) this file may build: tags, metadata, strings
/// and rules stop being built once it is used up, while the counts
/// (`rules_total`, `strings_total`) stay exact. The flag is true when detail
/// was left out for that reason.
fn scan_single_file(
    scanner: &mut yara_x::Scanner<'_>,
    file_path: &Path,
    options: &YaraScanOptions,
    allowance: usize,
) -> std::result::Result<Option<(YaraFileMatch, bool)>, ScanFailure> {
    let file_data = fs::read(file_path).map_err(|e| ScanFailure::Other(e.to_string()))?;
    let file_size = file_data.len() as u64;

    let scan_results = scanner.scan(&file_data).map_err(|e| match e {
        yara_x::errors::ScanError::Timeout => ScanFailure::Timeout,
        other => ScanFailure::Other(other.to_string()),
    })?;

    let path_text = file_path.display().to_string();
    let mut budget = allowance.saturating_sub(path_text.len() + 96);
    let mut trimmed = false;
    let mut rules_total = 0usize;
    let mut matches = Vec::new();
    let mut all_rules = Vec::new();
    for matching_rule in scan_results.matching_rules() {
        rules_total += 1;
        all_rules.push(matching_rule.identifier().to_string());
        if matches.len() >= options.max_rules_per_file {
            continue;
        }
        if matches.len() >= TRIMMED_RULES_PER_FILE && budget == 0 {
            trimmed = true;
            continue;
        }
        matches.push(convert_rule_match(
            &matching_rule,
            &file_data,
            options.detailed_matches,
            options.max_matches_per_rule,
            &mut budget,
            &mut trimmed,
        ));
    }
    if rules_total == 0 {
        return Ok(None);
    }
    Ok(Some((
        YaraFileMatch {
            file_path: path_text,
            file_size,
            matches,
            rules_total,
            all_rules,
        },
        trimmed,
    )))
}

/// One matching rule: tags, metadata, and (when asked) the first
/// `max_strings` string matches with their bytes. Everything but the rule's
/// name is built only while `budget` lasts (costs as in
/// `estimate_match_bytes`); `trimmed` is set when something was left out.
fn convert_rule_match(
    matching_rule: &yara_x::Rule<'_, '_>,
    file_data: &[u8],
    detailed: bool,
    max_strings: usize,
    budget: &mut usize,
    trimmed: &mut bool,
) -> YaraRuleMatch {
    let identifier = matching_rule.identifier().to_string();
    *budget = budget.saturating_sub(identifier.len() + 128);
    let mut rule_match = YaraRuleMatch {
        rule_identifier: identifier,
        tags: Vec::new(),
        metadata: HashMap::new(),
        strings: Vec::new(),
        strings_total: 0,
    };

    for tag in matching_rule.tags() {
        let cost = tag.identifier().len() + 24;
        if cost > *budget {
            *trimmed = true;
            break;
        }
        *budget -= cost;
        rule_match.tags.push(tag.identifier().to_string());
    }

    for (key, value) in matching_rule.metadata() {
        if *budget < key.len() + 64 {
            *trimmed = true;
            break;
        }
        let text = match value {
            yara_x::MetaValue::Bool(b) => b.to_string(),
            yara_x::MetaValue::Integer(i) => i.to_string(),
            yara_x::MetaValue::Float(f) => f.to_string(),
            yara_x::MetaValue::String(s) => s.to_string(),
            yara_x::MetaValue::Bytes(b) => format!("{b:?}"),
        };
        let cost = key.len() + text.len() + 64;
        if cost > *budget {
            *trimmed = true;
            break;
        }
        *budget -= cost;
        rule_match.metadata.insert(key.to_string(), text);
    }

    for pattern in matching_rule.patterns() {
        for pattern_match in pattern.matches() {
            rule_match.strings_total += 1;
            if !detailed || rule_match.strings.len() >= max_strings {
                continue;
            }
            // A string costs at most the identifier, 64 shown bytes (as hex
            // that is 3 characters each) and the fixed overhead.
            let range = pattern_match.range();
            let end = range.end.min(file_data.len());
            let start = range.start.min(end);
            let identifier = pattern.identifier();
            let upper = identifier.len() + 80 + 3 * (end - start).min(MAX_SHOWN_MATCH_BYTES);
            if upper > *budget {
                *trimmed = true;
                continue;
            }
            let (value, hex) = describe_matched_bytes(&file_data[start..end]);
            *budget = budget.saturating_sub(
                identifier.len()
                    + value.as_ref().map_or(0, String::len)
                    + hex.as_ref().map_or(0, String::len)
                    + 80,
            );
            rule_match.strings.push(YaraStringMatch {
                identifier: identifier.to_string(),
                offset: range.start as u64,
                length: range.len(),
                value,
                hex,
            });
        }
    }
    rule_match
}

/// Text for printable UTF-8, hex for anything else (first 64 bytes).
fn describe_matched_bytes(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let shown = &bytes[..bytes.len().min(MAX_SHOWN_MATCH_BYTES)];
    if let Ok(text) = std::str::from_utf8(shown) {
        if text.chars().all(|c| !c.is_control()) {
            return (Some(text.to_string()), None);
        }
    } else if bytes.len() > shown.len() {
        // A cut inside a multi-byte character: show the valid prefix as text.
        if let Err(error) = std::str::from_utf8(shown) {
            if error.error_len().is_none() {
                let valid = &shown[..error.valid_up_to()];
                if let Ok(text) = std::str::from_utf8(valid) {
                    if !text.is_empty() && text.chars().all(|c| !c.is_control()) {
                        return (Some(text.to_string()), None);
                    }
                }
            }
        }
    }
    let mut hex = String::with_capacity(shown.len() * 3);
    for (i, byte) in shown.iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        hex.push(
            char::from_digit(u32::from(byte >> 4), 16).map_or('0', |c| c.to_ascii_uppercase()),
        );
        hex.push(
            char::from_digit(u32::from(byte & 15), 16).map_or('0', |c| c.to_ascii_uppercase()),
        );
    }
    (None, Some(hex))
}

/// Rule sources named by a path: one file, or every `.yar`/`.yara` file in a
/// directory (recursively, in name order). Returns `(origin, text)` pairs.
pub fn load_rule_sources(path: &Path) -> std::result::Result<Vec<(String, String)>, String> {
    const MAX_RULE_FILES: usize = 1000;
    const MAX_RULE_FILE_BYTES: u64 = 5 * 1024 * 1024;
    const MAX_RULE_TOTAL_BYTES: u64 = 20 * 1024 * 1024;

    let read_one = |file: &Path| -> std::result::Result<(String, String), String> {
        let size = fs::metadata(file)
            .map_err(|e| format!("Cannot read rule file {}: {e}", file.display()))?
            .len();
        if size > MAX_RULE_FILE_BYTES {
            return Err(format!(
                "Rule file {} is {size} bytes, above the {MAX_RULE_FILE_BYTES}-byte limit.",
                file.display()
            ));
        }
        let text = fs::read_to_string(file).map_err(|e| {
            format!(
                "Cannot read rule file {} as UTF-8 text: {e}",
                file.display()
            )
        })?;
        Ok((file.display().to_string(), text))
    };

    if path.is_file() {
        return Ok(vec![read_one(path)?]);
    }
    if !path.is_dir() {
        return Err(format!(
            "Rule path {} is neither a file nor a directory.",
            path.display()
        ));
    }
    let mut files: Vec<PathBuf> = WalkDir::new(path)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|file| {
            file.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
                })
        })
        .collect();
    if files.is_empty() {
        return Err(format!(
            "The directory {} holds no .yar or .yara files.",
            path.display()
        ));
    }
    if files.len() > MAX_RULE_FILES {
        return Err(format!(
            "The directory {} holds {} rule files; the limit is {MAX_RULE_FILES}. Point rule_path \
             at a smaller directory.",
            path.display(),
            files.len()
        ));
    }
    files.sort();
    let total: u64 = files
        .iter()
        .filter_map(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();
    if total > MAX_RULE_TOTAL_BYTES {
        return Err(format!(
            "The rule files in {} add up to {total} bytes; the limit is {MAX_RULE_TOTAL_BYTES}. \
             Point rule_path at a smaller directory.",
            path.display()
        ));
    }
    files.iter().map(|file| read_one(file)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    // Helper function to create test file with specific content
    fn create_test_file(content: &[u8]) -> std::path::PathBuf {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_file.bin");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content).unwrap();
        file_path
    }

    #[cfg(unix)]
    #[test]
    fn non_recursive_collection_does_not_follow_symlinks_out_of_the_directory() {
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
        let scanned = tempdir().unwrap();
        std::fs::write(scanned.path().join("own.txt"), b"own").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            scanned.path().join("link.txt"),
        )
        .unwrap();
        for recursive in [false, true] {
            let options = YaraScanOptions {
                recursive,
                max_file_size: 1 << 20,
                ..YaraScanOptions::default()
            };
            let candidates = collect_files_to_scan(
                scanned.path(),
                &options,
                Instant::now() + Duration::from_secs(600),
            );
            let names: Vec<_> = candidates
                .files
                .iter()
                .filter_map(|file| file.file_name()?.to_str().map(str::to_string))
                .collect();
            assert_eq!(names, ["own.txt"], "recursive={recursive}");
        }
    }

    // Tests for ThreatLevel enum serialization/deserialization
    #[test]
    fn test_threat_level_serialization() {
        use serde_json;

        let clean = ThreatLevel::Clean;
        let serialized = serde_json::to_string(&clean).unwrap();
        let deserialized: ThreatLevel = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, ThreatLevel::Clean));

        let critical = ThreatLevel::Critical;
        let serialized = serde_json::to_string(&critical).unwrap();
        let deserialized: ThreatLevel = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, ThreatLevel::Critical));
    }

    // Tests for ThreatClassification enum
    #[test]
    fn test_threat_classification_equality() {
        assert_eq!(ThreatClassification::Trojan, ThreatClassification::Trojan);
        assert_ne!(ThreatClassification::Trojan, ThreatClassification::Virus);
        assert_eq!(
            ThreatClassification::Ransomware,
            ThreatClassification::Ransomware
        );
    }

    // Tests for data structure creation and serialization
    #[test]
    fn test_yara_match_creation() {
        let mut metadata = HashMap::new();
        metadata.insert("severity".to_string(), "high".to_string());
        metadata.insert("description".to_string(), "Test rule".to_string());

        let yara_match = YaraMatch {
            rule_identifier: "test_rule".to_string(),
            tags: vec!["trojan".to_string(), "suspicious".to_string()],
            metadata,
        };

        assert_eq!(yara_match.rule_identifier, "test_rule");
        assert_eq!(yara_match.tags.len(), 2);
        assert!(yara_match.tags.contains(&"trojan".to_string()));
        assert_eq!(yara_match.metadata.get("severity").unwrap(), "high");
    }

    #[test]
    fn test_threat_indicator_creation() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::KnownMalwareFamily,
            description: "Zeus banking trojan detected".to_string(),
            severity: Severity::Critical,
            confidence: 0.95,
        };

        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::KnownMalwareFamily
        ));
        assert!(matches!(indicator.severity, Severity::Critical));
        assert_eq!(indicator.confidence, 0.95);
        assert!(indicator.description.contains("Zeus"));
    }

    // Tests for threat classification
    #[test]
    fn test_tag_to_classification() {
        assert_eq!(
            tag_to_classification("trojan"),
            Some(ThreatClassification::Trojan)
        );
        assert_eq!(
            tag_to_classification("TROJAN"),
            Some(ThreatClassification::Trojan)
        );
        assert_eq!(
            tag_to_classification("Trojan"),
            Some(ThreatClassification::Trojan)
        );

        assert_eq!(
            tag_to_classification("virus"),
            Some(ThreatClassification::Virus)
        );
        assert_eq!(
            tag_to_classification("worm"),
            Some(ThreatClassification::Worm)
        );
        assert_eq!(
            tag_to_classification("rootkit"),
            Some(ThreatClassification::Rootkit)
        );
        assert_eq!(
            tag_to_classification("adware"),
            Some(ThreatClassification::Adware)
        );
        assert_eq!(
            tag_to_classification("spyware"),
            Some(ThreatClassification::Spyware)
        );
        assert_eq!(
            tag_to_classification("ransomware"),
            Some(ThreatClassification::Ransomware)
        );
        assert_eq!(
            tag_to_classification("apt"),
            Some(ThreatClassification::Apt)
        );
        assert_eq!(
            tag_to_classification("pua"),
            Some(ThreatClassification::Pua)
        );
        assert_eq!(
            tag_to_classification("banker"),
            Some(ThreatClassification::Banker)
        );
        assert_eq!(
            tag_to_classification("downloader"),
            Some(ThreatClassification::Downloader)
        );
        assert_eq!(
            tag_to_classification("backdoor"),
            Some(ThreatClassification::Backdoor)
        );
        assert_eq!(
            tag_to_classification("exploit"),
            Some(ThreatClassification::Exploit)
        );
        assert_eq!(
            tag_to_classification("cryptominer"),
            Some(ThreatClassification::Cryptominer)
        );
        assert_eq!(
            tag_to_classification("infostealer"),
            Some(ThreatClassification::InfoStealer)
        );

        assert_eq!(tag_to_classification("unknown_tag"), None);
        assert_eq!(tag_to_classification(""), None);
    }

    #[test]
    fn test_create_threat_indicator() {
        // Test with complete metadata
        let mut metadata = HashMap::new();
        metadata.insert(
            "description".to_string(),
            "Malicious API usage detected".to_string(),
        );
        metadata.insert("severity".to_string(), "critical".to_string());
        metadata.insert("family".to_string(), "Zeus".to_string());

        let rule_match = YaraMatch {
            rule_identifier: "malware_family_zeus".to_string(),
            tags: vec!["trojan".to_string(), "banker".to_string()],
            metadata,
        };

        let indicator = create_threat_indicator(&rule_match).unwrap();
        assert_eq!(indicator.description, "Malicious API usage detected");
        assert!(matches!(indicator.severity, Severity::Critical));
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::KnownMalwareFamily
        ));
        assert_eq!(indicator.confidence, 0.8);

        // Test with anti-analysis tags
        let anti_match = YaraMatch {
            rule_identifier: "anti_debug".to_string(),
            tags: vec!["anti_vm".to_string(), "anti_debug".to_string()],
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&anti_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::AntiAnalysis
        ));

        // Test with network tags
        let network_match = YaraMatch {
            rule_identifier: "network_comm".to_string(),
            tags: vec!["network".to_string()],
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&network_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::NetworkIndicator
        ));

        // Test with persistence tags
        let persistence_match = YaraMatch {
            rule_identifier: "persistence_mech".to_string(),
            tags: vec!["persistence".to_string()],
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&persistence_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::PersistenceMechanism
        ));

        // Test with exploit tags
        let exploit_match = YaraMatch {
            rule_identifier: "exploit_code".to_string(),
            tags: vec!["exploit".to_string()],
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&exploit_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::ExploitTechnique
        ));

        // Test with crypto tags
        let crypto_match = YaraMatch {
            rule_identifier: "crypto_ops".to_string(),
            tags: vec!["crypto".to_string()],
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&crypto_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::CryptoOperation
        ));

        // Test default case (no special tags)
        let default_match = YaraMatch {
            rule_identifier: "generic_rule".to_string(),
            tags: vec!["suspicious".to_string()],
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&default_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::SuspiciousBehavior
        ));
        assert_eq!(indicator.description, "Matched rule: generic_rule");
        assert!(matches!(indicator.severity, Severity::Medium)); // Default severity
    }

    // Tests for threat level calculation
    #[test]
    fn test_threat_level_calculation_comprehensive() {
        // Test clean file (no matches)
        assert!(matches!(
            calculate_threat_level(&[], &[]),
            ThreatLevel::Clean
        ));

        // Test critical indicators
        let critical_indicator = ThreatIndicator {
            indicator_type: IndicatorType::SuspiciousBehavior,
            description: "Critical threat".to_string(),
            severity: Severity::Critical,
            confidence: 0.9,
        };

        let matches = vec![YaraMatch {
            rule_identifier: "critical_rule".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
        }];

        assert!(matches!(
            calculate_threat_level(&matches, &[critical_indicator]),
            ThreatLevel::Critical
        ));

        // Test known malware family detection
        let malware_indicator = ThreatIndicator {
            indicator_type: IndicatorType::KnownMalwareFamily,
            description: "Known malware family".to_string(),
            severity: Severity::High,
            confidence: 0.9,
        };

        assert!(matches!(
            calculate_threat_level(&matches, &[malware_indicator]),
            ThreatLevel::Malicious
        ));

        // Test multiple high severity indicators
        let high_indicators = vec![
            ThreatIndicator {
                indicator_type: IndicatorType::SuspiciousBehavior,
                description: "High threat 1".to_string(),
                severity: Severity::High,
                confidence: 0.8,
            },
            ThreatIndicator {
                indicator_type: IndicatorType::AntiAnalysis,
                description: "High threat 2".to_string(),
                severity: Severity::High,
                confidence: 0.8,
            },
        ];

        assert!(matches!(
            calculate_threat_level(&matches, &high_indicators),
            ThreatLevel::Malicious
        ));

        // Test suspicious level (multiple matches)
        let multiple_matches = vec![
            YaraMatch {
                rule_identifier: "rule1".to_string(),
                tags: vec![],
                metadata: HashMap::new(),
            },
            YaraMatch {
                rule_identifier: "rule2".to_string(),
                tags: vec![],
                metadata: HashMap::new(),
            },
            YaraMatch {
                rule_identifier: "rule3".to_string(),
                tags: vec![],
                metadata: HashMap::new(),
            },
        ];

        assert!(matches!(
            calculate_threat_level(&multiple_matches, &[]),
            ThreatLevel::Suspicious
        ));

        // Test suspicious level (one high severity indicator)
        let single_high_indicator = vec![ThreatIndicator {
            indicator_type: IndicatorType::NetworkIndicator,
            description: "High threat".to_string(),
            severity: Severity::High,
            confidence: 0.8,
        }];

        let single_match = vec![YaraMatch {
            rule_identifier: "single_rule".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
        }];

        assert!(matches!(
            calculate_threat_level(&single_match, &single_high_indicator),
            ThreatLevel::Suspicious
        ));

        // Test edge case: matches but low severity
        let low_indicators = vec![ThreatIndicator {
            indicator_type: IndicatorType::SuspiciousBehavior,
            description: "Low threat".to_string(),
            severity: Severity::Low,
            confidence: 0.5,
        }];

        assert!(matches!(
            calculate_threat_level(&single_match, &low_indicators),
            ThreatLevel::Clean
        ));
    }

    // Tests for recommendation generation
    #[test]
    fn test_generate_recommendations_by_threat_level() {
        let empty_matches = vec![];
        let empty_classifications = vec![];

        // Test Critical recommendations
        let critical_recs = generate_recommendations(
            &ThreatLevel::Critical,
            &empty_matches,
            &empty_classifications,
        );
        assert!(critical_recs
            .iter()
            .any(|r| r.contains("CRITICAL THREAT DETECTED")));
        assert!(critical_recs
            .iter()
            .any(|r| r.contains("Isolate this file immediately")));
        assert!(critical_recs.iter().any(|r| r.contains("Do not execute")));

        // Test Malicious recommendations
        let malicious_recs = generate_recommendations(
            &ThreatLevel::Malicious,
            &empty_matches,
            &empty_classifications,
        );
        assert!(malicious_recs
            .iter()
            .any(|r| r.contains("Malicious file detected")));
        assert!(malicious_recs
            .iter()
            .any(|r| r.contains("Quarantine recommended")));
        assert!(malicious_recs.iter().any(|r| r.contains("deep analysis")));

        // Test Suspicious recommendations
        let suspicious_recs = generate_recommendations(
            &ThreatLevel::Suspicious,
            &empty_matches,
            &empty_classifications,
        );
        assert!(suspicious_recs
            .iter()
            .any(|r| r.contains("Suspicious patterns detected")));
        assert!(suspicious_recs
            .iter()
            .any(|r| r.contains("sandboxed environment")));
        assert!(suspicious_recs
            .iter()
            .any(|r| r.contains("Monitor behavior")));

        // Test Clean recommendations
        let clean_recs =
            generate_recommendations(&ThreatLevel::Clean, &empty_matches, &empty_classifications);
        assert!(clean_recs
            .iter()
            .any(|r| r.contains("No significant threats")));
        assert!(clean_recs
            .iter()
            .any(|r| r.contains("Standard security practices")));
    }

    #[test]
    fn test_generate_recommendations_by_classification() {
        let empty_matches = vec![];

        // Test Ransomware recommendations
        let ransomware_classifications = vec![ThreatClassification::Ransomware];
        let recs = generate_recommendations(
            &ThreatLevel::Malicious,
            &empty_matches,
            &ransomware_classifications,
        );
        assert!(recs.iter().any(|r| r.contains("Backup critical data")));
        assert!(recs.iter().any(|r| r.contains("encrypted files")));

        // Test InfoStealer recommendations
        let infostealer_classifications = vec![ThreatClassification::InfoStealer];
        let recs = generate_recommendations(
            &ThreatLevel::Malicious,
            &empty_matches,
            &infostealer_classifications,
        );
        assert!(recs.iter().any(|r| r.contains("Change all passwords")));
        assert!(recs
            .iter()
            .any(|r| r.contains("Monitor for unauthorized access")));

        // Test Backdoor recommendations
        let backdoor_classifications = vec![ThreatClassification::Backdoor];
        let recs = generate_recommendations(
            &ThreatLevel::Malicious,
            &empty_matches,
            &backdoor_classifications,
        );
        assert!(recs.iter().any(|r| r.contains("network connections")));
        assert!(recs
            .iter()
            .any(|r| r.contains("unauthorized remote access")));

        // Test Cryptominer recommendations
        let cryptominer_classifications = vec![ThreatClassification::Cryptominer];
        let recs = generate_recommendations(
            &ThreatLevel::Malicious,
            &empty_matches,
            &cryptominer_classifications,
        );
        assert!(recs.iter().any(|r| r.contains("CPU and GPU usage")));
        assert!(recs.iter().any(|r| r.contains("mining pools")));

        // Test other classifications (should not add specific recommendations)
        let other_classifications = vec![ThreatClassification::Virus, ThreatClassification::Trojan];
        let recs = generate_recommendations(
            &ThreatLevel::Malicious,
            &empty_matches,
            &other_classifications,
        );
        assert!(!recs.iter().any(|r| r.contains("Backup critical data")));
    }

    #[test]
    fn test_generate_recommendations_by_matches() {
        let empty_classifications = vec![];

        // Test anti-analysis matches
        let anti_analysis_match = YaraMatch {
            rule_identifier: "anti_debug".to_string(),
            tags: vec!["anti_analysis".to_string()],
            metadata: HashMap::new(),
        };
        let matches = vec![anti_analysis_match];

        let recs =
            generate_recommendations(&ThreatLevel::Suspicious, &matches, &empty_classifications);
        assert!(recs.iter().any(|r| r.contains("anti-analysis techniques")));
        assert!(recs.iter().any(|r| r.contains("advanced sandbox")));

        // Test persistence matches
        let persistence_match = YaraMatch {
            rule_identifier: "persistence_mechanism".to_string(),
            tags: vec!["persistence".to_string()],
            metadata: HashMap::new(),
        };
        let matches = vec![persistence_match];

        let recs =
            generate_recommendations(&ThreatLevel::Suspicious, &matches, &empty_classifications);
        assert!(recs.iter().any(|r| r.contains("startup locations")));
        assert!(recs.iter().any(|r| r.contains("persistence")));

        // Test matches without special tags
        let generic_match = YaraMatch {
            rule_identifier: "generic_rule".to_string(),
            tags: vec!["suspicious".to_string()],
            metadata: HashMap::new(),
        };
        let matches = vec![generic_match];

        let recs =
            generate_recommendations(&ThreatLevel::Suspicious, &matches, &empty_classifications);
        assert!(!recs.iter().any(|r| r.contains("anti-analysis")));
        assert!(!recs.iter().any(|r| r.contains("startup locations")));
    }

    // Tests for builtin rules
    #[test]
    fn test_get_builtin_rules() {
        let rules = get_builtin_rules();
        assert!(!rules.is_empty());
        assert_eq!(rules.len(), 13); // We have 13 builtin rules

        // Check that each rule contains expected elements
        for rule in &rules {
            assert!(rule.contains("rule "));
            assert!(rule.contains("meta:"));
            assert!(rule.contains("condition:"));
        }

        // Check specific rules exist
        assert!(rules.iter().any(|r| r.contains("suspicious_api_calls")));
        assert!(rules.iter().any(|r| r.contains("ransomware_indicators")));
        assert!(rules.iter().any(|r| r.contains("crypto_operations")));
        assert!(rules.iter().any(|r| r.contains("anti_analysis")));
        assert!(rules.iter().any(|r| r.contains("network_communication")));
        assert!(rules.iter().any(|r| r.contains("persistence_mechanisms")));
        assert!(rules.iter().any(|r| r.contains("shellcode_patterns")));
        assert!(rules.iter().any(|r| r.contains("cryptominer_patterns")));
        assert!(rules.iter().any(|r| r.contains("infostealer_patterns")));
        assert!(rules.iter().any(|r| r.contains("backdoor_patterns")));
    }

    // Tests for ThreatAnalysis structure
    #[test]
    fn test_threat_analysis_serialization() {
        let scan_stats = ScanStatistics {
            scan_duration: Duration::from_millis(100),
            rules_evaluated: 10,
            patterns_matched: 3,
            file_size_scanned: 1024,
        };

        let threat_analysis = ThreatAnalysis {
            matches: vec![],
            threat_level: ThreatLevel::Suspicious,
            classifications: vec![ThreatClassification::Trojan],
            indicators: vec![],
            scan_stats,
            recommendations: vec!["Test recommendation".to_string()],
            enhanced_analysis: None,
            evidence: Vec::new(),
        };

        // Test serialization to JSON
        let json_result = serde_json::to_string(&threat_analysis);
        assert!(json_result.is_ok());

        let json = json_result.unwrap();
        assert!(json.contains("Suspicious"));
        assert!(json.contains("Trojan"));
        assert!(json.contains("Test recommendation"));
    }

    // Integration test for complete threat analysis workflow
    #[test]
    fn test_analyze_threats_integration() {
        // Create a test file with suspicious content
        let suspicious_content = b"VirtualAlloc WriteProcessMemory CreateRemoteThread https://malicious.com AES encryption";
        let (_dir, test_file) = kept(suspicious_content);

        let analysis = analyze_threats(&test_file).unwrap();
        {
            // Verify the analysis completed successfully
            // Check that scan statistics are populated (duration is always non-negative)
            assert_eq!(analysis.scan_stats.rules_evaluated, 13); // Number of builtin rules
            assert_eq!(
                analysis.scan_stats.file_size_scanned,
                suspicious_content.len() as u64
            );

            // Check that recommendations are generated
            assert!(!analysis.recommendations.is_empty());
        }
    }

    #[test]
    fn test_analyze_threats_clean_file() {
        // Create a clean test file
        let clean_content = b"This is a clean text file with no suspicious content.";
        let (_dir, test_file) = kept(clean_content);

        let analysis = analyze_threats(&test_file).unwrap();
        {
            // Should have minimal or no matches for clean content
            assert!(!analysis.recommendations.is_empty());
            assert_eq!(
                analysis.scan_stats.file_size_scanned,
                clean_content.len() as u64
            );
        }
    }

    #[test]
    fn test_analyze_threats_nonexistent_file() {
        let nonexistent_path = std::path::Path::new("/nonexistent/file/path");
        let result = analyze_threats(nonexistent_path);
        assert!(result.is_err());
    }

    // Test compile_rules function
    #[test]
    fn test_compile_rules() {
        let rules = compile_rules().expect("the built-in rules compile");
        assert_eq!(rules.iter().count(), 13);
    }

    // Test all severity levels
    #[test]
    fn test_all_severity_levels() {
        let severities = [
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
            ("unknown", Severity::Medium), // Should default to Medium
        ];

        for (severity_str, expected_severity) in &severities {
            let mut metadata = HashMap::new();
            metadata.insert("severity".to_string(), severity_str.to_string());

            let rule_match = YaraMatch {
                rule_identifier: "test_rule".to_string(),
                tags: vec![],
                metadata,
            };

            let indicator = create_threat_indicator(&rule_match).unwrap();
            // Use discriminant comparison to avoid pattern matching on the reference
            assert_eq!(
                std::mem::discriminant(&indicator.severity),
                std::mem::discriminant(expected_severity)
            );
        }
    }

    // Test all indicator types
    #[test]
    fn test_all_indicator_types() {
        let test_cases = vec![
            (vec!["anti_vm"], IndicatorType::AntiAnalysis),
            (vec!["anti_debug"], IndicatorType::AntiAnalysis),
            (vec!["network"], IndicatorType::NetworkIndicator),
            (vec!["persistence"], IndicatorType::PersistenceMechanism),
            (vec!["exploit"], IndicatorType::ExploitTechnique),
            (vec!["crypto"], IndicatorType::CryptoOperation),
            (vec!["other"], IndicatorType::SuspiciousBehavior), // Default case
        ];

        for (tags, expected_type) in test_cases {
            let rule_match = YaraMatch {
                rule_identifier: "test_rule".to_string(),
                tags: tags
                    .into_iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                metadata: HashMap::new(),
            };

            let indicator = create_threat_indicator(&rule_match).unwrap();
            assert_eq!(
                std::mem::discriminant(&indicator.indicator_type),
                std::mem::discriminant(&expected_type)
            );
        }

        // Test KnownMalwareFamily (based on metadata)
        let mut metadata = HashMap::new();
        metadata.insert("family".to_string(), "Zeus".to_string());

        let malware_match = YaraMatch {
            rule_identifier: "malware_rule".to_string(),
            tags: vec![],
            metadata,
        };

        let indicator = create_threat_indicator(&malware_match).unwrap();
        assert!(matches!(
            indicator.indicator_type,
            IndicatorType::KnownMalwareFamily
        ));
    }

    // ---- analyze_threats reports what the engine matched

    /// A file that stays on disk while the returned directory lives.
    fn kept(content: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, content).unwrap();
        (dir, path)
    }

    fn rule_ids(analysis: &ThreatAnalysis) -> Vec<&str> {
        analysis
            .matches
            .iter()
            .map(|m| m.rule_identifier.as_str())
            .collect()
    }

    #[test]
    fn every_builtin_rule_can_be_reported() {
        let cases: [(&str, &[u8]); 8] = [
            (
                "ransomware_indicators",
                b"Your files have been encrypted. pay the ransom now",
            ),
            (
                "cryptominer_patterns",
                b"stratum+tcp://pool.example:3333 monero",
            ),
            ("persistence_mechanisms", b"cmd /c schtasks /create /tn x"),
            ("backdoor_patterns", b"starting a reverse shell"),
            ("anti_analysis", b"VMware and VirtualBox checks"),
            (
                "infostealer_patterns",
                b"\\Mozilla\\Firefox\\Profiles \\Google\\Chrome\\User Data",
            ),
            ("shellcode_patterns", &[0x90; 32]),
            (
                "suspicious_api_calls",
                b"VirtualAlloc WriteProcessMemory CreateRemoteThread",
            ),
        ];
        for (rule, content) in cases {
            let (_dir, file) = kept(content);
            let analysis = analyze_threats(&file).unwrap();
            assert!(
                rule_ids(&analysis).contains(&rule),
                "{rule}: {:?}",
                rule_ids(&analysis)
            );
            let evidence = analysis
                .evidence
                .iter()
                .find(|e| e.rule_identifier == rule)
                .unwrap();
            assert!(evidence.strings_total >= 1);
            assert!(!evidence.strings.is_empty());
        }
    }

    #[test]
    fn ransomware_text_is_critical_with_classification_and_evidence() {
        let content = b"intro\nYour files have been encrypted\nplease pay the ransom\n";
        let (_dir, file) = kept(content);
        let analysis = analyze_threats(&file).unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Critical);
        assert!(analysis
            .classifications
            .contains(&ThreatClassification::Ransomware));
        let m = analysis
            .matches
            .iter()
            .find(|m| m.rule_identifier == "ransomware_indicators")
            .unwrap();
        assert_eq!(
            m.metadata.get("severity").map(String::as_str),
            Some("critical")
        );
        assert!(m.tags.contains(&"ransomware".to_string()));
        let evidence = analysis
            .evidence
            .iter()
            .find(|e| e.rule_identifier == "ransomware_indicators")
            .unwrap();
        let first = &evidence.strings[0];
        assert_eq!(first.offset, 6); // after "intro\n"
        assert_eq!(
            first.value.as_deref(),
            Some("Your files have been encrypted")
        );
    }

    #[test]
    fn the_word_socket_alone_is_not_a_network_match() {
        let (_dir, file) = kept(b"socket");
        let analysis = analyze_threats(&file).unwrap();
        assert!(rule_ids(&analysis).is_empty(), "{:?}", rule_ids(&analysis));
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn informational_matches_do_not_raise_the_level_but_real_ones_do() {
        // A URL and the word AES: reported, informational.
        let (_dir, file) = kept(b"see https://example.com for AES docs");
        let analysis = analyze_threats(&file).unwrap();
        assert!(rule_ids(&analysis).contains(&"network_communication"));
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);

        let (_dir, file) = kept(
            b"VirtualAlloc WriteProcessMemory CreateRemoteThread https://malicious.example AES",
        );
        let analysis = analyze_threats(&file).unwrap();
        assert!(rule_ids(&analysis).contains(&"suspicious_api_calls"));
        assert_eq!(analysis.threat_level, ThreatLevel::Suspicious);
    }

    #[tokio::test]
    async fn enhanced_analysis_returns_the_engines_detections() {
        let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test_programs")
            .join("crypto_miner_binary");
        let analysis = analyze_threats_enhanced(&sample).await.unwrap();
        let info = analysis.enhanced_analysis.as_ref().unwrap();
        assert!(info.enabled, "{info:?}");
        assert!(info.error.is_none());
        assert!(info.engines_used >= 1);
        assert!(info.coverage_percentage.is_none());
        assert!(!info.engine_matches.is_empty(), "{info:?}");
        // The engine's specific matches are in the merged result, with a
        // verdict; its keyword rules (`*_Detection`) stay under `info`.
        for rule in &info.engine_matches {
            if is_keyword_engine_rule(rule) {
                assert!(!rule_ids(&analysis).contains(&rule.as_str()), "{rule}");
            } else {
                assert!(rule_ids(&analysis).contains(&rule.as_str()), "{rule}");
            }
        }
        assert!(info.engine_threat_level.is_some());
        assert!(!analysis.indicators.is_empty());
        assert!(analysis.scan_stats.patterns_matched == analysis.matches.len());
    }

    #[tokio::test]
    async fn enhanced_analysis_of_a_missing_file_is_an_error() {
        assert!(
            analyze_threats_enhanced(std::path::Path::new("/nonexistent/x"))
                .await
                .is_err()
        );
    }

    // ---- scanning with rules

    fn scan_text(
        rule: &str,
        files: &[(&str, &[u8])],
        options: &YaraScanOptions,
    ) -> CustomYaraScanResult {
        let dir = tempdir().unwrap();
        for (name, content) in files {
            std::fs::write(dir.path().join(name), content).unwrap();
        }
        let rules = compile_rule_sources(&[("t".to_string(), rule.to_string())]).unwrap();
        scan_path_with_rules(dir.path(), &rules, options)
    }

    #[test]
    fn compile_errors_carry_the_compiler_message() {
        let error = compile_rule_sources(&[(
            "mine".to_string(),
            "rule x { strings: $a = \"x\" condition: $b }".to_string(),
        )])
        .map(|_| ())
        .unwrap_err();
        assert!(
            error.contains("Failed to compile YARA rule (mine)"),
            "{error}"
        );
        assert!(error.contains("$b"), "{error}");
        assert!(error.contains('^') || error.contains("-->"), "{error}");
        let error = compile_rule_sources(&[("e".to_string(), String::new())])
            .map(|_| ())
            .unwrap_err();
        assert!(error.contains("no rules"), "{error}");
    }

    #[test]
    fn warnings_are_returned_with_the_rules() {
        let (_, warnings) = compile_rule_sources_with_warnings(&[(
            "w".to_string(),
            "rule w { condition: true }".to_string(),
        )])
        .unwrap();
        // A rule that is always true draws a warning in yara-x; it names its origin.
        assert!(!warnings.is_empty(), "{warnings:?}");
        assert!(warnings[0].contains("-->"), "{warnings:?}");
    }

    #[test]
    fn builtin_sources_raise_no_warnings_and_a_user_warning_mentioning_them_stays() {
        let (_, warnings) = compile_rule_sources_with_warnings(&builtin_rule_sources()).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        // The text of the user's rule says "builtin rule 3"; the warning is theirs.
        let mut sources = builtin_rule_sources();
        sources.push((
            "yara_rule".to_string(),
            "rule w { meta: d = \"like builtin rule 3\" condition: true }".to_string(),
        ));
        let (_, warnings) = compile_rule_sources_with_warnings(&sources).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
    }

    #[test]
    fn an_oversize_file_is_skipped_with_a_reason_not_dropped() {
        let options = YaraScanOptions {
            max_file_size: 5,
            ..YaraScanOptions::default()
        };
        let result = scan_text(
            "rule t { condition: true }",
            &[("small.txt", b"hi"), ("big.txt", b"much too large")],
            &options,
        );
        assert_eq!(result.total_files_scanned, 1);
        assert_eq!(result.skipped_total, 1);
        assert!(result.skipped[0].reason.contains("max_file_size"));
    }

    #[test]
    fn max_files_limits_the_walk_and_counts_the_rest() {
        let options = YaraScanOptions {
            max_files: 3,
            ..YaraScanOptions::default()
        };
        let files: Vec<(String, &[u8])> =
            (0..10).map(|i| (format!("f{i}.txt"), &b"x"[..])).collect();
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, c)| (n.as_str(), *c)).collect();
        let result = scan_text("rule t { condition: true }", &refs, &options);
        assert_eq!(result.total_files_scanned, 3);
        // The walk stops at the first file past the cap: a lower bound.
        assert_eq!(result.files_not_scanned, 1);
        assert!(result.more_files_not_counted);
    }

    #[test]
    fn the_walk_stops_at_the_deadline() {
        let options = YaraScanOptions {
            timeout: Duration::ZERO,
            ..YaraScanOptions::default()
        };
        let result = scan_text(
            "rule t { condition: true }",
            &[("a.txt", b"x"), ("b.txt", b"y")],
            &options,
        );
        assert!(result.walk_timed_out && result.timed_out);
        assert!(result.files_not_scanned >= 1);
        assert_eq!(result.total_files_scanned, 0);
    }

    #[test]
    fn rule_hits_count_rules_beyond_max_rules_per_file() {
        let rules: String = (0..5)
            .map(|i| format!("rule r{i} {{ condition: true }}\n"))
            .collect();
        let options = YaraScanOptions {
            max_rules_per_file: 2,
            ..YaraScanOptions::default()
        };
        let result = scan_text(&rules, &[("a.txt", b"x"), ("b.txt", b"y")], &options);
        assert_eq!(result.rule_hits.len(), 5);
        assert!(result.rule_hits.iter().all(|h| h.files == 2));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_unreadable_files_are_reported_not_counted_as_scanned() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("ok.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("locked.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("ok.txt"), dir.path().join("link")).unwrap();
        let locked = dir.path().join("locked.txt");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read(&locked).is_ok();
        let rules =
            compile_rule_sources(&[("t".to_string(), "rule t { condition: true }".to_string())])
                .unwrap();
        let result = scan_path_with_rules(dir.path(), &rules, &YaraScanOptions::default());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            result
                .skipped
                .iter()
                .any(|s| s.file_path.ends_with("link") && s.reason.contains("symbolic link")),
            "{result:?}"
        );
        if !readable {
            assert_eq!(result.total_files_scanned, 1, "{result:?}");
            assert_eq!(result.errors.len(), 1);
        }
    }

    #[tokio::test]
    async fn ordinary_text_is_not_malicious_under_the_enhanced_analysis() {
        // "rop" and "property" trip the engine's generic Exploit_Detection rule.
        let (_dir, file) = kept(b"Europe is a property of the group; see .note.gnu.property");
        let analysis = analyze_threats_enhanced(&file).await.unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Clean);
        assert!(analysis.classifications.is_empty());
        assert!(analysis
            .indicators
            .iter()
            .all(|i| !i.description.contains("Exploit_Detection")));
        #[cfg(target_os = "macos")]
        {
            let analysis = analyze_threats_enhanced(std::path::Path::new("/bin/ls"))
                .await
                .unwrap();
            assert_eq!(analysis.threat_level, ThreatLevel::Clean);
            assert!(analysis.classifications.is_empty());
        }
    }

    #[test]
    fn matched_bytes_are_text_or_hex() {
        assert_eq!(
            describe_matched_bytes(b"plain"),
            (Some("plain".to_string()), None)
        );
        assert_eq!(
            describe_matched_bytes(&[0xDE, 0xAD, 0x00]),
            (None, Some("DE AD 00".to_string()))
        );
        let long = vec![0xAB; 200];
        let (value, hex) = describe_matched_bytes(&long);
        assert!(value.is_none());
        assert_eq!(hex.unwrap().split(' ').count(), MAX_SHOWN_MATCH_BYTES);
        // Text cut inside a multi-byte character still reads as text.
        let text = "é".repeat(40);
        let (value, hex) = describe_matched_bytes(text.as_bytes());
        assert!(value.is_some() && hex.is_none());
    }

    #[test]
    fn rules_are_loaded_from_a_directory_in_name_order() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("b.yar"), "rule b { condition: true }").unwrap();
        std::fs::write(dir.path().join("a.YARA"), "rule a { condition: true }").unwrap();
        std::fs::write(dir.path().join("c.txt"), "nothing").unwrap();
        let sources = load_rule_sources(dir.path()).unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources[0].0.ends_with("a.YARA") && sources[1].0.ends_with("b.yar"));
        assert!(load_rule_sources(&dir.path().join("missing")).is_err());
    }

    /// The detail a file builds is held to its allowance while it is built,
    /// not cut afterwards: 1,000 rules of 64-byte hex patterns over one file.
    #[test]
    fn a_file_builds_no_more_detail_than_its_allowance() {
        let hex = vec!["FF"; 64].join(" ");
        let text: String = (0..1000)
            .map(|i| format!("rule q{i} {{ strings: $p = {{ {hex} }} condition: $p }}\n"))
            .collect();
        let rules = compile_rule_sources(&[("t".to_string(), text)]).unwrap();
        let dir = tempdir().unwrap();
        let file = dir.path().join("ff.bin");
        std::fs::write(&file, vec![0xFFu8; 2000]).unwrap();
        let options = YaraScanOptions {
            max_matches_per_rule: 1000,
            max_rules_per_file: 1000,
            ..YaraScanOptions::default()
        };
        let mut scanner = yara_x::Scanner::new(&rules);

        let allowance = 100_000;
        let (found, trimmed) = scan_single_file(&mut scanner, &file, &options, allowance)
            .unwrap()
            .unwrap();
        assert!(trimmed);
        assert_eq!(found.rules_total, 1000, "counts stay exact");
        assert!(estimate_match_bytes(&found) <= allowance + 2_000);
        assert!(
            found.matches.iter().any(|m| !m.strings.is_empty()),
            "the first rules keep their strings"
        );
        assert!(found.matches[0].strings_total > 0);

        let (found, trimmed) = scan_single_file(&mut scanner, &file, &options, 0)
            .unwrap()
            .unwrap();
        assert!(trimmed);
        assert_eq!(found.rules_total, 1000);
        assert!(found.matches.len() <= TRIMMED_RULES_PER_FILE);
        assert!(found.matches.iter().all(|m| m.strings.is_empty()));

        let (found, trimmed) = scan_single_file(&mut scanner, &file, &options, usize::MAX)
            .unwrap()
            .unwrap();
        assert!(!trimmed);
        assert_eq!(found.matches.len(), 1000);
    }

    /// Both sides of the three rules added for the simulated malware: the
    /// lookalike domain, the self-announcing evasion check and the XOR key.
    #[test]
    fn the_added_rules_flag_their_pattern_and_not_ordinary_text() {
        let flagged = [
            ("update_lookalike_domain", "http://msftupdater.com/x"),
            ("self_announcing_evasion", "\0ptrace\0Debugger detected!"),
            ("hardcoded_xor_key", "key=ThisIsASecretXORKey123456789012"),
        ];
        let ordinary = [
            "see https://windowsupdate.com and https://update.microsoft.com",
            "debugger detected in the list of options (no system call named)",
            "ptrace is a system call; sandbox settings",
            "crypto/cipher XORKeyStream and xorKeyStreamBlocks",
            "chrome_update.info('x'); java_update.run(); ms_update.compute();",
            "import './chrome-update.component'; x = foo.chrome_update.com",
            "ptrace was used and the note says debugger detected",
            "xorKeyStream123456",
            "Target non-existent domains (msftupdater.com), \"msftupdater.com\"",
        ];
        let dir = tempdir().unwrap();
        for (i, (rule, text)) in flagged.iter().enumerate() {
            let path = dir.path().join(format!("f{i}.bin"));
            std::fs::write(&path, text).unwrap();
            let analysis = analyze_threats(&path).unwrap();
            assert!(
                analysis.matches.iter().any(|m| m.rule_identifier == *rule),
                "{rule}: {:?}",
                analysis.matches
            );
            assert!(analysis.threat_level >= ThreatLevel::Suspicious, "{rule}");
        }
        for (i, text) in ordinary.iter().enumerate() {
            let path = dir.path().join(format!("o{i}.txt"));
            std::fs::write(&path, text).unwrap();
            let analysis = analyze_threats(&path).unwrap();
            for rule in [
                "update_lookalike_domain",
                "self_announcing_evasion",
                "hardcoded_xor_key",
            ] {
                assert!(
                    analysis.matches.iter().all(|m| m.rule_identifier != rule),
                    "{rule} on {text}"
                );
            }
        }
    }

    /// The entry check runs on each walked entry inside `max_files`: a tree
    /// far past the limit is checked only up to it, and a refused symlink
    /// stops the scan with its reason.
    #[test]
    fn the_entry_check_runs_inside_max_files_and_a_refusal_stops_the_scan() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        for i in 0..200 {
            std::fs::write(dir.path().join(format!("f{i:03}.txt")), "x").unwrap();
        }
        let rules =
            compile_rule_sources(&[("t".to_string(), "rule t { condition: true }".to_string())])
                .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let options = YaraScanOptions {
            max_files: 5,
            entry_check: Some(EntryCheck(Arc::new(move |_, _, _| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }))),
            ..YaraScanOptions::default()
        };
        let result = scan_path_with_rules(dir.path(), &rules, &options);
        assert_eq!(result.total_files_scanned, 5);
        assert_eq!(calls.load(Ordering::SeqCst), 6, "five taken, one past");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", dir.path().join("a-link")).unwrap();
            let options = YaraScanOptions {
                entry_check: Some(EntryCheck(Arc::new(|_, _, is_link| {
                    if is_link {
                        Err("link refused".to_string())
                    } else {
                        Ok(())
                    }
                }))),
                ..YaraScanOptions::default()
            };
            let result = scan_path_with_rules(dir.path(), &rules, &options);
            assert_eq!(result.refused.as_deref(), Some("link refused"));
            assert_eq!(result.total_files_scanned, 0);
        }
    }

    /// Files reserve their detail allowance from the shared budget before the
    /// scan and the total never passes it, however many reserve together.
    #[test]
    fn detail_reservations_never_pass_the_shared_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let held = AtomicUsize::new(0);
        let mut total = 0;
        for _ in 0..100 {
            total += reserve_detail(&held, MAX_FILE_DETAIL_BYTES);
        }
        assert_eq!(total, MAX_DETAIL_BYTES);
        assert_eq!(held.load(Ordering::SeqCst), MAX_DETAIL_BYTES);
        assert_eq!(reserve_detail(&held, MAX_FILE_DETAIL_BYTES), 0);
        held.fetch_sub(MAX_FILE_DETAIL_BYTES, Ordering::SeqCst);
        assert_eq!(
            reserve_detail(&held, MAX_FILE_DETAIL_BYTES),
            MAX_FILE_DETAIL_BYTES
        );
    }
}
