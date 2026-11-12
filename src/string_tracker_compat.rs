//! Compatibility DTOs and wrapper for the current string-analysis library.
//!
//! Preserve file-scanner's established Rust fields and JSON output while adapting
//! the upstream library's bounded tracking, fixed-width counts and validation.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use threatflux_string_analysis as current;

type StringCountVec = Vec<(String, usize)>;
type StringScoreVec = Vec<(String, f64)>;
type DateTimeRange = (DateTime<Utc>, DateTime<Utc>);

/// Context in which a string was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringContext {
    /// String found in file content
    FileString {
        /// Byte offset within the file where the string was found
        offset: Option<usize>,
    },
    /// String found in import tables or dependencies
    Import {
        /// Name of the imported library or module
        library: String,
    },
    /// String found in export tables or exported symbols
    Export {
        /// Name of the exported symbol or function
        symbol: String,
    },
    /// String found in embedded resources
    Resource {
        /// Type of resource (icon, string table, etc.)
        resource_type: String,
    },
    /// String found in file sections
    Section {
        /// Name of the section where the string was found
        section_name: String,
    },
    /// String found in file metadata
    Metadata {
        /// Metadata field name where the string was found
        field: String,
    },
    /// String representing a file system path
    Path {
        /// Type of path (absolute, relative, UNC, etc.)
        path_type: String,
    },
    /// String representing a URL
    Url {
        /// URL protocol (http, https, ftp, etc.)
        protocol: Option<String>,
    },
    /// String found in Windows registry context
    Registry {
        /// Registry hive name (HKLM, HKCU, etc.)
        hive: Option<String>,
    },
    /// String found in command or script context
    Command {
        /// Type of command (shell, powershell, batch, etc.)
        command_type: String,
    },
    /// String found in other contexts
    Other {
        /// Category description for the context
        category: String,
    },
}

/// Record of a single string occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    /// Path to the file where the string was found
    pub file_path: String,
    /// Hash of the file where the string was found
    pub file_hash: String,
    /// Name of the tool that discovered this string
    pub tool_name: String,
    /// Timestamp when the string was discovered
    pub timestamp: DateTime<Utc>,
    /// Context in which the string was found
    pub context: StringContext,
}

/// Complete information about a tracked string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    /// The actual string value
    pub value: String,
    /// Timestamp when this string was first discovered
    pub first_seen: DateTime<Utc>,
    /// Timestamp when this string was last seen
    pub last_seen: DateTime<Utc>,
    /// Total number of times this string has been found
    pub total_occurrences: usize,
    /// Set of unique file paths where this string was found
    pub unique_files: HashSet<String>,
    /// Detailed records of each occurrence
    pub occurrences: Vec<StringOccurrence>,
    /// Set of categories this string belongs to
    pub categories: HashSet<String>,
    /// Whether this string is flagged as suspicious
    pub is_suspicious: bool,
    /// Shannon entropy score of the string
    pub entropy: f64,
}

/// Statistics about tracked strings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringStatistics {
    /// Total number of unique strings tracked
    pub total_unique_strings: usize,
    /// Total number of string occurrences across all files
    pub total_occurrences: usize,
    /// Total number of files that have been analyzed
    pub total_files_analyzed: usize,
    /// Most frequently occurring strings with their occurrence counts
    pub most_common: StringCountVec,
    /// List of strings flagged as suspicious
    pub suspicious_strings: Vec<String>,
    /// Strings with high entropy scores and their entropy values
    pub high_entropy_strings: StringScoreVec,
    /// Distribution of strings across different categories
    pub category_distribution: HashMap<String, usize>,
    /// Distribution of strings by length ranges
    pub length_distribution: HashMap<String, usize>,
}

/// Filter criteria for string queries
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StringFilter {
    /// Minimum number of occurrences a string must have
    pub min_occurrences: Option<usize>,
    /// Maximum number of occurrences a string can have
    pub max_occurrences: Option<usize>,
    /// Minimum length of strings to include
    pub min_length: Option<usize>,
    /// Maximum length of strings to include
    pub max_length: Option<usize>,
    /// Filter by specific categories
    pub categories: Option<Vec<String>>,
    /// Filter by specific file paths
    pub file_paths: Option<Vec<String>>,
    /// Filter by specific file hashes
    pub file_hashes: Option<Vec<String>>,
    /// If true, only return suspicious strings
    pub suspicious_only: Option<bool>,
    /// Regular expression pattern to match string values
    pub regex_pattern: Option<String>,
    /// Minimum entropy score for strings
    pub min_entropy: Option<f64>,
    /// Maximum entropy score for strings
    pub max_entropy: Option<f64>,
    /// Date range filter for when strings were discovered
    #[schema(value_type = Option<Vec<String>>)]
    pub date_range: Option<DateTimeRange>,
}

impl From<StringContext> for current::StringContext {
    fn from(context: StringContext) -> Self {
        match context {
            StringContext::FileString { offset } => Self::FileString {
                offset: offset.map(|n| n as u64),
            },
            StringContext::Import { library } => Self::Import { library },
            StringContext::Export { symbol } => Self::Export { symbol },
            StringContext::Resource { resource_type } => Self::Resource { resource_type },
            StringContext::Section { section_name } => Self::Section { section_name },
            StringContext::Metadata { field } => Self::Metadata { field },
            StringContext::Path { path_type } => Self::Path { path_type },
            StringContext::Url { protocol } => Self::Url { protocol },
            StringContext::Registry { hive } => Self::Registry { hive },
            StringContext::Command { command_type } => Self::Command { command_type },
            StringContext::Other { category } => Self::Other { category },
        }
    }
}

impl From<current::StringContext> for StringContext {
    fn from(context: current::StringContext) -> Self {
        match context {
            current::StringContext::FileString { offset } => Self::FileString {
                offset: offset.map(legacy_count),
            },
            current::StringContext::Import { library } => Self::Import { library },
            current::StringContext::Export { symbol } => Self::Export { symbol },
            current::StringContext::Resource { resource_type } => Self::Resource { resource_type },
            current::StringContext::Section { section_name } => Self::Section { section_name },
            current::StringContext::Metadata { field } => Self::Metadata { field },
            current::StringContext::Path { path_type } => Self::Path { path_type },
            current::StringContext::Url { protocol } => Self::Url { protocol },
            current::StringContext::Registry { hive } => Self::Registry { hive },
            current::StringContext::Command { command_type } => Self::Command { command_type },
            current::StringContext::Other { category } => Self::Other { category },
        }
    }
}

// Preserve the legacy usize fields with saturation on 32-bit targets.
fn legacy_count(count: u64) -> usize {
    usize::try_from(count).unwrap_or(usize::MAX)
}

impl From<current::StringEntry> for StringEntry {
    fn from(entry: current::StringEntry) -> Self {
        Self {
            value: entry.value,
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            total_occurrences: legacy_count(entry.total_occurrences),
            unique_files: entry
                .unique_file_identities
                .into_iter()
                .map(|identity| identity.file_path)
                .collect(),
            occurrences: entry
                .occurrences
                .into_iter()
                .map(|occurrence| StringOccurrence {
                    file_path: occurrence.file_path,
                    file_hash: occurrence.file_hash,
                    tool_name: occurrence.tool_name,
                    timestamp: occurrence.timestamp,
                    context: occurrence.context.into(),
                })
                .collect(),
            categories: entry.categories.into_iter().collect(),
            is_suspicious: entry.is_suspicious,
            entropy: entry.entropy,
        }
    }
}

impl From<current::StringStatistics> for StringStatistics {
    fn from(stats: current::StringStatistics) -> Self {
        Self {
            total_unique_strings: legacy_count(stats.total_unique_strings),
            total_occurrences: legacy_count(stats.total_occurrences),
            total_files_analyzed: legacy_count(stats.total_files_analyzed),
            most_common: stats
                .most_common
                .into_iter()
                .map(|(value, count)| (value, legacy_count(count)))
                .collect(),
            suspicious_strings: stats.suspicious_strings,
            high_entropy_strings: stats.high_entropy_strings,
            category_distribution: stats
                .category_distribution
                .into_iter()
                .map(|(name, count)| (name, legacy_count(count)))
                .collect(),
            length_distribution: stats
                .length_distribution
                .into_iter()
                .map(|(name, count)| {
                    let name = if name == "201+" { "200+".into() } else { name };
                    (name, legacy_count(count))
                })
                .collect(),
        }
    }
}

impl From<&StringFilter> for current::StringFilter {
    fn from(filter: &StringFilter) -> Self {
        Self {
            min_occurrences: filter.min_occurrences.map(|n| n as u64),
            max_occurrences: filter.max_occurrences.map(|n| n as u64),
            min_length: filter.min_length,
            max_length: filter.max_length,
            categories: filter.categories.clone(),
            file_paths: filter.file_paths.clone(),
            file_hashes: filter.file_hashes.clone(),
            suspicious_only: filter.suspicious_only,
            regex_pattern: filter.regex_pattern.clone(),
            min_entropy: filter.min_entropy,
            max_entropy: filter.max_entropy,
            date_range: filter.date_range,
        }
    }
}

/// Most distinct values the side index of values keeps (the upstream tracker
/// holds at most 100,000 distinct strings; this follows it).
const MAX_INDEXED_VALUES: usize = 100_000;
/// Most batch fingerprints remembered (a batch is one file's strings).
const MAX_REMEMBERED_BATCHES: usize = 10_000;
/// Most values the classifier holds before it starts over.
const MAX_CLASSIFIED_VALUES: usize = 20_000;

/// What [`StringTracker::track_strings_at`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackReport {
    /// True when this exact batch was tracked before, so nothing was added.
    pub already_indexed: bool,
    /// Occurrences recorded.
    pub tracked: usize,
    /// Values the tracker refused (too long, or its capacity was full). A
    /// repeated batch reports the count of the call that indexed it.
    pub skipped: usize,
    /// True when the file's strings were tracked by another route (another
    /// tool) already, so this batch added nothing: occurrences are not counted
    /// twice.
    pub tracked_by_other_route: bool,
}

/// Existing scanner interface backed by bounded upstream tracking.
///
/// Memory is bounded by the upstream limits (distinct strings, occurrences
/// per string, files per string); the side index of values and the batch
/// fingerprints follow the same bounds. Tracking the same batch twice (a
/// repeated call on an unchanged file) records nothing the second time.
#[derive(Clone)]
pub struct StringTracker {
    inner: current::StringTracker,
    values: Arc<Mutex<BTreeSet<String>>>,
    /// Batches tracked so far, with the values each one could not track.
    batches: Arc<Mutex<HashMap<[u8; 16], usize>>>,
    /// Which tool tracked the strings of a file (path and hash), so a second
    /// route does not count the same strings again.
    file_routes: Arc<Mutex<HashMap<[u8; 16], String>>>,
    /// Classifies values without recording them (category, entropy, suspicion
    /// as the tracker would give a string found in a file), so a per-file
    /// answer does not depend on whether the shared tracker had room.
    classifier: Arc<Mutex<ClassifierState>>,
}

struct ClassifierState {
    tracker: current::StringTracker,
    held: usize,
}

impl Default for StringTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StringTracker {
    /// Create a tracker retaining up to 1,000 details per distinct string.
    pub fn new() -> Self {
        Self {
            inner: Self::build_inner(),
            values: Arc::new(Mutex::new(BTreeSet::new())),
            batches: Arc::new(Mutex::new(HashMap::new())),
            file_routes: Arc::new(Mutex::new(HashMap::new())),
            classifier: Arc::new(Mutex::new(ClassifierState {
                tracker: Self::build_inner(),
                held: 0,
            })),
        }
    }

    fn build_inner() -> current::StringTracker {
        let patterns = legacy_patterns()
            .into_iter()
            .map(current::PatternDef::compile)
            .collect::<current::AnalysisResult<Vec<_>>>()
            .expect("file-scanner's static string patterns must compile");
        let analyzer = current::DefaultStringAnalyzer::new()
            // Legacy detection uses entropy strictly greater than 4.5.
            .with_entropy_threshold(f64::from_bits(4.5_f64.to_bits() + 1))
            .expect("the scanner's static entropy threshold must be valid")
            .with_patterns(patterns)
            .expect("file-scanner's static string patterns must be valid");
        current::StringTracker::with_components_and_config(
            Box::new(analyzer),
            Box::new(current::DefaultCategorizer::new()),
            current::AnalysisConfig {
                // Statistical samples historically include entropy > 4.0,
                // independently of the analyzer's suspicion threshold.
                min_suspicious_entropy: f64::from_bits(4.0_f64.to_bits() + 1),
                ..current::AnalysisConfig::default()
            },
        )
        .expect("the scanner's static tracker configuration must be valid")
    }

    /// Category, entropy and suspicion of `value` as a string found in a file,
    /// without recording it in the tracker (the returned entry has no
    /// occurrences worth reading). `None` when the value is not acceptable to
    /// the tracker at all (empty or too long).
    pub fn classify(&self, value: &str) -> Option<StringEntry> {
        let mut state = self
            .classifier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.tracker.get_string_details(value) {
            return Some(entry.into());
        }
        if state.held >= MAX_CLASSIFIED_VALUES {
            state.tracker.clear();
            state.held = 0;
        }
        state
            .tracker
            .track_string(
                value,
                "classify",
                "classify",
                "classify",
                StringContext::FileString { offset: None }.into(),
            )
            .ok()?;
        state.held += 1;
        state.tracker.get_string_details(value).map(Into::into)
    }

    /// Most distinct values the tracker holds.
    pub const CAPACITY: usize = MAX_INDEXED_VALUES;

    /// True when the tracker cannot take another distinct value.
    pub fn is_full(&self) -> bool {
        self.values().len() >= MAX_INDEXED_VALUES
    }

    fn values(&self) -> MutexGuard<'_, BTreeSet<String>> {
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn note_value(&self, value: &str) {
        let mut values = self.values();
        if values.len() < MAX_INDEXED_VALUES && !values.contains(value) {
            values.insert(value.to_string());
        }
    }

    /// Remember a batch. `None` the first time; the skipped count of the
    /// call that indexed it when it was remembered already.
    fn seen_batch(&self, fingerprint: [u8; 16]) -> Option<usize> {
        let mut batches = self
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(skipped) = batches.get(&fingerprint) {
            return Some(*skipped);
        }
        if batches.len() >= MAX_REMEMBERED_BATCHES {
            batches.clear();
        }
        batches.insert(fingerprint, 0);
        None
    }

    fn set_batch_skipped(&self, fingerprint: [u8; 16], skipped: usize) {
        if let Some(slot) = self
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&fingerprint)
        {
            *slot = skipped;
        }
    }

    /// Claim the strings of a file for `tool_name`. False when another tool
    /// claimed them already: the same strings are not counted twice.
    fn claim_file(&self, file_path: &str, file_hash: &str, tool_name: &str) -> bool {
        let mut hasher = blake3::Hasher::new();
        for part in [file_path, file_hash] {
            hasher.update(part.as_bytes());
            hasher.update(&[0]);
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        let mut routes = self
            .file_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if routes.len() >= MAX_REMEMBERED_BATCHES {
            routes.clear();
        }
        routes
            .entry(key)
            .or_insert_with(|| tool_name.to_string())
            .as_str()
            == tool_name
    }

    /// Track values with the offset each was found at, once per
    /// `(file_path, file_hash, tool_name, batch_key)`: the same call repeated
    /// is a no-op, and a file whose strings another tool tracked is not
    /// counted again
    /// (`batch_key` names the options that change the values, for example
    /// `min=4`).
    pub fn track_strings_at(
        &self,
        items: impl FnOnce() -> Vec<(String, usize)>,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        batch_key: &str,
    ) -> TrackReport {
        let mut hasher = blake3::Hasher::new();
        for part in [file_path, file_hash, tool_name, batch_key] {
            hasher.update(part.as_bytes());
            hasher.update(&[0]);
        }
        let mut fingerprint = [0u8; 16];
        fingerprint.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        if let Some(skipped) = self.seen_batch(fingerprint) {
            return TrackReport {
                already_indexed: true,
                skipped,
                ..TrackReport::default()
            };
        }
        if !self.claim_file(file_path, file_hash, tool_name) {
            return TrackReport {
                already_indexed: true,
                tracked_by_other_route: true,
                ..TrackReport::default()
            };
        }
        let mut report = TrackReport::default();
        for (value, offset) in items() {
            let context = StringContext::FileString {
                offset: Some(offset),
            };
            match self.track_string(&value, file_path, file_hash, tool_name, context) {
                Ok(()) => report.tracked += 1,
                Err(_) => report.skipped += 1,
            }
        }
        self.set_batch_skipped(fingerprint, report.skipped);
        report
    }

    /// Entries whose value contains `query` (case-insensitive) and matches
    /// `pattern`, then accepted by `accept`, most frequent first, at most
    /// `limit`. Every tracked value is inspected (the tracker holds at most
    /// 100,000), so the filters never miss a match.
    pub fn search_filtered(
        &self,
        query: Option<&str>,
        pattern: Option<&regex::Regex>,
        limit: usize,
        accept: &dyn Fn(&StringEntry) -> bool,
    ) -> Vec<StringEntry> {
        let query = query.map(str::to_lowercase);
        let candidates: Vec<String> = self
            .values()
            .iter()
            .filter(|value| {
                query
                    .as_ref()
                    .is_none_or(|q| value.to_lowercase().contains(q.as_str()))
                    && pattern.is_none_or(|p| p.is_match(value))
            })
            .cloned()
            .collect();
        let mut found: Vec<StringEntry> = candidates
            .iter()
            .filter_map(|value| self.get_string_details(value))
            .filter(|entry| accept(entry))
            .collect();
        found.sort_by(|a, b| {
            b.total_occurrences
                .cmp(&a.total_occurrences)
                .then_with(|| a.value.cmp(&b.value))
        });
        found.truncate(limit);
        found
    }

    /// Track an occurrence, returning upstream input or capacity errors.
    pub fn track_string(
        &self,
        value: &str,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        context: StringContext,
    ) -> Result<()> {
        self.inner
            .track_string(value, file_path, file_hash, tool_name, context.into())
            .map(|()| self.note_value(value))
            .map_err(Into::into)
    }

    /// Track each extracted value even when another value exceeds upstream bounds.
    /// Accepted values are retained; the first validation or capacity error is returned.
    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        for part in [file_path, file_hash, tool_name] {
            hasher.update(part.as_bytes());
            hasher.update(&[0]);
        }
        for value in strings {
            hasher.update(value.as_bytes());
            hasher.update(&[0]);
        }
        let mut fingerprint = [0u8; 16];
        fingerprint.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        if self.seen_batch(fingerprint).is_some() {
            // The same strings of the same file were tracked by an earlier call.
            return Ok(());
        }
        if !self.claim_file(file_path, file_hash, tool_name) {
            // Another tool tracked this file's strings already.
            return Ok(());
        }
        let mut first_error = None;
        for value in strings {
            match self.inner.track_strings_from_results(
                std::slice::from_ref(value),
                file_path,
                file_hash,
                tool_name,
            ) {
                Ok(()) => self.note_value(value),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    /// Return statistics, or an empty result for invalid filter criteria.
    /// Use [`Self::try_get_statistics`] to inspect validation errors.
    pub fn get_statistics(&self, filter: Option<&StringFilter>) -> StringStatistics {
        self.try_get_statistics(filter).unwrap_or_default()
    }

    /// Return statistics with validated filter criteria.
    pub fn try_get_statistics(&self, filter: Option<&StringFilter>) -> Result<StringStatistics> {
        let filter = filter.map(current::StringFilter::from);
        self.inner
            .get_statistics(filter.as_ref())
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Get detailed information about a specific string.
    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        self.inner.get_string_details(value).map(Into::into)
    }

    /// Search values, returning no matches for invalid queries.
    /// Use [`Self::try_search_strings`] to inspect validation errors.
    pub fn search_strings(&self, query: &str, limit: usize) -> Vec<StringEntry> {
        self.try_search_strings(query, limit).unwrap_or_default()
    }

    /// Search values with upstream input validation.
    pub fn try_search_strings(&self, query: &str, limit: usize) -> Result<Vec<StringEntry>> {
        self.inner
            .search_strings(query, limit)
            .map(|entries| entries.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    /// Get related strings, returning no matches for invalid input.
    /// Use [`Self::try_get_related_strings`] to inspect validation errors.
    pub fn get_related_strings(&self, value: &str, limit: usize) -> Vec<(String, f64)> {
        self.try_get_related_strings(value, limit)
            .unwrap_or_default()
    }

    /// Get related strings with upstream input validation.
    pub fn try_get_related_strings(&self, value: &str, limit: usize) -> Result<Vec<(String, f64)>> {
        self.inner
            .get_related_strings(value, limit)
            .map_err(Into::into)
    }

    /// Clear all tracked strings (and the memory of which files were indexed).
    pub fn clear(&self) {
        self.inner.clear();
        self.values().clear();
        self.batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.file_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

// Preserve the scanner's established heuristic policy from published
// threatflux-string-analysis 0.1.1. The current library validates/bounds these
// definitions; its newer default treats several of these indicators as
// informational, which would otherwise change scanner detection behavior.
type LegacyPattern = (&'static str, &'static str, &'static str, &'static str, u8);

const LEGACY_PATTERNS: [LegacyPattern; 11] = [
    (
        "url_pattern",
        r"(?i)(https?|ftp|ssh|telnet|rdp)://",
        "network",
        "URL or network protocol",
        3,
    ),
    (
        "ip_address",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "network",
        "IP address pattern",
        4,
    ),
    (
        "shell_command",
        r"(?i)(cmd\.exe|powershell|bash|sh)",
        "command",
        "Shell command interpreter",
        6,
    ),
    (
        "code_execution",
        r"(?i)(eval|exec|system|shell)",
        "execution",
        "Code execution function",
        7,
    ),
    (
        "crypto_algorithm",
        r"(?i)(base64|rot13|xor|aes|des|rsa)",
        "crypto",
        "Cryptographic or encoding algorithm",
        5,
    ),
    (
        "base64_string",
        r"^[A-Za-z0-9+/]{20,}={0,2}$",
        "encoding",
        "Potential Base64 encoded string",
        4,
    ),
    (
        "suspicious_path",
        r"(?i)(\\temp\\|\/tmp\/|\\windows\\system32)",
        "path",
        "Suspicious file path",
        5,
    ),
    (
        "credential_keyword",
        r"(?i)(passwords?|credential|secret|token|api[_-]?key)",
        "credential",
        "Credential-related keyword",
        8,
    ),
    (
        "registry_key",
        r"(?i)(HKEY_|SOFTWARE\\Microsoft\\Windows)",
        "registry",
        "Windows registry key",
        5,
    ),
    (
        "malware_keyword",
        r"(?i)(dropper|payload|inject|hook|rootkit)",
        "malware",
        "Common malware terminology",
        9,
    ),
    (
        "surveillance_keyword",
        r"(?i)(keylog|screenshot|webcam|microphone)",
        "surveillance",
        "Surveillance/spyware functionality",
        8,
    ),
];

fn legacy_patterns() -> Vec<current::PatternDef> {
    LEGACY_PATTERNS
        .into_iter()
        .map(
            |(name, regex, category, description, severity)| current::PatternDef {
                name: name.into(),
                regex: regex.into(),
                category: category.into(),
                description: description.into(),
                is_suspicious: true,
                severity,
            },
        )
        .collect()
}

#[cfg(test)]
mod tests;
