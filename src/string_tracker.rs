use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    pub timestamp: DateTime<Utc>,
    pub context: StringContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringContext {
    FileString { offset: Option<usize> },
    Import { library: String },
    Export { symbol: String },
    Resource { resource_type: String },
    Section { section_name: String },
    Metadata { field: String },
    Path { path_type: String },
    Url { protocol: Option<String> },
    Registry { hive: Option<String> },
    Command { command_type: String },
    Other { category: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub value: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_occurrences: usize,
    pub unique_files: HashSet<String>,
    pub occurrences: Vec<StringOccurrence>,
    pub categories: HashSet<String>,
    pub is_suspicious: bool,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringStatistics {
    pub total_unique_strings: usize,
    pub total_occurrences: usize,
    pub total_files_analyzed: usize,
    pub most_common: Vec<(String, usize)>,
    pub suspicious_strings: Vec<String>,
    pub high_entropy_strings: Vec<(String, f64)>,
    pub category_distribution: HashMap<String, usize>,
    pub length_distribution: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringFilter {
    pub min_occurrences: Option<usize>,
    pub max_occurrences: Option<usize>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub categories: Option<Vec<String>>,
    pub file_paths: Option<Vec<String>>,
    pub file_hashes: Option<Vec<String>>,
    pub suspicious_only: Option<bool>,
    pub regex_pattern: Option<String>,
    pub min_entropy: Option<f64>,
    pub max_entropy: Option<f64>,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

#[derive(Clone)]
pub struct StringTracker {
    entries: Arc<Mutex<HashMap<String, StringEntry>>>,
    suspicious_patterns: Vec<regex::Regex>,
}

impl Default for StringTracker {
    fn default() -> Self {
        let suspicious_patterns = vec![
            // Network indicators
            regex::Regex::new(r"(?i)(https?|ftp|ssh|telnet|rdp)://").unwrap(),
            regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
            regex::Regex::new(r"(?i)(cmd\.exe|powershell|bash|sh)").unwrap(),
            regex::Regex::new(r"(?i)(eval|exec|system|shell)").unwrap(),
            // Crypto/encoding
            regex::Regex::new(r"(?i)(base64|rot13|xor|aes|des|rsa)").unwrap(),
            regex::Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap(), // Base64
            // Suspicious paths
            regex::Regex::new(r"(?i)(\\temp\\|\/tmp\/|\\windows\\system32)").unwrap(),
            regex::Regex::new(r"(?i)(passwords?|credential|secret|token|api[_-]?key)").unwrap(),
            // Registry keys
            regex::Regex::new(r"(?i)(HKEY_|SOFTWARE\\Microsoft\\Windows)").unwrap(),
            // Common malware strings
            regex::Regex::new(r"(?i)(dropper|payload|inject|hook|rootkit)").unwrap(),
            regex::Regex::new(r"(?i)(keylog|screenshot|webcam|microphone)").unwrap(),
        ];

        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            suspicious_patterns,
        }
    }
}

impl StringTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track_string(
        &self,
        value: &str,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        context: StringContext,
    ) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();

        let occurrence = StringOccurrence {
            file_path: file_path.to_string(),
            file_hash: file_hash.to_string(),
            tool_name: tool_name.to_string(),
            timestamp: Utc::now(),
            context: context.clone(),
        };

        let category = match &context {
            StringContext::FileString { .. } => "file_string",
            StringContext::Import { .. } => "import",
            StringContext::Export { .. } => "export",
            StringContext::Resource { .. } => "resource",
            StringContext::Section { .. } => "section",
            StringContext::Metadata { .. } => "metadata",
            StringContext::Path { .. } => "path",
            StringContext::Url { .. } => "url",
            StringContext::Registry { .. } => "registry",
            StringContext::Command { .. } => "command",
            StringContext::Other { category } => category,
        };

        let entry = entries.entry(value.to_string()).or_insert_with(|| {
            let entropy = self.calculate_entropy(value);
            let is_suspicious = self.is_suspicious(value);

            StringEntry {
                value: value.to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_occurrences: 0,
                unique_files: HashSet::new(),
                occurrences: Vec::new(),
                categories: HashSet::new(),
                is_suspicious,
                entropy,
            }
        });

        entry.last_seen = Utc::now();
        entry.total_occurrences += 1;
        entry.unique_files.insert(file_hash.to_string());
        entry.occurrences.push(occurrence);
        entry.categories.insert(category.to_string());

        // Limit occurrences per string to prevent memory explosion
        if entry.occurrences.len() > 1000 {
            entry.occurrences.remove(0);
        }

        Ok(())
    }

    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> Result<()> {
        for string in strings {
            // Categorize the string
            let context = self.categorize_string(string);
            self.track_string(string, file_path, file_hash, tool_name, context)?;
        }
        Ok(())
    }

    fn categorize_string(&self, s: &str) -> StringContext {
        // URL detection
        if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
            let protocol = s.split("://").next().map(|p| p.to_string());
            return StringContext::Url { protocol };
        }

        // Path detection
        if (s.contains('/') || s.contains('\\'))
            && (s.starts_with("/") || s.starts_with("\\") || s.contains(":\\"))
        {
            let path_type = if s.contains("\\Windows") || s.contains("/usr") {
                "system"
            } else if s.contains("\\Temp") || s.contains("/tmp") {
                "temp"
            } else {
                "general"
            };
            return StringContext::Path {
                path_type: path_type.to_string(),
            };
        }

        // Registry key detection
        if s.starts_with("HKEY_") || s.contains("\\SOFTWARE\\") {
            let hive = s.split('\\').next().map(|h| h.to_string());
            return StringContext::Registry { hive };
        }

        // Import/Export detection (simplified)
        if s.ends_with(".dll") || s.ends_with(".so") || s.ends_with(".dylib") {
            return StringContext::Import {
                library: s.to_string(),
            };
        }

        // Command detection
        if s.contains("cmd") || s.contains("powershell") || s.contains("bash") {
            return StringContext::Command {
                command_type: "shell".to_string(),
            };
        }

        // Default to file string
        StringContext::FileString { offset: None }
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts = HashMap::new();
        for ch in s.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in char_counts.values() {
            let probability = *count as f64 / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn is_suspicious(&self, s: &str) -> bool {
        // Check against suspicious patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(s) {
                return true;
            }
        }

        // Check entropy (high entropy might indicate encoding/encryption)
        let entropy = self.calculate_entropy(s);
        if entropy > 4.5 && s.len() > 10 {
            return true;
        }

        // Check for non-printable characters
        if s.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
        {
            return true;
        }

        false
    }

    pub fn get_statistics(&self, filter: Option<&StringFilter>) -> StringStatistics {
        let entries = self.entries.lock().unwrap();

        let filtered_entries: Vec<_> = entries
            .values()
            .filter(|entry| self.matches_filter(entry, filter))
            .collect();

        let total_unique_strings = filtered_entries.len();
        let total_occurrences: usize = filtered_entries.iter().map(|e| e.total_occurrences).sum();

        let total_files_analyzed: HashSet<_> = filtered_entries
            .iter()
            .flat_map(|e| e.unique_files.iter())
            .collect();

        // Most common strings
        let mut most_common: Vec<_> = filtered_entries
            .iter()
            .map(|e| (e.value.clone(), e.total_occurrences))
            .collect();
        most_common.sort_by(|a, b| b.1.cmp(&a.1));
        most_common.truncate(100);

        // Suspicious strings
        let suspicious_strings: Vec<_> = filtered_entries
            .iter()
            .filter(|e| e.is_suspicious)
            .map(|e| e.value.clone())
            .take(50)
            .collect();

        // High entropy strings
        let mut high_entropy_strings: Vec<_> = filtered_entries
            .iter()
            .filter(|e| e.entropy > 4.0)
            .map(|e| (e.value.clone(), e.entropy))
            .collect();
        high_entropy_strings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        high_entropy_strings.truncate(50);

        // Category distribution
        let mut category_distribution = HashMap::new();
        for entry in &filtered_entries {
            for category in &entry.categories {
                *category_distribution.entry(category.clone()).or_insert(0) += 1;
            }
        }

        // Length distribution
        let mut length_distribution = HashMap::new();
        for entry in &filtered_entries {
            let len_bucket = match entry.value.len() {
                0..=10 => "0-10",
                11..=20 => "11-20",
                21..=50 => "21-50",
                51..=100 => "51-100",
                101..=200 => "101-200",
                _ => "200+",
            };
            *length_distribution
                .entry(len_bucket.to_string())
                .or_insert(0) += 1;
        }

        StringStatistics {
            total_unique_strings,
            total_occurrences,
            total_files_analyzed: total_files_analyzed.len(),
            most_common,
            suspicious_strings,
            high_entropy_strings,
            category_distribution,
            length_distribution,
        }
    }

    fn matches_filter(&self, entry: &StringEntry, filter: Option<&StringFilter>) -> bool {
        let Some(f) = filter else {
            return true;
        };

        if let Some(min) = f.min_occurrences {
            if entry.total_occurrences < min {
                return false;
            }
        }

        if let Some(max) = f.max_occurrences {
            if entry.total_occurrences > max {
                return false;
            }
        }

        if let Some(min) = f.min_length {
            if entry.value.len() < min {
                return false;
            }
        }

        if let Some(max) = f.max_length {
            if entry.value.len() > max {
                return false;
            }
        }

        if let Some(ref categories) = f.categories {
            if !categories.iter().any(|c| entry.categories.contains(c)) {
                return false;
            }
        }

        if let Some(ref file_hashes) = f.file_hashes {
            if !file_hashes.iter().any(|h| entry.unique_files.contains(h)) {
                return false;
            }
        }

        if let Some(suspicious_only) = f.suspicious_only {
            if suspicious_only && !entry.is_suspicious {
                return false;
            }
        }

        if let Some(ref pattern) = f.regex_pattern {
            if let Ok(re) = regex::Regex::new(pattern) {
                if !re.is_match(&entry.value) {
                    return false;
                }
            }
        }

        if let Some(min_entropy) = f.min_entropy {
            if entry.entropy < min_entropy {
                return false;
            }
        }

        if let Some(max_entropy) = f.max_entropy {
            if entry.entropy > max_entropy {
                return false;
            }
        }

        true
    }

    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        let entries = self.entries.lock().unwrap();
        entries.get(value).cloned()
    }

    pub fn search_strings(&self, query: &str, limit: usize) -> Vec<StringEntry> {
        let entries = self.entries.lock().unwrap();
        let query_lower = query.to_lowercase();

        let mut results: Vec<_> = entries
            .values()
            .filter(|e| e.value.to_lowercase().contains(&query_lower))
            .cloned()
            .collect();

        results.sort_by(|a, b| b.total_occurrences.cmp(&a.total_occurrences));
        results.truncate(limit);
        results
    }

    pub fn get_related_strings(&self, value: &str, limit: usize) -> Vec<(String, f64)> {
        let entries = self.entries.lock().unwrap();

        let Some(target_entry) = entries.get(value) else {
            return vec![];
        };

        let mut similarities: Vec<_> = entries
            .iter()
            .filter(|(k, _)| *k != value)
            .map(|(k, v)| {
                let similarity = self.calculate_similarity(target_entry, v);
                (k.clone(), similarity)
            })
            .filter(|(_, sim)| *sim > 0.3)
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        similarities.truncate(limit);
        similarities
    }

    fn calculate_similarity(&self, a: &StringEntry, b: &StringEntry) -> f64 {
        let mut score = 0.0;
        let mut factors = 0.0;

        // Shared files
        let shared_files: HashSet<_> = a.unique_files.intersection(&b.unique_files).collect();
        if !shared_files.is_empty() {
            score +=
                shared_files.len() as f64 / a.unique_files.len().min(b.unique_files.len()) as f64;
            factors += 1.0;
        }

        // Shared categories
        let shared_categories: HashSet<_> = a.categories.intersection(&b.categories).collect();
        if !shared_categories.is_empty() {
            score +=
                shared_categories.len() as f64 / a.categories.len().min(b.categories.len()) as f64;
            factors += 1.0;
        }

        // Similar entropy
        let entropy_diff = (a.entropy - b.entropy).abs();
        if entropy_diff < 0.5 {
            score += 1.0 - (entropy_diff / 0.5);
            factors += 1.0;
        }

        // Similar length
        let len_a = a.value.len() as f64;
        let len_b = b.value.len() as f64;
        let len_ratio = len_a.min(len_b) / len_a.max(len_b);
        score += len_ratio;
        factors += 1.0;

        if factors > 0.0 {
            score / factors
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_string_tracker_new() {
        let tracker = StringTracker::new();
        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 0);
        assert_eq!(stats.total_occurrences, 0);
    }

    #[test]
    fn test_track_string_basic() {
        let tracker = StringTracker::new();
        let context = StringContext::FileString { offset: Some(100) };

        let result = tracker.track_string(
            "test string",
            "/path/to/file",
            "hash123",
            "test_tool",
            context,
        );

        assert!(result.is_ok());

        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 1);
        assert_eq!(stats.total_occurrences, 1);
    }

    #[test]
    fn test_track_string_multiple_occurrences() {
        let tracker = StringTracker::new();
        let context = StringContext::FileString { offset: Some(100) };

        // Track same string multiple times
        for i in 0..5 {
            tracker
                .track_string(
                    "repeated string",
                    &format!("/path/to/file{}", i),
                    &format!("hash{}", i),
                    "test_tool",
                    context.clone(),
                )
                .unwrap();
        }

        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 1);
        assert_eq!(stats.total_occurrences, 5);

        let entry = tracker.get_string_details("repeated string").unwrap();
        assert_eq!(entry.total_occurrences, 5);
        assert_eq!(entry.unique_files.len(), 5);
    }

    #[test]
    fn test_string_contexts() {
        let tracker = StringTracker::new();

        let contexts = vec![
            StringContext::Import {
                library: "kernel32.dll".to_string(),
            },
            StringContext::Export {
                symbol: "main".to_string(),
            },
            StringContext::Resource {
                resource_type: "icon".to_string(),
            },
            StringContext::Section {
                section_name: ".text".to_string(),
            },
            StringContext::Metadata {
                field: "version".to_string(),
            },
            StringContext::Path {
                path_type: "system".to_string(),
            },
            StringContext::Url {
                protocol: Some("https".to_string()),
            },
            StringContext::Registry {
                hive: Some("HKEY_LOCAL_MACHINE".to_string()),
            },
            StringContext::Command {
                command_type: "shell".to_string(),
            },
            StringContext::Other {
                category: "custom".to_string(),
            },
        ];

        for (i, context) in contexts.into_iter().enumerate() {
            tracker
                .track_string(
                    &format!("string{}", i),
                    "/test/file",
                    "hash123",
                    "test_tool",
                    context,
                )
                .unwrap();
        }

        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 10);
        assert!(stats.category_distribution.len() >= 9); // Should have multiple categories
    }

    #[test]
    fn test_track_strings_from_results() {
        let tracker = StringTracker::new();
        let strings = vec![
            "https://example.com".to_string(),
            "/usr/bin/bash".to_string(),
            "kernel32.dll".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE".to_string(),
        ];

        let result =
            tracker.track_strings_from_results(&strings, "/test/file", "hash123", "test_tool");

        assert!(result.is_ok());

        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 4);
        assert_eq!(stats.total_occurrences, 4);
    }

    #[test]
    fn test_categorize_string_url() {
        let tracker = StringTracker::new();

        let url_context = tracker.categorize_string("https://example.com");
        match url_context {
            StringContext::Url { protocol } => {
                assert_eq!(protocol, Some("https".to_string()));
            }
            _ => panic!("Expected URL context"),
        }
    }

    #[test]
    fn test_categorize_string_path() {
        let tracker = StringTracker::new();

        let path_context = tracker.categorize_string("/usr/bin/test");
        match path_context {
            StringContext::Path { path_type } => {
                assert_eq!(path_type, "system");
            }
            _ => panic!("Expected Path context"),
        }

        let temp_context = tracker.categorize_string("C:\\Temp\\file.txt");
        match temp_context {
            StringContext::Path { path_type } => {
                assert_eq!(path_type, "temp");
            }
            _ => panic!("Expected Path context"),
        }
    }

    #[test]
    fn test_categorize_string_registry() {
        let tracker = StringTracker::new();

        let registry_context = tracker.categorize_string("HKEY_LOCAL_MACHINE\\SOFTWARE\\Test");
        match registry_context {
            StringContext::Registry { hive } => {
                assert_eq!(hive, Some("HKEY_LOCAL_MACHINE".to_string()));
            }
            _ => panic!("Expected Registry context"),
        }
    }

    #[test]
    fn test_categorize_string_import() {
        let tracker = StringTracker::new();

        let import_context = tracker.categorize_string("kernel32.dll");
        match import_context {
            StringContext::Import { library } => {
                assert_eq!(library, "kernel32.dll");
            }
            _ => panic!("Expected Import context"),
        }
    }

    #[test]
    fn test_categorize_string_command() {
        let tracker = StringTracker::new();

        let cmd_context = tracker.categorize_string("cmd.exe /c dir");
        match cmd_context {
            StringContext::Command { command_type } => {
                assert_eq!(command_type, "shell");
            }
            _ => panic!("Expected Command context"),
        }
    }

    #[test]
    fn test_calculate_entropy() {
        let tracker = StringTracker::new();

        // Low entropy (repeated characters)
        let low_entropy = tracker.calculate_entropy("aaaaaaaaaa");
        assert!(low_entropy < 1.0);

        // High entropy (random-looking)
        let high_entropy = tracker.calculate_entropy("aB3xY9zK2m");
        assert!(high_entropy > 3.0);

        // Empty string
        let zero_entropy = tracker.calculate_entropy("");
        assert_eq!(zero_entropy, 0.0);
    }

    #[test]
    fn test_is_suspicious() {
        let tracker = StringTracker::new();

        // URL should be suspicious
        assert!(tracker.is_suspicious("https://malware.com/download"));

        // IP address should be suspicious
        assert!(tracker.is_suspicious("192.168.1.1"));

        // Command should be suspicious
        assert!(tracker.is_suspicious("cmd.exe"));

        // High entropy should be suspicious (make it longer to trigger the entropy check)
        assert!(tracker.is_suspicious("aB3xY9zK2mP5qW8eF7gH1iJ"));

        // Normal string should not be suspicious
        assert!(!tracker.is_suspicious("hello world"));

        // String with control characters should be suspicious
        assert!(tracker.is_suspicious("test\x01string"));
    }

    #[test]
    fn test_statistics_with_filter() {
        let tracker = StringTracker::new();

        // Add various strings
        tracker
            .track_string(
                "short",
                "/file1",
                "hash1",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
        tracker
            .track_string(
                "medium length string",
                "/file2",
                "hash2",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
        tracker
            .track_string(
                "https://suspicious.com",
                "/file3",
                "hash3",
                "tool",
                StringContext::Url { protocol: None },
            )
            .unwrap();

        // Test length filter
        let filter = StringFilter {
            min_length: Some(10),
            max_length: None,
            min_occurrences: None,
            max_occurrences: None,
            categories: None,
            file_paths: None,
            file_hashes: None,
            suspicious_only: None,
            regex_pattern: None,
            min_entropy: None,
            max_entropy: None,
            date_range: None,
        };

        let stats = tracker.get_statistics(Some(&filter));
        assert_eq!(stats.total_unique_strings, 2); // Only medium and URL strings

        // Test suspicious filter
        let suspicious_filter = StringFilter {
            min_length: None,
            max_length: None,
            min_occurrences: None,
            max_occurrences: None,
            categories: None,
            file_paths: None,
            file_hashes: None,
            suspicious_only: Some(true),
            regex_pattern: None,
            min_entropy: None,
            max_entropy: None,
            date_range: None,
        };

        let suspicious_stats = tracker.get_statistics(Some(&suspicious_filter));
        assert!(suspicious_stats.total_unique_strings >= 1); // At least the URL
    }

    #[test]
    fn test_search_strings() {
        let tracker = StringTracker::new();

        tracker
            .track_string(
                "test string one",
                "/file1",
                "hash1",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
        tracker
            .track_string(
                "test string two",
                "/file2",
                "hash2",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
        tracker
            .track_string(
                "different content",
                "/file3",
                "hash3",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let results = tracker.search_strings("test", 10);
        assert_eq!(results.len(), 2);

        let results = tracker.search_strings("string", 10);
        assert_eq!(results.len(), 2);

        let results = tracker.search_strings("different", 10);
        assert_eq!(results.len(), 1);

        let results = tracker.search_strings("nonexistent", 10);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_get_string_details() {
        let tracker = StringTracker::new();

        tracker
            .track_string(
                "detailed string",
                "/file1",
                "hash1",
                "tool",
                StringContext::FileString { offset: Some(100) },
            )
            .unwrap();

        let details = tracker.get_string_details("detailed string");
        assert!(details.is_some());

        let entry = details.unwrap();
        assert_eq!(entry.value, "detailed string");
        assert_eq!(entry.total_occurrences, 1);
        assert_eq!(entry.unique_files.len(), 1);
        assert!(entry.unique_files.contains("hash1"));

        let no_details = tracker.get_string_details("nonexistent string");
        assert!(no_details.is_none());
    }

    #[test]
    fn test_get_related_strings() {
        let tracker = StringTracker::new();

        // Add strings that should be related (same file, same category)
        let context = StringContext::Import {
            library: "test.dll".to_string(),
        };
        tracker
            .track_string("string1", "/file1", "hash1", "tool", context.clone())
            .unwrap();
        tracker
            .track_string("string2", "/file1", "hash1", "tool", context.clone())
            .unwrap();
        tracker
            .track_string(
                "unrelated",
                "/file2",
                "hash2",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let related = tracker.get_related_strings("string1", 10);
        assert!(!related.is_empty());

        // Should find string2 as related
        assert!(related.iter().any(|(s, _)| s == "string2"));
    }

    #[test]
    fn test_calculate_similarity() {
        let tracker = StringTracker::new();

        let entry_a = StringEntry {
            value: "string_a".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            total_occurrences: 1,
            unique_files: ["file1", "file2"].iter().map(|s| s.to_string()).collect(),
            occurrences: vec![],
            categories: ["category1", "category2"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            is_suspicious: false,
            entropy: 3.5,
        };

        let entry_b = StringEntry {
            value: "string_b".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            total_occurrences: 1,
            unique_files: ["file1", "file3"].iter().map(|s| s.to_string()).collect(),
            occurrences: vec![],
            categories: ["category1", "category3"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            is_suspicious: false,
            entropy: 3.7,
        };

        let similarity = tracker.calculate_similarity(&entry_a, &entry_b);
        assert!(similarity > 0.0);
        assert!(similarity <= 1.0);
    }

    #[test]
    fn test_filter_matching() {
        let tracker = StringTracker::new();

        let entry = StringEntry {
            value: "test string".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            total_occurrences: 5,
            unique_files: HashSet::new(),
            occurrences: vec![],
            categories: ["file_string"].iter().map(|s| s.to_string()).collect(),
            is_suspicious: false,
            entropy: 2.5,
        };

        // Test min occurrences
        let filter = StringFilter {
            min_occurrences: Some(3),
            max_occurrences: None,
            min_length: None,
            max_length: None,
            categories: None,
            file_paths: None,
            file_hashes: None,
            suspicious_only: None,
            regex_pattern: None,
            min_entropy: None,
            max_entropy: None,
            date_range: None,
        };
        assert!(tracker.matches_filter(&entry, Some(&filter)));

        // Test max occurrences
        let filter = StringFilter {
            min_occurrences: None,
            max_occurrences: Some(3),
            min_length: None,
            max_length: None,
            categories: None,
            file_paths: None,
            file_hashes: None,
            suspicious_only: None,
            regex_pattern: None,
            min_entropy: None,
            max_entropy: None,
            date_range: None,
        };
        assert!(!tracker.matches_filter(&entry, Some(&filter)));

        // Test categories
        let filter = StringFilter {
            min_occurrences: None,
            max_occurrences: None,
            min_length: None,
            max_length: None,
            categories: Some(vec!["file_string".to_string()]),
            file_paths: None,
            file_hashes: None,
            suspicious_only: None,
            regex_pattern: None,
            min_entropy: None,
            max_entropy: None,
            date_range: None,
        };
        assert!(tracker.matches_filter(&entry, Some(&filter)));
    }

    #[test]
    fn test_occurrence_limit() {
        let tracker = StringTracker::new();
        let context = StringContext::FileString { offset: None };

        // Add more than 1000 occurrences
        for i in 0..1200 {
            tracker
                .track_string(
                    "limited string",
                    &format!("/file{}", i),
                    &format!("hash{}", i),
                    "tool",
                    context.clone(),
                )
                .unwrap();
        }

        let entry = tracker.get_string_details("limited string").unwrap();
        assert_eq!(entry.total_occurrences, 1200);
        assert_eq!(entry.unique_files.len(), 1200);
        assert!(entry.occurrences.len() <= 1000); // Should be limited
    }

    #[test]
    fn test_clear() {
        let tracker = StringTracker::new();

        tracker
            .track_string(
                "test",
                "/file",
                "hash",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 1);

        tracker.clear();

        let stats = tracker.get_statistics(None);
        assert_eq!(stats.total_unique_strings, 0);
    }

    #[test]
    fn test_string_entry_serialization() {
        let entry = StringEntry {
            value: "test string".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            total_occurrences: 5,
            unique_files: ["hash1", "hash2"].iter().map(|s| s.to_string()).collect(),
            occurrences: vec![StringOccurrence {
                file_path: "/test/file".to_string(),
                file_hash: "hash1".to_string(),
                tool_name: "test_tool".to_string(),
                timestamp: Utc::now(),
                context: StringContext::FileString { offset: Some(100) },
            }],
            categories: ["file_string"].iter().map(|s| s.to_string()).collect(),
            is_suspicious: false,
            entropy: 2.5,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: StringEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.value, entry.value);
        assert_eq!(deserialized.total_occurrences, entry.total_occurrences);
        assert_eq!(deserialized.unique_files, entry.unique_files);
        assert_eq!(deserialized.categories, entry.categories);
    }

    #[test]
    fn test_string_statistics_serialization() {
        let stats = StringStatistics {
            total_unique_strings: 10,
            total_occurrences: 25,
            total_files_analyzed: 5,
            most_common: vec![("test".to_string(), 10), ("example".to_string(), 5)],
            suspicious_strings: vec!["malware.exe".to_string()],
            high_entropy_strings: vec![("encoded".to_string(), 4.5)],
            category_distribution: [("file_string".to_string(), 15)].iter().cloned().collect(),
            length_distribution: [("0-10".to_string(), 8)].iter().cloned().collect(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: StringStatistics = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.total_unique_strings,
            stats.total_unique_strings
        );
        assert_eq!(deserialized.total_occurrences, stats.total_occurrences);
        assert_eq!(deserialized.most_common, stats.most_common);
    }

    #[test]
    fn test_regex_filter() {
        let tracker = StringTracker::new();

        tracker
            .track_string(
                "test123",
                "/file1",
                "hash1",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
        tracker
            .track_string(
                "example456",
                "/file2",
                "hash2",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
        tracker
            .track_string(
                "nodigits",
                "/file3",
                "hash3",
                "tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let filter = StringFilter {
            min_occurrences: None,
            max_occurrences: None,
            min_length: None,
            max_length: None,
            categories: None,
            file_paths: None,
            file_hashes: None,
            suspicious_only: None,
            regex_pattern: Some(r"\d+".to_string()), // Strings with digits
            min_entropy: None,
            max_entropy: None,
            date_range: None,
        };

        let stats = tracker.get_statistics(Some(&filter));
        assert_eq!(stats.total_unique_strings, 2); // test123 and example456
    }
}
