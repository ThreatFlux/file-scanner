//! String tracking and analysis functionality

use crate::analyzer::{DefaultStringAnalyzer, StringAnalyzer};
use crate::categorizer::{Categorizer, DefaultCategorizer};
use crate::patterns::{DefaultPatternProvider, PatternProvider};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Context in which a string was found
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

/// Record of a single string occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    pub timestamp: DateTime<Utc>,
    pub context: StringContext,
}

/// Complete information about a tracked string
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

/// Statistics about tracked strings
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

/// Filter criteria for string queries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Main string tracking system
#[derive(Clone)]
pub struct StringTracker {
    entries: Arc<Mutex<HashMap<String, StringEntry>>>,
    analyzer: Arc<Box<dyn StringAnalyzer>>,
    categorizer: Arc<Box<dyn Categorizer>>,
    max_occurrences_per_string: usize,
}

impl Default for StringTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StringTracker {
    /// Create a new StringTracker with default analyzer and categorizer
    pub fn new() -> Self {
        let pattern_provider = DefaultPatternProvider::default();
        let analyzer = DefaultStringAnalyzer::new().with_patterns(pattern_provider.get_patterns());

        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            analyzer: Arc::new(Box::new(analyzer)),
            categorizer: Arc::new(Box::new(DefaultCategorizer::new())),
            max_occurrences_per_string: 1000,
        }
    }

    /// Create a StringTracker with custom analyzer and categorizer
    pub fn with_components(
        analyzer: Box<dyn StringAnalyzer>,
        categorizer: Box<dyn Categorizer>,
    ) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            analyzer: Arc::new(analyzer),
            categorizer: Arc::new(categorizer),
            max_occurrences_per_string: 1000,
        }
    }

    /// Set the maximum number of occurrences to track per string
    pub fn with_max_occurrences(mut self, max: usize) -> Self {
        self.max_occurrences_per_string = max;
        self
    }

    /// Track a string occurrence
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

        // Get category from context
        let context_category = match &context {
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
            let analysis = self.analyzer.analyze(value);
            let categories = self.categorizer.categorize(value);

            let mut category_set = HashSet::new();
            category_set.insert(context_category.to_string());
            for cat in categories {
                category_set.insert(cat.name);
            }
            for cat in analysis.categories {
                category_set.insert(cat);
            }

            StringEntry {
                value: value.to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                total_occurrences: 0,
                unique_files: HashSet::new(),
                occurrences: Vec::new(),
                categories: category_set,
                is_suspicious: analysis.is_suspicious,
                entropy: analysis.entropy,
            }
        });

        entry.last_seen = Utc::now();
        entry.total_occurrences += 1;
        entry.unique_files.insert(file_hash.to_string());
        entry.occurrences.push(occurrence);

        // Limit occurrences per string to prevent memory explosion
        if entry.occurrences.len() > self.max_occurrences_per_string {
            entry.occurrences.remove(0);
        }

        Ok(())
    }

    /// Track multiple strings from results
    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> Result<()> {
        for string in strings {
            // Categorize the string using the categorizer
            let categories = self.categorizer.categorize(string);

            // Determine context based on categories
            let context = if categories.iter().any(|c| c.name == "url") {
                let protocol = string.split("://").next().map(|p| p.to_string());
                StringContext::Url { protocol }
            } else if categories.iter().any(|c| c.name == "path") {
                let path_type = if string.contains("\\Windows") || string.contains("/usr") {
                    "system"
                } else if string.contains("\\Temp") || string.contains("/tmp") {
                    "temp"
                } else {
                    "general"
                };
                StringContext::Path {
                    path_type: path_type.to_string(),
                }
            } else if categories.iter().any(|c| c.name == "registry") {
                let hive = string.split('\\').next().map(|h| h.to_string());
                StringContext::Registry { hive }
            } else if categories.iter().any(|c| c.name == "library") {
                StringContext::Import {
                    library: string.to_string(),
                }
            } else if categories.iter().any(|c| c.name == "command") {
                StringContext::Command {
                    command_type: "shell".to_string(),
                }
            } else {
                StringContext::FileString { offset: None }
            };

            self.track_string(string, file_path, file_hash, tool_name, context)?;
        }
        Ok(())
    }

    /// Get statistics about tracked strings
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

    /// Get detailed information about a specific string
    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        let entries = self.entries.lock().unwrap();
        entries.get(value).cloned()
    }

    /// Search for strings matching a query
    pub fn search_strings(&self, query: &str, limit: usize) -> Vec<StringEntry> {
        // Return empty results for empty queries
        if query.trim().is_empty() {
            return Vec::new();
        }

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

    /// Get strings related to a given string
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

    /// Clear all tracked strings
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}
