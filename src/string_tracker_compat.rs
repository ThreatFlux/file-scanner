//! Compatibility wrapper for the threatflux-string-analysis library
//! This maintains the existing API for file-scanner while using the new library

use anyhow::Result;

// Re-export types from the library that match the original API
pub use threatflux_string_analysis::{StringContext, StringEntry, StringFilter, StringStatistics};

/// Wrapper around the threatflux-string-analysis `StringTracker`
/// that maintains backward compatibility
#[derive(Clone)]
pub struct StringTracker {
    inner: threatflux_string_analysis::StringTracker,
}

impl Default for StringTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StringTracker {
    /// Create a new `StringTracker` with file-scanner specific configuration
    pub fn new() -> Self {
        // Create the tracker with file-scanner specific patterns
        let tracker = threatflux_string_analysis::StringTracker::new().with_max_occurrences(1000);

        Self { inner: tracker }
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
        self.inner
            .track_string(value, file_path, file_hash, tool_name, context)
    }

    /// Track multiple strings from results
    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> Result<()> {
        self.inner
            .track_strings_from_results(strings, file_path, file_hash, tool_name)
    }

    /// Get statistics about tracked strings
    pub fn get_statistics(&self, filter: Option<&StringFilter>) -> StringStatistics {
        self.inner.get_statistics(filter)
    }

    /// Get detailed information about a specific string
    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        self.inner.get_string_details(value)
    }

    /// Search for strings matching a query
    pub fn search_strings(&self, query: &str, limit: usize) -> Vec<StringEntry> {
        self.inner.search_strings(query, limit)
    }

    /// Get strings related to a given string
    pub fn get_related_strings(&self, value: &str, limit: usize) -> Vec<(String, f64)> {
        self.inner.get_related_strings(value, limit)
    }

    /// Clear all tracked strings
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.inner.clear();
    }
}
