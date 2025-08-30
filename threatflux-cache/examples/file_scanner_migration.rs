//! Example showing how to migrate from file-scanner's cache to threatflux-cache

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use threatflux_cache::prelude::*;
use threatflux_cache::{PersistenceConfig, SearchQuery};

// Replicate file-scanner's cache entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileAnalysisResult {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    pub tool_args: HashMap<String, serde_json::Value>,
    pub result: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub file_size: u64,
    pub execution_time_ms: u64,
}

// Custom metadata for file analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileAnalysisMetadata {
    pub file_path: String,
    pub tool_name: String,
    pub tool_args: HashMap<String, serde_json::Value>,
    pub file_size: u64,
    pub execution_time_ms: u64,
}

impl EntryMetadata for FileAnalysisMetadata {
    fn execution_time_ms(&self) -> Option<u64> {
        Some(self.execution_time_ms)
    }

    fn size_bytes(&self) -> Option<u64> {
        Some(self.file_size)
    }

    fn category(&self) -> Option<&str> {
        Some(&self.tool_name)
    }
}

// Adapter functions to maintain API compatibility
pub struct FileAnalysisCacheAdapter {
    #[cfg(feature = "filesystem-backend")]
    cache: Cache<String, serde_json::Value, FileAnalysisMetadata, FilesystemBackend<String, serde_json::Value, FileAnalysisMetadata>>,
    #[cfg(not(feature = "filesystem-backend"))]
    cache: Cache<String, serde_json::Value, FileAnalysisMetadata, MemoryBackend<String, serde_json::Value, FileAnalysisMetadata>>,
}

impl FileAnalysisCacheAdapter {
    pub async fn new(cache_dir: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let config = CacheConfig::default()
            .with_max_entries_per_key(100)
            .with_max_total_entries(10000)
            .with_persistence(PersistenceConfig::with_path(cache_dir));

        #[cfg(feature = "filesystem-backend")]
        let backend = FilesystemBackend::new(cache_dir).await?;
        #[cfg(not(feature = "filesystem-backend"))]
        let backend = MemoryBackend::new();

        let cache = Cache::new(config, backend).await?;

        Ok(Self { cache })
    }

    pub async fn add_entry(
        &self,
        entry: FileAnalysisResult,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let metadata = FileAnalysisMetadata {
            file_path: entry.file_path,
            tool_name: entry.tool_name,
            tool_args: entry.tool_args,
            file_size: entry.file_size,
            execution_time_ms: entry.execution_time_ms,
        };

        let cache_entry = CacheEntry::with_metadata(entry.file_hash, entry.result, metadata);

        self.cache.add_entry(cache_entry).await?;
        Ok(())
    }

    pub async fn get_latest_analysis(
        &self,
        file_hash: &str,
        tool_name: &str,
    ) -> Option<serde_json::Value> {
        let entries = self.cache.get_entries(&file_hash.to_string()).await?;

        entries
            .into_iter()
            .filter(|e| e.metadata.tool_name == tool_name)
            .max_by_key(|e| e.timestamp)
            .map(|e| e.value)
    }

    pub async fn search_by_tool(&self, tool_name: &str) -> Vec<FileAnalysisResult> {
        let query = SearchQuery::new().with_category(tool_name);
        let results = self.cache.search(&query).await;

        results
            .into_iter()
            .map(|entry| FileAnalysisResult {
                file_path: entry.metadata.file_path,
                file_hash: entry.key,
                tool_name: entry.metadata.tool_name,
                tool_args: entry.metadata.tool_args,
                result: entry.value,
                timestamp: entry.timestamp,
                file_size: entry.metadata.file_size,
                execution_time_ms: entry.metadata.execution_time_ms,
            })
            .collect()
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Create adapter with file-scanner compatible API
    let adapter = FileAnalysisCacheAdapter::new("/tmp/file-scanner-cache").await?;

    // Add an analysis result (mimicking file-scanner usage)
    let analysis = FileAnalysisResult {
        file_path: "/bin/ls".to_string(),
        file_hash: "abc123def456".to_string(),
        tool_name: "calculate_hashes".to_string(),
        tool_args: HashMap::new(),
        result: serde_json::json!({
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }),
        timestamp: Utc::now(),
        file_size: 45056,
        execution_time_ms: 125,
    };

    adapter.add_entry(analysis).await?;

    // Get latest analysis for a file and tool
    if let Some(result) = adapter
        .get_latest_analysis("abc123def456", "calculate_hashes")
        .await
    {
        println!(
            "Latest hash analysis: {}",
            serde_json::to_string_pretty(&result)?
        );
    }

    // Search for all hash calculations
    let hash_results = adapter.search_by_tool("calculate_hashes").await;
    println!("Found {} hash calculation results", hash_results.len());

    Ok(())
}
