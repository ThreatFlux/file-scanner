//! Example showing custom entry metadata and search functionality

use serde::{Deserialize, Serialize};
use threatflux_cache::prelude::*;
use threatflux_cache::{entry::BasicMetadata, EvictionPolicy, PersistenceConfig, SearchQuery};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Document {
    id: String,
    title: String,
    content: String,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Create a cache with filesystem persistence
    let config = CacheConfig::default()
        .with_persistence(PersistenceConfig::with_path("/tmp/document-cache"))
        .with_eviction_policy(EvictionPolicy::Lru);

    #[cfg(feature = "filesystem-backend")]
    let backend = FilesystemBackend::new("/tmp/document-cache").await?;
    #[cfg(not(feature = "filesystem-backend"))]
    let backend = MemoryBackend::new();

    let cache: Cache<String, Document, BasicMetadata, _> = Cache::new(config, backend).await?;

    // Create documents with metadata
    let doc1 = Document {
        id: "doc1".to_string(),
        title: "Introduction to Rust".to_string(),
        content: "Rust is a systems programming language...".to_string(),
    };

    let metadata1 = BasicMetadata {
        execution_time_ms: Some(45),
        size_bytes: Some(doc1.content.len() as u64),
        category: Some("tutorial".to_string()),
        tags: vec!["rust".to_string(), "programming".to_string()],
    };

    let entry1 = CacheEntry::with_metadata("doc:1".to_string(), doc1, metadata1);

    cache.add_entry(entry1).await?;

    // Add more documents
    let doc2 = Document {
        id: "doc2".to_string(),
        title: "Advanced Rust Patterns".to_string(),
        content: "This document covers advanced patterns...".to_string(),
    };

    let metadata2 = BasicMetadata {
        execution_time_ms: Some(30),
        size_bytes: Some(doc2.content.len() as u64),
        category: Some("advanced".to_string()),
        tags: vec!["rust".to_string(), "patterns".to_string()],
    };

    let entry2 = CacheEntry::with_metadata("doc:2".to_string(), doc2, metadata2);

    cache.add_entry(entry2).await?;

    // Search for documents
    let query = SearchQuery::new()
        .with_pattern("doc")
        .with_category("tutorial");

    let results = cache.search(&query).await;
    println!("Found {} documents matching query", results.len());

    for result in results {
        println!(
            "- {} (category: {:?})",
            result.value.title,
            result.metadata.category()
        );
    }

    // Get all entries for a specific key
    if let Some(entries) = cache.get_entries(&"doc:1".to_string()).await {
        for entry in entries {
            println!(
                "Entry: {} - Access count: {}, Age: {:?}",
                entry.value.title,
                entry.access_count,
                entry.age()
            );
        }
    }

    Ok(())
}
