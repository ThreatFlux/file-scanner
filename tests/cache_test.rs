use chrono::{Duration, Utc};
use file_scanner::cache::{
    AnalysisCache, CacheEntry, CacheMetadata, CacheSearchQuery, CacheStatistics,
};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::time::sleep;

// Helper function to create test cache entries
fn create_test_entry(file_hash: &str, tool_name: &str, file_path: &str) -> CacheEntry {
    CacheEntry {
        file_path: file_path.to_string(),
        file_hash: file_hash.to_string(),
        tool_name: tool_name.to_string(),
        tool_args: [("test_arg".to_string(), serde_json::json!("value"))]
            .iter()
            .cloned()
            .collect(),
        result: serde_json::json!({"result": "test"}),
        timestamp: Utc::now(),
        file_size: 1024,
        execution_time_ms: 100,
    }
}

// Helper function to create entry with custom parameters
fn create_custom_entry(
    file_hash: &str,
    tool_name: &str,
    file_path: &str,
    file_size: u64,
    execution_time_ms: u64,
    timestamp: chrono::DateTime<Utc>,
) -> CacheEntry {
    CacheEntry {
        file_path: file_path.to_string(),
        file_hash: file_hash.to_string(),
        tool_name: tool_name.to_string(),
        tool_args: HashMap::new(),
        result: serde_json::json!({"custom": true}),
        timestamp,
        file_size,
        execution_time_ms,
    }
}

#[cfg(test)]
mod cache_creation_tests {
    use super::*;

    #[tokio::test]
    async fn test_new_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let metadata = cache.get_metadata();
        assert_eq!(metadata.total_entries, 0);
        assert_eq!(metadata.total_unique_files, 0);
        assert_eq!(metadata.cache_size_bytes, 0);
    }

    #[tokio::test]
    async fn test_cache_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("non_existent_dir");

        assert!(!cache_path.exists());
        let _cache = AnalysisCache::new(&cache_path).unwrap();
        assert!(cache_path.exists());
    }

    #[tokio::test]
    async fn test_cache_with_invalid_path() {
        // Test cache creation with a path that cannot be created
        let result = AnalysisCache::new("/dev/null/invalid");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod entry_operations_tests {
    use super::*;

    #[tokio::test]
    async fn test_add_single_entry() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry = create_test_entry("hash123", "test_tool", "/test/file.bin");
        cache.add_entry(entry.clone()).unwrap();

        let entries = cache.get_entries("hash123").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool_name, "test_tool");
        assert_eq!(entries[0].file_path, "/test/file.bin");
    }

    #[tokio::test]
    async fn test_add_multiple_entries_same_file() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        for i in 0..5 {
            let entry = create_test_entry("hash123", &format!("tool_{}", i), "/test/file.bin");
            cache.add_entry(entry).unwrap();
        }

        let entries = cache.get_entries("hash123").unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[tokio::test]
    async fn test_get_entries_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        assert!(cache.get_entries("nonexistent_hash").is_none());
    }

    #[tokio::test]
    async fn test_get_latest_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let now = Utc::now();
        let timestamps = vec![now - Duration::hours(2), now - Duration::hours(1), now];

        for (_i, timestamp) in timestamps.iter().enumerate() {
            let entry = create_custom_entry(
                "hash123",
                "test_tool",
                "/test/file.bin",
                1024,
                100,
                *timestamp,
            );
            cache.add_entry(entry).unwrap();
        }

        let latest = cache.get_latest_analysis("hash123", "test_tool").unwrap();
        assert_eq!(latest.timestamp, now);
    }

    #[tokio::test]
    async fn test_get_latest_analysis_multiple_tools() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let now = Utc::now();

        // Add entries for different tools with different timestamps
        let entry1 = create_custom_entry(
            "hash123",
            "tool1",
            "/test/file.bin",
            1024,
            100,
            now - Duration::hours(1),
        );
        let entry2 = create_custom_entry("hash123", "tool2", "/test/file.bin", 1024, 200, now);
        let entry3 = create_custom_entry(
            "hash123",
            "tool1",
            "/test/file.bin",
            1024,
            150,
            now - Duration::minutes(30),
        );

        cache.add_entry(entry1).unwrap();
        cache.add_entry(entry2).unwrap();
        cache.add_entry(entry3).unwrap();

        let latest_tool1 = cache.get_latest_analysis("hash123", "tool1").unwrap();
        let latest_tool2 = cache.get_latest_analysis("hash123", "tool2").unwrap();

        assert_eq!(latest_tool1.timestamp, now - Duration::minutes(30));
        assert_eq!(latest_tool2.timestamp, now);
    }

    #[tokio::test]
    async fn test_get_all_entries() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "tool1", "/file1.bin"),
            ("hash2", "tool2", "/file2.bin"),
            ("hash3", "tool3", "/file3.bin"),
            ("hash1", "tool2", "/file1.bin"), // Same file, different tool
        ];

        for (hash, tool, path) in test_data {
            let entry = create_test_entry(hash, tool, path);
            cache.add_entry(entry).unwrap();
        }

        let all_entries = cache.get_all_entries();
        assert_eq!(all_entries.len(), 4);
    }

    #[tokio::test]
    async fn test_max_entries_per_file_limit() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Add more than 100 entries (the default max_entries_per_file)
        for i in 0..150 {
            let entry = create_test_entry("hash123", &format!("tool_{}", i), "/test/file.bin");
            cache.add_entry(entry).unwrap();
        }

        let entries = cache.get_entries("hash123").unwrap();
        assert_eq!(entries.len(), 100); // Should be limited to 100

        // Verify that the oldest entries were removed
        let tool_names: Vec<String> = entries.iter().map(|e| e.tool_name.clone()).collect();
        assert!(!tool_names.contains(&"tool_0".to_string())); // First entry should be removed
        assert!(tool_names.contains(&"tool_149".to_string())); // Last entry should be present
    }
}

#[cfg(test)]
mod search_functionality_tests {
    use super::*;

    #[tokio::test]
    async fn test_search_by_tool_name() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "hash_tool", "/file1.bin"),
            ("hash2", "string_tool", "/file2.bin"),
            ("hash3", "hash_tool", "/file3.bin"),
            ("hash4", "binary_tool", "/file4.bin"),
        ];

        for (hash, tool, path) in test_data {
            let entry = create_test_entry(hash, tool, path);
            cache.add_entry(entry).unwrap();
        }

        let query = CacheSearchQuery {
            tool_name: Some("hash_tool".to_string()),
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.tool_name == "hash_tool"));
    }

    #[tokio::test]
    async fn test_search_by_file_path_pattern() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "tool", "/bin/ls"),
            ("hash2", "tool", "/usr/bin/cat"),
            ("hash3", "tool", "/home/user/file.txt"),
            ("hash4", "tool", "/usr/local/bin/grep"),
        ];

        for (hash, tool, path) in test_data {
            let entry = create_test_entry(hash, tool, path);
            cache.add_entry(entry).unwrap();
        }

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: Some("/bin/".to_string()),
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|e| e.file_path.contains("/bin/")));
    }

    #[tokio::test]
    async fn test_search_by_time_range() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let now = Utc::now();
        let test_data = vec![
            ("hash1", "tool", "/file1.bin", now - Duration::days(2)),
            ("hash2", "tool", "/file2.bin", now - Duration::hours(1)),
            ("hash3", "tool", "/file3.bin", now),
            ("hash4", "tool", "/file4.bin", now + Duration::hours(1)),
        ];

        for (hash, tool, path, timestamp) in test_data {
            let entry = create_custom_entry(hash, tool, path, 1024, 100, timestamp);
            cache.add_entry(entry).unwrap();
        }

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: Some(now - Duration::hours(2)),
            end_time: Some(now + Duration::minutes(30)),
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 2); // Should include entries 2 and 3
    }

    #[tokio::test]
    async fn test_search_by_file_size() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "tool", "/small.bin", 100),
            ("hash2", "tool", "/medium.bin", 1024),
            ("hash3", "tool", "/large.bin", 10240),
            ("hash4", "tool", "/huge.bin", 102400),
        ];

        for (hash, tool, path, size) in test_data {
            let entry = create_custom_entry(hash, tool, path, size, 100, Utc::now());
            cache.add_entry(entry).unwrap();
        }

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: Some(1000),
            max_file_size: Some(20000),
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 2); // medium.bin and large.bin
    }

    #[tokio::test]
    async fn test_search_combined_criteria() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let now = Utc::now();
        let test_data = vec![
            (
                "hash1",
                "hash_tool",
                "/bin/ls",
                1024,
                now - Duration::hours(1),
            ),
            ("hash2", "string_tool", "/bin/cat", 2048, now),
            ("hash3", "hash_tool", "/usr/bin/grep", 512, now),
            (
                "hash4",
                "hash_tool",
                "/home/file.txt",
                1536,
                now - Duration::days(1),
            ),
        ];

        for (hash, tool, path, size, timestamp) in test_data {
            let entry = create_custom_entry(hash, tool, path, size, 100, timestamp);
            cache.add_entry(entry).unwrap();
        }

        let query = CacheSearchQuery {
            tool_name: Some("hash_tool".to_string()),
            file_path_pattern: Some("bin".to_string()),
            start_time: Some(now - Duration::hours(2)),
            end_time: None,
            min_file_size: Some(500),
            max_file_size: Some(2000),
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 2); // Should match entries 1 and 3
    }

    #[tokio::test]
    async fn test_search_no_matches() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry = create_test_entry("hash1", "test_tool", "/test/file.bin");
        cache.add_entry(entry).unwrap();

        let query = CacheSearchQuery {
            tool_name: Some("nonexistent_tool".to_string()),
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query);
        assert!(results.is_empty());
    }
}

#[cfg(test)]
mod statistics_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "tool1", "/file1.bin"),
            ("hash2", "tool2", "/file2.bin"),
            ("hash1", "tool2", "/file1.bin"), // Same file, different tool
        ];

        for (hash, tool, path) in test_data {
            let entry = create_test_entry(hash, tool, path);
            cache.add_entry(entry).unwrap();
        }

        let metadata = cache.get_metadata();
        assert_eq!(metadata.total_entries, 3);
        assert_eq!(metadata.total_unique_files, 2);
        assert!(metadata.cache_size_bytes > 0);
        assert!(metadata.last_updated <= Utc::now());
    }

    #[tokio::test]
    async fn test_get_statistics() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "hash_tool", "/test/file.exe", 100),
            ("hash2", "string_tool", "/test/file.dll", 200),
            ("hash3", "hash_tool", "/test/file.txt", 150),
            ("hash4", "binary_tool", "/test/file.exe", 300),
            ("hash5", "string_tool", "/test/script.py", 50),
        ];

        for (hash, tool, path, exec_time) in test_data {
            let entry = create_custom_entry(hash, tool, path, 1024, exec_time, Utc::now());
            cache.add_entry(entry).unwrap();
        }

        let stats = cache.get_statistics();

        // Check tool counts
        assert_eq!(stats.tool_counts["hash_tool"], 2);
        assert_eq!(stats.tool_counts["string_tool"], 2);
        assert_eq!(stats.tool_counts["binary_tool"], 1);

        // Check file type counts
        assert_eq!(stats.file_type_counts["exe"], 2);
        assert_eq!(stats.file_type_counts["dll"], 1);
        assert_eq!(stats.file_type_counts["txt"], 1);
        assert_eq!(stats.file_type_counts["py"], 1);

        // Check other statistics
        assert_eq!(stats.total_analyses, 5);
        assert_eq!(stats.unique_files, 5);
        assert_eq!(stats.avg_execution_time_ms, 160); // (100+200+150+300+50)/5
    }

    #[tokio::test]
    async fn test_statistics_empty_cache() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let stats = cache.get_statistics();
        assert_eq!(stats.total_analyses, 0);
        assert_eq!(stats.unique_files, 0);
        assert_eq!(stats.avg_execution_time_ms, 0);
        assert!(stats.tool_counts.is_empty());
        assert!(stats.file_type_counts.is_empty());
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    #[tokio::test]
    async fn test_save_and_load_cache() {
        let temp_dir = TempDir::new().unwrap();

        // Create and populate cache
        {
            let cache = AnalysisCache::new(temp_dir.path()).unwrap();

            let test_data = vec![
                ("hash1", "tool1", "/file1.bin"),
                ("hash2", "tool2", "/file2.bin"),
                ("hash3", "tool3", "/file3.bin"),
            ];

            for (hash, tool, path) in test_data {
                let entry = create_test_entry(hash, tool, path);
                cache.add_entry(entry).unwrap();
            }

            // Wait for async save to complete
            sleep(tokio::time::Duration::from_millis(500)).await;
        }

        // Create new cache instance and verify data was loaded
        let cache2 = AnalysisCache::new(temp_dir.path()).unwrap();

        let all_entries = cache2.get_all_entries();
        assert_eq!(all_entries.len(), 3);

        // Verify specific entries
        assert!(cache2.get_entries("hash1").is_some());
        assert!(cache2.get_entries("hash2").is_some());
        assert!(cache2.get_entries("hash3").is_some());
    }

    #[tokio::test]
    async fn test_clear_cache_removes_files() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Add some entries
        for i in 0..3 {
            let entry = create_test_entry(&format!("hash{}", i), "tool", "/file.bin");
            cache.add_entry(entry).unwrap();
        }

        // Wait for save
        sleep(tokio::time::Duration::from_millis(200)).await;

        // Verify files exist
        let cache_files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        assert!(!cache_files.is_empty());

        // Clear cache
        cache.clear().unwrap();

        // Verify files are removed
        let cache_files_after: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        assert!(cache_files_after.is_empty());

        // Verify cache is empty
        let metadata = cache.get_metadata();
        assert_eq!(metadata.total_entries, 0);
    }

    #[tokio::test]
    async fn test_metadata_file_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Add entry and wait for save
        let entry = create_test_entry("hash1", "tool", "/file.bin");
        cache.add_entry(entry).unwrap();
        sleep(tokio::time::Duration::from_millis(500)).await;

        // Check metadata file exists
        let metadata_path = temp_dir.path().join("metadata.json");
        assert!(metadata_path.exists());

        // Verify metadata content
        let metadata_content = std::fs::read_to_string(&metadata_path).unwrap();
        let metadata: CacheMetadata = serde_json::from_str(&metadata_content).unwrap();
        assert_eq!(metadata.total_entries, 1);
        assert_eq!(metadata.total_unique_files, 1);
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_add_entries() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Arc::new(AnalysisCache::new(temp_dir.path()).unwrap());

        let mut handles = vec![];

        // Spawn multiple tasks adding entries concurrently
        for i in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                for j in 0..10 {
                    let entry = create_test_entry(
                        &format!("hash_{}", i),
                        &format!("tool_{}_{}", i, j),
                        &format!("/file_{}.bin", i),
                    );
                    cache_clone.add_entry(entry).unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all entries were added
        let all_entries = cache.get_all_entries();
        assert_eq!(all_entries.len(), 100);
    }

    #[tokio::test]
    async fn test_concurrent_read_write() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Arc::new(AnalysisCache::new(temp_dir.path()).unwrap());

        // Add initial entries
        for i in 0..5 {
            let entry = create_test_entry(&format!("hash{}", i), "tool", "/file.bin");
            cache.add_entry(entry).unwrap();
        }

        let mut handles = vec![];

        // Spawn readers
        for i in 0..5 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                for _ in 0..20 {
                    let _entries = cache_clone.get_entries(&format!("hash{}", i));
                    let _all = cache_clone.get_all_entries();
                    let _metadata = cache_clone.get_metadata();
                }
            });
            handles.push(handle);
        }

        // Spawn writers
        for i in 5..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                for j in 0..10 {
                    let entry = create_test_entry(
                        &format!("hash{}", i),
                        &format!("tool_{}", j),
                        "/file.bin",
                    );
                    cache_clone.add_entry(entry).unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify final state
        let metadata = cache.get_metadata();
        assert_eq!(metadata.total_unique_files, 10);
    }

    #[tokio::test]
    async fn test_concurrent_search() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Arc::new(AnalysisCache::new(temp_dir.path()).unwrap());

        // Add test data
        for i in 0..100 {
            let entry = create_test_entry(
                &format!("hash{}", i),
                if i % 2 == 0 { "tool_even" } else { "tool_odd" },
                &format!("/path/{}/file.bin", i % 10),
            );
            cache.add_entry(entry).unwrap();
        }

        let mut handles = vec![];

        // Spawn multiple search tasks
        for i in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                let query = CacheSearchQuery {
                    tool_name: if i % 2 == 0 {
                        Some("tool_even".to_string())
                    } else {
                        Some("tool_odd".to_string())
                    },
                    file_path_pattern: Some(format!("/{}/", i)),
                    start_time: None,
                    end_time: None,
                    min_file_size: None,
                    max_file_size: None,
                };

                for _ in 0..10 {
                    let _results = cache_clone.search_entries(&query);
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }
    }
}

#[cfg(test)]
mod memory_management_tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_size_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Add entries with known sizes
        for i in 0..10 {
            let mut entry = create_test_entry(&format!("hash{}", i), "tool", "/file.bin");
            entry.result = serde_json::json!({
                "data": "x".repeat(1000) // Large result data
            });
            cache.add_entry(entry).unwrap();
        }

        let metadata = cache.get_metadata();
        assert!(metadata.cache_size_bytes > 10000); // Should be significant size
    }

    #[tokio::test]
    async fn test_entry_limit_enforcement() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Add exactly 100 entries
        for i in 0..100 {
            let entry = create_test_entry("hash1", &format!("tool_{}", i), "/file.bin");
            cache.add_entry(entry).unwrap();
        }

        let entries = cache.get_entries("hash1").unwrap();
        assert_eq!(entries.len(), 100);

        // Add one more entry
        let entry = create_test_entry("hash1", "tool_100", "/file.bin");
        cache.add_entry(entry).unwrap();

        // Should still be 100 (oldest removed)
        let entries = cache.get_entries("hash1").unwrap();
        assert_eq!(entries.len(), 100);

        // Verify newest entry exists
        assert!(entries.iter().any(|e| e.tool_name == "tool_100"));
        // Verify oldest entry was removed
        assert!(!entries.iter().any(|e| e.tool_name == "tool_0"));
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_cache_operations() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Test all operations on empty cache
        assert!(cache.get_entries("any_hash").is_none());
        assert!(cache.get_latest_analysis("any_hash", "any_tool").is_none());
        assert_eq!(cache.get_all_entries().len(), 0);

        let empty_query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };
        assert_eq!(cache.search_entries(&empty_query).len(), 0);
    }

    #[tokio::test]
    async fn test_invalid_json_in_cache_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create invalid JSON file in cache directory
        std::fs::write(temp_dir.path().join("invalid.json"), "not valid json").unwrap();

        // Should still create cache successfully (ignoring invalid files)
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();
        let metadata = cache.get_metadata();
        assert_eq!(metadata.total_entries, 0);
    }

    #[tokio::test]
    async fn test_partial_match_search() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry = create_test_entry("hash1", "tool", "/very/long/path/to/file.bin");
        cache.add_entry(entry).unwrap();

        // Test partial path matching
        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: Some("long/path".to_string()),
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 1);
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_entry_serialization() {
        let entry = CacheEntry {
            file_path: "/test/file.bin".to_string(),
            file_hash: "abc123def456".to_string(),
            tool_name: "advanced_tool".to_string(),
            tool_args: [
                ("arg1".to_string(), serde_json::json!("value1")),
                ("arg2".to_string(), serde_json::json!(42)),
                ("arg3".to_string(), serde_json::json!({"nested": "object"})),
            ]
            .iter()
            .cloned()
            .collect(),
            result: serde_json::json!({
                "status": "success",
                "data": [1, 2, 3, 4, 5],
                "metadata": {
                    "version": "1.0",
                    "timestamp": "2024-01-01T00:00:00Z"
                }
            }),
            timestamp: Utc::now(),
            file_size: 4096,
            execution_time_ms: 500,
        };

        // Test JSON serialization/deserialization
        let json = serde_json::to_string_pretty(&entry).unwrap();
        let deserialized: CacheEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.file_path, entry.file_path);
        assert_eq!(deserialized.file_hash, entry.file_hash);
        assert_eq!(deserialized.tool_name, entry.tool_name);
        assert_eq!(deserialized.file_size, entry.file_size);
        assert_eq!(deserialized.execution_time_ms, entry.execution_time_ms);
        assert_eq!(deserialized.tool_args, entry.tool_args);
        assert_eq!(deserialized.result, entry.result);
    }

    #[tokio::test]
    async fn test_cache_metadata_serialization() {
        let metadata = CacheMetadata {
            total_entries: 100,
            total_unique_files: 50,
            cache_size_bytes: 1048576,
            last_updated: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let deserialized: CacheMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_entries, metadata.total_entries);
        assert_eq!(deserialized.total_unique_files, metadata.total_unique_files);
        assert_eq!(deserialized.cache_size_bytes, metadata.cache_size_bytes);
    }

    #[tokio::test]
    async fn test_cache_search_query_serialization() {
        let query = CacheSearchQuery {
            tool_name: Some("test_tool".to_string()),
            file_path_pattern: Some("/test/pattern".to_string()),
            start_time: Some(Utc::now() - Duration::hours(1)),
            end_time: Some(Utc::now()),
            min_file_size: Some(1024),
            max_file_size: Some(1048576),
        };

        let json = serde_json::to_string_pretty(&query).unwrap();
        let deserialized: CacheSearchQuery = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tool_name, query.tool_name);
        assert_eq!(deserialized.file_path_pattern, query.file_path_pattern);
        assert_eq!(deserialized.min_file_size, query.min_file_size);
        assert_eq!(deserialized.max_file_size, query.max_file_size);
        assert!(deserialized.start_time.is_some());
        assert!(deserialized.end_time.is_some());
    }

    #[tokio::test]
    async fn test_cache_statistics_serialization() {
        let stats = CacheStatistics {
            tool_counts: [
                ("tool1".to_string(), 10),
                ("tool2".to_string(), 20),
                ("tool3".to_string(), 15),
            ]
            .iter()
            .cloned()
            .collect(),
            file_type_counts: [
                ("exe".to_string(), 5),
                ("dll".to_string(), 8),
                ("so".to_string(), 3),
            ]
            .iter()
            .cloned()
            .collect(),
            total_analyses: 45,
            unique_files: 30,
            avg_execution_time_ms: 250,
        };

        let json = serde_json::to_string_pretty(&stats).unwrap();
        let deserialized: CacheStatistics = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_analyses, stats.total_analyses);
        assert_eq!(deserialized.unique_files, stats.unique_files);
        assert_eq!(
            deserialized.avg_execution_time_ms,
            stats.avg_execution_time_ms
        );
        assert_eq!(deserialized.tool_counts, stats.tool_counts);
        assert_eq!(deserialized.file_type_counts, stats.file_type_counts);
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[tokio::test]
    async fn test_files_without_extensions() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_files = vec![
            "/usr/bin/ls",
            "/etc/passwd",
            "/tmp/tempfile",
            "/home/user/Makefile",
        ];

        for (i, path) in test_files.iter().enumerate() {
            let entry = create_test_entry(&format!("hash{}", i), "tool", path);
            cache.add_entry(entry).unwrap();
        }

        let stats = cache.get_statistics();
        assert_eq!(stats.total_analyses, 4);
        // Files without extensions should not appear in file_type_counts
        assert!(
            stats.file_type_counts.is_empty() || !stats.file_type_counts.values().any(|&v| v == 4)
        );
    }

    #[tokio::test]
    async fn test_very_long_file_paths() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let long_path = format!("/very/long/path/{}/file.bin", "sub/".repeat(50));
        let entry = create_test_entry("hash1", "tool", &long_path);
        cache.add_entry(entry).unwrap();

        let entries = cache.get_entries("hash1").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_path, long_path);
    }

    #[tokio::test]
    async fn test_unicode_in_paths_and_tools() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "tool_测试", "/文件/测试.bin"),
            ("hash2", "инструмент", "/путь/файл.exe"),
            ("hash3", "outil_français", "/chemin/fichier.txt"),
        ];

        for (hash, tool, path) in test_data {
            let entry = create_test_entry(hash, tool, path);
            cache.add_entry(entry).unwrap();
        }

        let all_entries = cache.get_all_entries();
        assert_eq!(all_entries.len(), 3);

        // Test search with unicode
        let query = CacheSearchQuery {
            tool_name: Some("tool_测试".to_string()),
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_zero_size_files() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let mut entry = create_test_entry("hash1", "tool", "/empty/file.txt");
        entry.file_size = 0;
        cache.add_entry(entry).unwrap();

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: Some(0),
            max_file_size: Some(0),
        };

        let results = cache.search_entries(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_size, 0);
    }

    #[tokio::test]
    async fn test_extreme_execution_times() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let test_data = vec![
            ("hash1", "fast_tool", 0),       // Instant execution
            ("hash2", "slow_tool", 3600000), // 1 hour
            ("hash3", "normal_tool", 100),   // 100ms
        ];

        for (hash, tool, exec_time) in test_data {
            let entry = create_custom_entry(hash, tool, "/file.bin", 1024, exec_time, Utc::now());
            cache.add_entry(entry).unwrap();
        }

        let stats = cache.get_statistics();
        assert_eq!(stats.avg_execution_time_ms, 1200033); // Average of all three
    }

    #[tokio::test]
    async fn test_same_hash_different_paths() {
        // This simulates files with identical content (same hash) but different paths
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let identical_hash = "identical_content_hash";
        let paths = vec!["/original/file.bin", "/copy/file.bin", "/backup/file.bin"];

        for path in paths {
            let entry = create_test_entry(identical_hash, "hash_tool", path);
            cache.add_entry(entry).unwrap();
        }

        let entries = cache.get_entries(identical_hash).unwrap();
        assert_eq!(entries.len(), 3);

        // All entries should have the same hash but different paths
        let unique_paths: std::collections::HashSet<_> =
            entries.iter().map(|e| &e.file_path).collect();
        assert_eq!(unique_paths.len(), 3);
    }
}
