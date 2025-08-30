//! Comprehensive tests for cache functionality

use serde::{Deserialize, Serialize};
use std::time::Duration;
use threatflux_cache::{AsyncCache, Cache, CacheConfig};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestData {
    id: u32,
    name: String,
    value: i32,
    data: Vec<u8>,
}

impl TestData {
    fn new(id: u32, name: &str, value: i32) -> Self {
        Self {
            id,
            name: name.to_string(),
            value,
            data: vec![0u8; 100], // Some payload data
        }
    }

    fn large(id: u32, size_kb: usize) -> Self {
        Self {
            id,
            name: format!("large_data_{}", id),
            value: id as i32,
            data: vec![0u8; size_kb * 1024],
        }
    }
}

#[tokio::test]
async fn test_cache_basic_crud_operations() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    let test_data = TestData::new(1, "test_item", 42);
    let key = "test_key".to_string();

    // Initially empty
    assert!(cache.is_empty().await.unwrap());
    assert_eq!(cache.len().await.unwrap(), 0);
    assert!(!cache.contains(&key).await.unwrap());
    assert!(cache.get(&key).await.unwrap().is_none());

    // Put operation
    cache.put(key.clone(), test_data.clone()).await.unwrap();

    // Verify state after put
    assert!(!cache.is_empty().await.unwrap());
    assert_eq!(cache.len().await.unwrap(), 1);
    assert!(cache.contains(&key).await.unwrap());

    // Get operation
    let retrieved = cache.get(&key).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), test_data);

    // Update operation (put with same key)
    let updated_data = TestData::new(2, "updated_item", 84);
    cache.put(key.clone(), updated_data.clone()).await.unwrap();

    // Verify update
    assert_eq!(cache.len().await.unwrap(), 1); // Still one entry
    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved, updated_data);
    assert_ne!(retrieved, test_data);

    // Remove operation
    let removed = cache.remove(&key).await.unwrap();
    assert!(removed.is_some());
    assert_eq!(removed.unwrap(), updated_data);

    // Verify state after remove
    assert!(cache.is_empty().await.unwrap());
    assert_eq!(cache.len().await.unwrap(), 0);
    assert!(!cache.contains(&key).await.unwrap());
    assert!(cache.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_cache_multiple_entries() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    let num_entries: usize = 100;

    // Insert multiple entries
    for i in 0..num_entries {
        let key = format!("key_{}", i);
        let data = TestData::new(i as u32, &format!("item_{}", i), i as i32 * 10);
        cache.put(key, data).await.unwrap();
    }

    // Verify all entries
    assert_eq!(cache.len().await.unwrap(), num_entries);
    assert!(!cache.is_empty().await.unwrap());

    for i in 0..num_entries {
        let key = format!("key_{}", i);
        assert!(cache.contains(&key).await.unwrap());

        let data = cache.get(&key).await.unwrap().unwrap();
        assert_eq!(data.id, i as u32);
        assert_eq!(data.name, format!("item_{}", i));
        assert_eq!(data.value, i as i32 * 10);
    }

    // Remove some entries
    for i in 0..num_entries / 2 {
        let key = format!("key_{}", i);
        let removed = cache.remove(&key).await.unwrap();
        assert!(removed.is_some());
    }

    // Verify partial removal
    assert_eq!(cache.len().await.unwrap(), num_entries - num_entries / 2);

    for i in 0..num_entries / 2 {
        let key = format!("key_{}", i);
        assert!(!cache.contains(&key).await.unwrap());
    }

    for i in num_entries / 2..num_entries {
        let key = format!("key_{}", i);
        assert!(cache.contains(&key).await.unwrap());
    }
}

#[tokio::test]
async fn test_cache_clear_operation() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Add some entries
    for i in 0..10 {
        let key = format!("clear_key_{}", i);
        let data = TestData::new(i, &format!("clear_item_{}", i), i as i32);
        cache.put(key, data).await.unwrap();
    }

    // Verify entries exist
    assert_eq!(cache.len().await.unwrap(), 10);
    assert!(!cache.is_empty().await.unwrap());

    // Clear all entries
    cache.clear().await.unwrap();

    // Verify cache is empty
    assert_eq!(cache.len().await.unwrap(), 0);
    assert!(cache.is_empty().await.unwrap());

    // Verify specific entries are gone
    for i in 0..10 {
        let key = format!("clear_key_{}", i);
        assert!(!cache.contains(&key).await.unwrap());
        assert!(cache.get(&key).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn test_cache_concurrent_operations() {
    use std::sync::Arc;
    use tokio::task;

    let config = CacheConfig::default();
    let cache = Arc::new(
        Cache::<String, TestData>::with_config(config)
            .await
            .unwrap(),
    );

    let num_tasks: usize = 10;
    let entries_per_task: usize = 100;

    // Concurrent writes
    let mut write_handles = vec![];
    for task_id in 0..num_tasks {
        let cache_clone = Arc::clone(&cache);
        let handle = task::spawn(async move {
            for i in 0..entries_per_task {
                let key = format!("concurrent_{}_{}", task_id, i);
                let data = TestData::new((task_id * 1000 + i) as u32, &key, i as i32);
                cache_clone.put(key, data).await.unwrap();
            }
        });
        write_handles.push(handle);
    }

    // Wait for all writes
    for handle in write_handles {
        handle.await.unwrap();
    }

    // Verify all entries were written
    assert_eq!(cache.len().await.unwrap(), num_tasks * entries_per_task);

    // Concurrent reads
    let mut read_handles = vec![];
    for task_id in 0..num_tasks {
        let cache_clone = Arc::clone(&cache);
        let handle = task::spawn(async move {
            for i in 0..entries_per_task {
                let key = format!("concurrent_{}_{}", task_id, i);
                let data = cache_clone.get(&key).await.unwrap();
                assert!(data.is_some());

                let entry = data.unwrap();
                assert_eq!(entry.id, (task_id * 1000 + i) as u32);
                assert_eq!(entry.name, key);
                assert_eq!(entry.value, i as i32);
            }
        });
        read_handles.push(handle);
    }

    // Wait for all reads
    for handle in read_handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_cache_with_custom_config() {
    let config = CacheConfig::default()
        .with_max_entries_per_key(3)
        .with_max_total_entries(50)
        .with_default_ttl(Duration::from_secs(60));

    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Test that cache accepts configuration
    for i in 0..10 {
        let key = format!("config_key_{}", i);
        let data = TestData::new(i, &format!("config_item_{}", i), i as i32);
        cache.put(key, data).await.unwrap();
    }

    assert_eq!(cache.len().await.unwrap(), 10);
}

#[tokio::test]
async fn test_cache_large_data_handling() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Test with various data sizes
    let sizes_kb = vec![1, 10, 100, 1000]; // 1KB to 1MB

    for (i, size) in sizes_kb.iter().enumerate() {
        let key = format!("large_key_{}", i);
        let data = TestData::large(i as u32, *size);

        // Store large data
        cache.put(key.clone(), data.clone()).await.unwrap();

        // Retrieve and verify
        let retrieved = cache.get(&key).await.unwrap().unwrap();
        assert_eq!(retrieved.id, i as u32);
        assert_eq!(retrieved.data.len(), size * 1024);
        assert_eq!(retrieved, data);
    }

    assert_eq!(cache.len().await.unwrap(), sizes_kb.len());
}

#[tokio::test]
async fn test_cache_error_handling() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Operations on empty cache should not error
    assert!(cache
        .get(&"nonexistent".to_string())
        .await
        .unwrap()
        .is_none());
    assert!(!cache.contains(&"nonexistent".to_string()).await.unwrap());
    assert!(cache
        .remove(&"nonexistent".to_string())
        .await
        .unwrap()
        .is_none());

    // Clear empty cache should not error
    cache.clear().await.unwrap();

    // Test with empty key
    let empty_key = String::new();
    let data = TestData::new(1, "empty_key_test", 42);

    // Should handle empty key gracefully
    let result = cache.put(empty_key.clone(), data.clone()).await;
    if result.is_ok() {
        let retrieved = cache.get(&empty_key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);
    }
    // Empty key might be rejected - that's also acceptable
}

#[tokio::test]
async fn test_cache_key_collision_handling() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    let key = "collision_key".to_string();

    // Store first value
    let data1 = TestData::new(1, "first", 100);
    cache.put(key.clone(), data1.clone()).await.unwrap();

    // Verify first value
    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved, data1);

    // Store second value with same key (should overwrite)
    let data2 = TestData::new(2, "second", 200);
    cache.put(key.clone(), data2.clone()).await.unwrap();

    // Verify second value overwrote first
    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved, data2);
    assert_ne!(retrieved, data1);

    // Cache should still have only one entry
    assert_eq!(cache.len().await.unwrap(), 1);
}

#[tokio::test]
async fn test_cache_different_key_types() {
    // Test cache with integer keys
    let int_cache = Cache::<i32, String>::with_config(CacheConfig::default())
        .await
        .unwrap();

    int_cache.put(42, "answer".to_string()).await.unwrap();
    int_cache.put(100, "century".to_string()).await.unwrap();

    assert_eq!(int_cache.get(&42).await.unwrap().unwrap(), "answer");
    assert_eq!(int_cache.get(&100).await.unwrap().unwrap(), "century");
    assert!(int_cache.get(&999).await.unwrap().is_none());

    // Test cache with tuple keys
    let tuple_cache = Cache::<(String, i32), TestData>::with_config(CacheConfig::default())
        .await
        .unwrap();

    let key1 = ("user".to_string(), 1);
    let key2 = ("user".to_string(), 2);
    let data1 = TestData::new(1, "user_1", 1);
    let data2 = TestData::new(2, "user_2", 2);

    tuple_cache.put(key1.clone(), data1.clone()).await.unwrap();
    tuple_cache.put(key2.clone(), data2.clone()).await.unwrap();

    assert_eq!(tuple_cache.get(&key1).await.unwrap().unwrap(), data1);
    assert_eq!(tuple_cache.get(&key2).await.unwrap().unwrap(), data2);
    assert!(tuple_cache
        .get(&("user".to_string(), 3))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_cache_performance_characteristics() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    let num_entries: usize = 10000;

    // Measure insertion performance
    let start_time = std::time::Instant::now();
    for i in 0..num_entries {
        let key = format!("perf_key_{}", i);
        let data = TestData::new(i as u32, &format!("perf_item_{}", i), i as i32);
        cache.put(key, data).await.unwrap();
    }
    let insertion_time = start_time.elapsed();

    println!("Inserted {} entries in {:?}", num_entries, insertion_time);
    assert!(insertion_time.as_secs() < 30); // Should complete in reasonable time

    // Measure retrieval performance
    let start_time = std::time::Instant::now();
    for i in 0..num_entries {
        let key = format!("perf_key_{}", i);
        let data = cache.get(&key).await.unwrap();
        assert!(data.is_some());
    }
    let retrieval_time = start_time.elapsed();

    println!("Retrieved {} entries in {:?}", num_entries, retrieval_time);
    assert!(retrieval_time.as_secs() < 15); // Should be faster than insertion

    // Measure contains performance
    let start_time = std::time::Instant::now();
    for i in 0..num_entries {
        let key = format!("perf_key_{}", i);
        assert!(cache.contains(&key).await.unwrap());
    }
    let contains_time = start_time.elapsed();

    println!(
        "Checked {} entries existence in {:?}",
        num_entries, contains_time
    );
    assert!(contains_time.as_secs() < 10); // Should be fastest operation
}

#[tokio::test]
async fn test_cache_memory_efficiency() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Add many entries and then remove them to test memory cleanup
    let batch_size: usize = 1000;
    let num_batches = 10;

    for batch in 0..num_batches {
        // Add a batch of entries
        for i in 0..batch_size {
            let key = format!("memory_key_{}_{}", batch, i);
            let data = TestData::new((batch * 1000 + i) as u32, &key, i as i32);
            cache.put(key, data).await.unwrap();
        }

        assert_eq!(cache.len().await.unwrap(), batch_size);

        // Remove the batch
        for i in 0..batch_size {
            let key = format!("memory_key_{}_{}", batch, i);
            let removed = cache.remove(&key).await.unwrap();
            assert!(removed.is_some());
        }

        assert!(cache.is_empty().await.unwrap());
    }

    // Final verification
    assert!(cache.is_empty().await.unwrap());
    assert_eq!(cache.len().await.unwrap(), 0);
}

#[tokio::test]
async fn test_cache_serialization_roundtrip() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Test data with various characteristics
    let test_cases = vec![
        TestData::new(1, "simple", 42),
        TestData::new(2, "", 0),                   // Empty name, zero value
        TestData::new(3, "unicode_🦀_test", -100), // Unicode and negative
        TestData {
            id: 4,
            name: "complex".to_string(),
            value: i32::MAX,
            data: vec![0x00, 0xFF, 0x55, 0xAA], // Binary data
        },
    ];

    // Store all test cases
    for (i, test_data) in test_cases.iter().enumerate() {
        let key = format!("serialization_key_{}", i);
        cache.put(key, test_data.clone()).await.unwrap();
    }

    // Retrieve and verify serialization roundtrip
    for (i, expected_data) in test_cases.iter().enumerate() {
        let key = format!("serialization_key_{}", i);
        let retrieved = cache.get(&key).await.unwrap().unwrap();

        assert_eq!(retrieved.id, expected_data.id);
        assert_eq!(retrieved.name, expected_data.name);
        assert_eq!(retrieved.value, expected_data.value);
        assert_eq!(retrieved.data, expected_data.data);
        assert_eq!(retrieved, *expected_data);
    }
}

#[tokio::test]
async fn test_cache_edge_cases() {
    let config = CacheConfig::default();
    let cache = Cache::<String, TestData>::with_config(config)
        .await
        .unwrap();

    // Test with maximum length key (within reason)
    let long_key = "x".repeat(1000);
    let data = TestData::new(1, "long_key_test", 42);

    let result = cache.put(long_key.clone(), data.clone()).await;
    if result.is_ok() {
        let retrieved = cache.get(&long_key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);
    }
    // Long keys might be rejected - that's acceptable

    // Test with special characters in key
    let special_key = "key with spaces and symbols: !@#$%^&*()".to_string();
    let special_data = TestData::new(2, "special_key_test", 84);

    let result = cache.put(special_key.clone(), special_data.clone()).await;
    if result.is_ok() {
        let retrieved = cache.get(&special_key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), special_data);
    }
    // Special characters might be handled differently - both outcomes are valid
}
