use anyhow::Result;
use encoding_rs::{UTF_16BE, UTF_16LE};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExtractedStrings {
    pub total_count: usize,
    pub unique_count: usize,
    pub ascii_strings: Vec<String>,
    pub unicode_strings: Vec<String>,
    pub interesting_strings: Vec<InterestingString>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InterestingString {
    pub category: String,
    pub value: String,
    pub offset: usize,
}

pub fn extract_strings(path: &Path, min_length: usize) -> Result<ExtractedStrings> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len() as usize;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::with_capacity(file_size.min(100_000_000)); // Cap at 100MB
    reader.read_to_end(&mut buffer)?;

    let ascii_pattern = format!(r"[\x20-\x7E]{{{},}}", min_length);
    let ascii_regex = Regex::new(&ascii_pattern)?;

    let mut ascii_strings = Vec::new();
    let mut unicode_strings = Vec::new();
    let mut interesting_strings = Vec::new();
    let mut unique_strings = HashSet::new();

    for mat in ascii_regex.find_iter(&buffer) {
        if let Ok(s) = std::str::from_utf8(mat.as_bytes()) {
            let string = s.to_string();
            unique_strings.insert(string.clone());
            ascii_strings.push(string.clone());

            if let Some(interesting) = categorize_string(&string, mat.start()) {
                interesting_strings.push(interesting);
            }
        }
    }

    let utf16_le_pattern = format!(r"(?:[\x00-\x7F]\x00){{{},}}", min_length);
    let utf16_le_regex = Regex::new(&utf16_le_pattern)?;

    for mat in utf16_le_regex.find_iter(&buffer) {
        let (decoded, _, _) = UTF_16LE.decode(mat.as_bytes());
        let string = decoded.into_owned();
        if string.len() >= min_length {
            unique_strings.insert(string.clone());
            unicode_strings.push(string.clone());

            if let Some(interesting) = categorize_string(&string, mat.start()) {
                interesting_strings.push(interesting);
            }
        }
    }

    let utf16_be_pattern = format!(r"(?:\x00[\x00-\x7F]){{{},}}", min_length);
    let utf16_be_regex = Regex::new(&utf16_be_pattern)?;

    for mat in utf16_be_regex.find_iter(&buffer) {
        let (decoded, _, _) = UTF_16BE.decode(mat.as_bytes());
        let string = decoded.into_owned();
        if string.len() >= min_length {
            unique_strings.insert(string.clone());
            unicode_strings.push(string.clone());

            if let Some(interesting) = categorize_string(&string, mat.start()) {
                interesting_strings.push(interesting);
            }
        }
    }

    Ok(ExtractedStrings {
        total_count: ascii_strings.len() + unicode_strings.len(),
        unique_count: unique_strings.len(),
        ascii_strings: ascii_strings.into_iter().take(1000).collect(), // Limit output
        unicode_strings: unicode_strings.into_iter().take(1000).collect(),
        interesting_strings,
    })
}

fn categorize_string(s: &str, offset: usize) -> Option<InterestingString> {
    let patterns = [
        (r"(?i)https?://[^\s]+", "URL"),
        (r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "Email"),
        (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password"),
        (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*\S+", "API Key"),
        (r"(?i)(?:secret|token)\s*[:=]\s*\S+", "Secret/Token"),
        (r"[A-Z]{3,}_[A-Z_]{3,}", "Environment Variable"),
        (r"(?i)copyright\s+.*\d{4}", "Copyright"),
        (r"(?i)version\s*[:=]?\s*\d+\.\d+", "Version"),
        (r"(?:/[a-zA-Z0-9._-]+){3,}", "File Path"),
        (
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            "IP Address",
        ),
        (r"(?i)(?:error|warning|fatal|critical).*", "Error/Warning"),
        (r"(?i)(?:debug|trace|info).*", "Debug Info"),
    ];

    for (pattern, category) in patterns.iter() {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(s.as_bytes()) {
                return Some(InterestingString {
                    category: category.to_string(),
                    value: s.to_string(),
                    offset,
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf)> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[test]
    fn test_extract_ascii_strings() {
        let content = b"Hello World\x00\x01\x02This is a test\x00More text here";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = extract_strings(&file_path, 4).unwrap();

        assert!(result.ascii_strings.contains(&"Hello World".to_string()));
        assert!(result.ascii_strings.contains(&"This is a test".to_string()));
        assert!(result.ascii_strings.contains(&"More text here".to_string()));
        assert_eq!(result.total_count, 3);
        assert_eq!(result.unique_count, 3);
    }

    #[test]
    fn test_min_length_filter() {
        let content = b"Hi\x00Test\x00Longer string here\x00Ok";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = extract_strings(&file_path, 5).unwrap();

        // Only strings >= 5 chars should be included
        assert!(!result.ascii_strings.contains(&"Hi".to_string()));
        assert!(!result.ascii_strings.contains(&"Test".to_string()));
        assert!(!result.ascii_strings.contains(&"Ok".to_string()));
        assert!(result
            .ascii_strings
            .contains(&"Longer string here".to_string()));
    }

    #[test]
    fn test_unicode_utf16_le_strings() {
        // UTF-16 LE: "Hello" = H\x00e\x00l\x00l\x00o\x00
        let mut content = Vec::new();
        content.extend_from_slice(b"H\x00e\x00l\x00l\x00o\x00");
        content.extend_from_slice(&[0xFF, 0xFF]); // Non-string bytes
        content.extend_from_slice(b"W\x00o\x00r\x00l\x00d\x00");

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();
        let result = extract_strings(&file_path, 4).unwrap();

        assert!(result.unicode_strings.iter().any(|s| s.contains("Hello")));
        assert!(result.unicode_strings.iter().any(|s| s.contains("World")));
    }

    #[test]
    fn test_unicode_utf16_be_strings() {
        // UTF-16 BE: "Hello" = \x00H\x00e\x00l\x00l\x00o
        let mut content = Vec::new();
        content.extend_from_slice(b"\x00H\x00e\x00l\x00l\x00o");
        content.extend_from_slice(&[0xFF, 0xFF]); // Non-string bytes
        content.extend_from_slice(b"\x00T\x00e\x00s\x00t");

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();
        let result = extract_strings(&file_path, 4).unwrap();

        assert!(result.unicode_strings.iter().any(|s| s.contains("Hello")));
        assert!(result.unicode_strings.iter().any(|s| s.contains("Test")));
    }

    #[test]
    fn test_unique_string_counting() {
        let content = b"duplicate\x00duplicate\x00unique\x00duplicate";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = extract_strings(&file_path, 4).unwrap();

        assert_eq!(result.total_count, 4); // Total occurrences
        assert_eq!(result.unique_count, 2); // Only "duplicate" and "unique"
    }

    #[test]
    fn test_categorize_string_url() {
        let url = "https://example.com/path";
        let result = categorize_string(url, 0);

        assert!(result.is_some());
        let interesting = result.unwrap();
        assert_eq!(interesting.category, "URL");
        assert_eq!(interesting.value, url);
    }

    #[test]
    fn test_categorize_string_email() {
        let email = "test@example.com";
        let result = categorize_string(email, 100);

        assert!(result.is_some());
        let interesting = result.unwrap();
        assert_eq!(interesting.category, "Email");
        assert_eq!(interesting.value, email);
        assert_eq!(interesting.offset, 100);
    }

    #[test]
    fn test_categorize_string_password() {
        let passwords = vec![
            "password: secret123",
            "Password=mypass",
            "pwd: hidden",
            "PASSWD:test123",
        ];

        for pwd in passwords {
            let result = categorize_string(pwd, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "Password");
        }
    }

    #[test]
    fn test_categorize_string_api_key() {
        let api_keys = vec![
            "api_key: sk-1234567890",
            "apikey=abcdef123456",
            "API-KEY: xyz789",
        ];

        for key in api_keys {
            let result = categorize_string(key, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "API Key");
        }
    }

    #[test]
    fn test_categorize_string_env_var() {
        let env_vars = vec!["HOME_DIR", "PATH_VAR", "JAVA_HOME", "LD_LIBRARY_PATH"];

        for var in env_vars {
            let result = categorize_string(var, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "Environment Variable");
        }
    }

    #[test]
    fn test_categorize_string_file_path() {
        let paths = vec![
            "/usr/bin/bash",
            "/home/user/documents/file.txt",
            "/etc/nginx/nginx.conf",
        ];

        for path in paths {
            let result = categorize_string(path, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "File Path");
        }
    }

    #[test]
    fn test_categorize_string_ip_address() {
        let ips = vec!["192.168.1.1", "10.0.0.1", "172.16.254.1", "8.8.8.8"];

        for ip in ips {
            let result = categorize_string(ip, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "IP Address");
        }
    }

    #[test]
    fn test_categorize_string_version() {
        let versions = vec!["version 1.0", "Version: 2.3.4", "version=3.14"];

        for ver in versions {
            let result = categorize_string(ver, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "Version");
        }
    }

    #[test]
    fn test_categorize_string_copyright() {
        let copyrights = vec![
            "Copyright 2024",
            "copyright (c) 2023",
            "Copyright Microsoft Corporation 2022",
        ];

        for copyright in copyrights {
            let result = categorize_string(copyright, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "Copyright");
        }
    }

    #[test]
    fn test_categorize_string_errors() {
        let errors = vec![
            "Error: File not found",
            "WARNING: Low memory",
            "FATAL: System crash",
            "Critical error occurred",
        ];

        for err in errors {
            let result = categorize_string(err, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "Error/Warning");
        }
    }

    #[test]
    fn test_categorize_string_debug() {
        let debugs = vec![
            "DEBUG: Starting process",
            "trace: function called",
            "INFO: Server started",
        ];

        for debug in debugs {
            let result = categorize_string(debug, 0);
            assert!(result.is_some());
            assert_eq!(result.unwrap().category, "Debug Info");
        }
    }

    #[test]
    fn test_categorize_string_no_match() {
        let normal_strings = vec![
            "Just a normal string",
            "Nothing special here",
            "Regular text",
        ];

        for s in normal_strings {
            let result = categorize_string(s, 0);
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_empty_file() {
        let (_temp_dir, file_path) = create_test_file(b"").unwrap();
        let result = extract_strings(&file_path, 4).unwrap();

        assert_eq!(result.total_count, 0);
        assert_eq!(result.unique_count, 0);
        assert!(result.ascii_strings.is_empty());
        assert!(result.unicode_strings.is_empty());
        assert!(result.interesting_strings.is_empty());
    }

    #[test]
    fn test_binary_file_with_no_strings() {
        let content = vec![0xFF; 1024]; // All 0xFF bytes
        let (_temp_dir, file_path) = create_test_file(&content).unwrap();
        let result = extract_strings(&file_path, 4).unwrap();

        assert_eq!(result.total_count, 0);
        assert_eq!(result.unique_count, 0);
    }

    #[test]
    fn test_mixed_content() {
        let mut content = Vec::new();
        content.extend_from_slice(b"ASCII string here");
        content.extend_from_slice(&[0x00; 10]);
        content.extend_from_slice(b"https://example.com");
        content.extend_from_slice(&[0xFF; 5]);
        content.extend_from_slice(b"error: something failed");

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();
        let result = extract_strings(&file_path, 4).unwrap();

        assert!(result
            .ascii_strings
            .contains(&"ASCII string here".to_string()));
        assert!(result
            .ascii_strings
            .contains(&"https://example.com".to_string()));
        assert!(result
            .ascii_strings
            .contains(&"error: something failed".to_string()));

        // Check interesting strings
        assert!(result
            .interesting_strings
            .iter()
            .any(|s| s.category == "URL"));
        assert!(result
            .interesting_strings
            .iter()
            .any(|s| s.category == "Error/Warning"));
    }

    #[test]
    fn test_large_strings_limit() {
        // Create a file with more than 1000 strings
        let mut content = Vec::new();
        for i in 0..1500 {
            content.extend_from_slice(format!("String number {}\x00", i).as_bytes());
        }

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();
        let result = extract_strings(&file_path, 4).unwrap();

        // Should be limited to 1000
        assert_eq!(result.ascii_strings.len(), 1000);
        assert_eq!(result.total_count, 1500);
    }

    #[test]
    fn test_special_characters_in_strings() {
        let content = b"String with\ttabs\nand\rnewlines\x20and spaces";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = extract_strings(&file_path, 4).unwrap();

        // String will be split at newlines since they're not in the printable ASCII range
        assert!(result.ascii_strings.len() >= 1);
        // Check that we captured the expected parts
        let all_strings = result.ascii_strings.join(" ");
        assert!(all_strings.contains("String with"));
        assert!(all_strings.contains("tabs"));
        assert!(all_strings.contains("and"));
        assert!(all_strings.contains("newlines"));
        assert!(all_strings.contains("and spaces"));
    }

    #[test]
    fn test_nonexistent_file() {
        let path = std::path::Path::new("/nonexistent/file");
        let result = extract_strings(path, 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_extracted_strings_serialization() {
        let extracted = ExtractedStrings {
            total_count: 10,
            unique_count: 8,
            ascii_strings: vec!["test1".to_string(), "test2".to_string()],
            unicode_strings: vec!["unicode1".to_string()],
            interesting_strings: vec![InterestingString {
                category: "URL".to_string(),
                value: "https://example.com".to_string(),
                offset: 100,
            }],
        };

        // Test JSON serialization
        let json = serde_json::to_string(&extracted).unwrap();
        let deserialized: ExtractedStrings = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_count, extracted.total_count);
        assert_eq!(deserialized.unique_count, extracted.unique_count);
        assert_eq!(deserialized.ascii_strings, extracted.ascii_strings);
        assert_eq!(deserialized.unicode_strings, extracted.unicode_strings);
        assert_eq!(
            deserialized.interesting_strings.len(),
            extracted.interesting_strings.len()
        );
    }
}
