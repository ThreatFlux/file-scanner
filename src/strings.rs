use anyhow::Result;
use encoding_rs::{UTF_16BE, UTF_16LE};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::LazyLock;

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

/// Where a string was found and how it was encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StringEncoding {
    /// Printable ASCII bytes.
    Ascii,
    /// UTF-16 little endian, printable ASCII code units only.
    Utf16Le,
    /// UTF-16 big endian, printable ASCII code units only.
    Utf16Be,
}

impl StringEncoding {
    /// The name used in tool output and filters.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf16le",
            Self::Utf16Be => "utf16be",
        }
    }
}

/// One string found in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoundString {
    /// Byte offset of the first byte of the string in the file.
    pub offset: usize,
    pub encoding: StringEncoding,
    pub value: String,
    /// What the string looks like (URL, IP Address, ...), when it matches one
    /// of the categories.
    pub category: Option<String>,
}

/// Strings a scan keeps by default: this many without a category ...
pub const KEEP_PLAIN: usize = 50_000;
/// ... and this many with one. Counts are always exact; only the kept list is
/// bounded.
pub const KEEP_CATEGORIZED: usize = 50_000;
/// Most bytes of a file one scan reads.
pub const MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;

/// The strings of a file in file order (the ones kept), with exact counts.
///
/// A file of millions of strings is counted and categorized while it is
/// scanned; the list keeps the categorized strings and the first plain ones up
/// to [`ScanLimits`], and `truncated` says when it cut.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StringScan {
    pub min_length: usize,
    /// Occurrences found (ASCII plus UTF-16).
    pub total_count: usize,
    /// Distinct values (by a 64-bit hash of the text).
    pub unique_count: usize,
    pub ascii_count: usize,
    pub utf16_count: usize,
    /// How many occurrences of each category were found (all of them, not only
    /// the kept ones).
    #[serde(default)]
    pub category_counts: BTreeMap<String, usize>,
    /// Length of `strings`.
    #[serde(default)]
    pub kept: usize,
    /// True when `strings` holds fewer than `total_count` strings.
    #[serde(default)]
    pub truncated: bool,
    /// True when the file was longer than [`MAX_SCAN_BYTES`] and only its
    /// start was scanned.
    #[serde(default)]
    pub input_truncated: bool,
    /// Why the list is short, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub strings: Vec<FoundString>,
}

/// What a scan keeps in its list.
#[derive(Clone, Copy)]
pub struct ScanLimits<'f> {
    /// Strings without a category kept.
    pub keep_plain: usize,
    /// Strings with a category kept.
    pub keep_categorized: usize,
    /// When set, only strings it accepts are kept (they are all still counted).
    pub only: Option<&'f dyn Fn(&FoundString) -> bool>,
}

impl Default for ScanLimits<'_> {
    fn default() -> Self {
        Self {
            keep_plain: KEEP_PLAIN,
            keep_categorized: KEEP_CATEGORIZED,
            only: None,
        }
    }
}

impl StringScan {
    /// The categorized strings, in file order.
    pub fn interesting(&self) -> impl Iterator<Item = &FoundString> {
        self.strings.iter().filter(|s| s.category.is_some())
    }

    /// The legacy view: the first 1000 strings of each kind, and every
    /// categorized string that was kept.
    pub fn to_extracted(&self) -> ExtractedStrings {
        let mut ascii_strings = Vec::new();
        let mut unicode_strings = Vec::new();
        let mut interesting_strings = Vec::new();
        for found in &self.strings {
            let list = if found.encoding == StringEncoding::Ascii {
                &mut ascii_strings
            } else {
                &mut unicode_strings
            };
            if list.len() < MAX_LEGACY_STRINGS {
                list.push(found.value.clone());
            }
            if let Some(category) = &found.category {
                interesting_strings.push(InterestingString {
                    category: category.clone(),
                    value: found.value.clone(),
                    offset: found.offset,
                });
            }
        }
        ExtractedStrings {
            total_count: self.total_count,
            unique_count: self.unique_count,
            ascii_strings,
            unicode_strings,
            interesting_strings,
        }
    }
}

/// Strings per kind that the legacy [`ExtractedStrings`] view keeps.
const MAX_LEGACY_STRINGS: usize = 1000;

/// Strings of at least `min_length` characters, capped at 1000 per kind (the
/// view the CLI prints). Use [`scan_strings`] for the counted list.
pub fn extract_strings(path: &Path, min_length: usize) -> Result<ExtractedStrings> {
    Ok(scan_strings(path, min_length)?.to_extracted())
}

/// Every ASCII and UTF-16 string of at least `min_length` characters, counted
/// exactly; the list keeps what [`ScanLimits::default`] allows, in file order.
///
/// UTF-16 strings contain printable ASCII code units only, so runs of zero
/// bytes and small integers are not reported as text. A run that reads as both
/// little and big endian (the two overlap by one byte) is reported once, as
/// the longer reading.
pub fn scan_strings(path: &Path, min_length: usize) -> Result<StringScan> {
    scan_strings_limited(path, min_length, &ScanLimits::default())
}

/// [`scan_strings`] with explicit limits on what the list keeps. At most
/// [`MAX_SCAN_BYTES`] of the file are read.
pub fn scan_strings_limited(
    path: &Path,
    min_length: usize,
    limits: &ScanLimits<'_>,
) -> Result<StringScan> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut buffer = Vec::with_capacity(file_size.min(MAX_SCAN_BYTES) as usize);
    BufReader::new(file)
        .take(MAX_SCAN_BYTES)
        .read_to_end(&mut buffer)?;
    let mut scan = scan_bytes_limited(&buffer, min_length, limits)?;
    if file_size > MAX_SCAN_BYTES {
        scan.input_truncated = true;
        scan.truncated = true;
        scan.note = Some(format!(
            "only the first {} MiB of the {} MiB file were scanned",
            MAX_SCAN_BYTES / (1024 * 1024),
            file_size / (1024 * 1024)
        ));
    }
    Ok(scan)
}

/// [`scan_strings`] over bytes already in memory.
pub fn scan_bytes(buffer: &[u8], min_length: usize) -> Result<StringScan> {
    scan_bytes_limited(buffer, min_length, &ScanLimits::default())
}

/// Counts strings as they are found and keeps a bounded list.
struct Collector<'l, 'f> {
    limits: &'l ScanLimits<'f>,
    strings: Vec<FoundString>,
    seen: HashSet<u64>,
    total: usize,
    ascii: usize,
    utf16: usize,
    plain_kept: usize,
    categorized_kept: usize,
    category_counts: BTreeMap<String, usize>,
}

impl Collector<'_, '_> {
    fn add(&mut self, offset: usize, encoding: StringEncoding, value: &str) {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        value.hash(&mut hasher);
        self.seen.insert(hasher.finish());
        self.total += 1;
        if encoding == StringEncoding::Ascii {
            self.ascii += 1;
        } else {
            self.utf16 += 1;
        }
        let category = category_of(value);
        if let Some(category) = category {
            *self
                .category_counts
                .entry(category.to_string())
                .or_default() += 1;
        }
        let room = if category.is_some() {
            self.categorized_kept < self.limits.keep_categorized
        } else {
            self.plain_kept < self.limits.keep_plain
        };
        if !room {
            return;
        }
        let candidate = FoundString {
            offset,
            encoding,
            value: value.to_string(),
            category: category.map(str::to_string),
        };
        if self.limits.only.is_some_and(|accept| !accept(&candidate)) {
            return;
        }
        if category.is_some() {
            self.categorized_kept += 1;
        } else {
            self.plain_kept += 1;
        }
        self.strings.push(candidate);
    }
}

/// [`scan_bytes`] with explicit limits on what the list keeps.
pub fn scan_bytes_limited(
    buffer: &[u8],
    min_length: usize,
    limits: &ScanLimits<'_>,
) -> Result<StringScan> {
    let min_length = min_length.max(1);
    let ascii_regex = Regex::new(&format!(r"[\x20-\x7E]{{{min_length},}}"))?;
    let utf16_le_regex = Regex::new(&format!(r"(?:[\x20-\x7E]\x00){{{min_length},}}"))?;
    let utf16_be_regex = Regex::new(&format!(r"(?:\x00[\x20-\x7E]){{{min_length},}}"))?;

    let mut collector = Collector {
        limits,
        strings: Vec::new(),
        seen: HashSet::new(),
        total: 0,
        ascii: 0,
        utf16: 0,
        plain_kept: 0,
        categorized_kept: 0,
        category_counts: BTreeMap::new(),
    };
    for mat in ascii_regex.find_iter(buffer) {
        if let Ok(s) = std::str::from_utf8(mat.as_bytes()) {
            collector.add(mat.start(), StringEncoding::Ascii, s);
        }
    }

    // UTF-16 candidates of both byte orders; where two overlap, the longer
    // wins and a little endian reading beats an equally long big endian one
    // (an LE string preceded by a zero byte also matches BE one byte early).
    let is_printable = |b: u8| (0x20..=0x7E).contains(&b);
    let mut candidates: Vec<(usize, usize, StringEncoding)> = Vec::new();
    for m in utf16_le_regex.find_iter(buffer) {
        let (mut start, end) = (m.start(), m.end());
        // The first unit may be the last character of an ASCII string that
        // was already reported (its NUL terminator is this unit's high byte);
        // that string is the printable run before the unit plus the unit's
        // own low byte.
        let ascii_before = buffer[..start]
            .iter()
            .rev()
            .take_while(|&&b| is_printable(b))
            .count();
        if ascii_before + 1 >= min_length {
            start += 2;
        }
        if end > start && (end - start) / 2 >= min_length {
            candidates.push((start, end, StringEncoding::Utf16Le));
        }
    }
    candidates.extend(
        utf16_be_regex
            .find_iter(buffer)
            .map(|m| (m.start(), m.end(), StringEncoding::Utf16Be)),
    );
    candidates.sort_by_key(|&(start, end, encoding)| {
        (
            std::cmp::Reverse(end - start),
            encoding == StringEncoding::Utf16Be,
            start,
        )
    });
    let mut taken: BTreeMap<usize, usize> = BTreeMap::new();
    for (start, end, encoding) in candidates {
        let overlaps = taken
            .range(..end)
            .next_back()
            .is_some_and(|(_, &taken_end)| taken_end > start);
        if overlaps {
            continue;
        }
        taken.insert(start, end);
        let (decoded, _, _) = if encoding == StringEncoding::Utf16Le {
            UTF_16LE.decode(&buffer[start..end])
        } else {
            UTF_16BE.decode(&buffer[start..end])
        };
        if decoded.len() >= min_length {
            collector.add(start, encoding, &decoded);
        }
    }
    // File order (ASCII first on a tie, the way the two passes ran before).
    let mut strings = collector.strings;
    strings.sort_by_key(|s| (s.offset, s.encoding != StringEncoding::Ascii));

    let kept = strings.len();
    let truncated = kept < collector.total;
    let note = truncated.then(|| {
        format!(
            "the list holds {kept} of {} strings (the categorized ones first, then the first \
             plain ones); counts and categories cover all of them. query_analysis with a \
             filter, category or encoding scans the whole file again for the matches",
            collector.total
        )
    });
    Ok(StringScan {
        min_length,
        total_count: collector.total,
        unique_count: collector.seen.len(),
        ascii_count: collector.ascii,
        utf16_count: collector.utf16,
        category_counts: collector.category_counts,
        kept,
        truncated,
        input_truncated: false,
        note,
        strings,
    })
}

/// Categorization patterns, compiled once and checked in order; the first
/// match decides a string's category.
static CATEGORY_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
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

    patterns
        .into_iter()
        .filter_map(|(pattern, category)| Regex::new(pattern).ok().map(|regex| (regex, category)))
        .collect()
});

/// The category of `s`: the first pattern that matches.
fn category_of(s: &str) -> Option<&'static str> {
    // Compiling these patterns for every extracted string dominated string
    // extraction (about 2.6 ms per string), so they are compiled once.
    CATEGORY_PATTERNS
        .iter()
        .find(|(regex, _)| regex.is_match(s.as_bytes()))
        .map(|(_, category)| *category)
}

#[cfg(test)]
fn categorize_string(s: &str, offset: usize) -> Option<InterestingString> {
    category_of(s).map(|category| InterestingString {
        category: category.to_string(),
        value: s.to_string(),
        offset,
    })
}

/// Byte range of the text that made `s` a string of its category (the URL
/// itself, the address, the key assignment), for showing the indicator
/// instead of the start of a long string.
pub fn category_span(s: &str) -> Option<(usize, usize)> {
    CATEGORY_PATTERNS
        .iter()
        .find_map(|(regex, _)| regex.find(s.as_bytes()).map(|m| (m.start(), m.end())))
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
    fn test_category_patterns_all_compile() {
        // categorize_string skips a pattern that fails to compile, so a broken
        // edit would silently drop a category; every pattern must compile.
        assert_eq!(CATEGORY_PATTERNS.len(), 12);
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
            content.extend_from_slice(format!("String number {i}\x00").as_bytes());
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
        assert!(!result.ascii_strings.is_empty());
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

    /// CB06: runs of zero bytes and small integers are not UTF-16 "strings".
    #[test]
    fn utf16_extraction_returns_printable_strings_only() {
        let mut content = vec![0u8; 64];
        content.extend_from_slice(&[1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0]);
        content.extend_from_slice(&[0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6]);
        content.extend_from_slice(b"H\x00e\x00l\x00l\x00o\x00");
        let scan = scan_bytes(&content, 4).unwrap();
        assert_eq!(scan.strings.len(), 1, "{:?}", scan.strings);
        assert_eq!(scan.strings[0].value, "Hello");
        assert_eq!(scan.strings[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(scan.strings[0].offset, 64 + 24);
        for found in &scan.strings {
            assert!(found.value.chars().all(|c| (' '..='~').contains(&c)));
        }
        // The legacy view is clean too.
        let legacy = scan.to_extracted();
        assert_eq!(legacy.unicode_strings, vec!["Hello".to_string()]);
    }

    /// A little endian string is not also reported as a shifted big endian one.
    #[test]
    fn utf16_runs_are_reported_once_in_the_right_byte_order() {
        let mut content = Vec::new();
        content.extend_from_slice(b"H\x00e\x00l\x00l\x00o\x00");
        content.extend_from_slice(&[0xFF, 0xFF]);
        content.extend_from_slice(b"\x00W\x00o\x00r\x00l\x00d");
        let scan = scan_bytes(&content, 4).unwrap();
        let values: Vec<(&str, StringEncoding)> = scan
            .strings
            .iter()
            .map(|s| (s.value.as_str(), s.encoding))
            .collect();
        assert_eq!(
            values,
            vec![
                ("Hello", StringEncoding::Utf16Le),
                ("World", StringEncoding::Utf16Be)
            ]
        );
    }

    /// A little endian string after a zero byte or after an ASCII string.
    #[test]
    fn utf16le_after_zero_or_ascii_keeps_its_order_offset_and_text() {
        let mut content = vec![0xFF, 0xFF, 0x00, 0x00];
        content.extend_from_slice(b"W\x00i\x00d\x00e\x00");
        let scan = scan_bytes(&content, 4).unwrap();
        assert_eq!(scan.strings.len(), 1, "{:?}", scan.strings);
        assert_eq!(scan.strings[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(scan.strings[0].offset, 4);
        assert_eq!(scan.strings[0].value, "Wide");

        let mut content = b"ASCII String\0".to_vec();
        content.extend_from_slice(b"T\x00e\x00s\x00t\x00");
        content.extend_from_slice(&[0xFF, 0xFE, 0, 0]);
        content.extend_from_slice(b"Another ASCII\0");
        let scan = scan_bytes(&content, 4).unwrap();
        let values: Vec<&str> = scan.strings.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(values, vec!["ASCII String", "Test", "Another ASCII"]);
    }

    #[test]
    fn scan_keeps_offsets_categories_and_every_string() {
        let mut content = Vec::new();
        content.extend_from_slice(b"\x00\x00see https://example.com/x now\x00");
        for i in 0..2500 {
            content.extend_from_slice(format!("string number {i}\x00").as_bytes());
        }
        let (_dir, path) = create_test_file(&content).unwrap();
        let scan = scan_strings(&path, 4).unwrap();
        assert_eq!(scan.total_count, 2501);
        assert_eq!(scan.strings.len(), 2501, "not capped");
        let url = scan.interesting().next().expect("a categorized string");
        assert_eq!(url.category.as_deref(), Some("URL"));
        assert_eq!(url.offset, 2);
        // The legacy CLI view stays capped.
        let legacy = extract_strings(&path, 4).unwrap();
        assert_eq!(legacy.ascii_strings.len(), 1000);
        assert_eq!(legacy.total_count, 2501);
        assert_eq!(legacy.interesting_strings[0].offset, 2);
    }

    /// An ASCII string of exactly `min_length` before a UTF-16LE one keeps its
    /// last character.
    #[test]
    fn ascii_of_exactly_min_length_before_utf16le_keeps_its_last_character() {
        let mut content = vec![0x01, 0x02];
        content.extend_from_slice(b"abcd\0");
        content.extend_from_slice(b"W\x00i\x00n\x00d\x00o\x00w\x00s\x00");
        content.extend_from_slice(&[0, 0, 0xFF]);
        let scan = scan_bytes(&content, 4).unwrap();
        let found: Vec<(usize, StringEncoding, &str)> = scan
            .strings
            .iter()
            .map(|s| (s.offset, s.encoding, s.value.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                (2, StringEncoding::Ascii, "abcd"),
                (7, StringEncoding::Utf16Le, "Windows")
            ]
        );
    }

    /// Counts stay exact when the list is capped, and the cut is said.
    #[test]
    fn a_capped_scan_counts_everything_and_keeps_a_bounded_list() {
        let mut content = Vec::new();
        content.extend_from_slice(b"see http://example.com/a now\0");
        for i in 0..3000 {
            content.extend_from_slice(format!("plain string {i}\0").as_bytes());
        }
        content.extend_from_slice(b"needle string at the end\0");
        let limits = ScanLimits {
            keep_plain: 100,
            keep_categorized: 10,
            only: None,
        };
        let scan = scan_bytes_limited(&content, 4, &limits).unwrap();
        assert_eq!(scan.total_count, 3002);
        assert_eq!(scan.unique_count, 3002);
        assert_eq!(scan.kept, scan.strings.len());
        assert_eq!(scan.kept, 101);
        assert!(scan.truncated);
        assert!(scan.note.as_deref().unwrap().contains("101 of 3002"));
        assert_eq!(scan.category_counts.get("URL"), Some(&1));
        // A predicate keeps what it accepts, even past the plain cap.
        let only_needle = |s: &FoundString| s.value.contains("needle");
        let limits = ScanLimits {
            keep_plain: 100,
            keep_categorized: 10,
            only: Some(&only_needle),
        };
        let scan = scan_bytes_limited(&content, 4, &limits).unwrap();
        assert_eq!(scan.total_count, 3002);
        assert_eq!(scan.strings.len(), 1);
        assert_eq!(scan.strings[0].value, "needle string at the end");
    }
}
