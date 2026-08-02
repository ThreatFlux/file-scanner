//! Malicious pattern detection framework

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Malicious pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub description: String,
    pub category: PatternCategory,
    pub severity: PatternSeverity,
    pub indicators: Vec<String>,
    pub regex_patterns: Vec<String>,
    pub file_patterns: Vec<String>,
    pub evidence: Vec<String>,
}

impl MaliciousPattern {
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Pattern categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    CodeExecution,
    DataExfiltration,
    Backdoor,
    CryptoMining,
    Obfuscation,
    NetworkAccess,
    FileSystemAccess,
    PrivilegeEscalation,
    Persistence,
    AntiAnalysis,
}

/// Pattern severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Pattern matcher for detecting malicious code
pub struct PatternMatcher {
    patterns: Vec<CompiledPattern>,
}

/// Compiled pattern with regex
struct CompiledPattern {
    pattern: MaliciousPattern,
    regex_matchers: Vec<Regex>,
}

impl PatternMatcher {
    /// Create a new pattern matcher with default patterns
    pub fn new() -> Result<Self> {
        let patterns = Self::default_patterns();
        let compiled = patterns
            .into_iter()
            .map(Self::compile_pattern)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { patterns: compiled })
    }

    /// Create matcher with custom patterns
    pub fn with_patterns(patterns: Vec<MaliciousPattern>) -> Result<Self> {
        let compiled = patterns
            .into_iter()
            .map(Self::compile_pattern)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { patterns: compiled })
    }

    /// Compile a pattern
    fn compile_pattern(pattern: MaliciousPattern) -> Result<CompiledPattern> {
        let regex_matchers = pattern
            .regex_patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CompiledPattern {
            pattern,
            regex_matchers,
        })
    }

    /// Scan content for malicious patterns
    pub fn scan(&self, content: &str, file_path: Option<&str>) -> Vec<MaliciousPattern> {
        let mut detected = Vec::new();

        for compiled in &self.patterns {
            let mut matches = false;
            let mut evidence = Vec::new();

            // Check regex patterns
            for regex in &compiled.regex_matchers {
                if let Some(m) = regex.find(content) {
                    matches = true;
                    evidence.push(format!(
                        "Pattern '{}' found at position {}",
                        regex.as_str(),
                        m.start()
                    ));
                }
            }

            // Check file patterns if path provided
            if let Some(path) = file_path {
                for file_pattern in &compiled.pattern.file_patterns {
                    if path.contains(file_pattern) {
                        matches = true;
                        evidence.push(format!("File pattern '{}' matched", file_pattern));
                    }
                }
            }

            if matches {
                let mut pattern = compiled.pattern.clone();
                pattern.evidence = evidence;
                detected.push(pattern);
            }
        }

        detected
    }

    /// Get default malicious patterns
    fn default_patterns() -> Vec<MaliciousPattern> {
        vec![
            // Code execution patterns
            MaliciousPattern {
                pattern_id: "EXEC_001".to_string(),
                pattern_name: "Dynamic code execution".to_string(),
                description: "Detects dynamic code execution attempts".to_string(),
                category: PatternCategory::CodeExecution,
                severity: PatternSeverity::Critical,
                indicators: vec![
                    "eval".to_string(),
                    "exec".to_string(),
                    "Function constructor".to_string(),
                ],
                regex_patterns: vec![
                    r"eval\s*\(".to_string(),
                    r"exec\s*\(".to_string(),
                    r"new\s+Function\s*\(".to_string(),
                    r"subprocess\.(call|run|Popen)".to_string(),
                    r"os\.system\s*\(".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Data exfiltration patterns
            MaliciousPattern {
                pattern_id: "EXFIL_001".to_string(),
                pattern_name: "Environment variable access".to_string(),
                description: "Detects attempts to access environment variables".to_string(),
                category: PatternCategory::DataExfiltration,
                severity: PatternSeverity::High,
                indicators: vec!["process.env".to_string(), "os.environ".to_string()],
                regex_patterns: vec![
                    r"process\.env\.[A-Z_]+".to_string(),
                    r"os\.environ\[".to_string(),
                    r"getenv\s*\(".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Backdoor patterns
            MaliciousPattern {
                pattern_id: "BACK_001".to_string(),
                pattern_name: "Reverse shell".to_string(),
                description: "Detects reverse shell patterns".to_string(),
                category: PatternCategory::Backdoor,
                severity: PatternSeverity::Critical,
                indicators: vec![
                    "nc -e".to_string(),
                    "bash -i".to_string(),
                    "/dev/tcp".to_string(),
                ],
                regex_patterns: vec![
                    r"nc\s+-[elvp]*e".to_string(),
                    r"bash\s+-i".to_string(),
                    r"/dev/tcp/".to_string(),
                    r"socket\.socket\s*\(".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Crypto mining patterns
            MaliciousPattern {
                pattern_id: "MINE_001".to_string(),
                pattern_name: "Cryptocurrency mining".to_string(),
                description: "Detects cryptocurrency mining code".to_string(),
                category: PatternCategory::CryptoMining,
                severity: PatternSeverity::High,
                indicators: vec![
                    "stratum".to_string(),
                    "mining pool".to_string(),
                    "hashrate".to_string(),
                ],
                regex_patterns: vec![
                    r"stratum\+tcp://".to_string(),
                    r"(monero|bitcoin|ethereum).*mining".to_string(),
                    r"coinhive|cryptoloot".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Obfuscation patterns
            MaliciousPattern {
                pattern_id: "OBFU_001".to_string(),
                pattern_name: "Base64 obfuscation".to_string(),
                description: "Detects base64 encoded/decoded content".to_string(),
                category: PatternCategory::Obfuscation,
                severity: PatternSeverity::Medium,
                indicators: vec!["base64".to_string(), "atob".to_string(), "btoa".to_string()],
                regex_patterns: vec![
                    r"base64\.(b64)?decode".to_string(),
                    r"atob\s*\(".to_string(),
                    r#"Buffer\.from\([^,]+,\s*['"]base64"#.to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
        ]
    }
}

/// Pattern database for managing pattern definitions
pub struct PatternDatabase {
    patterns: HashMap<String, MaliciousPattern>,
    categories: HashMap<PatternCategory, Vec<String>>,
}

impl PatternDatabase {
    /// Create a new pattern database
    pub fn new() -> Self {
        let mut db = Self {
            patterns: HashMap::new(),
            categories: HashMap::new(),
        };

        // Load default patterns
        for pattern in PatternMatcher::default_patterns() {
            db.add_pattern(pattern);
        }

        db
    }

    /// Add a pattern to the database
    pub fn add_pattern(&mut self, pattern: MaliciousPattern) {
        let id = pattern.pattern_id.clone();
        let category = pattern.category.clone();

        self.patterns.insert(id.clone(), pattern);
        self.categories.entry(category).or_default().push(id);
    }

    /// Get pattern by ID
    pub fn get_pattern(&self, id: &str) -> Option<&MaliciousPattern> {
        self.patterns.get(id)
    }

    /// Get patterns by category
    pub fn get_by_category(&self, category: &PatternCategory) -> Vec<&MaliciousPattern> {
        self.categories
            .get(category)
            .map(|ids| ids.iter().filter_map(|id| self.patterns.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all patterns
    pub fn all_patterns(&self) -> Vec<&MaliciousPattern> {
        self.patterns.values().collect()
    }

    /// Export patterns to JSON
    pub fn export_json(&self) -> Result<String> {
        let patterns: Vec<_> = self.patterns.values().cloned().collect();
        Ok(serde_json::to_string_pretty(&patterns)?)
    }

    /// Import patterns from JSON
    pub fn import_json(&mut self, json: &str) -> Result<usize> {
        let patterns: Vec<MaliciousPattern> = serde_json::from_str(json)?;
        let count = patterns.len();

        for pattern in patterns {
            self.add_pattern(pattern);
        }

        Ok(count)
    }
}

impl Default for PatternDatabase {
    fn default() -> Self {
        Self::new()
    }
}
