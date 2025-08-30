//! Error types for threat detection operations

use thiserror::Error;

/// Result type for threat detection operations
pub type Result<T> = std::result::Result<T, ThreatError>;

/// Errors that can occur during threat detection
#[derive(Error, Debug)]
pub enum ThreatError {
    /// YARA engine error
    #[error("YARA engine error: {0}")]
    YaraError(String),

    /// ClamAV engine error
    #[error("ClamAV engine error: {0}")]
    ClamAVError(String),

    /// Pattern matching error
    #[error("Pattern matching error: {0}")]
    PatternError(String),

    /// Rule compilation error
    #[error("Rule compilation failed: {0}")]
    RuleCompilationError(String),

    /// Rule loading error
    #[error("Failed to load rules: {0}")]
    RuleLoadError(String),

    /// Rule update error
    #[error("Failed to update rules: {0}")]
    RuleUpdateError(String),

    /// File access error
    #[error("File access error: {0}")]
    FileError(String),

    /// Network error (for rule updates)
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Engine not available
    #[error("Detection engine not available: {0}")]
    EngineNotAvailable(String),

    /// Scan timeout
    #[error("Scan operation timed out after {timeout_secs} seconds")]
    ScanTimeout { timeout_secs: u64 },

    /// File too large
    #[error("File too large: {size} bytes (max: {max_size} bytes)")]
    FileTooLarge { size: u64, max_size: u64 },

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(feature = "yara-engine")]
impl From<yara_x::ScanError> for ThreatError {
    fn from(err: yara_x::ScanError) -> Self {
        ThreatError::YaraError(err.to_string())
    }
}

#[cfg(feature = "yara-engine")]
impl From<yara_x::errors::CompileError> for ThreatError {
    fn from(err: yara_x::errors::CompileError) -> Self {
        ThreatError::YaraError(err.to_string())
    }
}

#[cfg(feature = "serde-support")]
impl From<serde_json::Error> for ThreatError {
    fn from(err: serde_json::Error) -> Self {
        ThreatError::SerializationError(err.to_string())
    }
}

#[cfg(feature = "rule-management")]
impl From<reqwest::Error> for ThreatError {
    fn from(err: reqwest::Error) -> Self {
        ThreatError::NetworkError(err.to_string())
    }
}

#[cfg(feature = "rule-management")]
impl From<git2::Error> for ThreatError {
    fn from(err: git2::Error) -> Self {
        ThreatError::RuleUpdateError(format!("Git error: {}", err))
    }
}

impl ThreatError {
    /// Create a new YARA error
    pub fn yara<S: Into<String>>(msg: S) -> Self {
        Self::YaraError(msg.into())
    }

    /// Create a new ClamAV error
    pub fn clamav<S: Into<String>>(msg: S) -> Self {
        Self::ClamAVError(msg.into())
    }

    /// Create a new pattern error
    pub fn pattern<S: Into<String>>(msg: S) -> Self {
        Self::PatternError(msg.into())
    }

    /// Create a new rule compilation error
    pub fn rule_compilation<S: Into<String>>(msg: S) -> Self {
        Self::RuleCompilationError(msg.into())
    }

    /// Create a new rule load error
    pub fn rule_load<S: Into<String>>(msg: S) -> Self {
        Self::RuleLoadError(msg.into())
    }

    /// Create a new rule update error
    pub fn rule_update<S: Into<String>>(msg: S) -> Self {
        Self::RuleUpdateError(msg.into())
    }

    /// Create a new file error
    pub fn file<S: Into<String>>(msg: S) -> Self {
        Self::FileError(msg.into())
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        Self::NetworkError(msg.into())
    }

    /// Create a new engine not available error
    pub fn engine_not_available<S: Into<String>>(engine: S) -> Self {
        Self::EngineNotAvailable(engine.into())
    }

    /// Create a new scan timeout error
    pub fn scan_timeout(timeout_secs: u64) -> Self {
        Self::ScanTimeout { timeout_secs }
    }

    /// Create a new file too large error
    pub fn file_too_large(size: u64, max_size: u64) -> Self {
        Self::FileTooLarge { size, max_size }
    }

    /// Create a new config error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::ConfigError(msg.into())
    }

    /// Create a new serialization error
    pub fn serialization<S: Into<String>>(msg: S) -> Self {
        Self::SerializationError(msg.into())
    }

    /// Create a new database error
    pub fn database<S: Into<String>>(msg: S) -> Self {
        Self::DatabaseError(msg.into())
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a rule not found error
    pub fn rule_not_found<S: Into<String>>(path: S) -> Self {
        Self::RuleLoadError(format!("Rule not found: {}", path.into()))
    }

    /// Create an invalid rule error
    pub fn invalid_rule<S: Into<String>>(msg: S) -> Self {
        Self::RuleCompilationError(format!("Invalid rule: {}", msg.into()))
    }
}
