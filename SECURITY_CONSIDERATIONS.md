# Security Considerations

This document outlines comprehensive security best practices for all ThreatFlux libraries and the File Scanner application.

## 📋 Table of Contents

- [Security Overview](#security-overview)
- [Library-Specific Security](#library-specific-security)
- [Input Validation](#input-validation)
- [Memory Safety](#memory-safety)
- [Process Isolation](#process-isolation)
- [Network Security](#network-security)
- [Authentication & Authorization](#authentication--authorization)
- [Cryptographic Security](#cryptographic-security)
- [Deployment Security](#deployment-security)
- [Incident Response](#incident-response)

## 🛡️ Security Overview

### Security Model

The ThreatFlux ecosystem follows a **defense-in-depth** security model:

1. **Input Validation**: All inputs are validated and sanitized
2. **Memory Safety**: Rust's ownership model prevents common vulnerabilities
3. **Process Isolation**: Components run with minimal privileges
4. **Resource Limits**: Prevent denial-of-service attacks
5. **Cryptographic Integrity**: All hashes and signatures are verified
6. **Audit Logging**: All operations are logged for analysis

### Threat Model

#### Assets to Protect
- File analysis results and metadata
- Cached analysis data
- System resources (CPU, memory, disk)
- Network communications
- User credentials and API keys

#### Threat Actors
- **Malicious Files**: Crafted to exploit analysis tools
- **Network Attackers**: Attempting to intercept or modify communications
- **Insider Threats**: Authorized users with malicious intent
- **Supply Chain Attacks**: Compromised dependencies or build tools

#### Attack Vectors
- Malformed binary files
- Path traversal attacks
- Resource exhaustion (DoS)
- Network interception
- Cache poisoning
- Dependency confusion

## 🔒 Library-Specific Security

### threatflux-hashing

#### Security Features

```rust
use threatflux_hashing::{HashConfig, SecurityConfig};

let security_config = SecurityConfig {
    // Prevent hash length extension attacks
    use_secure_algorithms: true,
    
    // Validate input file sizes
    max_file_size: 10 * 1024 * 1024 * 1024,  // 10GB limit
    
    // Timeout protection
    max_processing_time: Duration::from_secs(300),
    
    // Memory limits
    max_buffer_size: 64 * 1024,  // 64KB
};

let config = HashConfig::with_security(security_config);
```

#### Security Best Practices

```rust
// ✅ Validate file paths
fn validate_file_path(path: &Path) -> Result<(), SecurityError> {
    // Prevent path traversal
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SecurityError::PathTraversal);
    }
    
    // Ensure path is within allowed directory
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(&allowed_base_dir) {
        return Err(SecurityError::UnauthorizedPath);
    }
    
    Ok(())
}

// ✅ Use secure hash verification
async fn verify_hash_integrity(file_path: &Path, expected_hash: &str) -> Result<bool> {
    validate_file_path(file_path)?;
    
    let calculated_hash = calculate_sha256(file_path).await?;
    Ok(constant_time_eq(calculated_hash.as_bytes(), expected_hash.as_bytes()))
}

// ❌ Never trust user-provided hash values directly
// let user_hash = user_input.hash;  // Dangerous!
```

### threatflux-cache

#### Secure Cache Configuration

```rust
use threatflux_cache::{Cache, CacheConfig, SecurityPolicy};

let security_policy = SecurityPolicy {
    // Encrypt sensitive data at rest
    encryption_enabled: true,
    encryption_key: load_encryption_key()?,
    
    // Prevent cache poisoning
    integrity_checks: true,
    
    // Access controls
    require_authentication: true,
    
    // Rate limiting
    max_operations_per_second: 1000,
    
    // TTL enforcement
    enforce_ttl: true,
    max_ttl: Duration::from_secs(3600),
};

let config = CacheConfig::with_security_policy(security_policy);
```

#### Cache Security Patterns

```rust
// ✅ Secure cache key generation
fn generate_secure_cache_key(file_path: &Path, user_id: &str) -> Result<String> {
    let file_hash = calculate_sha256(file_path).await?;
    let user_hash = calculate_sha256(user_id.as_bytes()).await?;
    
    // Combine hashes to prevent cache key collisions
    Ok(format!("{}:{}", file_hash, user_hash))
}

// ✅ Validate cache entries
async fn get_with_validation(cache: &Cache, key: &str) -> Result<Option<CacheEntry>> {
    if let Some(entry) = cache.get(key).await? {
        // Verify integrity
        if verify_cache_entry_integrity(&entry)? {
            Ok(Some(entry))
        } else {
            // Remove corrupted entry
            cache.remove(key).await?;
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

// ❌ Don't store sensitive data unencrypted
// cache.put("api_key", user_api_key).await?;  // Dangerous!
```

### threatflux-string-analysis

#### Secure String Processing

```rust
use threatflux_string_analysis::{StringAnalyzer, SecurityConfig};

let security_config = SecurityConfig {
    // Prevent ReDoS attacks
    regex_timeout: Duration::from_millis(100),
    
    // Limit output to prevent memory exhaustion
    max_strings: 10000,
    max_string_length: 1024,
    
    // Sanitize outputs
    sanitize_output: true,
    
    // Prevent information disclosure
    redact_sensitive_patterns: true,
};

let analyzer = StringAnalyzer::with_security_config(security_config);
```

#### Pattern Matching Security

```rust
// ✅ Use safe regex patterns
const SAFE_PATTERNS: &[&str] = &[
    r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/?.*$",  // Safe URL pattern
    r"^[a-zA-Z]:[\\\/][^<>:|?*]+$",                    // Safe Windows path
];

// ✅ Implement regex timeouts
use regex::RegexBuilder;

fn create_safe_regex(pattern: &str) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .size_limit(10 * 1024 * 1024)  // 10MB limit
        .dfa_size_limit(10 * 1024 * 1024)
        .build()
        .map_err(|e| SecurityError::UnsafeRegex(e))
}

// ❌ Dangerous patterns that can cause ReDoS
// r"(a+)+" - Exponential backtracking
// r"([a-zA-Z]+)*" - Catastrophic backtracking
```

### threatflux-binary-analysis

#### Safe Binary Parsing

```rust
use threatflux_binary_analysis::{BinaryAnalyzer, ParseConfig, SecurityLimits};

let security_limits = SecurityLimits {
    // Prevent ZIP bombs and similar attacks
    max_uncompressed_size: 1024 * 1024 * 1024,  // 1GB
    max_compression_ratio: 100,
    
    // Prevent infinite loops in parsers
    max_parse_iterations: 10000,
    
    // Memory limits
    max_memory_usage: 512 * 1024 * 1024,  // 512MB
    
    // File format specific limits
    max_sections: 1000,
    max_symbols: 100000,
};

let config = ParseConfig::with_security_limits(security_limits);
```

#### Format-Specific Security

```rust
// ✅ Validate PE file structure
fn validate_pe_file(pe_data: &[u8]) -> Result<(), SecurityError> {
    // Check magic number
    if pe_data.len() < 2 || &pe_data[0..2] != b"MZ" {
        return Err(SecurityError::InvalidFormat);
    }
    
    // Validate DOS header
    if pe_data.len() < 64 {
        return Err(SecurityError::TruncatedFile);
    }
    
    // Check PE signature location
    let pe_offset = u32::from_le_bytes([
        pe_data[60], pe_data[61], pe_data[62], pe_data[63]
    ]) as usize;
    
    if pe_offset >= pe_data.len() - 4 {
        return Err(SecurityError::InvalidPEOffset);
    }
    
    Ok(())
}

// ✅ Bounds checking for section parsing
fn parse_section_safely(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    if offset.saturating_add(size) > data.len() {
        return Err(SecurityError::BufferOverflow);
    }
    
    Ok(&data[offset..offset + size])
}
```

### threatflux-package-security

#### Package Validation

```rust
use threatflux_package_security::{PackageAnalyzer, ValidationConfig};

let validation_config = ValidationConfig {
    // Verify package signatures
    require_signatures: true,
    trusted_keys: load_trusted_keys()?,
    
    // Validate package integrity
    verify_checksums: true,
    
    // Scan for malicious content
    scan_for_malware: true,
    
    // Check against vulnerability databases
    vulnerability_scanning: true,
    
    // Validate dependencies
    check_dependency_integrity: true,
};
```

#### Supply Chain Security

```rust
// ✅ Verify package integrity
async fn verify_package_integrity(package_path: &Path) -> Result<bool> {
    // Verify package hash against registry
    let calculated_hash = calculate_sha256(package_path).await?;
    let registry_hash = fetch_package_hash_from_registry(&package_path).await?;
    
    if !constant_time_eq(calculated_hash.as_bytes(), registry_hash.as_bytes()) {
        return Ok(false);
    }
    
    // Verify digital signature if present
    if let Some(signature) = extract_package_signature(package_path)? {
        verify_package_signature(package_path, &signature)?;
    }
    
    Ok(true)
}

// ✅ Detect typosquatting
fn detect_typosquatting(package_name: &str) -> Result<Vec<TyposquattingWarning>> {
    let popular_packages = load_popular_package_list()?;
    let mut warnings = Vec::new();
    
    for popular in &popular_packages {
        let distance = edit_distance(package_name, popular);
        let similarity = 1.0 - (distance as f64 / popular.len().max(package_name.len()) as f64);
        
        if similarity > 0.8 && package_name != popular {
            warnings.push(TyposquattingWarning {
                suspicious_name: package_name.to_string(),
                similar_package: popular.to_string(),
                similarity_score: similarity,
            });
        }
    }
    
    Ok(warnings)
}
```

### threatflux-threat-detection

#### YARA Rule Security

```rust
use threatflux_threat_detection::{ThreatDetector, RuleConfig, SecurityConstraints};

let security_constraints = SecurityConstraints {
    // Prevent infinite loops in rules
    max_rule_complexity: 1000,
    rule_timeout: Duration::from_secs(30),
    
    // Memory limits
    max_memory_per_rule: 64 * 1024 * 1024,  // 64MB
    
    // Prevent ReDoS in rule patterns
    validate_regex_patterns: true,
    
    // Sandboxing
    enable_rule_sandboxing: true,
};

let config = RuleConfig::with_security_constraints(security_constraints);
```

## 🔍 Input Validation

### File Path Validation

```rust
use std::path::{Path, PathBuf, Component};

#[derive(Debug, Error)]
pub enum PathValidationError {
    #[error("Path traversal attempt detected")]
    PathTraversal,
    #[error("Invalid characters in path")]
    InvalidCharacters,
    #[error("Path too long")]
    PathTooLong,
    #[error("Unauthorized directory access")]
    UnauthorizedAccess,
}

pub struct PathValidator {
    allowed_roots: Vec<PathBuf>,
    max_path_length: usize,
    forbidden_names: HashSet<String>,
}

impl PathValidator {
    pub fn validate(&self, path: &Path) -> Result<PathBuf, PathValidationError> {
        // Check path length
        if path.as_os_str().len() > self.max_path_length {
            return Err(PathValidationError::PathTooLong);
        }
        
        // Check for path traversal
        for component in path.components() {
            match component {
                Component::ParentDir => return Err(PathValidationError::PathTraversal),
                Component::Normal(name) => {
                    let name_str = name.to_string_lossy();
                    
                    // Check for forbidden names
                    if self.forbidden_names.contains(&name_str.to_lowercase()) {
                        return Err(PathValidationError::InvalidCharacters);
                    }
                    
                    // Check for suspicious characters
                    if name_str.contains('\0') || name_str.contains('<') || name_str.contains('>') {
                        return Err(PathValidationError::InvalidCharacters);
                    }
                }
                _ => {}
            }
        }
        
        // Canonicalize and check against allowed roots
        let canonical = path.canonicalize()
            .map_err(|_| PathValidationError::UnauthorizedAccess)?;
            
        let authorized = self.allowed_roots.iter()
            .any(|root| canonical.starts_with(root));
            
        if !authorized {
            return Err(PathValidationError::UnauthorizedAccess);
        }
        
        Ok(canonical)
    }
}
```

### File Size and Content Validation

```rust
pub struct FileValidator {
    max_file_size: u64,
    allowed_mime_types: HashSet<String>,
    forbidden_extensions: HashSet<String>,
}

impl FileValidator {
    pub async fn validate_file(&self, path: &Path) -> Result<FileMetadata, ValidationError> {
        let metadata = tokio::fs::metadata(path).await?;
        
        // Check file size
        if metadata.len() > self.max_file_size {
            return Err(ValidationError::FileTooLarge {
                size: metadata.len(),
                limit: self.max_file_size,
            });
        }
        
        // Check file extension
        if let Some(extension) = path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            if self.forbidden_extensions.contains(&ext_str) {
                return Err(ValidationError::ForbiddenExtension(ext_str));
            }
        }
        
        // Validate MIME type
        let mime_type = detect_mime_type(path).await?;
        if !self.allowed_mime_types.is_empty() && !self.allowed_mime_types.contains(&mime_type) {
            return Err(ValidationError::InvalidMimeType(mime_type));
        }
        
        Ok(FileMetadata {
            size: metadata.len(),
            mime_type,
            validated: true,
        })
    }
}
```

## 🧠 Memory Safety

### Buffer Overflow Prevention

```rust
// ✅ Safe buffer operations
use std::convert::TryInto;

fn safe_read_u32(data: &[u8], offset: usize) -> Result<u32, ParseError> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)
        .ok_or(ParseError::BufferUnderflow)?
        .try_into()
        .map_err(|_| ParseError::InvalidFormat)?;
        
    Ok(u32::from_le_bytes(bytes))
}

fn safe_slice(data: &[u8], start: usize, len: usize) -> Result<&[u8], ParseError> {
    let end = start.checked_add(len)
        .ok_or(ParseError::IntegerOverflow)?;
        
    data.get(start..end)
        .ok_or(ParseError::BufferUnderflow)
}

// ❌ Unsafe operations
// let value = *(data.as_ptr().add(offset) as *const u32);  // Dangerous!
// let slice = &data[start..start + len];  // Can panic!
```

### Memory Limits

```rust
pub struct MemoryManager {
    max_allocation: usize,
    current_usage: AtomicUsize,
}

impl MemoryManager {
    pub fn allocate(&self, size: usize) -> Result<Vec<u8>, MemoryError> {
        let current = self.current_usage.load(Ordering::Relaxed);
        
        if current + size > self.max_allocation {
            return Err(MemoryError::AllocationLimitExceeded {
                requested: size,
                current: current,
                limit: self.max_allocation,
            });
        }
        
        let mut buffer = Vec::new();
        buffer.try_reserve(size)?;
        buffer.resize(size, 0);
        
        self.current_usage.fetch_add(size, Ordering::Relaxed);
        
        Ok(buffer)
    }
    
    pub fn deallocate(&self, size: usize) {
        self.current_usage.fetch_sub(size, Ordering::Relaxed);
    }
}
```

## 🏰 Process Isolation

### Privilege Dropping

```rust
use nix::unistd::{setuid, setgid, Uid, Gid};

pub struct PrivilegeManager;

impl PrivilegeManager {
    pub fn drop_privileges() -> Result<(), SecurityError> {
        // Get nobody user/group IDs
        let nobody_uid = Uid::from_raw(65534);
        let nobody_gid = Gid::from_raw(65534);
        
        // Drop group privileges first
        setgid(nobody_gid)?;
        
        // Drop user privileges
        setuid(nobody_uid)?;
        
        // Verify privileges were dropped
        if !nix::unistd::getuid().is_root() {
            Ok(())
        } else {
            Err(SecurityError::PrivilegeDropFailed)
        }
    }
}
```

### Resource Limits

```rust
use rlimit::{Resource, setrlimit};

pub fn set_security_limits() -> Result<(), SecurityError> {
    // Limit memory usage (1GB)
    setrlimit(Resource::RLIMIT_AS, 1024 * 1024 * 1024, 1024 * 1024 * 1024)?;
    
    // Limit CPU time (5 minutes)
    setrlimit(Resource::RLIMIT_CPU, 300, 300)?;
    
    // Limit file descriptors
    setrlimit(Resource::RLIMIT_NOFILE, 1024, 1024)?;
    
    // Limit number of processes
    setrlimit(Resource::RLIMIT_NPROC, 10, 10)?;
    
    Ok(())
}
```

### Sandboxing

```rust
#[cfg(target_os = "linux")]
pub mod sandbox {
    use seccomp::*;
    
    pub fn enable_seccomp() -> Result<(), SecurityError> {
        let mut ctx = ScmpFilterCtx::new_filter(ScmpAction::KillProcess)?;
        
        // Allow essential system calls
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("read"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("write"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("openat"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("close"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("mmap"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("munmap"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("brk"))?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::new("exit_group"))?;
        
        // Block dangerous system calls
        ctx.add_rule(ScmpAction::KillProcess, ScmpSyscall::new("execve"))?;
        ctx.add_rule(ScmpAction::KillProcess, ScmpSyscall::new("fork"))?;
        ctx.add_rule(ScmpAction::KillProcess, ScmpSyscall::new("clone"))?;
        ctx.add_rule(ScmpAction::KillProcess, ScmpSyscall::new("ptrace"))?;
        
        ctx.load()?;
        Ok(())
    }
}
```

## 🌐 Network Security

### TLS Configuration

```rust
use rustls::{ClientConfig, ServerConfig, Certificate, PrivateKey};
use rustls_pemfile;

pub fn create_secure_client_config() -> Result<ClientConfig, TlsError> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(load_ca_certificates()?)
        .with_no_client_auth();
        
    // Enable only secure cipher suites
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    
    Ok(config)
}

pub fn create_secure_server_config(
    cert_chain: Vec<Certificate>,
    private_key: PrivateKey,
) -> Result<ServerConfig, TlsError> {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;
        
    Ok(config)
}
```

### HTTP Security Headers

```rust
use axum::{
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
    extract::Request,
};

pub async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    
    // Prevent XSS attacks
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    
    // Prevent clickjacking
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    
    // Enable XSS protection
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );
    
    // Content Security Policy
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"),
    );
    
    // HSTS
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    
    response
}
```

### API Rate Limiting

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }
    
    pub fn check_rate_limit(&self, client_id: &str) -> Result<(), RateLimitError> {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let client_requests = requests.entry(client_id.to_string()).or_default();
        
        // Remove old requests outside the window
        client_requests.retain(|&time| now.duration_since(time) < self.window);
        
        if client_requests.len() >= self.max_requests {
            return Err(RateLimitError::RateLimitExceeded {
                limit: self.max_requests,
                window: self.window,
            });
        }
        
        client_requests.push(now);
        Ok(())
    }
}
```

## 🔐 Authentication & Authorization

### API Key Management

```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};

pub struct ApiKeyManager {
    keys: HashMap<String, HashedApiKey>,
}

#[derive(Clone)]
pub struct HashedApiKey {
    hash: String,
    permissions: Vec<Permission>,
    expires_at: Option<SystemTime>,
}

impl ApiKeyManager {
    pub fn hash_api_key(key: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2.hash_password(key.as_bytes(), &salt)?;
        Ok(password_hash.to_string())
    }
    
    pub fn verify_api_key(&self, key: &str, key_id: &str) -> Result<Vec<Permission>, AuthError> {
        let stored_key = self.keys.get(key_id)
            .ok_or(AuthError::InvalidApiKey)?;
            
        // Check expiration
        if let Some(expires_at) = stored_key.expires_at {
            if SystemTime::now() > expires_at {
                return Err(AuthError::ExpiredApiKey);
            }
        }
        
        // Verify hash
        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&stored_key.hash)?;
        
        argon2.verify_password(key.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidApiKey)?;
            
        Ok(stored_key.permissions.clone())
    }
}
```

### Permission System

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum Permission {
    ReadFiles,
    AnalyzeFiles,
    AccessCache,
    ManageUsers,
    ViewLogs,
}

#[derive(Debug, Clone)]
pub struct AccessControl {
    user_permissions: HashMap<String, Vec<Permission>>,
}

impl AccessControl {
    pub fn check_permission(&self, user_id: &str, required: Permission) -> Result<(), AuthError> {
        let user_perms = self.user_permissions.get(user_id)
            .ok_or(AuthError::UserNotFound)?;
            
        if user_perms.contains(&required) {
            Ok(())
        } else {
            Err(AuthError::InsufficientPermissions)
        }
    }
    
    pub fn require_permissions(&self, user_id: &str, required: &[Permission]) -> Result<(), AuthError> {
        for permission in required {
            self.check_permission(user_id, permission.clone())?;
        }
        Ok(())
    }
}
```

## 🔢 Cryptographic Security

### Secure Random Number Generation

```rust
use rand::{rngs::OsRng, RngCore};
use ring::rand::{SecureRandom, SystemRandom};

pub struct SecureRng {
    rng: SystemRandom,
}

impl SecureRng {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
    
    pub fn generate_bytes(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = vec![0u8; len];
        self.rng.fill(&mut bytes)?;
        Ok(bytes)
    }
    
    pub fn generate_api_key(&self) -> Result<String, CryptoError> {
        let bytes = self.generate_bytes(32)?;
        Ok(base64::encode(bytes))
    }
}
```

### Constant-Time Comparisons

```rust
use subtle::ConstantTimeEq;

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

pub fn verify_hash_constant_time(calculated: &str, expected: &str) -> bool {
    constant_time_eq(calculated.as_bytes(), expected.as_bytes())
}
```

### Key Derivation

```rust
use ring::{pbkdf2, digest};

pub fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>, CryptoError> {
    let mut key = vec![0u8; 32];
    
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );
    
    Ok(key)
}
```

## 🚀 Deployment Security

### Container Security

This Debian slim example runs as a nonroot user but is not the published runtime;
the repository `Dockerfile` ships a distroless Debian 13 image that runs as uid
65532 with no shell or package manager.

```dockerfile
# Use minimal base image
FROM debian:trixie-slim

# Create non-root user
RUN groupadd -r threatflux && useradd -r -g threatflux threatflux

# Install security updates only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY --chown=threatflux:threatflux target/release/file-scanner /usr/local/bin/

# Set secure permissions
RUN chmod 755 /usr/local/bin/file-scanner

# Switch to non-root user
USER threatflux

# Set security options
ENTRYPOINT ["/usr/local/bin/file-scanner"]
```

### Kubernetes Security

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: threatflux-analyzer
  annotations:
    container.apparmor.security.beta.kubernetes.io/analyzer: runtime/default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: analyzer
    image: threatflux/file-scanner:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        memory: "2Gi"
        cpu: "2"
      requests:
        memory: "1Gi"
        cpu: "1"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache/threatflux
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    persistentVolumeClaim:
      claimName: threatflux-cache-pvc
```

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: threatflux-network-policy
spec:
  podSelector:
    matchLabels:
      app: threatflux
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: threatflux-clients
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS only
  - to: []
    ports:
    - protocol: TCP
      port: 53   # DNS
  - to: []
    ports:
    - protocol: UDP
      port: 53   # DNS
```

## 🚨 Incident Response

### Security Logging

```rust
use tracing::{info, warn, error, instrument};
use serde_json::json;

#[derive(Debug)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: Severity,
    pub user_id: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub details: serde_json::Value,
    pub timestamp: SystemTime,
}

#[derive(Debug)]
pub enum SecurityEventType {
    AuthenticationFailure,
    AuthorizationFailure,
    RateLimitExceeded,
    SuspiciousFileDetected,
    PathTraversalAttempt,
    InvalidInput,
    ResourceLimitExceeded,
}

pub struct SecurityLogger;

impl SecurityLogger {
    #[instrument(skip(event))]
    pub fn log_security_event(event: SecurityEvent) {
        let log_entry = json!({
            "event_type": format!("{:?}", event.event_type),
            "severity": format!("{:?}", event.severity),
            "user_id": event.user_id,
            "client_ip": event.client_ip.map(|ip| ip.to_string()),
            "details": event.details,
            "timestamp": event.timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        match event.severity {
            Severity::Critical | Severity::High => error!("Security event: {}", log_entry),
            Severity::Medium => warn!("Security event: {}", log_entry),
            Severity::Low => info!("Security event: {}", log_entry),
        }
    }
}
```

### Alerting System

```rust
pub struct AlertManager {
    channels: Vec<AlertChannel>,
}

pub enum AlertChannel {
    Email(EmailConfig),
    Slack(SlackConfig),
    Webhook(WebhookConfig),
}

impl AlertManager {
    pub async fn send_security_alert(&self, event: &SecurityEvent) -> Result<(), AlertError> {
        // Only alert on high-severity events
        if !matches!(event.severity, Severity::Critical | Severity::High) {
            return Ok(());
        }
        
        let alert_message = format!(
            "Security Alert: {:?} - {} at {}",
            event.event_type,
            event.details,
            event.timestamp.duration_since(SystemTime::UNIX_EPOCH)?.as_secs()
        );
        
        for channel in &self.channels {
            if let Err(e) = self.send_to_channel(channel, &alert_message).await {
                error!("Failed to send alert to channel: {}", e);
            }
        }
        
        Ok(())
    }
}
```

### Emergency Response

```rust
pub struct EmergencyResponse {
    shutdown_channels: Vec<tokio::sync::oneshot::Sender<()>>,
}

impl EmergencyResponse {
    pub async fn emergency_shutdown(&mut self, reason: &str) {
        error!("Emergency shutdown initiated: {}", reason);
        
        // Send shutdown signals to all components
        for sender in self.shutdown_channels.drain(..) {
            let _ = sender.send(());
        }
        
        // Log the emergency shutdown
        SecurityLogger::log_security_event(SecurityEvent {
            event_type: SecurityEventType::EmergencyShutdown,
            severity: Severity::Critical,
            user_id: None,
            client_ip: None,
            details: json!({"reason": reason}),
            timestamp: SystemTime::now(),
        });
    }
}
```

## 📋 Security Checklist

### Development Security
- [ ] Use `cargo audit` to check for vulnerable dependencies
- [ ] Enable all Clippy lints for security patterns
- [ ] Use `cargo deny` for license and dependency management
- [ ] Implement comprehensive input validation
- [ ] Use secure random number generation
- [ ] Implement constant-time comparisons for sensitive data
- [ ] Use memory-safe APIs and avoid `unsafe` code
- [ ] Set appropriate resource limits

### Testing Security
- [ ] Implement security-focused unit tests
- [ ] Perform fuzz testing on parsers
- [ ] Test with malicious input files
- [ ] Verify error handling doesn't leak sensitive information
- [ ] Test authentication and authorization systems
- [ ] Perform penetration testing
- [ ] Validate TLS configuration

### Deployment Security
- [ ] Use minimal container images
- [ ] Run containers as non-root users
- [ ] Enable security contexts and AppArmor/SELinux
- [ ] Implement network policies
- [ ] Use secrets management for sensitive data
- [ ] Enable comprehensive logging and monitoring
- [ ] Set up alerting for security events
- [ ] Implement backup and disaster recovery
- [ ] Regular security updates and patches

### Operational Security
- [ ] Monitor for suspicious activities
- [ ] Regularly rotate API keys and certificates
- [ ] Perform security audits
- [ ] Maintain incident response procedures
- [ ] Keep security documentation up to date
- [ ] Train team members on security best practices
- [ ] Implement principle of least privilege
- [ ] Regular vulnerability assessments

Remember: **Security is an ongoing process, not a one-time setup**. Regularly review and update your security posture as threats evolve.