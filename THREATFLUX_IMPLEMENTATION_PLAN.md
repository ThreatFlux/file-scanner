# ThreatFlux Threat Detection Library - Implementation Plan

## Project Structure

```
threatflux-threat-detection/
├── Cargo.toml
├── README.md
├── LICENSE
├── examples/
│   ├── simple_scan.rs
│   ├── batch_scan.rs
│   ├── custom_rules.rs
│   └── integration.rs
├── benches/
│   ├── scanning.rs
│   └── rule_compilation.rs
├── src/
│   ├── lib.rs
│   ├── core/
│   │   ├── mod.rs
│   │   ├── engine.rs         # Detection engine traits
│   │   ├── rule.rs           # Rule abstractions
│   │   ├── scanner.rs        # Core scanner implementation
│   │   └── result.rs         # Result types
│   ├── engines/
│   │   ├── mod.rs
│   │   ├── yara/
│   │   │   ├── mod.rs
│   │   │   ├── engine.rs     # YARA engine implementation
│   │   │   ├── compiler.rs   # YARA rule compiler
│   │   │   └── rules.rs      # Built-in YARA rules
│   │   ├── pattern/
│   │   │   ├── mod.rs
│   │   │   ├── engine.rs     # Pattern matching engine
│   │   │   ├── matcher.rs    # Aho-Corasick implementation
│   │   │   └── patterns.rs   # Pattern definitions
│   │   └── behavioral/
│   │       ├── mod.rs
│   │       ├── engine.rs     # Behavioral analysis engine
│   │       └── analyzers.rs  # Behavior analyzers
│   ├── categorization/
│   │   ├── mod.rs
│   │   ├── classifier.rs     # Threat classifier
│   │   ├── mitre.rs         # MITRE ATT&CK mapping
│   │   └── scoring.rs       # Threat scoring engine
│   ├── rules/
│   │   ├── mod.rs
│   │   ├── manager.rs       # Rule management
│   │   ├── repository.rs    # Rule repository traits
│   │   ├── updater.rs       # Rule update mechanism
│   │   └── validator.rs     # Rule validation
│   ├── optimization/
│   │   ├── mod.rs
│   │   ├── cache.rs         # Caching implementation
│   │   ├── parallel.rs      # Parallel scanning
│   │   └── memory.rs        # Memory optimization
│   ├── intelligence/
│   │   ├── mod.rs
│   │   ├── feeds.rs         # Threat intelligence feeds
│   │   └── enrichment.rs    # Detection enrichment
│   └── utils/
│       ├── mod.rs
│       ├── error.rs         # Error types
│       ├── config.rs        # Configuration
│       └── metrics.rs       # Performance metrics
└── tests/
    ├── integration/
    │   ├── yara_tests.rs
    │   ├── pattern_tests.rs
    │   └── behavioral_tests.rs
    └── samples/
        ├── malware/
        └── clean/
```

## Core Implementation

### 1. Engine Trait System (src/core/engine.rs)

```rust
use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

/// Core trait for all detection engines
#[async_trait]
pub trait DetectionEngine: Send + Sync {
    /// Unique identifier for the engine
    fn id(&self) -> &str;
    
    /// Human-readable name
    fn name(&self) -> &str;
    
    /// Engine version
    fn version(&self) -> &str;
    
    /// Scan raw data
    async fn scan_data(&self, data: &[u8]) -> Result<ScanResult>;
    
    /// Scan a file
    async fn scan_file(&self, path: &Path) -> Result<ScanResult>;
    
    /// Scan with context (for correlation)
    async fn scan_with_context(
        &self, 
        data: &[u8], 
        context: &ScanContext
    ) -> Result<ScanResult> {
        // Default implementation ignores context
        self.scan_data(data).await
    }
    
    /// Get engine capabilities
    fn capabilities(&self) -> EngineCapabilities;
    
    /// Update engine rules/patterns
    async fn update(&mut self) -> Result<UpdateResult>;
}

/// Engine capabilities
#[derive(Debug, Clone)]
pub struct EngineCapabilities {
    pub supports_streaming: bool,
    pub supports_memory_scan: bool,
    pub supports_file_scan: bool,
    pub supports_network_scan: bool,
    pub max_scan_size: Option<u64>,
    pub supported_formats: Vec<String>,
}

/// Scan context for correlation
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub file_path: Option<PathBuf>,
    pub process_info: Option<ProcessInfo>,
    pub network_info: Option<NetworkInfo>,
    pub parent_scan_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Scan result from an engine
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub engine_id: String,
    pub detections: Vec<Detection>,
    pub scan_time: Duration,
    pub bytes_scanned: u64,
    pub errors: Vec<ScanError>,
}

/// Individual detection
#[derive(Debug, Clone)]
pub struct Detection {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: f32,
    pub category: ThreatCategory,
    pub offsets: Vec<u64>,
    pub matched_data: Option<Vec<u8>>,
    pub metadata: HashMap<String, String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}
```

### 2. YARA Engine Implementation (src/engines/yara/engine.rs)

```rust
use crate::core::{DetectionEngine, ScanResult, EngineCapabilities};
use yara_x::{Compiler, Rules, Scanner};
use std::sync::RwLock;

pub struct YaraEngine {
    id: String,
    rules: Arc<RwLock<Rules>>,
    config: YaraConfig,
    rule_sources: Vec<RuleSource>,
}

impl YaraEngine {
    pub fn new(config: YaraConfig) -> Result<Self> {
        let mut compiler = Compiler::new();
        
        // Load built-in rules
        for rule in get_builtin_rules() {
            compiler.add_source(rule)?;
        }
        
        let rules = Arc::new(RwLock::new(compiler.build()));
        
        Ok(Self {
            id: "yara".to_string(),
            rules,
            config,
            rule_sources: vec![],
        })
    }
    
    pub fn add_rule_source(&mut self, source: RuleSource) {
        self.rule_sources.push(source);
    }
    
    fn compile_rules(&self, sources: &[String]) -> Result<Rules> {
        let mut compiler = Compiler::new();
        
        for source in sources {
            compiler.add_source(source)?;
        }
        
        Ok(compiler.build())
    }
}

#[async_trait]
impl DetectionEngine for YaraEngine {
    fn id(&self) -> &str {
        &self.id
    }
    
    fn name(&self) -> &str {
        "YARA Detection Engine"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    async fn scan_data(&self, data: &[u8]) -> Result<ScanResult> {
        let start = Instant::now();
        let rules = self.rules.read().unwrap();
        
        let mut scanner = Scanner::new(&*rules);
        if let Some(timeout) = self.config.timeout {
            scanner.set_timeout(timeout);
        }
        
        let scan_results = scanner.scan(data)?;
        let detections = self.process_yara_results(scan_results)?;
        
        Ok(ScanResult {
            engine_id: self.id.clone(),
            detections,
            scan_time: start.elapsed(),
            bytes_scanned: data.len() as u64,
            errors: vec![],
        })
    }
    
    async fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        if self.config.use_memory_map {
            // Memory-mapped file scanning
            let file = File::open(path)?;
            let mmap = unsafe { MmapOptions::new().map(&file)? };
            self.scan_data(&mmap).await
        } else {
            // Regular file reading
            let data = tokio::fs::read(path).await?;
            self.scan_data(&data).await
        }
    }
    
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            supports_streaming: false,
            supports_memory_scan: true,
            supports_file_scan: true,
            supports_network_scan: false,
            max_scan_size: self.config.max_scan_size,
            supported_formats: vec!["*".to_string()],
        }
    }
    
    async fn update(&mut self) -> Result<UpdateResult> {
        let mut new_rules = Vec::new();
        let mut updated = 0;
        let mut failed = 0;
        
        for source in &self.rule_sources {
            match source.fetch_rules().await {
                Ok(rules) => {
                    new_rules.extend(rules);
                    updated += 1;
                }
                Err(e) => {
                    eprintln!("Failed to fetch rules from {:?}: {}", source, e);
                    failed += 1;
                }
            }
        }
        
        if !new_rules.is_empty() {
            let compiled = self.compile_rules(&new_rules)?;
            *self.rules.write().unwrap() = compiled;
        }
        
        Ok(UpdateResult {
            updated_count: new_rules.len(),
            sources_updated: updated,
            sources_failed: failed,
        })
    }
}
```

### 3. Pattern Matching Engine (src/engines/pattern/engine.rs)

```rust
use crate::core::{DetectionEngine, ScanResult};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::bytes::RegexSet;

pub struct PatternEngine {
    id: String,
    exact_matcher: AhoCorasick,
    regex_matcher: RegexSet,
    fuzzy_patterns: Vec<FuzzyPattern>,
    entropy_analyzer: EntropyAnalyzer,
    config: PatternConfig,
}

impl PatternEngine {
    pub fn new(config: PatternConfig) -> Result<Self> {
        let patterns = load_patterns(&config.pattern_file)?;
        
        // Build exact pattern matcher
        let exact_patterns: Vec<&[u8]> = patterns
            .iter()
            .filter_map(|p| match p {
                Pattern::Exact(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        
        let exact_matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(exact_patterns)?;
        
        // Build regex matcher
        let regex_patterns: Vec<String> = patterns
            .iter()
            .filter_map(|p| match p {
                Pattern::Regex(pattern) => Some(pattern.clone()),
                _ => None,
            })
            .collect();
        
        let regex_matcher = RegexSet::new(regex_patterns)?;
        
        // Collect fuzzy patterns
        let fuzzy_patterns: Vec<FuzzyPattern> = patterns
            .iter()
            .filter_map(|p| match p {
                Pattern::Fuzzy { pattern, distance } => Some(FuzzyPattern {
                    pattern: pattern.clone(),
                    max_distance: *distance,
                }),
                _ => None,
            })
            .collect();
        
        Ok(Self {
            id: "pattern".to_string(),
            exact_matcher,
            regex_matcher,
            fuzzy_patterns,
            entropy_analyzer: EntropyAnalyzer::new(),
            config,
        })
    }
}

#[async_trait]
impl DetectionEngine for PatternEngine {
    async fn scan_data(&self, data: &[u8]) -> Result<ScanResult> {
        let start = Instant::now();
        let mut detections = Vec::new();
        
        // Exact pattern matching
        for mat in self.exact_matcher.find_iter(data) {
            detections.push(Detection {
                rule_id: format!("exact_{}", mat.pattern()),
                rule_name: format!("Exact Pattern {}", mat.pattern()),
                severity: Severity::Medium,
                confidence: 1.0,
                category: ThreatCategory::Suspicious,
                offsets: vec![mat.start() as u64],
                matched_data: Some(data[mat.range()].to_vec()),
                metadata: HashMap::new(),
                mitre_tactics: vec![],
                mitre_techniques: vec![],
            });
        }
        
        // Regex pattern matching
        let regex_matches = self.regex_matcher.matches(data);
        for (idx, _) in regex_matches.iter().enumerate() {
            detections.push(Detection {
                rule_id: format!("regex_{}", idx),
                rule_name: format!("Regex Pattern {}", idx),
                severity: Severity::Medium,
                confidence: 0.9,
                category: ThreatCategory::Suspicious,
                offsets: vec![],
                matched_data: None,
                metadata: HashMap::new(),
                mitre_tactics: vec![],
                mitre_techniques: vec![],
            });
        }
        
        // Fuzzy pattern matching
        for (idx, fuzzy) in self.fuzzy_patterns.iter().enumerate() {
            if let Some(offset) = fuzzy.find_in(data) {
                detections.push(Detection {
                    rule_id: format!("fuzzy_{}", idx),
                    rule_name: format!("Fuzzy Pattern {}", idx),
                    severity: Severity::Low,
                    confidence: 0.7,
                    category: ThreatCategory::Suspicious,
                    offsets: vec![offset],
                    matched_data: None,
                    metadata: HashMap::new(),
                    mitre_tactics: vec![],
                    mitre_techniques: vec![],
                });
            }
        }
        
        // Entropy analysis
        if let Some(high_entropy_regions) = self.entropy_analyzer.analyze(data) {
            for region in high_entropy_regions {
                detections.push(Detection {
                    rule_id: "high_entropy".to_string(),
                    rule_name: "High Entropy Region".to_string(),
                    severity: Severity::Low,
                    confidence: 0.6,
                    category: ThreatCategory::Obfuscation,
                    offsets: vec![region.offset],
                    matched_data: None,
                    metadata: hashmap! {
                        "entropy".to_string() => region.entropy.to_string(),
                        "size".to_string() => region.size.to_string(),
                    },
                    mitre_tactics: vec!["TA0005".to_string()], // Defense Evasion
                    mitre_techniques: vec!["T1027".to_string()], // Obfuscated Files
                });
            }
        }
        
        Ok(ScanResult {
            engine_id: self.id.clone(),
            detections,
            scan_time: start.elapsed(),
            bytes_scanned: data.len() as u64,
            errors: vec![],
        })
    }
}
```

### 4. Rule Management System (src/rules/manager.rs)

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct RuleManager {
    rules: Arc<RwLock<HashMap<String, Rule>>>,
    repositories: Vec<Box<dyn RuleRepository>>,
    validator: RuleValidator,
    update_policy: UpdatePolicy,
    last_update: Arc<RwLock<Option<Instant>>>,
}

impl RuleManager {
    pub fn new(update_policy: UpdatePolicy) -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            repositories: Vec::new(),
            validator: RuleValidator::new(),
            update_policy,
            last_update: Arc::new(RwLock::new(None)),
        }
    }
    
    pub async fn add_repository(&mut self, repo: Box<dyn RuleRepository>) -> Result<()> {
        // Validate repository
        repo.validate().await?;
        self.repositories.push(repo);
        Ok(())
    }
    
    pub async fn update_rules(&self) -> Result<UpdateResult> {
        let mut total_added = 0;
        let mut total_updated = 0;
        let mut total_removed = 0;
        let mut errors = Vec::new();
        
        for repo in &self.repositories {
            match repo.fetch_rules().await {
                Ok(fetched_rules) => {
                    let mut rules = self.rules.write().await;
                    
                    for rule in fetched_rules {
                        // Validate rule
                        if let Err(e) = self.validator.validate(&rule) {
                            errors.push(format!("Invalid rule {}: {}", rule.id, e));
                            continue;
                        }
                        
                        // Add or update rule
                        if rules.contains_key(&rule.id) {
                            total_updated += 1;
                        } else {
                            total_added += 1;
                        }
                        rules.insert(rule.id.clone(), rule);
                    }
                }
                Err(e) => {
                    errors.push(format!("Failed to fetch from {}: {}", repo.name(), e));
                }
            }
        }
        
        // Update timestamp
        *self.last_update.write().await = Some(Instant::now());
        
        Ok(UpdateResult {
            added: total_added,
            updated: total_updated,
            removed: total_removed,
            errors,
        })
    }
    
    pub async fn get_rules_for_engine(&self, engine_id: &str) -> Vec<Rule> {
        let rules = self.rules.read().await;
        rules
            .values()
            .filter(|rule| rule.engine_id == engine_id)
            .cloned()
            .collect()
    }
    
    pub async fn should_update(&self) -> bool {
        match &self.update_policy {
            UpdatePolicy::Manual => false,
            UpdatePolicy::Automatic { interval } => {
                let last = self.last_update.read().await;
                match *last {
                    Some(timestamp) => timestamp.elapsed() > *interval,
                    None => true,
                }
            }
            UpdatePolicy::OnDemand => false,
        }
    }
}

/// Rule repository implementations
pub struct GitHubRepository {
    owner: String,
    repo: String,
    branch: String,
    path: String,
    client: reqwest::Client,
}

#[async_trait]
impl RuleRepository for GitHubRepository {
    async fn fetch_rules(&self) -> Result<Vec<Rule>> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
            self.owner, self.repo, self.path, self.branch
        );
        
        let response = self.client
            .get(&url)
            .header("User-Agent", "ThreatFlux")
            .send()
            .await?;
        
        let files: Vec<GitHubFile> = response.json().await?;
        let mut rules = Vec::new();
        
        for file in files {
            if file.name.ends_with(".yar") || file.name.ends_with(".yara") {
                let content = self.fetch_file_content(&file.download_url).await?;
                let parsed_rules = parse_yara_rules(&content)?;
                rules.extend(parsed_rules);
            }
        }
        
        Ok(rules)
    }
    
    fn name(&self) -> &str {
        "GitHub Repository"
    }
    
    async fn validate(&self) -> Result<()> {
        // Check if repository exists and is accessible
        let url = format!(
            "https://api.github.com/repos/{}/{}",
            self.owner, self.repo
        );
        
        let response = self.client
            .get(&url)
            .header("User-Agent", "ThreatFlux")
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Repository not accessible"));
        }
        
        Ok(())
    }
}
```

### 5. Threat Categorization (src/categorization/classifier.rs)

```rust
use crate::core::{Detection, ThreatCategory};

pub struct ThreatClassifier {
    classifiers: Vec<Box<dyn Classifier>>,
    scoring_engine: ScoringEngine,
    mitre_mapper: MitreMapper,
}

impl ThreatClassifier {
    pub fn new() -> Self {
        Self {
            classifiers: vec![
                Box::new(RansomwareClassifier::new()),
                Box::new(TrojanClassifier::new()),
                Box::new(CryptominerClassifier::new()),
                Box::new(InfostealerClassifier::new()),
                Box::new(BackdoorClassifier::new()),
            ],
            scoring_engine: ScoringEngine::new(),
            mitre_mapper: MitreMapper::new(),
        }
    }
    
    pub fn classify(&self, detections: &[Detection]) -> ThreatClassification {
        let mut classifications = Vec::new();
        let mut total_confidence = 0.0;
        
        // Run each classifier
        for classifier in &self.classifiers {
            if let Some(classification) = classifier.classify(detections) {
                total_confidence += classification.confidence;
                classifications.push(classification);
            }
        }
        
        // Determine primary category
        let primary_category = classifications
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
            .map(|c| c.category.clone())
            .unwrap_or(ThreatCategory::Unknown);
        
        // Calculate overall threat score
        let threat_score = self.scoring_engine.calculate_score(detections, &classifications);
        
        // Map to MITRE ATT&CK
        let (tactics, techniques) = self.mitre_mapper.map_detections(detections);
        
        ThreatClassification {
            primary_category,
            sub_categories: classifications.into_iter().map(|c| c.category).collect(),
            confidence: total_confidence / self.classifiers.len() as f32,
            threat_score,
            severity: self.determine_severity(threat_score),
            mitre_tactics: tactics,
            mitre_techniques: techniques,
        }
    }
    
    fn determine_severity(&self, score: f32) -> Severity {
        match score {
            s if s >= 0.9 => Severity::Critical,
            s if s >= 0.7 => Severity::High,
            s if s >= 0.4 => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

/// Specific threat classifiers
pub struct RansomwareClassifier {
    indicators: Vec<String>,
    weights: HashMap<String, f32>,
}

impl RansomwareClassifier {
    pub fn new() -> Self {
        Self {
            indicators: vec![
                "encryption".to_string(),
                "bitcoin".to_string(),
                "ransom".to_string(),
                "decrypt".to_string(),
                ".locked".to_string(),
                "payment".to_string(),
            ],
            weights: HashMap::from([
                ("encryption".to_string(), 0.8),
                ("bitcoin".to_string(), 0.9),
                ("ransom".to_string(), 1.0),
                ("decrypt".to_string(), 0.7),
                (".locked".to_string(), 0.8),
                ("payment".to_string(), 0.6),
            ]),
        }
    }
}

impl Classifier for RansomwareClassifier {
    fn classify(&self, detections: &[Detection]) -> Option<ClassificationResult> {
        let mut score = 0.0;
        let mut matched_indicators = 0;
        
        for detection in detections {
            for indicator in &self.indicators {
                if detection.rule_name.to_lowercase().contains(indicator) ||
                   detection.metadata.values().any(|v| v.to_lowercase().contains(indicator)) {
                    score += self.weights.get(indicator).unwrap_or(&0.5);
                    matched_indicators += 1;
                }
            }
        }
        
        if matched_indicators >= 2 {
            Some(ClassificationResult {
                category: ThreatCategory::Ransomware,
                confidence: (score / matched_indicators as f32).min(1.0),
                evidence: format!("Matched {} ransomware indicators", matched_indicators),
            })
        } else {
            None
        }
    }
}
```

### 6. Performance Optimization (src/optimization/parallel.rs)

```rust
use rayon::prelude::*;
use tokio::task::JoinSet;
use std::sync::Arc;

pub struct ParallelScanner {
    engines: Vec<Arc<dyn DetectionEngine>>,
    strategy: ParallelStrategy,
    thread_pool: Option<rayon::ThreadPool>,
}

#[derive(Clone)]
pub enum ParallelStrategy {
    Sequential,
    ThreadPool { max_threads: usize },
    Async { max_concurrent: usize },
    WorkStealing,
}

impl ParallelScanner {
    pub fn new(engines: Vec<Arc<dyn DetectionEngine>>, strategy: ParallelStrategy) -> Self {
        let thread_pool = match &strategy {
            ParallelStrategy::ThreadPool { max_threads } => {
                Some(rayon::ThreadPoolBuilder::new()
                    .num_threads(*max_threads)
                    .build()
                    .unwrap())
            }
            _ => None,
        };
        
        Self {
            engines,
            strategy,
            thread_pool,
        }
    }
    
    pub async fn scan_files(&self, files: Vec<PathBuf>) -> Result<Vec<FileScanResult>> {
        match &self.strategy {
            ParallelStrategy::Sequential => self.scan_sequential(files).await,
            ParallelStrategy::ThreadPool { .. } => self.scan_thread_pool(files).await,
            ParallelStrategy::Async { max_concurrent } => {
                self.scan_async(files, *max_concurrent).await
            }
            ParallelStrategy::WorkStealing => self.scan_work_stealing(files).await,
        }
    }
    
    async fn scan_sequential(&self, files: Vec<PathBuf>) -> Result<Vec<FileScanResult>> {
        let mut results = Vec::new();
        
        for file in files {
            let result = self.scan_single_file(&file).await?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    async fn scan_thread_pool(&self, files: Vec<PathBuf>) -> Result<Vec<FileScanResult>> {
        let scanner = Arc::new(self.clone());
        let pool = self.thread_pool.as_ref().unwrap();
        
        let results: Vec<_> = pool.install(|| {
            files
                .into_par_iter()
                .map(|file| {
                    tokio::runtime::Handle::current()
                        .block_on(scanner.scan_single_file(&file))
                })
                .collect()
        });
        
        results.into_iter().collect()
    }
    
    async fn scan_async(
        &self,
        files: Vec<PathBuf>,
        max_concurrent: usize,
    ) -> Result<Vec<FileScanResult>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        let mut join_set = JoinSet::new();
        
        for file in files {
            let scanner = self.clone();
            let permit = semaphore.clone().acquire_owned().await?;
            
            join_set.spawn(async move {
                let result = scanner.scan_single_file(&file).await;
                drop(permit);
                result
            });
        }
        
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result??);
        }
        
        Ok(results)
    }
    
    async fn scan_single_file(&self, file: &Path) -> Result<FileScanResult> {
        let mut all_detections = Vec::new();
        let mut engine_results = HashMap::new();
        
        for engine in &self.engines {
            match engine.scan_file(file).await {
                Ok(result) => {
                    all_detections.extend(result.detections.clone());
                    engine_results.insert(engine.id().to_string(), result);
                }
                Err(e) => {
                    eprintln!("Engine {} failed on {}: {}", engine.id(), file.display(), e);
                }
            }
        }
        
        Ok(FileScanResult {
            file_path: file.to_path_buf(),
            engine_results,
            combined_detections: all_detections,
            scan_time: Instant::now().elapsed(),
        })
    }
}
```

### 7. Cache Implementation (src/optimization/cache.rs)

```rust
use lru::LruCache;
use std::num::NonZeroUsize;
use blake3::Hasher;

pub struct ScanCache {
    file_cache: Arc<Mutex<LruCache<FileHash, CachedResult>>>,
    string_cache: Arc<Mutex<StringCache>>,
    rule_cache: Arc<RwLock<RuleCache>>,
    config: CacheConfig,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct FileHash([u8; 32]);

impl FileHash {
    pub fn from_file(path: &Path) -> Result<Self> {
        let mut hasher = Hasher::new();
        let mut file = File::open(path)?;
        let mut buffer = vec![0; 8192];
        
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        
        Ok(FileHash(*hasher.finalize().as_bytes()))
    }
}

#[derive(Clone)]
pub struct CachedResult {
    pub result: ScanResult,
    pub timestamp: Instant,
    pub file_size: u64,
}

impl ScanCache {
    pub fn new(config: CacheConfig) -> Self {
        let file_cache = LruCache::new(
            NonZeroUsize::new(config.max_file_entries).unwrap()
        );
        
        Self {
            file_cache: Arc::new(Mutex::new(file_cache)),
            string_cache: Arc::new(Mutex::new(StringCache::new())),
            rule_cache: Arc::new(RwLock::new(RuleCache::new())),
            config,
        }
    }
    
    pub async fn get_or_scan<F, Fut>(
        &self,
        path: &Path,
        scan_fn: F,
    ) -> Result<ScanResult>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<ScanResult>>,
    {
        // Calculate file hash
        let hash = FileHash::from_file(path)?;
        let metadata = tokio::fs::metadata(path).await?;
        
        // Check cache
        {
            let mut cache = self.file_cache.lock().unwrap();
            if let Some(cached) = cache.get(&hash) {
                // Validate cache entry
                if cached.file_size == metadata.len() &&
                   cached.timestamp.elapsed() < self.config.max_age {
                    return Ok(cached.result.clone());
                }
            }
        }
        
        // Perform scan
        let result = scan_fn().await?;
        
        // Update cache
        {
            let mut cache = self.file_cache.lock().unwrap();
            cache.put(hash, CachedResult {
                result: result.clone(),
                timestamp: Instant::now(),
                file_size: metadata.len(),
            });
        }
        
        Ok(result)
    }
    
    pub fn invalidate(&self, path: &Path) -> Result<()> {
        let hash = FileHash::from_file(path)?;
        let mut cache = self.file_cache.lock().unwrap();
        cache.pop(&hash);
        Ok(())
    }
    
    pub fn clear(&self) {
        self.file_cache.lock().unwrap().clear();
        self.string_cache.lock().unwrap().clear();
        self.rule_cache.write().unwrap().clear();
    }
}
```

## Usage Examples

### Basic Scanning

```rust
use threatflux::{ThreatDetector, DetectorConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Create detector with default configuration
    let detector = ThreatDetector::new()?;
    
    // Scan a single file
    let result = detector.scan_file("suspicious.exe").await?;
    
    if result.is_threat() {
        println!("Threat detected!");
        println!("Category: {:?}", result.classification.primary_category);
        println!("Severity: {:?}", result.classification.severity);
        println!("Confidence: {:.2}%", result.classification.confidence * 100.0);
        
        for detection in &result.detections {
            println!("  - {}: {}", detection.rule_name, detection.metadata.get("description").unwrap_or(&"".to_string()));
        }
    }
    
    Ok(())
}
```

### Advanced Configuration

```rust
use threatflux::{
    ThreatDetector, DetectorConfig, YaraEngine, PatternEngine,
    ParallelStrategy, UpdatePolicy
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure YARA engine
    let yara_config = YaraConfig {
        timeout: Some(Duration::from_secs(30)),
        max_scan_size: Some(100 * 1024 * 1024), // 100MB
        use_memory_map: true,
        fast_scan: false,
    };
    
    // Configure pattern engine
    let pattern_config = PatternConfig {
        pattern_file: "patterns.dat".into(),
        max_patterns: 10000,
        enable_fuzzy: true,
        entropy_threshold: 7.0,
    };
    
    // Build detector configuration
    let config = DetectorConfig::builder()
        .add_engine(YaraEngine::new(yara_config)?)
        .add_engine(PatternEngine::new(pattern_config)?)
        .parallel_strategy(ParallelStrategy::Async { max_concurrent: 8 })
        .cache_size(1000)
        .cache_max_age(Duration::from_hours(24))
        .update_policy(UpdatePolicy::Automatic { 
            interval: Duration::from_hours(6) 
        })
        .build()?;
    
    let detector = ThreatDetector::with_config(config)?;
    
    // Add rule repositories
    detector.add_rule_repository(
        GitHubRepository::new("threatflux/community-rules", "main")
    ).await?;
    
    // Scan directory
    let results = detector.scan_directory("/path/to/scan", true).await?;
    
    // Generate report
    let report = detector.generate_report(&results)?;
    report.save_html("scan_report.html")?;
    
    Ok(())
}
```

### Custom Rules

```rust
use threatflux::{ThreatDetector, YaraRule, CustomRule};

#[tokio::main]
async fn main() -> Result<()> {
    let mut detector = ThreatDetector::new()?;
    
    // Add custom YARA rule
    let yara_rule = YaraRule::from_string(r#"
        rule custom_malware {
            meta:
                author = "Security Team"
                description = "Custom malware detection"
                severity = "high"
            strings:
                $mz = { 4D 5A }
                $api1 = "VirtualProtect"
                $api2 = "CreateRemoteThread"
            condition:
                $mz at 0 and all of ($api*)
        }
    "#)?;
    
    detector.add_custom_rule(yara_rule)?;
    
    // Add custom pattern rule
    let pattern_rule = CustomRule::builder()
        .id("CUSTOM_001")
        .name("Suspicious PowerShell")
        .pattern(r"powershell.*-enc.*-nop.*-w\s+hidden")
        .severity(Severity::High)
        .category(ThreatCategory::Malware)
        .build()?;
    
    detector.add_custom_rule(pattern_rule)?;
    
    Ok(())
}
```

### Integration with CI/CD

```rust
use threatflux::{ThreatDetector, CiCdIntegration};

#[tokio::main]
async fn main() -> Result<()> {
    let detector = ThreatDetector::new()?;
    let ci_integration = CiCdIntegration::new(detector);
    
    // Scan build artifacts
    let scan_config = CiCdScanConfig {
        paths: vec!["./build/", "./dist/"],
        fail_on_severity: Severity::Medium,
        output_format: OutputFormat::Sarif,
        ignore_patterns: vec!["*.test", "*.spec"],
    };
    
    match ci_integration.scan(scan_config).await {
        Ok(report) => {
            report.save("scan_results.sarif")?;
            if report.has_failures() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Scan failed: {}", e);
            std::process::exit(2);
        }
    }
    
    Ok(())
}
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_yara_engine_basic_detection() {
        let config = YaraConfig::default();
        let engine = YaraEngine::new(config).unwrap();
        
        let malware_sample = include_bytes!("../tests/samples/malware/test1.exe");
        let result = engine.scan_data(malware_sample).await.unwrap();
        
        assert!(!result.detections.is_empty());
        assert_eq!(result.engine_id, "yara");
    }
    
    #[tokio::test]
    async fn test_pattern_engine_entropy_detection() {
        let config = PatternConfig {
            entropy_threshold: 7.0,
            ..Default::default()
        };
        let engine = PatternEngine::new(config).unwrap();
        
        // High entropy data (encrypted/compressed)
        let high_entropy_data = generate_high_entropy_data(1024);
        let result = engine.scan_data(&high_entropy_data).await.unwrap();
        
        let entropy_detections: Vec<_> = result.detections
            .iter()
            .filter(|d| d.category == ThreatCategory::Obfuscation)
            .collect();
        
        assert!(!entropy_detections.is_empty());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_multi_engine_detection() {
    let detector = create_test_detector().await.unwrap();
    
    let test_file = "tests/samples/malware/ransomware_sample.exe";
    let result = detector.scan_file(test_file).await.unwrap();
    
    assert!(result.is_threat());
    assert_eq!(result.classification.primary_category, ThreatCategory::Ransomware);
    assert!(result.classification.confidence > 0.8);
}

#[tokio::test]
async fn test_rule_update_mechanism() {
    let mut detector = create_test_detector().await.unwrap();
    
    // Add test repository
    let test_repo = TestRepository::new(vec![
        create_test_rule("TEST_001", "Test Rule 1"),
        create_test_rule("TEST_002", "Test Rule 2"),
    ]);
    
    detector.add_rule_repository(Box::new(test_repo)).await.unwrap();
    
    // Trigger update
    let update_result = detector.update_rules().await.unwrap();
    
    assert_eq!(update_result.added, 2);
    assert!(update_result.errors.is_empty());
}
```

### Performance Benchmarks

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_yara_scanning(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = runtime.block_on(create_yara_engine()).unwrap();
    
    let small_file = vec![0u8; 1024]; // 1KB
    let medium_file = vec![0u8; 1024 * 1024]; // 1MB
    let large_file = vec![0u8; 10 * 1024 * 1024]; // 10MB
    
    c.bench_function("yara_scan_1kb", |b| {
        b.to_async(&runtime).iter(|| async {
            engine.scan_data(black_box(&small_file)).await.unwrap()
        });
    });
    
    c.bench_function("yara_scan_1mb", |b| {
        b.to_async(&runtime).iter(|| async {
            engine.scan_data(black_box(&medium_file)).await.unwrap()
        });
    });
    
    c.bench_function("yara_scan_10mb", |b| {
        b.to_async(&runtime).iter(|| async {
            engine.scan_data(black_box(&large_file)).await.unwrap()
        });
    });
}

criterion_group!(benches, benchmark_yara_scanning);
criterion_main!(benches);
```

## Deployment Considerations

### Docker Image

```dockerfile
FROM rust:1.96.0-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/threatflux /usr/local/bin/

# Copy default rules
COPY rules /opt/threatflux/rules

ENV THREATFLUX_RULES_PATH=/opt/threatflux/rules

ENTRYPOINT ["threatflux"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threatflux-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threatflux-scanner
  template:
    metadata:
      labels:
        app: threatflux-scanner
    spec:
      containers:
      - name: scanner
        image: threatflux/scanner:latest
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2"
        env:
        - name: THREATFLUX_CACHE_SIZE
          value: "10000"
        - name: THREATFLUX_UPDATE_INTERVAL
          value: "6h"
        volumeMounts:
        - name: rules
          mountPath: /opt/threatflux/rules
        - name: cache
          mountPath: /var/cache/threatflux
      volumes:
      - name: rules
        configMap:
          name: threatflux-rules
      - name: cache
        emptyDir: {}
```

## Conclusion

This implementation plan provides a solid foundation for building the ThreatFlux Threat Detection Library. The modular architecture allows for easy extension and customization while maintaining high performance and accuracy. The library can be deployed in various environments and integrated with existing security infrastructure.
