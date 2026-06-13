# Performance Guide

This guide provides comprehensive performance optimization recommendations for all ThreatFlux libraries and the File Scanner application.

## 📋 Table of Contents

- [Performance Overview](#performance-overview)
- [Library-Specific Optimizations](#library-specific-optimizations)
- [System-Level Optimizations](#system-level-optimizations)
- [Benchmarking](#benchmarking)
- [Profiling](#profiling)
- [Common Performance Issues](#common-performance-issues)
- [Production Recommendations](#production-recommendations)

## 📊 Performance Overview

### Library Performance Characteristics

| Library | Operation | Throughput | Memory Usage | Scaling |
|---------|-----------|------------|--------------|---------|
| **threatflux-hashing** | Hash calculation | 500MB/s - 1GB/s | 64KB buffers | O(n) |
| **threatflux-cache** | Cache operations | 10K-100K ops/s | Configurable | O(1) |
| **threatflux-string-analysis** | String extraction | 100-200MB/s | 32MB limit | O(n) |
| **threatflux-binary-analysis** | Binary parsing | 500-1000 files/s | Memory-mapped | O(1) |
| **threatflux-package-security** | Package analysis | 50-100 packages/s | Variable | O(n*m) |
| **threatflux-threat-detection** | YARA scanning | 100-300MB/s | Rule-dependent | O(n*r) |

### Performance Categories

#### ⚡ High Performance (Optimized)
- **threatflux-hashing**: BLAKE3 with SIMD
- **threatflux-cache**: Memory backend with LRU
- **threatflux-binary-analysis**: Memory-mapped files

#### 🚀 Good Performance (Standard)
- **threatflux-string-analysis**: Pattern matching
- **threatflux-threat-detection**: YARA rules

#### 🔄 Variable Performance (Depends on Input)
- **threatflux-package-security**: Dependency complexity

## 🔧 Library-Specific Optimizations

### threatflux-hashing

#### Configuration for Maximum Speed

```rust
use threatflux_hashing::{HashConfig, HashAlgorithms};

let config = HashConfig {
    algorithms: HashAlgorithms {
        blake3: true,    // Fastest algorithm
        sha256: false,   // Disable if not needed
        sha512: false,   // Disable if not needed
        md5: false,      // Disable if not needed
    },
    buffer_size: 65536,  // 64KB for optimal I/O
    max_concurrent_operations: num_cpus::get() * 2,
};
```

#### Performance Tips

```rust
// ✅ Fast: Use BLAKE3 for speed
let hash = calculate_blake3(&file_path).await?;

// ✅ Fast: Parallel hash calculation
let tasks = vec![
    tokio::spawn(calculate_blake3(file_path.clone())),
    tokio::spawn(calculate_sha256(file_path.clone())),
];
let results = join_all(tasks).await;

// ❌ Slow: Sequential calculation
let md5 = calculate_md5(&file_path).await?;
let sha256 = calculate_sha256(&file_path).await?;
let blake3 = calculate_blake3(&file_path).await?;
```

#### Feature Flags for Performance

```toml
[dependencies]
threatflux-hashing = { 
    version = "0.1.0", 
    features = [
        "simd",      # SIMD optimizations
        "parallel",  # Parallel processing
        "blake3",    # Fastest algorithm
    ] 
}
```

### threatflux-cache

#### High-Performance Configuration

```rust
use threatflux_cache::{Cache, CacheConfig, MemoryBackend, EvictionPolicy};

// For maximum speed (memory backend)
let config = CacheConfig::default()
    .with_max_entries(100_000)
    .with_eviction_policy(EvictionPolicy::Lru)
    .with_compression(false);  // Disable for speed

let backend = MemoryBackend::new();
let cache = Cache::new(config, backend).await?;
```

#### Optimized Cache Access Patterns

```rust
// ✅ Fast: Batch operations
let keys = vec!["key1", "key2", "key3"];
let results = cache.get_batch(&keys).await?;

// ✅ Fast: Async concurrent access
let tasks = keys.into_iter().map(|key| {
    let cache = cache.clone();
    tokio::spawn(async move {
        cache.get(&key).await
    })
}).collect::<Vec<_>>();

// ❌ Slow: Sequential access
for key in keys {
    let result = cache.get(&key).await?;
}
```

#### Cache Configuration by Use Case

```rust
// High-throughput, memory-rich environment
let high_perf_config = CacheConfig::default()
    .with_max_entries_per_key(1000)
    .with_max_total_entries(1_000_000)
    .with_eviction_policy(EvictionPolicy::Lru);

// Memory-constrained environment
let memory_optimized_config = CacheConfig::default()
    .with_max_entries_per_key(10)
    .with_max_total_entries(10_000)
    .with_compression(true)
    .with_eviction_policy(EvictionPolicy::Lfu);
```

### threatflux-string-analysis

#### Performance Configuration

```rust
use threatflux_string_analysis::{StringAnalyzer, AnalysisConfig, StringCategory};

let config = AnalysisConfig {
    min_length: 6,           // Higher threshold = faster
    max_strings: 1000,       // Limit output size
    max_file_size: 100_000_000,  // 100MB limit
    parallel_processing: true,
    categories: vec![         // Only analyze needed categories
        StringCategory::Url,
        StringCategory::Path,
    ],
    entropy_calculation: false,  // Disable if not needed
    ..Default::default()
};
```

#### Optimization Techniques

```rust
// ✅ Fast: Stream processing for large files
let analyzer = StringAnalyzer::new(config);
let results = analyzer.analyze_stream(file_stream).await?;

// ✅ Fast: Parallel processing with chunks
let chunks = split_file_into_chunks(&file_path, chunk_size).await?;
let tasks = chunks.into_iter().map(|chunk| {
    let analyzer = analyzer.clone();
    tokio::spawn(async move {
        analyzer.analyze_chunk(chunk).await
    })
}).collect::<Vec<_>>();

// ❌ Slow: Full file analysis with all categories
let config = AnalysisConfig {
    categories: StringCategory::all(),  // Expensive
    entropy_calculation: true,          // Expensive
    ..Default::default()
};
```

### threatflux-binary-analysis

#### Memory-Mapped File Access

```rust
use threatflux_binary_analysis::{BinaryAnalyzer, AnalysisConfig};

let config = AnalysisConfig {
    use_memory_mapping: true,    // Enable for large files
    parse_symbols: false,        // Disable if not needed
    parse_debug_info: false,     // Disable if not needed
    calculate_entropy: false,    // Disable if not needed
};

let analyzer = BinaryAnalyzer::new(config);
```

#### Selective Analysis

```rust
// ✅ Fast: Only analyze what you need
let analysis = analyzer.analyze_headers_only(&file_path).await?;

// ✅ Fast: Conditional deeper analysis
if analysis.is_executable() && analysis.is_suspicious() {
    let detailed = analyzer.analyze_detailed(&file_path).await?;
}

// ❌ Slow: Always full analysis
let full_analysis = analyzer.analyze_full(&file_path).await?;
```

### threatflux-package-security

#### Optimization Configuration

```rust
use threatflux_package_security::{PackageAnalyzer, AnalysisConfig, PackageType};

let config = AnalysisConfig {
    vulnerability_scanning: true,
    typosquatting_detection: false,   // Disable if not needed
    dependency_depth: 2,              // Limit recursion
    parallel_dependency_analysis: true,
    cache_vulnerability_db: true,
    ..Default::default()
};
```

#### Batch Processing

```rust
// ✅ Fast: Batch package analysis
let packages = vec![
    "package1.tar.gz",
    "package2.whl", 
    "package3.jar"
];

let analyzer = PackageAnalyzer::new(config).await?;
let results = analyzer.analyze_batch(&packages).await?;

// ❌ Slow: Individual analysis
for package in packages {
    let result = analyzer.analyze_package(&package, PackageType::Auto).await?;
}
```

### threatflux-threat-detection

#### YARA Rule Optimization

```rust
use threatflux_threat_detection::{ThreatDetector, DetectionConfig, RuleSet};

let config = DetectionConfig {
    rule_compilation_cache: true,     // Cache compiled rules
    parallel_rule_execution: true,    // Enable parallelism
    timeout_per_file: Duration::from_secs(30),
    memory_limit: 512 * 1024 * 1024,  // 512MB limit
};

// Optimize rule loading
let ruleset = RuleSet::from_compiled_cache("rules.cache")?;
let detector = ThreatDetector::with_rules(config, ruleset).await?;
```

## 🖥️ System-Level Optimizations

### Hardware Considerations

#### CPU Optimization
```bash
# Enable CPU performance governor
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Set process priority
nice -n -10 ./target/release/file-scanner

# Use taskset for CPU affinity
taskset -c 0-7 ./target/release/file-scanner
```

#### Memory Optimization
```bash
# Increase file descriptor limits
ulimit -n 65536

# Configure transparent huge pages
echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

# Set optimal vm.swappiness
echo 10 | sudo tee /proc/sys/vm/swappiness
```

#### I/O Optimization
```bash
# Use deadline I/O scheduler for SSDs
echo deadline | sudo tee /sys/block/sda/queue/scheduler

# Increase read-ahead buffer
echo 4096 | sudo tee /sys/block/sda/queue/read_ahead_kb

# Mount with optimal options
mount -o noatime,nodiratime /dev/sda1 /mnt/analysis
```

### Container Optimization

#### Docker Configuration
```dockerfile
FROM rust:1.96.0-bookworm

# Optimize for analysis workloads
ENV RUST_LOG=warn
ENV TOKIO_WORKER_THREADS=8
ENV THREATFLUX_CACHE_SIZE=10000

# Use jemalloc for better memory management
RUN apt-get update && apt-get install -y libjemalloc2
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2

# Set CPU affinity
CMD ["taskset", "-c", "0-7", "./file-scanner"]
```

#### Resource Limits
```yaml
# docker-compose.yml
services:
  file-scanner:
    cpus: 8
    memory: 16G
    ulimits:
      nofile: 65536
      memlock: -1
    volumes:
      - /dev/shm:/tmp:rw  # Use shared memory for temporary files
```

## 📈 Benchmarking

### Built-in Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific library benchmarks
cargo bench --package threatflux-hashing
cargo bench --package threatflux-cache

# Run with custom configurations
BENCH_FILE_SIZE=1GB cargo bench hash_benchmark
BENCH_CACHE_SIZE=100000 cargo bench cache_benchmark
```

### Custom Benchmarks

```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use threatflux_hashing::calculate_all_hashes;

fn bench_hash_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_algorithms");
    
    for size in [1024, 1024*1024, 10*1024*1024].iter() {
        group.bench_with_input(
            BenchmarkId::new("blake3", size), 
            size, 
            |b, &size| {
                let data = vec![0u8; size];
                b.to_async(Runtime::new().unwrap()).iter(|| async {
                    calculate_blake3(&data).await
                });
            }
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_hash_algorithms);
criterion_main!(benches);
```

### Performance Testing

```rust
use std::time::Instant;
use threatflux_hashing::calculate_all_hashes;

#[tokio::test]
async fn performance_test_hashing() {
    let start = Instant::now();
    let hashes = calculate_all_hashes("large_file.bin").await.unwrap();
    let duration = start.elapsed();
    
    // Assert performance targets
    assert!(duration.as_secs() < 10, "Hashing took too long: {:?}", duration);
    
    println!("Hash calculation took: {:?}", duration);
    println!("Throughput: {:.2} MB/s", 
        (file_size as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64());
}
```

## 🔍 Profiling

### CPU Profiling

```bash
# Install perf tools
sudo apt-get install linux-perf

# Profile the application
perf record --call-graph=dwarf ./target/release/file-scanner large_file.bin
perf report

# Generate flame graph
git clone https://github.com/brendangregg/FlameGraph
perf script | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > profile.svg
```

### Memory Profiling

```bash
# Use Valgrind (for debugging builds)
valgrind --tool=massif ./target/debug/file-scanner test_file.bin

# Use jemalloc profiling
export MALLOC_CONF="prof:true,prof_active:true,prof_prefix:jeprof"
./target/release/file-scanner test_file.bin
jeprof --pdf ./target/release/file-scanner jeprof.*.heap > memory_profile.pdf
```

### Async Profiling

```rust
// Add to Cargo.toml
[dependencies]
tokio = { version = "1.47", features = ["full", "tracing"] }
console-subscriber = "0.1"

// Add to main.rs
#[tokio::main]
async fn main() -> Result<()> {
    console_subscriber::init();
    
    // Your application code
    analyze_files().await?;
    
    Ok(())
}
```

```bash
# Use tokio-console for async profiling
cargo install tokio-console
tokio-console
```

## ⚠️ Common Performance Issues

### Issue 1: Blocking Operations in Async Context

#### Problem:
```rust
// ❌ Blocks the async runtime
async fn bad_analysis() {
    let content = std::fs::read("large_file.bin").unwrap();  // Blocking!
    process_content(content).await;
}
```

#### Solution:
```rust
// ✅ Uses async I/O
async fn good_analysis() {
    let content = tokio::fs::read("large_file.bin").await?;
    process_content(content).await;
}
```

### Issue 2: Excessive Memory Allocation

#### Problem:
```rust
// ❌ Creates many temporary allocations
fn bad_string_processing(data: &[u8]) -> Vec<String> {
    data.iter()
        .map(|&b| format!("{:02x}", b))  // Many allocations
        .collect()
}
```

#### Solution:
```rust
// ✅ Pre-allocates and reuses buffers
fn good_string_processing(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        write!(&mut result, "{:02x}", byte).unwrap();
    }
    result
}
```

### Issue 3: Inefficient Cache Usage

#### Problem:
```rust
// ❌ Cache miss for similar keys
for i in 0..1000 {
    let key = format!("file_{}", i);
    let result = expensive_analysis(&key).await?;
    cache.put(key, result).await?;
}
```

#### Solution:
```rust
// ✅ Better cache key strategy
fn get_cache_key(file_path: &str) -> String {
    let hash = calculate_sha256(file_path).await.unwrap();
    format!("analysis_{}", hash)
}

// Check cache before expensive operations
let cache_key = get_cache_key(file_path);
if let Some(cached) = cache.get(&cache_key).await? {
    return Ok(cached);
}
```

### Issue 4: Suboptimal Concurrency

#### Problem:
```rust
// ❌ Too much concurrency, overwhelming system
let mut tasks = Vec::new();
for file in files {  // 10,000 files
    tasks.push(tokio::spawn(analyze_file(file)));
}
join_all(tasks).await;
```

#### Solution:
```rust
// ✅ Controlled concurrency
use tokio::sync::Semaphore;

let semaphore = Arc::new(Semaphore::new(10));  // Limit to 10 concurrent
let mut tasks = Vec::new();

for file in files {
    let permit = semaphore.clone().acquire_owned().await?;
    tasks.push(tokio::spawn(async move {
        let _permit = permit;
        analyze_file(file).await
    }));
}
```

## 🏭 Production Recommendations

### Configuration for Production

```rust
// Production configuration
let production_config = ProductionConfig {
    // Cache configuration
    cache: CacheConfig {
        backend: CacheBackend::Filesystem("/var/cache/threatflux".into()),
        max_size: 10_000_000,  // 10M entries
        eviction_policy: EvictionPolicy::Lru,
        compression: true,
    },
    
    // Performance tuning
    performance: PerformanceConfig {
        worker_threads: num_cpus::get(),
        max_concurrent_files: 50,
        buffer_size: 64 * 1024,  // 64KB
        timeout: Duration::from_secs(300),  // 5 minutes
    },
    
    // Resource limits
    limits: ResourceLimits {
        max_file_size: 1024 * 1024 * 1024,  // 1GB
        max_memory_usage: 8 * 1024 * 1024 * 1024,  // 8GB
        max_analysis_time: Duration::from_secs(600),  // 10 minutes
    },
};
```

### Monitoring and Metrics

```rust
use prometheus::{Counter, Histogram, register_counter, register_histogram};

lazy_static! {
    static ref ANALYSIS_COUNTER: Counter = register_counter!(
        "threatflux_analyses_total", 
        "Total number of file analyses"
    ).unwrap();
    
    static ref ANALYSIS_DURATION: Histogram = register_histogram!(
        "threatflux_analysis_duration_seconds",
        "Time taken for file analysis"
    ).unwrap();
}

async fn monitored_analysis(file_path: &str) -> Result<AnalysisResult> {
    let _timer = ANALYSIS_DURATION.start_timer();
    
    let result = analyze_file(file_path).await?;
    
    ANALYSIS_COUNTER.inc();
    Ok(result)
}
```

### Deployment Configuration

```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threatflux-analyzer
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: analyzer
        image: threatflux/file-scanner:latest
        resources:
          requests:
            cpu: 2
            memory: 4Gi
          limits:
            cpu: 4
            memory: 8Gi
        env:
        - name: RUST_LOG
          value: "info"
        - name: TOKIO_WORKER_THREADS
          value: "4"
        - name: THREATFLUX_CACHE_SIZE
          value: "100000"
        volumeMounts:
        - name: cache-volume
          mountPath: /var/cache/threatflux
        - name: tmp-volume
          mountPath: /tmp
      volumes:
      - name: cache-volume
        persistentVolumeClaim:
          claimName: threatflux-cache-pvc
      - name: tmp-volume
        emptyDir:
          medium: Memory
          sizeLimit: 2Gi
```

### Load Testing

```rust
use criterion::{criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

fn load_test(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("concurrent_analysis", |b| {
        b.to_async(&rt).iter(|| async {
            let tasks = (0..100).map(|i| {
                let file = format!("test_file_{}.bin", i);
                tokio::spawn(async move {
                    analyze_file(&file).await
                })
            }).collect::<Vec<_>>();
            
            futures::future::join_all(tasks).await
        })
    });
}

criterion_group!(load_tests, load_test);
criterion_main!(load_tests);
```

## 🎯 Performance Targets

### Target Metrics by Use Case

#### Development Environment
- Hash calculation: > 100 MB/s
- Cache operations: > 1K ops/s
- Memory usage: < 1GB
- Analysis time: < 30s per file

#### CI/CD Pipeline
- Hash calculation: > 300 MB/s
- Cache hit ratio: > 80%
- Memory usage: < 2GB
- Analysis time: < 10s per file

#### Production Environment
- Hash calculation: > 500 MB/s
- Cache operations: > 10K ops/s
- Memory usage: < 8GB
- Analysis time: < 5s per file
- Throughput: > 1000 files/hour

### Optimization Checklist

- [ ] Enable appropriate compiler optimizations (`--release`)
- [ ] Use optimal buffer sizes for your workload
- [ ] Enable SIMD instructions where available
- [ ] Configure appropriate concurrency limits
- [ ] Use memory mapping for large files
- [ ] Enable caching for repeated operations
- [ ] Profile and identify bottlenecks
- [ ] Monitor memory usage and fix leaks
- [ ] Set appropriate resource limits
- [ ] Use efficient data structures
- [ ] Minimize unnecessary allocations
- [ ] Optimize I/O patterns

Remember: **Profile first, optimize second**. Always measure performance before and after optimizations to ensure they're effective.
