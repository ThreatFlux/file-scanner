//! State shared by every handler instance, on every transport.
//!
//! One [`ServerState`] exists per process (behind an `Arc`). It owns the
//! analysis cache and the string tracker that the REST routes (`/cache/*`,
//! `/strings/*`) read, so the side effects of a tool call land in the same
//! objects whichever transport made the call. It also owns the bounded
//! in-memory [`SectionCache`], the path policy and the panic-safe
//! [`ServerState::run_blocking`] helper.

use std::{
    cell::Cell,
    collections::HashMap,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use chrono::Utc;
use rmcp::model::JsonObject;
use serde_json::Value;

use super::paths::{Expect, PathPolicy};
use crate::{
    cache::{AnalysisCache, CacheEntry},
    string_tracker_compat::StringTracker,
};

/// Environment variable holding `:`-separated allow-root directories.
pub const ALLOWED_ROOTS_ENV: &str = "FILE_SCANNER_ALLOWED_ROOTS";

/// Default byte budget of the [`SectionCache`] (bytes of compressed JSON text).
pub const SECTION_CACHE_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Environment variable that sets the section cache budget, in MiB.
pub const SECTION_CACHE_MB_ENV: &str = "FILE_SCANNER_SECTION_CACHE_MB";
/// Largest `analyze_file` result (compact JSON bytes) the analysis cache keeps
/// whole; bigger ones are kept as the trimmed result the caller received.
pub const ENTRY_RESULT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Default entry bound of the [`SectionCache`].
pub const SECTION_CACHE_MAX_ENTRIES: usize = 256;

/// Configuration of a [`ServerState`].
#[derive(Debug, Clone)]
pub struct StateConfig {
    /// Where the analysis cache persists (`<tmp>/file-scanner-cache`).
    pub cache_dir: PathBuf,
    /// Directories every tool path must be under (empty: no limit).
    pub allow_roots: Vec<PathBuf>,
    /// Byte bound of the section cache.
    pub section_cache_max_bytes: usize,
    /// Entry bound of the section cache.
    pub section_cache_max_entries: usize,
    /// Most analyses running at once across every transport; further calls wait.
    pub max_concurrent_analyses: usize,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            cache_dir: std::env::temp_dir().join("file-scanner-cache"),
            allow_roots: Vec::new(),
            section_cache_max_bytes: SECTION_CACHE_MAX_BYTES,
            section_cache_max_entries: SECTION_CACHE_MAX_ENTRIES,
            max_concurrent_analyses: std::thread::available_parallelism()
                .map_or(4, std::num::NonZero::get)
                .max(4),
        }
    }
}

impl StateConfig {
    /// Defaults plus the allow-roots named by `FILE_SCANNER_ALLOWED_ROOTS`.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(value) = std::env::var_os(ALLOWED_ROOTS_ENV) {
            config.allow_roots = std::env::split_paths(&value)
                .filter(|root| !root.as_os_str().is_empty())
                .collect();
        }
        if let Some(mb) = std::env::var(SECTION_CACHE_MB_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            config.section_cache_max_bytes = mb.saturating_mul(1024 * 1024);
        }
        config
    }
}

// ---------------------------------------------------------------------------
// Section cache
// ---------------------------------------------------------------------------

/// Default bound, in bytes of source JSON text, of the parsed "hot" values
/// kept in front of the compressed store.
pub const SECTION_CACHE_HOT_BYTES: usize = 64 * 1024 * 1024;

type CacheKey = (String, String);

struct Slot {
    /// Compact JSON text, deflate-compressed. Held compressed so a full run of
    /// a big binary fits the byte bound.
    data: Arc<[u8]>,
    /// Length of the JSON text before compression.
    text_bytes: usize,
    last_used: u64,
}

/// A parsed value kept in front of the compressed store, so paging through
/// one section again and again does not parse it again.
struct Hot {
    value: Arc<Value>,
    text_bytes: usize,
    last_used: u64,
}

struct Inner {
    map: HashMap<CacheKey, Slot>,
    /// Compressed bytes held by `map` (what the byte bound counts).
    bytes: usize,
    hot: HashMap<CacheKey, Hot>,
    hot_bytes: usize,
    tick: u64,
}

impl Inner {
    fn drop_hot(&mut self, key: &CacheKey) {
        if let Some(old) = self.hot.remove(key) {
            self.hot_bytes -= old.text_bytes;
        }
    }

    /// Remove a stored value (and its parsed copy).
    fn remove(&mut self, key: &CacheKey) -> Option<Slot> {
        self.drop_hot(key);
        let slot = self.map.remove(key)?;
        self.bytes -= slot.data.len();
        Some(slot)
    }
}

/// A bounded in-memory cache of analysis results, keyed by a file's SHA-256
/// and a section key (the section name plus the options that change its
/// content, for example `strings:min=4`).
///
/// Values are stored as deflate-compressed JSON text and the byte bound counts
/// the compressed size. When the cache is full, other files' values go first
/// (least recently used first); only then are older values of the file being
/// inserted dropped, and [`PutOutcome::evicted_same_file`] names them. A small
/// bounded map of parsed values (the "hot" map) sits in front of the store.
pub struct SectionCache {
    inner: Mutex<Inner>,
    max_bytes: usize,
    max_entries: usize,
    hot_max_bytes: usize,
}

/// What [`SectionCache::put`] did with a value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PutOutcome {
    /// False when the value is bigger than the whole cache and was not kept.
    pub kept: bool,
    /// Size of the value as compact JSON text.
    pub bytes: usize,
    /// Section keys of the same file (same SHA-256) dropped to make room.
    pub evicted_same_file: Vec<String>,
}

impl Default for SectionCache {
    fn default() -> Self {
        Self::new(SECTION_CACHE_MAX_BYTES, SECTION_CACHE_MAX_ENTRIES)
    }
}

impl std::fmt::Debug for SectionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SectionCache")
            .field("entries", &self.len())
            .field("bytes", &self.bytes())
            .finish()
    }
}

fn compress(text: &str) -> Option<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(text.len() / 8 + 64),
        flate2::Compression::fast(),
    );
    encoder.write_all(text.as_bytes()).ok()?;
    encoder.finish().ok()
}

fn inflate(data: &[u8], text_bytes: usize) -> Option<String> {
    use std::io::Read;
    let mut out = String::with_capacity(text_bytes);
    flate2::read::DeflateDecoder::new(data)
        .read_to_string(&mut out)
        .ok()?;
    Some(out)
}

impl SectionCache {
    /// A cache holding at most `max_entries` values and `max_bytes` bytes of
    /// compressed JSON text in total.
    pub fn new(max_bytes: usize, max_entries: usize) -> Self {
        Self::with_hot_limit(max_bytes, max_entries, SECTION_CACHE_HOT_BYTES)
    }

    /// Like [`Self::new`], with the bound (source text bytes) of the parsed
    /// hot map. The most recently read value is always kept, whatever its size.
    pub fn with_hot_limit(max_bytes: usize, max_entries: usize, hot_max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                bytes: 0,
                hot: HashMap::new(),
                hot_bytes: 0,
                tick: 0,
            }),
            max_bytes,
            max_entries,
            hot_max_bytes,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means another thread panicked mid-update; the map
        // is still structurally valid, and a cache can always be cleared.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The stored text for `(sha256, section_key)`, marking it recently used.
    pub fn get_text(&self, sha256: &str, section_key: &str) -> Option<Arc<str>> {
        let (data, text_bytes) = self.touch(sha256, section_key)?;
        inflate(&data, text_bytes).map(Arc::from)
    }

    /// Mark a stored value as used and hand out its compressed bytes.
    fn touch(&self, sha256: &str, section_key: &str) -> Option<(Arc<[u8]>, usize)> {
        let mut inner = self.lock();
        inner.tick += 1;
        let tick = inner.tick;
        let key = (sha256.to_string(), section_key.to_string());
        if let Some(hot) = inner.hot.get_mut(&key) {
            hot.last_used = tick;
        }
        let slot = inner.map.get_mut(&key)?;
        slot.last_used = tick;
        Some((Arc::clone(&slot.data), slot.text_bytes))
    }

    /// The stored value for `(sha256, section_key)`. Repeated calls return the
    /// same `Arc` (a parsed copy is kept in the hot map) until it is evicted.
    pub fn get(&self, sha256: &str, section_key: &str) -> Option<Arc<Value>> {
        let key = (sha256.to_string(), section_key.to_string());
        {
            let mut inner = self.lock();
            inner.tick += 1;
            let tick = inner.tick;
            if let Some(hot) = inner.hot.get_mut(&key) {
                hot.last_used = tick;
                let value = Arc::clone(&hot.value);
                if let Some(slot) = inner.map.get_mut(&key) {
                    slot.last_used = tick;
                }
                return Some(value);
            }
        }
        let (data, text_bytes) = self.touch(sha256, section_key)?;
        let parsed: Arc<Value> = Arc::new(serde_json::from_str(&inflate(&data, text_bytes)?).ok()?);
        let mut inner = self.lock();
        if !inner.map.contains_key(&key) {
            // Evicted or replaced while parsing: still a valid answer for this call.
            return Some(parsed);
        }
        if let Some(existing) = inner.hot.get(&key) {
            return Some(Arc::clone(&existing.value));
        }
        let tick = inner.tick;
        inner.hot_bytes += text_bytes;
        inner.hot.insert(
            key.clone(),
            Hot {
                value: Arc::clone(&parsed),
                text_bytes,
                last_used: tick,
            },
        );
        // Bounded by source bytes; the value just read always stays.
        while inner.hot_bytes > self.hot_max_bytes && inner.hot.len() > 1 {
            let Some(oldest) = inner
                .hot
                .iter()
                .filter(|(k, _)| **k != key)
                .min_by_key(|(_, hot)| hot.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            inner.drop_hot(&oldest);
        }
        Some(parsed)
    }

    /// Store a value (as compact JSON text).
    pub fn put(&self, sha256: &str, section_key: &str, value: &Value) -> PutOutcome {
        match serde_json::to_string(value) {
            Ok(text) => self.put_text(sha256, section_key, text),
            Err(_) => PutOutcome::default(),
        }
    }

    /// Store JSON text as it is (compressed).
    pub fn put_text(&self, sha256: &str, section_key: &str, text: String) -> PutOutcome {
        let text_bytes = text.len();
        let not_kept = PutOutcome {
            kept: false,
            bytes: text_bytes,
            evicted_same_file: Vec::new(),
        };
        let Some(packed) = compress(&text) else {
            return not_kept;
        };
        drop(text);
        if packed.len() > self.max_bytes {
            return not_kept;
        }
        let mut inner = self.lock();
        inner.tick += 1;
        let tick = inner.tick;
        let key = (sha256.to_string(), section_key.to_string());
        inner.remove(&key);
        inner.bytes += packed.len();
        inner.map.insert(
            key.clone(),
            Slot {
                data: Arc::from(packed),
                text_bytes,
                last_used: tick,
            },
        );
        let mut evicted_same_file = Vec::new();
        while inner.bytes > self.max_bytes || inner.map.len() > self.max_entries {
            // Other files' values first, then older values of this file; the
            // value just stored is never the victim.
            let victim = inner
                .map
                .iter()
                .filter(|(k, _)| **k != key)
                .min_by_key(|(k, slot)| (k.0 == sha256, slot.last_used))
                .map(|(k, _)| k.clone());
            let Some(victim) = victim else { break };
            inner.remove(&victim);
            if victim.0 == sha256 {
                evicted_same_file.push(victim.1);
            }
        }
        PutOutcome {
            kept: true,
            bytes: text_bytes,
            evicted_same_file,
        }
    }

    /// Number of stored values.
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// True when nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Compressed bytes held.
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// Drop everything.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.map.clear();
        inner.bytes = 0;
        inner.hot.clear();
        inner.hot_bytes = 0;
    }
}

// ---------------------------------------------------------------------------
// Panic-safe blocking work
// ---------------------------------------------------------------------------

thread_local! {
    static CURRENT_SECTION: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// Record which section of an analysis is running on this thread, so a panic
/// can be reported by section. Cheap; call it before each section.
pub fn mark_section(section: &'static str) {
    CURRENT_SECTION.with(|current| current.set(Some(section)));
}

struct Crash {
    message: String,
    section: Option<&'static str>,
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

fn crash_text(name: &str, message: &str, section: Option<&str>) -> String {
    let location = section.map_or_else(String::new, |s| format!(" in section '{s}'"));
    format!(
        "{name} crashed{location}: {message}. The server is still running. Retry without that \
         section, or try a different file."
    )
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

/// Everything the handler instances share. See the module documentation.
pub struct ServerState {
    config: StateConfig,
    policy: PathPolicy,
    analysis_cache: OnceLock<Arc<AnalysisCache>>,
    string_tracker: OnceLock<Arc<StringTracker>>,
    section_cache: SectionCache,
    /// Permits for [`Self::run_blocking`]: one per analysis allowed to run.
    slots: Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("config", &self.config)
            .field("section_cache", &self.section_cache)
            .finish_non_exhaustive()
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new(StateConfig::default())
    }
}

impl ServerState {
    /// State for `config`. Nothing heavy happens here: the analysis cache and
    /// the string tracker are built on first use (or by [`Self::warm_up`]), so
    /// constructing a state needs no Tokio runtime.
    pub fn new(config: StateConfig) -> Self {
        let policy = PathPolicy::new(config.allow_roots.clone());
        let config_slots = config.max_concurrent_analyses.max(1);
        let section_cache = SectionCache::new(
            config.section_cache_max_bytes,
            config.section_cache_max_entries,
        );
        Self {
            config,
            policy,
            analysis_cache: OnceLock::new(),
            string_tracker: OnceLock::new(),
            section_cache,
            slots: Arc::new(tokio::sync::Semaphore::new(config_slots)),
        }
    }

    /// The configuration this state was built from.
    pub const fn config(&self) -> &StateConfig {
        &self.config
    }

    /// Build the analysis cache and string tracker now. Call inside the Tokio
    /// runtime before serving, so the cache loads from disk at start-up.
    pub fn warm_up(&self) {
        let _ = self.analysis_cache();
        let _ = self.string_tracker();
    }

    /// The process-wide analysis cache (the one `/cache/*` reads).
    ///
    /// If the cache directory cannot be created or written, or no Tokio runtime
    /// is running, the cache is memory-only and one line is printed to stderr.
    pub fn analysis_cache(&self) -> Arc<AnalysisCache> {
        Arc::clone(
            self.analysis_cache
                .get_or_init(|| Arc::new(build_cache(&self.config.cache_dir))),
        )
    }

    /// The process-wide string tracker (the one `/strings/*` reads).
    pub fn string_tracker(&self) -> Arc<StringTracker> {
        Arc::clone(
            self.string_tracker
                .get_or_init(|| Arc::new(StringTracker::new())),
        )
    }

    /// The bounded in-memory cache of complete section results.
    pub const fn section_cache(&self) -> &SectionCache {
        &self.section_cache
    }

    /// Resolve a tool path argument (see [`PathPolicy::resolve`]).
    pub fn resolve_path(&self, raw: &str, noun: &str, expect: Expect) -> Result<PathBuf, String> {
        self.policy.resolve(raw, noun, expect)
    }

    /// Vet the contents of a directory argument (see [`PathPolicy::check_tree`]).
    pub fn check_tree(&self, dir: &std::path::Path, recursive: bool) -> Result<(), String> {
        self.policy.check_tree(dir, recursive)
    }

    /// Run blocking work off the async workers; a panic becomes an error text
    /// that names the section (`section` is the tool or step, and the
    /// analysis may refine it with [`mark_section`]).
    pub async fn run_blocking<T, F>(&self, section: &str, work: F) -> Result<T, String>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // The semaphore is never closed, so acquiring cannot fail.
        let _slot = self.slots.acquire().await.ok();
        let joined = tokio::task::spawn_blocking(move || {
            CURRENT_SECTION.with(|current| current.set(None));
            std::panic::catch_unwind(AssertUnwindSafe(work)).map_err(|payload| Crash {
                message: panic_message(payload.as_ref()),
                section: CURRENT_SECTION.with(Cell::take),
            })
        })
        .await;
        match joined {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(crash)) => Err(crash_text(section, &crash.message, crash.section)),
            Err(error) if error.is_panic() => Err(crash_text(
                section,
                &panic_message(error.into_panic().as_ref()),
                None,
            )),
            Err(error) => Err(format!(
                "{section} was cancelled before it finished: {error}"
            )),
        }
    }

    // -- side effects of tool calls --------------------------------------

    /// What a successful `analyze_file` call leaves behind: its strings go to
    /// the string tracker and one entry goes to the analysis cache. Failures
    /// here never change the tool's response.
    ///
    /// `entry_result` is the full result, or, when that is bigger than
    /// [`ENTRY_RESULT_MAX_BYTES`], the trimmed result the caller received (it
    /// carries the `truncated` object), so one big file cannot fill memory and
    /// the cache directory.
    pub async fn record_analyze_file(
        &self,
        raw_args: &JsonObject,
        raw_path: &str,
        strings: Option<Vec<String>>,
        entry_result: Value,
        sha256: &str,
        file_size: u64,
        started: Instant,
    ) {
        if let Some(strings) = strings {
            let tracker = self.string_tracker();
            let path = raw_path.to_string();
            let hash = sha256.to_string();
            match self
                .run_blocking("string tracking", move || {
                    tracker.track_strings_from_results(&strings, &path, &hash, "analyze_file")
                })
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    eprintln!("String indexing skipped values outside tracker bounds: {error}");
                }
                Err(message) => eprintln!("String indexing skipped: {message}"),
            }
        }

        let entry = CacheEntry {
            file_path: raw_path.to_string(),
            file_hash: sha256.to_string(),
            tool_name: "analyze_file".to_string(),
            tool_args: to_args_map(raw_args),
            result: entry_result,
            timestamp: Utc::now(),
            file_size,
            execution_time_ms: elapsed_ms(started),
        };
        let _ = self.analysis_cache().add_entry(entry).await;
    }

    /// What a successful `yara_scan_file` call leaves behind: one cache entry.
    pub async fn record_yara_scan(
        &self,
        raw_args: &JsonObject,
        raw_path: &str,
        result: &Value,
        started: Instant,
    ) {
        let entry = CacheEntry {
            file_path: raw_path.to_string(),
            file_hash: "yara_scan".to_string(),
            tool_name: "yara_scan_file".to_string(),
            tool_args: to_args_map(raw_args),
            result: result.clone(),
            timestamp: Utc::now(),
            file_size: 0,
            execution_time_ms: elapsed_ms(started),
        };
        let _ = self.analysis_cache().add_entry(entry).await;
    }
}

fn to_args_map(args: &JsonObject) -> HashMap<String, Value> {
    args.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Build the analysis cache, degrading to memory-only (with one stderr line)
/// when the directory cannot be used.
fn build_cache(dir: &Path) -> AnalysisCache {
    if tokio::runtime::Handle::try_current().is_err() {
        eprintln!(
            "file-scanner: no async runtime when the analysis cache was created; \
             the cache is memory-only"
        );
        return AnalysisCache::memory_only();
    }
    match probe_writable(dir).and_then(|()| AnalysisCache::new(dir).map_err(|e| e.to_string())) {
        Ok(cache) => cache,
        Err(error) => {
            eprintln!(
                "file-scanner: cache directory {} is not usable ({error}); the analysis cache is \
                 memory-only",
                dir.display()
            );
            AnalysisCache::memory_only()
        }
    }
}

fn probe_writable(dir: &Path) -> Result<(), String> {
    crate::cache::create_private_dir(dir).map_err(|e| e.to_string())?;
    let probe = dir.join(format!(".write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"").map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn section_cache_round_trip_and_miss() {
        let cache = SectionCache::default();
        assert!(cache.get("abc", "strings:min=4").is_none());
        cache.put("abc", "strings:min=4", &json!(["a", "b"]));
        assert_eq!(
            *cache.get("abc", "strings:min=4").unwrap(),
            json!(["a", "b"])
        );
        assert!(cache.get("abc", "strings:min=8").is_none());
        assert!(cache.get("def", "strings:min=4").is_none());
    }

    #[test]
    fn section_cache_evicts_least_recently_used_by_entries() {
        let cache = SectionCache::new(usize::MAX, 2);
        cache.put("h", "a", &json!(1));
        cache.put("h", "b", &json!(2));
        assert!(cache.get("h", "a").is_some()); // a is now more recent than b
        cache.put("h", "c", &json!(3));
        assert_eq!(cache.len(), 2);
        assert!(cache.get("h", "b").is_none());
        assert!(cache.get("h", "a").is_some());
        assert!(cache.get("h", "c").is_some());
    }

    /// Text that does not compress much: a deterministic pseudo-random string.
    fn noisy(len: usize, seed: u64) -> String {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                char::from(b'a' + (x % 26) as u8)
            })
            .collect()
    }

    #[test]
    fn section_cache_is_bounded_in_bytes_and_skips_oversized_values() {
        let cache = SectionCache::new(10_000, 100);
        for i in 0..50 {
            cache.put("h", &format!("k{i}"), &json!(noisy(1_000, i)));
        }
        assert!(cache.bytes() <= 10_000, "{}", cache.bytes());
        assert!(cache.len() < 50);
        let big = cache.put("h", "huge", &json!(noisy(50_000, 99)));
        assert!(
            !big.kept,
            "an oversized value is reported, not dropped silently"
        );
        assert_eq!(big.bytes, 50_002);
        assert!(cache.get("h", "huge").is_none());
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn section_cache_stores_compressed_and_counts_the_compressed_size() {
        let cache = SectionCache::new(10_000, 100);
        let text = json!("x".repeat(100_000));
        let outcome = cache.put("h", "squeezes", &text);
        assert!(outcome.kept, "100 KB of repeats fits a 10 KB cache");
        assert_eq!(outcome.bytes, 100_002);
        assert!(cache.bytes() < 1_000, "{}", cache.bytes());
        assert_eq!(*cache.get("h", "squeezes").unwrap(), text);
        assert_eq!(cache.get_text("h", "squeezes").unwrap().len(), 100_002);
    }

    #[test]
    fn a_full_cache_drops_other_files_before_the_file_being_inserted() {
        // Room for about three noisy values.
        let cache = SectionCache::new(3_500, 100);
        cache.put("other", "a", &json!(noisy(1_000, 1)));
        cache.put("mine", "s1", &json!(noisy(1_000, 2)));
        cache.put("mine", "s2", &json!(noisy(1_000, 3)));
        // `other` is the oldest and also the other file: it goes first.
        let outcome = cache.put("mine", "s3", &json!(noisy(1_000, 4)));
        assert!(outcome.kept);
        assert!(outcome.evicted_same_file.is_empty(), "{outcome:?}");
        assert!(cache.get("other", "a").is_none());
        // `other` is gone; now only this file's own values can make room, and
        // the call says which.
        let outcome = cache.put("mine", "s4", &json!(noisy(1_000, 5)));
        assert_eq!(outcome.evicted_same_file, vec!["s1".to_string()]);
        assert!(cache.get("mine", "s4").is_some());
        assert!(cache.get("mine", "s1").is_none());
    }

    #[test]
    fn a_fresh_value_of_a_busy_file_survives_other_files_being_more_recent() {
        let cache = SectionCache::new(2_500, 100);
        cache.put("mine", "old", &json!(noisy(1_000, 1)));
        cache.put("other", "recent", &json!(noisy(1_000, 2)));
        let outcome = cache.put("mine", "new", &json!(noisy(1_000, 3)));
        assert!(outcome.evicted_same_file.is_empty(), "{outcome:?}");
        assert!(cache.get("other", "recent").is_none());
        assert!(cache.get("mine", "old").is_some());
        assert!(cache.get("mine", "new").is_some());
    }

    #[test]
    fn get_returns_the_same_parsed_value_until_it_is_replaced() {
        let cache = SectionCache::default();
        cache.put("h", "k", &json!({"a": [1, 2, 3]}));
        let first = cache.get("h", "k").unwrap();
        let second = cache.get("h", "k").unwrap();
        assert!(Arc::ptr_eq(&first, &second), "no second parse");
        cache.put("h", "k", &json!({"a": [4]}));
        let third = cache.get("h", "k").unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(*third, json!({"a": [4]}));
        cache.clear();
        assert!(cache.get("h", "k").is_none());
    }

    #[test]
    fn the_hot_map_is_bounded_but_always_holds_the_latest_value() {
        // A hot limit smaller than any one value.
        let cache = SectionCache::with_hot_limit(usize::MAX, 100, 10);
        cache.put("h", "a", &json!(noisy(100, 1)));
        cache.put("h", "b", &json!(noisy(100, 2)));
        let b1 = cache.get("h", "b").unwrap();
        assert!(Arc::ptr_eq(&b1, &cache.get("h", "b").unwrap()));
        let a1 = cache.get("h", "a").unwrap();
        assert!(Arc::ptr_eq(&a1, &cache.get("h", "a").unwrap()));
        // `b` was pushed out of the hot map by `a`; it parses again, correctly.
        let b2 = cache.get("h", "b").unwrap();
        assert!(!Arc::ptr_eq(&b1, &b2));
        assert_eq!(*b1, *b2);
    }

    #[tokio::test]
    async fn run_blocking_returns_values_and_names_panicking_sections() {
        let state = ServerState::default();
        assert_eq!(state.run_blocking("probe", || 41 + 1).await.unwrap(), 42);

        let error = state
            .run_blocking("analyze_file", || -> u32 {
                mark_section("code_quality");
                panic!("attempt to multiply with overflow")
            })
            .await
            .unwrap_err();
        assert!(
            error.contains("analyze_file crashed in section 'code_quality'"),
            "{error}"
        );
        assert!(
            error.contains("attempt to multiply with overflow"),
            "{error}"
        );

        // The pool is still healthy afterwards, and the marker did not leak.
        let error = state
            .run_blocking("yara_scan_file", || -> u32 { panic!("boom") })
            .await
            .unwrap_err();
        assert!(error.starts_with("yara_scan_file crashed: boom"), "{error}");
    }

    #[tokio::test]
    async fn analyses_beyond_the_concurrency_limit_wait_their_turn() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let state = Arc::new(ServerState::new(StateConfig {
            max_concurrent_analyses: 2,
            ..StateConfig::default()
        }));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let (state, running, peak) = (state.clone(), running.clone(), peak.clone());
            jobs.push(tokio::spawn(async move {
                state
                    .run_blocking("probe", move || {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(30));
                        running.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                    .unwrap();
            }));
        }
        for job in jobs {
            job.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unwritable_cache_directory_degrades_to_memory_only() {
        let file = tempfile::NamedTempFile::new().unwrap();
        // A cache "directory" below a regular file can neither be created nor written.
        let config = StateConfig {
            cache_dir: file.path().join("cache"),
            ..StateConfig::default()
        };
        let state = ServerState::new(config);
        let cache = state.analysis_cache(); // must not panic
        let entry = CacheEntry {
            file_path: "/x".into(),
            file_hash: "h".into(),
            tool_name: "analyze_file".into(),
            tool_args: HashMap::new(),
            result: json!({}),
            timestamp: Utc::now(),
            file_size: 1,
            execution_time_ms: 1,
        };
        cache.add_entry(entry).await.unwrap();
        assert_eq!(cache.get_metadata().await.total_entries, 1);
    }

    #[test]
    fn building_a_state_needs_no_runtime() {
        let state = ServerState::default();
        assert!(state.section_cache().is_empty());
        // Without a runtime the cache is memory-only instead of panicking.
        let _ = state.analysis_cache();
    }
}
