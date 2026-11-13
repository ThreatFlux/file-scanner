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
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use rmcp::model::JsonObject;
use serde_json::Value;

use super::paths::{Expect, PathPolicy};
use crate::{
    cache::{AnalysisCache, CacheDir, CacheEntry, DEFAULT_MAX_TOTAL_BYTES},
    string_tracker_compat::{StringEntry, StringStatistics, StringTracker},
};

/// Environment variable holding `:`-separated allow-root directories.
pub const ALLOWED_ROOTS_ENV: &str = "FILE_SCANNER_ALLOWED_ROOTS";

/// Default byte budget of the [`SectionCache`] (bytes of compressed JSON text).
pub const SECTION_CACHE_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Environment variable that sets the section cache budget, in MiB.
pub const SECTION_CACHE_MB_ENV: &str = "FILE_SCANNER_SECTION_CACHE_MB";
/// Environment variable naming the cache directory (`--cache-dir` wins).
pub const CACHE_DIR_ENV: &str = "FILE_SCANNER_CACHE_DIR";
/// Environment variable that sets the on-disk cache budget, in MiB.
pub const CACHE_DISK_MB_ENV: &str = "FILE_SCANNER_CACHE_DISK_MB";
/// Largest `analyze_file` result (compact JSON bytes) the analysis cache keeps
/// whole; bigger ones are kept as the trimmed result the caller received.
pub const ENTRY_RESULT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Default entry bound of the [`SectionCache`].
pub const SECTION_CACHE_MAX_ENTRIES: usize = 256;

/// Configuration of a [`ServerState`].
#[derive(Debug, Clone)]
pub struct StateConfig {
    /// Where the caches persist. `from_env` puts it under the user's cache
    /// directory; `Default` uses a per-user directory under the system temp
    /// directory (never a shared, predictable name).
    pub cache_dir: PathBuf,
    /// False (`--no-cache`) turns caching off: nothing is stored or served.
    pub cache_enabled: bool,
    /// Byte bound of the analysis history on disk.
    pub cache_max_bytes: u64,
    /// Byte bound of the section files on disk (0: sections stay in memory).
    pub section_disk_max_bytes: u64,
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
            cache_dir: private_temp_cache_dir(),
            cache_enabled: true,
            cache_max_bytes: DEFAULT_MAX_TOTAL_BYTES,
            section_disk_max_bytes: 0,
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
        config.cache_dir = std::env::var_os(CACHE_DIR_ENV)
            .filter(|dir| !dir.is_empty())
            .map_or_else(user_cache_dir, PathBuf::from);
        config.section_disk_max_bytes = SECTION_DISK_MAX_BYTES;
        if let Some(mb) = std::env::var(CACHE_DISK_MB_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            config.cache_max_bytes = mb.saturating_mul(1024 * 1024) / 4;
            config.section_disk_max_bytes = mb.saturating_mul(1024 * 1024);
        }
        config
    }
}

/// A per-user directory under the system temp directory.
fn private_temp_cache_dir() -> PathBuf {
    let user: String = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    std::env::temp_dir().join(format!("file-scanner-cache-{user}"))
}

/// The default cache directory: under the user's cache directory (not a
/// shared temp path), falling back to a per-user temp directory.
pub fn user_cache_dir() -> PathBuf {
    let absolute = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(xdg) = absolute("XDG_CACHE_HOME") {
        return xdg.join("file-scanner");
    }
    if let Some(home) = absolute("HOME") {
        return if cfg!(target_os = "macos") {
            home.join("Library/Caches/file-scanner")
        } else {
            home.join(".cache/file-scanner")
        };
    }
    private_temp_cache_dir()
}

// ---------------------------------------------------------------------------
// Section cache
// ---------------------------------------------------------------------------

/// Default bound, in bytes of source JSON text, of the parsed "hot" values
/// kept in front of the compressed store.
pub const SECTION_CACHE_HOT_BYTES: usize = 64 * 1024 * 1024;
/// Default bound, in bytes, of the section files kept on disk.
pub const SECTION_DISK_MAX_BYTES: u64 = 1024 * 1024 * 1024;
/// Name of the section directory inside the cache directory.
const SECTION_SUBDIR: &str = "sections";
/// Extension of a section file.
const SECTION_EXT: &str = "sec";

type CacheKey = (String, String);

struct Slot {
    /// Compact JSON text, deflate-compressed. Held compressed so a full run of
    /// a big binary fits the byte bound.
    data: Arc<[u8]>,
    /// Length of the JSON text before compression.
    text_bytes: usize,
    last_used: u64,
    /// True when a copy of this value is also on disk.
    on_disk: bool,
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

/// What a section file holds in its first line.
#[derive(serde::Serialize, serde::Deserialize)]
struct SectionHeader {
    sha: String,
    key: String,
    text_bytes: usize,
}

struct DiskFile {
    bytes: u64,
    last_used: u64,
    sha: String,
    /// Empty for a file found at start-up (only its name is known).
    key: String,
}

#[derive(Default)]
struct DiskState {
    files: HashMap<String, DiskFile>,
    total: u64,
    clock: u64,
}

/// The on-disk tier of a [`SectionCache`]: one file per (file, section) under
/// `<cache dir>/sections`, written atomically, looked up by name, so
/// start-up lists the directory and reads no values.
struct DiskTier {
    dir: Arc<CacheDir>,
    max_bytes: u64,
    state: OnceLock<Option<(PathBuf, Mutex<DiskState>)>>,
}

fn plain_name_part(text: &str) -> String {
    let plain = !text.is_empty()
        && text.len() <= 100
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if plain {
        text.to_string()
    } else {
        format!(
            "h{}",
            &blake3::hash(text.as_bytes()).to_hex().as_str()[..32]
        )
    }
}

fn section_file_name(sha256: &str, key: &str) -> String {
    format!(
        "{}.{}.{SECTION_EXT}",
        plain_name_part(sha256),
        &blake3::hash(key.as_bytes()).to_hex().as_str()[..16]
    )
}

impl DiskTier {
    fn state(&self) -> Option<(&Path, MutexGuard<'_, DiskState>)> {
        let (root, state) = self
            .state
            .get_or_init(|| {
                let root = self.dir.ready()?.join(SECTION_SUBDIR);
                crate::cache::create_private_dir(&root).ok()?;
                let mut state = DiskState::default();
                if let Ok(listing) = std::fs::read_dir(&root) {
                    for item in listing.flatten() {
                        let name = item.file_name().to_string_lossy().into_owned();
                        let Ok(meta) = item.metadata() else { continue };
                        if !meta.is_file() || !name.ends_with(&format!(".{SECTION_EXT}")) {
                            continue;
                        }
                        let modified = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
                        state.clock = state.clock.max(modified);
                        state.total += meta.len();
                        state.files.insert(
                            name.clone(),
                            DiskFile {
                                bytes: meta.len(),
                                last_used: modified,
                                sha: name.split('.').next().unwrap_or("").to_string(),
                                key: String::new(),
                            },
                        );
                    }
                }
                Some((root, Mutex::new(state)))
            })
            .as_ref()?;
        Some((
            root,
            state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        ))
    }

    /// The compressed bytes and text length stored for `(sha256, key)`.
    fn get(&self, sha256: &str, key: &str) -> Option<(Vec<u8>, usize)> {
        let (root, mut state) = self.state()?;
        let name = section_file_name(sha256, key);
        state.files.get(&name)?;
        let bytes = crate::cache::read_private(&root.join(&name), self.max_bytes).ok();
        let parsed = bytes.and_then(|bytes| {
            let newline = bytes.iter().position(|b| *b == b'\n')?;
            let header: SectionHeader = serde_json::from_slice(&bytes[..newline]).ok()?;
            (header.sha == sha256 && header.key == key)
                .then(|| (bytes[newline + 1..].to_vec(), header.text_bytes))
        });
        state.clock += 1;
        let clock = state.clock;
        match parsed {
            Some(found) => {
                if let Some(file) = state.files.get_mut(&name) {
                    file.last_used = clock;
                    file.key = key.to_string();
                }
                Some(found)
            }
            None => {
                // Unreadable or not what its name says: forget it.
                if let Some(file) = state.files.remove(&name) {
                    state.total -= file.bytes;
                }
                let _ = std::fs::remove_file(root.join(&name));
                None
            }
        }
    }

    /// Write a value; returns whether it was stored and the section keys of
    /// the same file that were dropped to make room.
    fn put(
        &self,
        sha256: &str,
        key: &str,
        packed: &[u8],
        text_bytes: usize,
    ) -> (bool, Vec<String>) {
        let Some((root, mut state)) = self.state() else {
            return (false, Vec::new());
        };
        let header = SectionHeader {
            sha: sha256.to_string(),
            key: key.to_string(),
            text_bytes,
        };
        let mut content = serde_json::to_vec(&header).unwrap_or_default();
        content.push(b'\n');
        content.extend_from_slice(packed);
        if content.len() as u64 > self.max_bytes {
            return (false, Vec::new());
        }
        let name = section_file_name(sha256, key);
        if crate::cache::write_private_atomic(&root.join(&name), &content).is_err() {
            return (false, Vec::new());
        }
        state.clock += 1;
        let clock = state.clock;
        if let Some(old) = state.files.insert(
            name.clone(),
            DiskFile {
                bytes: content.len() as u64,
                last_used: clock,
                sha: sha256.to_string(),
                key: key.to_string(),
            },
        ) {
            state.total -= old.bytes;
        }
        state.total += content.len() as u64;
        let mut evicted_same_file = Vec::new();
        while state.total > self.max_bytes {
            let victim = state
                .files
                .iter()
                .filter(|(n, _)| **n != name)
                .min_by_key(|(_, f)| (f.sha == sha256, f.last_used))
                .map(|(n, _)| n.clone());
            let Some(victim) = victim else { break };
            if let Some(file) = state.files.remove(&victim) {
                state.total -= file.bytes;
                if file.sha == sha256 {
                    evicted_same_file.push(if file.key.is_empty() {
                        "(section from an earlier run)".to_string()
                    } else {
                        file.key
                    });
                }
            }
            let _ = std::fs::remove_file(root.join(&victim));
        }
        (true, evicted_same_file)
    }

    fn clear(&self) {
        let Some((root, mut state)) = self.state() else {
            return;
        };
        for name in state.files.keys() {
            let _ = std::fs::remove_file(root.join(name));
        }
        state.files.clear();
        state.total = 0;
    }

    fn stats(&self) -> (usize, u64) {
        self.state()
            .map_or((0, 0), |(_, state)| (state.files.len(), state.total))
    }
}

/// A bounded cache of analysis results, keyed by a file's SHA-256 and a
/// section key (the section name plus the options that change its content,
/// for example `strings:min=4`).
///
/// Values are stored as deflate-compressed JSON text and the byte bound counts
/// the compressed size. When the cache is full, other files' values go first
/// (least recently used first); only then are older values of the file being
/// inserted dropped, and [`PutOutcome::evicted_same_file`] names them. A small
/// bounded map of parsed values (the "hot" map) sits in front of the store; a
/// value bigger than the hot bound is parsed for the caller and not kept
/// parsed. With [`SectionCache::with_disk`] every value is also written under
/// the cache directory and survives restarts.
pub struct SectionCache {
    inner: Mutex<Inner>,
    max_bytes: usize,
    max_entries: usize,
    hot_max_bytes: usize,
    disk: Option<DiskTier>,
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

/// A snapshot of a [`SectionCache`] for `cache_status`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SectionStats {
    pub entries: usize,
    pub bytes: usize,
    pub max_bytes: usize,
    pub max_entries: usize,
    pub hot_entries: usize,
    pub hot_bytes: usize,
    pub disk_enabled: bool,
    pub disk_files: usize,
    pub disk_bytes: u64,
    pub disk_max_bytes: u64,
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

/// Largest text one cached value may inflate to. A header claiming more is
/// treated as a corrupt file.
const MAX_INFLATED_BYTES: usize = 1 << 30;
/// Most bytes reserved up front for an inflated value; the buffer grows with
/// the data actually read, so a corrupt header cannot reserve gigabytes.
const MAX_INFLATE_RESERVE: usize = 64 << 20;

fn inflate(data: &[u8], text_bytes: usize) -> Option<String> {
    use std::io::Read;
    if text_bytes > MAX_INFLATED_BYTES {
        return None;
    }
    let mut out = String::with_capacity(text_bytes.min(MAX_INFLATE_RESERVE));
    // One byte more than declared: a stream longer than its header says is corrupt.
    flate2::read::DeflateDecoder::new(data)
        .take(text_bytes as u64 + 1)
        .read_to_string(&mut out)
        .ok()?;
    (out.len() <= text_bytes).then_some(out)
}

impl SectionCache {
    /// A cache holding at most `max_entries` values and `max_bytes` bytes of
    /// compressed JSON text in total.
    pub fn new(max_bytes: usize, max_entries: usize) -> Self {
        Self::with_hot_limit(max_bytes, max_entries, SECTION_CACHE_HOT_BYTES)
    }

    /// Like [`Self::new`], with the bound (source text bytes) of the parsed
    /// hot map. A value bigger than the bound is never kept parsed.
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
            disk: None,
        }
    }

    /// Also keep every value on disk under `dir`, at most `max_disk_bytes`
    /// of files. The directory is prepared on first use; if it is unusable
    /// the cache stays in memory.
    #[must_use]
    pub fn with_disk(mut self, dir: Arc<CacheDir>, max_disk_bytes: u64) -> Self {
        if max_disk_bytes > 0 {
            self.disk = Some(DiskTier {
                dir,
                max_bytes: max_disk_bytes,
                state: OnceLock::new(),
            });
        }
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
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

    /// Mark a stored value as used and hand out its compressed bytes. A value
    /// that is only on disk is brought back into memory first.
    fn touch(&self, sha256: &str, section_key: &str) -> Option<(Arc<[u8]>, usize)> {
        let key = (sha256.to_string(), section_key.to_string());
        {
            let mut inner = self.lock();
            inner.tick += 1;
            let tick = inner.tick;
            if let Some(hot) = inner.hot.get_mut(&key) {
                hot.last_used = tick;
            }
            if let Some(slot) = inner.map.get_mut(&key) {
                slot.last_used = tick;
                return Some((Arc::clone(&slot.data), slot.text_bytes));
            }
        }
        let (packed, text_bytes) = self.disk.as_ref()?.get(sha256, section_key)?;
        let data: Arc<[u8]> = Arc::from(packed);
        if data.len() <= self.max_bytes {
            let mut inner = self.lock();
            inner.tick += 1;
            let tick = inner.tick;
            if !inner.map.contains_key(&key) {
                self.insert_slot(&mut inner, &key, Arc::clone(&data), text_bytes, tick, true);
            }
        }
        Some((data, text_bytes))
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
        if text_bytes > self.hot_max_bytes {
            // Too big to keep parsed: one drill-down on a huge section must not
            // leave many times its size resident.
            return Some(parsed);
        }
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

    /// Insert a slot and evict until the bounds hold. Returns the keys of the
    /// same file whose values are gone from memory and have no disk copy.
    fn insert_slot(
        &self,
        inner: &mut Inner,
        key: &CacheKey,
        data: Arc<[u8]>,
        text_bytes: usize,
        tick: u64,
        on_disk: bool,
    ) -> Vec<String> {
        inner.remove(key);
        inner.bytes += data.len();
        inner.map.insert(
            key.clone(),
            Slot {
                data,
                text_bytes,
                last_used: tick,
                on_disk,
            },
        );
        let mut lost_same_file = Vec::new();
        while inner.bytes > self.max_bytes || inner.map.len() > self.max_entries {
            // Other files' values first, then older values of this file; the
            // value just stored is never the victim.
            let victim = inner
                .map
                .iter()
                .filter(|(k, _)| *k != key)
                .min_by_key(|(k, slot)| (k.0 == key.0, slot.last_used))
                .map(|(k, _)| k.clone());
            let Some(victim) = victim else { break };
            if let Some(slot) = inner.remove(&victim) {
                if victim.0 == key.0 && !slot.on_disk {
                    lost_same_file.push(victim.1);
                }
            }
        }
        lost_same_file
    }

    /// Store JSON text as it is (compressed).
    pub fn put_text(&self, sha256: &str, section_key: &str, text: String) -> PutOutcome {
        let text_bytes = text.len();
        let not_kept = PutOutcome {
            kept: false,
            bytes: text_bytes,
            evicted_same_file: Vec::new(),
        };
        if text_bytes > MAX_INFLATED_BYTES {
            return not_kept;
        }
        let Some(packed) = compress(&text) else {
            return not_kept;
        };
        drop(text);
        let (on_disk, mut evicted_same_file) = match &self.disk {
            Some(disk) => disk.put(sha256, section_key, &packed, text_bytes),
            None => (false, Vec::new()),
        };
        if packed.len() > self.max_bytes {
            // Too big for memory: kept only if the disk took it.
            return PutOutcome {
                kept: on_disk,
                bytes: text_bytes,
                evicted_same_file,
            };
        }
        let mut inner = self.lock();
        inner.tick += 1;
        let tick = inner.tick;
        let key = (sha256.to_string(), section_key.to_string());
        evicted_same_file.extend(self.insert_slot(
            &mut inner,
            &key,
            Arc::from(packed),
            text_bytes,
            tick,
            on_disk,
        ));
        PutOutcome {
            kept: true,
            bytes: text_bytes,
            evicted_same_file,
        }
    }

    /// Number of values held in memory.
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// True when nothing is held in memory.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Compressed bytes held in memory.
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// A snapshot of the sizes and bounds.
    pub fn stats(&self) -> SectionStats {
        let (disk_files, disk_bytes) = self.disk.as_ref().map_or((0, 0), DiskTier::stats);
        let inner = self.lock();
        SectionStats {
            entries: inner.map.len(),
            bytes: inner.bytes,
            max_bytes: self.max_bytes,
            max_entries: self.max_entries,
            hot_entries: inner.hot.len(),
            hot_bytes: inner.hot_bytes,
            disk_enabled: self.disk.as_ref().is_some_and(|d| d.dir.ready().is_some()),
            disk_files,
            disk_bytes,
            disk_max_bytes: self.disk.as_ref().map_or(0, |d| d.max_bytes),
        }
    }

    /// Drop everything, on disk too.
    pub fn clear(&self) {
        {
            let mut inner = self.lock();
            inner.map.clear();
            inner.bytes = 0;
            inner.hot.clear();
            inner.hot_bytes = 0;
        }
        if let Some(disk) = &self.disk {
            disk.clear();
        }
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
    cache_dir: Arc<CacheDir>,
    analysis_cache: OnceLock<Arc<AnalysisCache>>,
    string_tracker: OnceLock<Arc<StringTracker>>,
    section_cache: Arc<SectionCache>,
    /// Hashes already computed, keyed by path (see [`Self::file_sha256`]).
    file_identities: Mutex<HashMap<PathBuf, FileIdentity>>,
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
        let cache_dir = Arc::new(CacheDir::new(config.cache_dir.clone()));
        let section_cache = Arc::new(if config.cache_enabled {
            SectionCache::new(
                config.section_cache_max_bytes,
                config.section_cache_max_entries,
            )
            .with_disk(Arc::clone(&cache_dir), config.section_disk_max_bytes)
        } else {
            // Caching is off: nothing is kept, every call recomputes.
            SectionCache::new(0, 0)
        });
        Self {
            config,
            policy,
            cache_dir,
            analysis_cache: OnceLock::new(),
            string_tracker: OnceLock::new(),
            file_identities: Mutex::new(HashMap::new()),
            section_cache,
            slots: Arc::new(tokio::sync::Semaphore::new(config_slots)),
        }
    }

    /// The configuration this state was built from.
    pub const fn config(&self) -> &StateConfig {
        &self.config
    }

    /// Build the analysis cache and string tracker now and prepare the cache
    /// directory, so an unusable one is reported at start-up (one stderr
    /// line) and not in the middle of a call. Reads no cached results.
    pub fn warm_up(&self) {
        let _ = self.analysis_cache();
        let _ = self.string_tracker();
        if self.config.cache_enabled {
            let _ = self.cache_dir.ready();
        }
    }

    /// True unless caching was switched off (`--no-cache`).
    pub const fn cache_enabled(&self) -> bool {
        self.config.cache_enabled
    }

    /// The process-wide analysis cache (the one `/cache/*` reads).
    ///
    /// If the cache directory cannot be created or written the cache is
    /// memory-only and one line is printed to stderr; with caching off it is
    /// memory-only and nothing is recorded in it.
    pub fn analysis_cache(&self) -> Arc<AnalysisCache> {
        Arc::clone(self.analysis_cache.get_or_init(|| {
            Arc::new(if self.config.cache_enabled {
                AnalysisCache::lazy(Arc::clone(&self.cache_dir)).with_limits(
                    self.config.cache_max_bytes,
                    crate::cache::DEFAULT_MAX_TOTAL_ENTRIES,
                )
            } else {
                AnalysisCache::memory_only()
            })
        }))
    }

    /// Forget cached analyses (history, sections, files on disk).
    pub async fn clear_analysis_caches(&self) -> anyhow::Result<()> {
        self.section_cache.clear();
        self.analysis_cache().clear().await
    }

    /// The SHA-256 of a file, computed once per unchanged file.
    ///
    /// A repeat call for a file whose size, modification time and inode are
    /// as they were when it was hashed returns the remembered hash without
    /// reading the file. A file modified in the last two seconds before it was
    /// hashed is hashed again (a later edit could keep its timestamp). Any
    /// difference means the file is hashed again, and the same content still
    /// finds its cached sections because they are keyed by the hash.
    pub async fn file_sha256(&self, path: &Path) -> Result<String, String> {
        let stamp = FileIdentity::stat(path);
        if let Some(stamp) = &stamp {
            let known = self.identities().get(path).cloned();
            if let Some(known) = known {
                if known.matches(stamp) {
                    return Ok(known.sha256);
                }
            }
        }
        let sha256 = crate::hash::calculate_sha256_only(path)
            .await
            .map_err(|error| format!("Cannot read {}: {error:#}", path.display()))?;
        if let Some(mut stamp) = stamp {
            stamp.sha256 = sha256.clone();
            stamp.hashed_at = SystemTime::now();
            let mut known = self.identities();
            if known.len() >= FILE_IDENTITY_LIMIT {
                known.clear();
            }
            known.insert(path.to_path_buf(), stamp);
        }
        Ok(sha256)
    }

    fn identities(&self) -> MutexGuard<'_, HashMap<PathBuf, FileIdentity>> {
        self.file_identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The process-wide string tracker (the one `/strings/*` reads).
    pub fn string_tracker(&self) -> Arc<StringTracker> {
        Arc::clone(
            self.string_tracker
                .get_or_init(|| Arc::new(StringTracker::new())),
        )
    }

    /// The bounded in-memory cache of complete section results.
    pub fn section_cache(&self) -> &SectionCache {
        &self.section_cache
    }

    /// A shared handle on the section cache, for work that moves to a
    /// blocking thread.
    pub fn section_cache_handle(&self) -> Arc<SectionCache> {
        Arc::clone(&self.section_cache)
    }

    /// The allowed roots as the path policy uses them: `~` expanded and
    /// existing directories canonicalized. Empty means unrestricted.
    pub fn allowed_roots(&self) -> &[PathBuf] {
        self.policy.roots()
    }

    /// Whether a path stored by an earlier call (analysis history, string
    /// index) may be shown by this server. Unrestricted servers show every
    /// path. With roots, the path must be inside a root: canonical when the
    /// file still exists, otherwise judged by the stored path itself (a path
    /// with `..` or a relative path is never shown).
    pub fn path_is_visible(&self, stored: &str) -> bool {
        self.display_path(stored).is_some()
    }

    /// The spelling of a stored path this server may print, or `None` when
    /// the path must stay hidden. Unrestricted servers print the stored
    /// spelling. With roots, the canonical path is printed (a file stored as
    /// `<outside>/../in/a.bin` shows as `<root>/in/a.bin`, so no directory
    /// name outside the roots is ever shown) and it must lie inside a root.
    pub fn display_path(&self, stored: &str) -> Option<String> {
        let roots = self.policy.roots();
        if roots.is_empty() {
            return Some(stored.to_string());
        }
        let path = std::path::Path::new(stored);
        let canonical = match std::fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(_) => {
                // The file is gone: resolve the nearest directory that still
                // exists and keep the rest of the stored name.
                let plain = path.is_absolute()
                    && path
                        .components()
                        .all(|part| !matches!(part, std::path::Component::ParentDir));
                if !plain {
                    return None;
                }
                let mut tail = Vec::new();
                let mut head = path;
                let mut base = None;
                while let Some(parent) = head.parent() {
                    if let Some(name) = head.file_name() {
                        tail.push(name);
                    }
                    if let Ok(found) = std::fs::canonicalize(parent) {
                        base = Some(found);
                        break;
                    }
                    head = parent;
                }
                let mut resolved = base.unwrap_or_else(|| path.to_path_buf());
                resolved.extend(tail.iter().rev());
                resolved
            }
        };
        roots
            .iter()
            .any(|root| canonical.starts_with(root))
            .then(|| canonical.to_string_lossy().into_owned())
    }

    /// Rewrites the paths in a cache row's arguments for a rooted server: a
    /// value equal to `stored`, or the cache's cut of it (the first 200
    /// characters plus "... (N characters in all)"), becomes `shown`; any
    /// other string argument whose key ends in `path` is printed in its
    /// canonical spelling, or as a placeholder when it is outside the roots.
    pub fn show_args_path(
        &self,
        args: &mut std::collections::HashMap<String, serde_json::Value>,
        stored: &str,
        shown: &str,
    ) {
        const CUT_TAIL: &str = " characters in all)";
        const CUT_HEAD: usize = 200;
        let stored_head: String = stored.chars().take(CUT_HEAD).collect();
        for (key, value) in args.iter_mut() {
            let Some(text) = value.as_str() else { continue };
            let is_stored = text == stored
                || (stored.chars().count() > CUT_HEAD
                    && text.starts_with(&stored_head)
                    && text.ends_with(CUT_TAIL));
            let replacement = if is_stored {
                Some(shown.to_string())
            } else if key.ends_with("path") {
                Some(
                    self.display_path(text)
                        .unwrap_or_else(|| "<outside the allowed roots>".to_string()),
                )
            } else {
                None
            };
            if let Some(new) = replacement {
                if new != text {
                    *value = serde_json::Value::String(new);
                }
            }
        }
    }

    /// Replaces, anywhere in a stored result, each string equal to `stored`
    /// by `shown` (one pass over the value).
    fn show_value_path(value: &mut serde_json::Value, stored: &str, shown: &str) {
        match value {
            serde_json::Value::String(text) if text == stored => *text = shown.to_string(),
            serde_json::Value::Array(items) => items
                .iter_mut()
                .for_each(|item| Self::show_value_path(item, stored, shown)),
            serde_json::Value::Object(map) => map
                .values_mut()
                .for_each(|item| Self::show_value_path(item, stored, shown)),
            _ => {}
        }
    }

    /// The history rows this server may show, newest first. A rooted server
    /// prints each row under its canonical path (also in the arguments) and
    /// matches `file_path_pattern` against that printed path, never against
    /// the spelling the row was stored under.
    pub fn visible_cache_rows(
        &self,
        query: &crate::cache::CacheSearchQuery,
    ) -> Vec<crate::cache::EntrySummary> {
        if self.policy.roots().is_empty() {
            return self.analysis_cache().list_summaries(query);
        }
        let mut stored_query = query.clone();
        stored_query.file_path_pattern = None;
        self.analysis_cache()
            .list_summaries(&stored_query)
            .into_iter()
            .filter_map(|mut row| {
                let shown = self.display_path(&row.file_path)?;
                if let Some(pattern) = &query.file_path_pattern {
                    if !shown.contains(pattern.as_str()) {
                        return None;
                    }
                }
                self.show_args_path(&mut row.tool_args, &row.file_path, &shown);
                row.file_path = shown;
                Some(row)
            })
            .collect()
    }

    /// Full cache entries this server may show, with the same printing and
    /// matching rule as `visible_cache_rows`.
    pub fn visible_cache_entries(
        &self,
        entries: Vec<crate::cache::CacheEntry>,
        pattern: Option<&str>,
    ) -> Vec<crate::cache::CacheEntry> {
        if self.policy.roots().is_empty() {
            return entries;
        }
        entries
            .into_iter()
            .filter_map(|mut entry| {
                let shown = self.display_path(&entry.file_path)?;
                if pattern.is_some_and(|p| !shown.contains(p)) {
                    return None;
                }
                self.show_args_path(&mut entry.tool_args, &entry.file_path, &shown);
                if entry.file_path != shown {
                    Self::show_value_path(&mut entry.result, &entry.file_path, &shown);
                }
                entry.file_path = shown;
                Some(entry)
            })
            .collect()
    }

    /// A string-index entry as this server may show it: occurrences and files
    /// outside the roots are dropped (`None` when none are left). The total
    /// then counts the occurrences kept. Unrestricted servers get the entry
    /// unchanged.
    pub fn visible_string_entry(&self, mut entry: StringEntry) -> Option<StringEntry> {
        if self.policy.roots().is_empty() {
            return Some(entry);
        }
        let hidden = entry.unique_files.iter().any(|f| !self.path_is_visible(f))
            || entry
                .occurrences
                .iter()
                .any(|o| !self.path_is_visible(&o.file_path));
        entry.unique_files.retain(|f| self.path_is_visible(f));
        if entry.unique_files.is_empty() {
            return None;
        }
        if hidden {
            entry
                .occurrences
                .retain(|o| self.path_is_visible(&o.file_path));
            entry.total_occurrences = entry.occurrences.len().max(entry.unique_files.len());
        }
        Some(entry)
    }

    /// Whether the string index holds `value` in a file this server may show.
    pub fn string_value_is_visible(&self, value: &str) -> bool {
        self.policy.roots().is_empty()
            || self
                .string_tracker()
                .get_string_details(value)
                .and_then(|entry| self.visible_string_entry(entry))
                .is_some()
    }

    /// String statistics without the values that occur only in files outside
    /// the roots. Counts stay global (they name no path or value).
    pub fn visible_string_statistics(&self, mut stats: StringStatistics) -> StringStatistics {
        if self.policy.roots().is_empty() {
            return stats;
        }
        stats
            .most_common
            .retain(|(value, _)| self.string_value_is_visible(value));
        stats
            .suspicious_strings
            .retain(|value| self.string_value_is_visible(value));
        stats
            .high_entropy_strings
            .retain(|(value, _)| self.string_value_is_visible(value));
        stats
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
        let policy = self.policy.clone();
        let joined = tokio::task::spawn_blocking(move || {
            CURRENT_SECTION.with(|current| current.set(None));
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                super::paths::with_current_policy(policy, work)
            }))
            .map_err(|payload| Crash {
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
            let cache = self.section_cache_handle();
            let path = raw_path.to_string();
            let resolved = self
                .resolve_path(raw_path, "File", super::paths::Expect::File)
                .ok();
            let hash = sha256.to_string();
            match self
                .run_blocking("string tracking", move || {
                    // With the file's string index the occurrences carry
                    // their offsets; without it they are tracked plain.
                    super::tools_services::track_analyzed_strings(
                        &cache,
                        &tracker,
                        resolved.as_deref(),
                        &path,
                        &hash,
                        &strings,
                    )
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

        if !self.config.cache_enabled {
            return;
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
        let mtime = super::paths::expand_tilde(raw_path)
            .ok()
            .and_then(|path| FileIdentity::stat(&path))
            .map(|stamp| stamp.mtime_ms());
        let _ = self
            .analysis_cache()
            .add_entry_with_mtime(entry, mtime)
            .await;
    }

    /// What a successful `yara_scan_file` call leaves behind: one cache entry.
    pub async fn record_yara_scan(
        &self,
        raw_args: &JsonObject,
        raw_path: &str,
        result: &Value,
        started: Instant,
    ) {
        if !self.config.cache_enabled {
            return;
        }
        // One key per path, rule and options: scans with different rules no
        // longer share (and overwrite) one slot.
        let scan_key = format!(
            "yara-{}",
            &blake3::hash(
                serde_json::to_string(raw_args)
                    .unwrap_or_default()
                    .as_bytes()
            )
            .to_hex()
            .as_str()[..32]
        );
        let entry = CacheEntry {
            file_path: raw_path.to_string(),
            file_hash: scan_key,
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

/// Files whose hash is remembered at once (the table is emptied when full).
const FILE_IDENTITY_LIMIT: usize = 4096;
/// A file modified this recently when hashed is not trusted by timestamp.
const RACY_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// What identifies an unchanged file without reading it.
///
/// The modification time alone is not enough: an archive extractor or `touch -r`
/// can put it back after the content was rewritten with the same length. So the
/// identity also holds what a write changes and the writer cannot set back.
/// On Unix that is the change time (`ctime`, nanoseconds), which every write,
/// truncate, rename-over and `utimensat` call advances, plus the device and
/// inode numbers. Std exposes no change time on Windows, so there the identity
/// is the length, the write time, the creation time and nothing else: an
/// in-place rewrite of the same length whose write time is set back is not
/// detected there (a replaced file, which gets a new creation time, is). The
/// identity lives in memory only, so no stored entry of an older build exists.
/// When anything differs the file is hashed again, which is always correct.
#[derive(Debug, Clone)]
struct FileIdentity {
    len: u64,
    modified: SystemTime,
    /// Last status change (Unix `ctime`), or the creation time elsewhere.
    changed: SystemTime,
    inode: u64,
    device: u64,
    sha256: String,
    hashed_at: SystemTime,
}

impl FileIdentity {
    fn stat(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        #[cfg(unix)]
        let (inode, device, changed) = {
            use std::os::unix::fs::MetadataExt;
            let nanos = u32::try_from(meta.ctime_nsec()).unwrap_or(0);
            let changed = match u64::try_from(meta.ctime()) {
                Ok(secs) => UNIX_EPOCH + std::time::Duration::new(secs, nanos),
                Err(_) => {
                    UNIX_EPOCH - std::time::Duration::new(meta.ctime().unsigned_abs(), 0)
                        + std::time::Duration::from_nanos(u64::from(nanos))
                }
            };
            (meta.ino(), meta.dev(), changed)
        };
        #[cfg(not(unix))]
        let (inode, device, changed) = (0, 0, meta.created().unwrap_or(UNIX_EPOCH));
        Some(Self {
            len: meta.len(),
            modified: meta.modified().ok()?,
            changed,
            inode,
            device,
            sha256: String::new(),
            hashed_at: UNIX_EPOCH,
        })
    }

    fn matches(&self, now: &Self) -> bool {
        self.len == now.len
            && self.modified == now.modified
            && self.changed == now.changed
            && self.inode == now.inode
            && self.device == now.device
            && self
                .modified
                .max(self.changed)
                .checked_add(RACY_WINDOW)
                .is_some_and(|stable| stable <= self.hashed_at)
    }

    /// Modification time as Unix milliseconds.
    fn mtime_ms(&self) -> i64 {
        self.modified
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

/// The size and modification time (Unix milliseconds) of a file, as recorded
/// with analysis entries and checked by `AnalysisCache::find_valid`.
pub fn file_stamp(path: &Path) -> Option<(u64, i64)> {
    FileIdentity::stat(path).map(|stamp| (stamp.len, stamp.mtime_ms()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inflate_rejects_a_lying_header_without_reserving_or_inflating_it() {
        let packed = compress(&"x".repeat(1000)).unwrap();
        assert_eq!(inflate(&packed, 1000).unwrap().len(), 1000);
        // A header far bigger than any legal value: refused before any allocation.
        assert!(inflate(&packed, 1 << 60).is_none());
        // A header smaller than the stream: the stream is cut and refused.
        assert!(inflate(&packed, 10).is_none());
        // A big header within bounds still reserves only a bounded buffer.
        assert!(inflate(&packed, MAX_INFLATED_BYTES).is_some());
    }

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
    fn a_value_over_the_hot_limit_is_returned_but_not_kept_parsed() {
        // A hot limit smaller than any one value: nothing is kept parsed, so a
        // big section read once does not stay resident many times over.
        let cache = SectionCache::with_hot_limit(usize::MAX, 100, 10);
        cache.put("h", "a", &json!(noisy(100, 1)));
        let first = cache.get("h", "a").unwrap();
        let second = cache.get("h", "a").unwrap();
        assert_eq!(*first, *second);
        assert!(!Arc::ptr_eq(&first, &second), "parsed again, not retained");
        assert_eq!(cache.stats().hot_entries, 0);
        assert_eq!(cache.stats().hot_bytes, 0);
    }

    #[test]
    fn the_hot_map_keeps_small_values_within_its_bound() {
        // Room for about one 102-byte value.
        let cache = SectionCache::with_hot_limit(usize::MAX, 100, 150);
        cache.put("h", "a", &json!(noisy(100, 1)));
        cache.put("h", "b", &json!(noisy(100, 2)));
        let b1 = cache.get("h", "b").unwrap();
        assert!(Arc::ptr_eq(&b1, &cache.get("h", "b").unwrap()));
        let a1 = cache.get("h", "a").unwrap();
        assert!(Arc::ptr_eq(&a1, &cache.get("h", "a").unwrap()));
        assert!(cache.stats().hot_bytes <= 150);
        // `b` was pushed out of the hot map by `a`; it parses again, correctly.
        let b2 = cache.get("h", "b").unwrap();
        assert!(!Arc::ptr_eq(&b1, &b2));
        assert_eq!(*b1, *b2);
    }

    #[test]
    fn sections_on_disk_survive_a_restart_and_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = Arc::new(CacheDir::new(dir.path().join("c")));
        let first = SectionCache::default().with_disk(Arc::clone(&cache_dir), 1 << 20);
        first.put("sha1", "strings:min=4", &json!({"a": [1, 2, 3]}));
        drop(first);
        // A new process: nothing in memory, the value comes from the file.
        let second = SectionCache::default()
            .with_disk(Arc::new(CacheDir::new(dir.path().join("c"))), 1 << 20);
        assert!(second.is_empty());
        assert_eq!(
            *second.get("sha1", "strings:min=4").unwrap(),
            json!({"a": [1, 2, 3]})
        );
        assert_eq!(second.len(), 1, "now also in memory");
        assert!(second.get("sha1", "strings:min=8").is_none());
        assert!(second.get("sha2", "strings:min=4").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let sections = dir.path().join("c/sections");
            assert_eq!(mode(&sections), 0o700);
            for file in std::fs::read_dir(&sections).unwrap().flatten() {
                assert_eq!(mode(&file.path()), 0o600);
            }
        }
        second.clear();
        assert!(second.get("sha1", "strings:min=4").is_none());
        assert_eq!(second.stats().disk_files, 0);
    }

    #[test]
    fn the_disk_tier_is_bounded_and_evicts_other_files_first() {
        let dir = tempfile::tempdir().unwrap();
        let cache = SectionCache::new(usize::MAX, 100)
            .with_disk(Arc::new(CacheDir::new(dir.path().join("c"))), 4_000);
        cache.put("other", "a", &json!(noisy(1_500, 1)));
        cache.put("mine", "s1", &json!(noisy(1_500, 2)));
        let outcome = cache.put("mine", "s2", &json!(noisy(1_500, 3)));
        assert!(outcome.kept);
        assert!(outcome.evicted_same_file.is_empty(), "{outcome:?}");
        assert!(cache.stats().disk_bytes <= 4_000, "{:?}", cache.stats());
        // After a restart only what is on disk is left: `other` went first.
        let fresh = SectionCache::new(usize::MAX, 100)
            .with_disk(Arc::new(CacheDir::new(dir.path().join("c"))), 4_000);
        assert!(fresh.get("other", "a").is_none());
        assert!(fresh.get("mine", "s1").is_some());
        assert!(fresh.get("mine", "s2").is_some());
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
        // The section cache says its disk tier is off, not merely unconfigured.
        let sections = state.section_cache();
        sections.put("h", "k", &json!([1]));
        assert!(!sections.stats().disk_enabled);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unchanged_file_is_hashed_once_and_a_changed_one_again() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"first content").unwrap();
        // Old enough that its timestamps can be trusted: the change time is the
        // moment of the write above, so wait out the racy window.
        let old = filetime::FileTime::from_unix_time(1_000_000, 0);
        filetime::set_file_mtime(&path, old).unwrap();
        std::thread::sleep(RACY_WINDOW + std::time::Duration::from_millis(300));
        let state = ServerState::default();
        let first = state.file_sha256(&path).await.unwrap();
        assert_eq!(first.len(), 64);
        // Hashed after the window: the remembered answer is trusted as it is.
        let stamp = FileIdentity::stat(&path).unwrap();
        let known = state.identities().get(&path).cloned().unwrap();
        assert!(known.matches(&stamp));
        assert_eq!(state.file_sha256(&path).await.unwrap(), first);

        // A permission change moves the change time: hashed again, which is
        // visible because the file can no longer be read.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&path).is_err() {
            assert!(!known.matches(&FileIdentity::stat(&path).unwrap()));
            assert!(state.file_sha256(&path).await.is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Changed (size and time): hashed again, to the new content's hash.
        std::fs::write(&path, b"second, longer content").unwrap();
        let second = state.file_sha256(&path).await.unwrap();
        assert_ne!(second, first);
        // Same length, modification time put back: the change time still moves.
        std::fs::write(&path, b"SECOND, LONGER CONTENT").unwrap();
        filetime::set_file_mtime(&path, old).unwrap();
        let third = state.file_sha256(&path).await.unwrap();
        assert_ne!(third, second);
        // A file that does not exist is an error naming it.
        let error = state
            .file_sha256(&dir.path().join("gone"))
            .await
            .unwrap_err();
        assert!(error.contains("gone"), "{error}");
    }

    #[test]
    fn building_a_state_needs_no_runtime() {
        let state = ServerState::default();
        assert!(state.section_cache().is_empty());
        // Without a runtime the cache is memory-only instead of panicking.
        let _ = state.analysis_cache();
    }
}
