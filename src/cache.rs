//! The analysis history: what each tool call returned, kept per file hash.
//!
//! Entries live in a private per-user directory (mode 0700, files 0600), one
//! file per file hash, each written to a temporary name and renamed into
//! place, so a reader (or a process that exits mid-write) never sees half an
//! entry. Start-up reads only an index (`metadata.json`: one summary row per
//! entry, no results); the results of a hash are read when something asks for
//! them. The cache is bounded in total bytes and in entries, evicting the
//! least recently used file hash first, and a lookup can be validated against
//! the file's size and modification time before it is trusted.
//!
//! When the directory cannot be used the cache is memory-only (one line on
//! stderr); it never panics and never fails a tool call.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use utoipa::ToSchema;

/// Default bound, in bytes on disk, of all cached entries together.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Default bound on the number of cached entries.
pub const DEFAULT_MAX_TOTAL_ENTRIES: usize = 10_000;
/// Default bound on the entries kept per file hash.
pub const DEFAULT_MAX_ENTRIES_PER_FILE: usize = 100;
/// Largest result (compact JSON bytes) one entry keeps; bigger ones are
/// replaced by a note saying how big they were.
pub const DEFAULT_MAX_ENTRY_RESULT_BYTES: usize = 4 * 1024 * 1024;
/// Name of the index file.
const INDEX_FILE: &str = "metadata.json";
/// Largest index file that is read at start-up.
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// The user id this process creates files as, found by creating one in `dir`.
#[cfg(unix)]
fn creator_uid_in(dir: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let probe = dir.join(format!(".owner-probe-{}", std::process::id()));
    let _ = fs::remove_file(&probe);
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let _ = fs::remove_file(&probe);
    uid
}

/// Refuse a directory owned by `dir_uid` when this process creates files as
/// `creator_uid`.
#[cfg(unix)]
fn check_owner(dir_uid: u32, creator_uid: u32) -> std::io::Result<()> {
    if dir_uid == creator_uid {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "the directory belongs to another user (uid {dir_uid}); pick a directory of your own \
             with --cache-dir"
        ),
    ))
}

/// Create `dir` (and its parents) for the cache. On Unix the directory is made
/// readable by its owner only (mode 0700), also when it already exists, and a
/// directory that belongs to another user is refused.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let meta = fs::metadata(dir)?;
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "not a directory",
            ));
        }
        check_owner(meta.uid(), creator_uid_in(dir)?)?;
        if meta.permissions().mode() & 0o777 != 0o700 {
            // An older run (or another tool) may have made it with looser rights.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` through a temporary file in the same directory and
/// a rename. The file is created fresh (never through a planted symlink) and,
/// on Unix, readable by its owner only (mode 0600).
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("entry");
    let temp = path.with_file_name(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let outcome = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.flush()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temp);
    }
    outcome
}

/// Read a cache file without following a symlink in its place.
pub fn read_private(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    // The directory is private, so the gap between this check and the open
    // is not reachable by another user.
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::other("cache file is a symbolic link"));
    }
    let file = fs::File::open(path)?;
    let mut out = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut out)?;
    if out.len() as u64 > max_bytes {
        return Err(std::io::Error::other("cache file is too big"));
    }
    Ok(out)
}

/// A cache directory that is prepared the first time something needs it.
/// Shared by the analysis cache and the section cache so an unusable
/// directory is reported once.
#[derive(Debug)]
pub struct CacheDir {
    path: PathBuf,
    ready: OnceLock<Option<PathBuf>>,
}

impl CacheDir {
    /// A directory to prepare on first use.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ready: OnceLock::new(),
        }
    }

    /// The directory as configured.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn resolved(path: PathBuf) -> Self {
        let ready = OnceLock::new();
        let _ = ready.set(Some(path.clone()));
        Self { path, ready }
    }

    /// The directory when it is usable (created, owned by this user, mode 0700,
    /// writable). Otherwise one line goes to stderr, once, and this is `None`.
    pub fn ready(&self) -> Option<&Path> {
        self.ready
            .get_or_init(|| match prepare_dir(&self.path) {
                Ok(()) => Some(self.path.clone()),
                Err(error) => {
                    eprintln!(
                        "file-scanner: cache directory {} is not usable ({error}); results are \
                         cached in memory only",
                        self.path.display()
                    );
                    None
                }
            })
            .as_deref()
    }
}

fn prepare_dir(dir: &Path) -> std::io::Result<()> {
    create_private_dir(dir)?;
    let probe = dir.join(format!(".write-probe-{}", std::process::id()));
    write_private_atomic(&probe, b"")?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CacheEntry {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    pub tool_args: HashMap<String, serde_json::Value>,
    pub result: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub file_size: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub total_entries: usize,
    pub total_unique_files: usize,
    pub cache_size_bytes: u64,
    pub last_updated: DateTime<Utc>,
}

/// An entry without its result: what the index holds and what listings show.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummary {
    pub file_path: String,
    pub file_hash: String,
    pub tool_name: String,
    /// The call's arguments in a bounded form: long strings and big values are
    /// shortened (the entry file keeps them whole).
    pub tool_args: HashMap<String, serde_json::Value>,
    /// Digest of the full arguments; lookups compare it, not `tool_args`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args_digest: String,
    pub timestamp: DateTime<Utc>,
    pub file_size: u64,
    /// Modification time of the file when it was analyzed (Unix milliseconds),
    /// when the caller recorded it; lets a lookup skip hashing the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_mtime_ms: Option<i64>,
    pub execution_time_ms: u64,
    /// Size of the stored result as compact JSON.
    pub result_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexRow {
    hash: String,
    file: String,
    bytes: u64,
    last_used_ms: u64,
    entries: Vec<EntrySummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    #[serde(flatten)]
    meta: CacheMetadata,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    index: Vec<IndexRow>,
}

struct Slot {
    rows: Vec<EntrySummary>,
    /// Bytes of the entry file (or an estimate for a memory-only slot).
    bytes: u64,
    last_used: u64,
    /// The entries themselves, for a slot that is not on disk.
    mem: Option<Vec<CacheEntry>>,
}

struct State {
    slots: HashMap<String, Slot>,
    clock: u64,
    loaded: bool,
}

struct Shared {
    /// Where entries persist; `None` is a memory-only cache.
    dir: Option<Arc<CacheDir>>,
    state: Mutex<State>,
    /// Set after the first failed write, so it is reported once.
    write_failed: std::sync::atomic::AtomicBool,
}

/// File name of the entry file of `hash` (the hash itself when it is plain).
fn entry_file_name(hash: &str) -> String {
    let plain = !hash.is_empty()
        && hash.len() <= 100
        && hash
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && hash != "metadata";
    if plain {
        format!("{hash}.json")
    } else {
        let digest = blake3::hash(hash.as_bytes()).to_hex();
        format!("h-{}.json", &digest.as_str()[..32])
    }
}

fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0)
}

#[derive(Clone)]
pub struct AnalysisCache {
    shared: Arc<Shared>,
    max_entries_per_file: usize,
    max_total_entries: usize,
    max_total_bytes: u64,
    max_entry_result_bytes: usize,
}

impl AnalysisCache {
    /// A cache persisting to `cache_dir`, created now. An error means the
    /// directory cannot be used; callers wanting to carry on use
    /// [`Self::memory_only`].
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        prepare_dir(&cache_dir)?;
        Ok(Self::build(Some(Arc::new(CacheDir::resolved(cache_dir)))))
    }

    /// A cache persisting to `dir`, which is prepared (and its index read) the
    /// first time the cache is used. If the directory is unusable the cache
    /// is memory-only and one line goes to stderr.
    pub fn lazy(dir: Arc<CacheDir>) -> Self {
        Self::build(Some(dir))
    }

    /// A cache that lives only in memory. Used when the cache directory cannot
    /// be created or written, or when caching is switched off.
    pub fn memory_only() -> Self {
        Self::build(None)
    }

    fn build(dir: Option<Arc<CacheDir>>) -> Self {
        Self {
            shared: Arc::new(Shared {
                dir,
                state: Mutex::new(State {
                    slots: HashMap::new(),
                    clock: 0,
                    loaded: false,
                }),
                write_failed: std::sync::atomic::AtomicBool::new(false),
            }),
            max_entries_per_file: DEFAULT_MAX_ENTRIES_PER_FILE,
            max_total_entries: DEFAULT_MAX_TOTAL_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_entry_result_bytes: DEFAULT_MAX_ENTRY_RESULT_BYTES,
        }
    }

    /// Set the total byte bound and the entry bound.
    #[must_use]
    pub fn with_limits(mut self, max_total_bytes: u64, max_total_entries: usize) -> Self {
        self.max_total_bytes = max_total_bytes;
        self.max_total_entries = max_total_entries.max(1);
        self
    }

    /// True when entries are written to disk.
    pub fn is_persistent(&self) -> bool {
        self.shared
            .dir
            .as_ref()
            .is_some_and(|dir| dir.ready().is_some())
    }

    /// The directory entries persist to, when they do.
    pub fn directory(&self) -> Option<PathBuf> {
        self.shared
            .dir
            .as_ref()
            .and_then(|dir| dir.ready().map(Path::to_path_buf))
    }

    /// The configured byte bound.
    pub const fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.loaded {
            state.loaded = true;
            if let Some(dir) = self.directory() {
                load_index(&mut state, &dir, self.max_total_bytes);
            }
        }
        state
    }

    fn tick(state: &mut State) -> u64 {
        state.clock = now_ms().max(state.clock + 1);
        state.clock
    }

    /// Read the entries of one slot (memory copy or entry file).
    fn read_slot(&self, hash: &str, slot: &Slot) -> Option<Vec<CacheEntry>> {
        if let Some(mem) = &slot.mem {
            return Some(mem.clone());
        }
        let dir = self.directory()?;
        let bytes = read_private(&dir.join(entry_file_name(hash)), self.max_total_bytes).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn report_write_failure(&self, error: &std::io::Error) {
        if !self
            .shared
            .write_failed
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!(
                "file-scanner: could not write the analysis cache ({error}); keeping results in \
                 memory for now"
            );
        }
    }

    /// Store an entry now (blocking). `file_mtime_ms` is the file's
    /// modification time, recorded so a later lookup can validate the file
    /// without hashing it.
    pub fn add_entry_sync(&self, entry: CacheEntry, file_mtime_ms: Option<i64>) {
        let mut entry = entry;
        let mut result_bytes = serde_json::to_vec(&entry.result).map_or(0, |v| v.len());
        if result_bytes > self.max_entry_result_bytes {
            entry.result = serde_json::json!({
                "omitted": "the result was too big for the analysis cache; run the call again to \
                            get it",
                "result_bytes": result_bytes,
            });
            result_bytes = serde_json::to_vec(&entry.result).map_or(0, |v| v.len());
        }
        let summary = EntrySummary {
            file_path: entry.file_path.clone(),
            file_hash: entry.file_hash.clone(),
            tool_name: entry.tool_name.clone(),
            tool_args: bounded_args(&entry.tool_args),
            args_digest: args_digest(&entry.tool_args),
            timestamp: entry.timestamp,
            file_size: entry.file_size,
            file_mtime_ms,
            execution_time_ms: entry.execution_time_ms,
            result_bytes,
        };
        let hash = entry.file_hash.clone();
        let persist_dir = self.directory();
        let mut state = self.lock();
        let tick = Self::tick(&mut state);

        // The entries already stored for this hash, then the new one.
        let mut entries = match state.slots.get(&hash) {
            Some(slot) => self.read_slot(&hash, slot).unwrap_or_default(),
            // No slot here: another process on this directory may have written
            // entries for the hash since the index was read; keep them.
            None => persist_dir
                .as_ref()
                .and_then(|dir| {
                    read_private(&dir.join(entry_file_name(&hash)), self.max_total_bytes).ok()
                })
                .and_then(|bytes| serde_json::from_slice::<Vec<CacheEntry>>(&bytes).ok())
                .unwrap_or_default(),
        };
        let mut rows = state
            .slots
            .get(&hash)
            .map(|slot| slot.rows.clone())
            .unwrap_or_default();
        // A file that went missing or unreadable leaves rows without entries.
        if rows.len() != entries.len() {
            rows = entries.iter().map(summary_of).collect();
        }
        entries.push(entry);
        rows.push(summary);
        while entries.len() > self.max_entries_per_file {
            entries.remove(0);
            rows.remove(0);
        }
        // One hash may not use more than the whole cache.
        let mut bytes = estimate_bytes(&rows);
        while bytes > self.max_total_bytes && entries.len() > 1 {
            entries.remove(0);
            rows.remove(0);
            bytes = estimate_bytes(&rows);
        }

        let mut mem = None;
        if let Some(dir) = &persist_dir {
            let written = serde_json::to_vec(&entries)
                .map_err(std::io::Error::other)
                .and_then(|json| {
                    write_private_atomic(&dir.join(entry_file_name(&hash)), &json)
                        .map(|()| json.len() as u64)
                });
            match written {
                Ok(len) => bytes = len,
                Err(error) => {
                    self.report_write_failure(&error);
                    mem = Some(entries);
                }
            }
        } else {
            mem = Some(entries);
        }
        state.slots.insert(
            hash.clone(),
            Slot {
                rows,
                bytes,
                last_used: tick,
                mem,
            },
        );
        // Another process on this directory may have added hashes since the
        // index was read; keep them in the index this process writes.
        if let Some(dir) = &persist_dir {
            for row in read_index(dir) {
                adopt_row(&mut state, dir, row);
            }
            // Hashes this process already holds may have grown on disk (another
            // process added an entry): take what is on disk before writing,
            // or this write would hide those rows from the index.
            refresh_changed_slots(&mut state, dir, &hash, self.max_total_bytes);
        }
        self.evict(&mut state, &hash);
        self.save_index(&state);
    }

    /// Drop least recently used hashes (never `keep`) until the bounds hold.
    fn evict(&self, state: &mut State, keep: &str) {
        loop {
            let total_entries: usize = state.slots.values().map(|s| s.rows.len()).sum();
            let total_bytes: u64 = state.slots.values().map(|s| s.bytes).sum();
            if total_entries <= self.max_total_entries && total_bytes <= self.max_total_bytes {
                return;
            }
            let victim = state
                .slots
                .iter()
                .filter(|(hash, _)| hash.as_str() != keep)
                .min_by_key(|(_, slot)| slot.last_used)
                .map(|(hash, _)| hash.clone());
            let Some(victim) = victim else { return };
            self.drop_slot(state, &victim);
        }
    }

    fn drop_slot(&self, state: &mut State, hash: &str) {
        if let Some(slot) = state.slots.remove(hash) {
            if slot.mem.is_none() {
                if let Some(dir) = self.directory() {
                    let _ = fs::remove_file(dir.join(entry_file_name(hash)));
                }
            }
        }
    }

    fn metadata_of(state: &State) -> CacheMetadata {
        CacheMetadata {
            total_entries: state.slots.values().map(|s| s.rows.len()).sum(),
            total_unique_files: state.slots.len(),
            cache_size_bytes: state.slots.values().map(|s| s.bytes).sum(),
            last_updated: Utc::now(),
        }
    }

    fn save_index(&self, state: &State) {
        let Some(dir) = self.directory() else { return };
        let index = IndexFile {
            meta: Self::metadata_of(state),
            version: 1,
            index: state
                .slots
                .iter()
                .filter(|(_, slot)| slot.mem.is_none())
                .map(|(hash, slot)| IndexRow {
                    hash: hash.clone(),
                    file: entry_file_name(hash),
                    bytes: slot.bytes,
                    last_used_ms: slot.last_used,
                    entries: slot.rows.clone(),
                })
                .collect(),
        };
        if let Ok(json) = serde_json::to_vec(&index) {
            if let Err(error) = write_private_atomic(&dir.join(INDEX_FILE), &json) {
                self.report_write_failure(&error);
            }
        }
    }

    /// Store an entry. When this returns the entry is on disk (or, when the
    /// directory is unusable, in memory).
    pub async fn add_entry(&self, entry: CacheEntry) -> Result<()> {
        self.add_entry_with_mtime(entry, None).await
    }

    /// [`Self::add_entry`] that also records the analyzed file's modification
    /// time (Unix milliseconds), so [`Self::find_valid`] can later trust the
    /// entry without hashing the file.
    pub async fn add_entry_with_mtime(
        &self,
        entry: CacheEntry,
        file_mtime_ms: Option<i64>,
    ) -> Result<()> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.add_entry_sync(entry, file_mtime_ms)).await?;
        Ok(())
    }

    /// Every entry stored for a file hash.
    pub async fn get_entries(&self, file_hash: &str) -> Option<Vec<CacheEntry>> {
        let cache = self.clone();
        let hash = file_hash.to_string();
        tokio::task::spawn_blocking(move || cache.get_entries_sync(&hash))
            .await
            .ok()
            .flatten()
    }

    fn get_entries_sync(&self, hash: &str) -> Option<Vec<CacheEntry>> {
        let mut state = self.lock();
        let tick = Self::tick(&mut state);
        let found = {
            let slot = state.slots.get(hash)?;
            self.read_slot(hash, slot)
        };
        match found {
            Some(entries) => {
                if let Some(slot) = state.slots.get_mut(hash) {
                    slot.last_used = tick;
                }
                Some(entries)
            }
            None => {
                // The file is gone or unreadable: forget the hash.
                state.slots.remove(hash);
                self.save_index(&state);
                None
            }
        }
    }

    /// The newest entry of `tool_name` for a file hash.
    pub async fn get_latest_analysis(
        &self,
        file_hash: &str,
        tool_name: &str,
    ) -> Option<CacheEntry> {
        self.get_entries(file_hash)
            .await?
            .into_iter()
            .filter(|e| e.tool_name == tool_name)
            .max_by_key(|e| e.timestamp)
    }

    /// The newest entry for a file hash, tool and arguments (a lookup by
    /// content: the caller already hashed the file).
    pub async fn find_by_hash(
        &self,
        file_hash: &str,
        tool_name: &str,
        tool_args: &HashMap<String, Value>,
    ) -> Option<CacheEntry> {
        self.get_entries(file_hash)
            .await?
            .into_iter()
            .filter(|e| e.tool_name == tool_name && &e.tool_args == tool_args)
            .max_by_key(|e| e.timestamp)
    }

    /// The newest entry for a path, tool and arguments whose file is unchanged
    /// (same size and modification time as recorded), found without hashing
    /// the file. `None` when nothing matches or the file changed; the caller
    /// then hashes the file and may use [`Self::find_by_hash`].
    pub async fn find_valid(
        &self,
        file_path: &str,
        tool_name: &str,
        tool_args: &HashMap<String, Value>,
        file_size: u64,
        file_mtime_ms: i64,
    ) -> Option<CacheEntry> {
        let wanted_digest = args_digest(tool_args);
        let wanted = {
            let state = self.lock();
            state
                .slots
                .values()
                .flat_map(|slot| slot.rows.iter())
                .filter(|row| {
                    row.file_path == file_path
                        && row.tool_name == tool_name
                        && row.args_digest == wanted_digest
                        && row.file_size == file_size
                        && row.file_mtime_ms == Some(file_mtime_ms)
                })
                .max_by_key(|row| row.timestamp)
                .map(|row| (row.file_hash.clone(), row.timestamp))?
        };
        let entries = self.get_entries(&wanted.0).await?;
        entries.into_iter().find(|e| {
            e.tool_name == tool_name && e.timestamp == wanted.1 && &e.tool_args == tool_args
        })
    }

    /// Every entry, results included. Reads every entry file: prefer
    /// [`Self::list_summaries`] for anything shown to a caller.
    pub async fn get_all_entries(&self) -> Vec<CacheEntry> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            let hashes: Vec<String> = cache.lock().slots.keys().cloned().collect();
            hashes
                .iter()
                .filter_map(|hash| cache.get_entries_sync(hash))
                .flatten()
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// Every entry's summary, newest first (no results are read).
    pub fn list_summaries(&self, query: &CacheSearchQuery) -> Vec<EntrySummary> {
        let state = self.lock();
        let mut rows: Vec<EntrySummary> = state
            .slots
            .values()
            .flat_map(|slot| slot.rows.iter())
            .filter(|row| {
                matches_query(
                    query,
                    &row.tool_name,
                    &row.file_path,
                    row.timestamp,
                    row.file_size,
                )
            })
            .cloned()
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.timestamp));
        rows
    }

    pub async fn get_metadata(&self) -> CacheMetadata {
        Self::metadata_of(&self.lock())
    }

    /// Forget every entry and delete the entry files this cache wrote.
    pub async fn clear(&self) -> Result<()> {
        let mut state = self.lock();
        if let Some(dir) = self.directory() {
            // Entries another process added (or an older version left) go too.
            for row in read_index(&dir) {
                adopt_row(&mut state, &dir, row);
            }
            adopt_unlisted_files(&mut state, &dir, self.max_total_bytes);
        }
        let hashes: Vec<String> = state.slots.keys().cloned().collect();
        for hash in hashes {
            self.drop_slot(&mut state, &hash);
        }
        if let Some(dir) = self.directory() {
            match fs::remove_file(dir.join(INDEX_FILE)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub async fn search_entries(&self, query: &CacheSearchQuery) -> Vec<CacheEntry> {
        let wanted: Vec<(String, DateTime<Utc>)> = self
            .list_summaries(query)
            .into_iter()
            .map(|row| (row.file_hash, row.timestamp))
            .collect();
        let mut hashes: Vec<&String> = wanted.iter().map(|(hash, _)| hash).collect();
        hashes.sort();
        hashes.dedup();
        let mut out = Vec::new();
        for hash in hashes {
            if let Some(entries) = self.get_entries(hash).await {
                out.extend(entries.into_iter().filter(|e| {
                    matches_query(query, &e.tool_name, &e.file_path, e.timestamp, e.file_size)
                }));
            }
        }
        out
    }

    pub async fn get_statistics(&self) -> CacheStatistics {
        let state = self.lock();
        let mut tool_counts: HashMap<String, usize> = HashMap::new();
        let mut total_execution_time = 0u64;
        let mut file_type_counts: HashMap<String, usize> = HashMap::new();
        let mut total_entries = 0usize;
        for row in state.slots.values().flat_map(|slot| slot.rows.iter()) {
            total_entries += 1;
            *tool_counts.entry(row.tool_name.clone()).or_insert(0) += 1;
            total_execution_time += row.execution_time_ms;
            if let Some(ext) = Path::new(&row.file_path)
                .extension()
                .and_then(|s| s.to_str())
            {
                *file_type_counts.entry(ext.to_string()).or_insert(0) += 1;
            }
        }
        let avg_execution_time = if total_entries > 0 {
            total_execution_time / total_entries as u64
        } else {
            0
        };
        CacheStatistics {
            tool_counts,
            file_type_counts,
            total_analyses: total_entries,
            unique_files: state.slots.len(),
            avg_execution_time_ms: avg_execution_time,
        }
    }
}

/// Longest string argument an index row keeps (characters).
const MAX_ARG_CHARS: usize = 200;
/// Largest non-string argument an index row keeps whole (compact JSON bytes).
const MAX_ARG_JSON_BYTES: usize = 400;

/// Digest of a call's arguments, independent of key order.
fn args_digest(args: &HashMap<String, Value>) -> String {
    let sorted: std::collections::BTreeMap<&String, &Value> = args.iter().collect();
    let json = serde_json::to_vec(&sorted).unwrap_or_default();
    blake3::hash(&json).to_hex().as_str()[..32].to_string()
}

/// The arguments as an index row and a listing show them: long strings are
/// cut (with their length said) and big arrays or objects are summarized.
fn bounded_args(args: &HashMap<String, Value>) -> HashMap<String, Value> {
    args.iter()
        .map(|(key, value)| {
            let bounded = match value {
                Value::String(text) if text.chars().count() > MAX_ARG_CHARS => {
                    let head: String = text.chars().take(MAX_ARG_CHARS).collect();
                    Value::String(format!(
                        "{head}... ({} characters in all)",
                        text.chars().count()
                    ))
                }
                Value::Array(_) | Value::Object(_) => {
                    let len = serde_json::to_vec(value).map_or(0, |v| v.len());
                    if len > MAX_ARG_JSON_BYTES {
                        Value::String(format!("<{len} bytes of JSON>"))
                    } else {
                        value.clone()
                    }
                }
                other => other.clone(),
            };
            (key.clone(), bounded)
        })
        .collect()
}

fn summary_of(entry: &CacheEntry) -> EntrySummary {
    EntrySummary {
        file_path: entry.file_path.clone(),
        file_hash: entry.file_hash.clone(),
        tool_name: entry.tool_name.clone(),
        tool_args: bounded_args(&entry.tool_args),
        args_digest: args_digest(&entry.tool_args),
        timestamp: entry.timestamp,
        file_size: entry.file_size,
        file_mtime_ms: None,
        execution_time_ms: entry.execution_time_ms,
        result_bytes: serde_json::to_vec(&entry.result).map_or(0, |v| v.len()),
    }
}

/// Bytes a set of entries takes: their results plus a fixed cost per entry.
fn estimate_bytes(rows: &[EntrySummary]) -> u64 {
    rows.iter()
        .map(|row| (row.result_bytes + row.file_path.len() + row.tool_name.len() + 512) as u64)
        .sum()
}

fn matches_query(
    query: &CacheSearchQuery,
    tool: &str,
    path: &str,
    timestamp: DateTime<Utc>,
    size: u64,
) -> bool {
    query.tool_name.as_ref().is_none_or(|t| tool == t)
        && query
            .file_path_pattern
            .as_ref()
            .is_none_or(|p| path.contains(p.as_str()))
        && query.start_time.is_none_or(|s| timestamp >= s)
        && query.end_time.is_none_or(|e| timestamp <= e)
        && query.min_file_size.is_none_or(|m| size >= m)
        && query.max_file_size.is_none_or(|m| size <= m)
}

/// The rows of the index file on disk (empty when it is missing or unreadable).
fn read_index(dir: &Path) -> Vec<IndexRow> {
    let Ok(bytes) = read_private(&dir.join(INDEX_FILE), MAX_INDEX_BYTES) else {
        return Vec::new();
    };
    serde_json::from_slice::<IndexFile>(&bytes).map_or_else(|_| Vec::new(), |index| index.index)
}

/// Take a row of the on-disk index into `state` unless `state` has the hash.
/// A row whose entry file is gone (or replaced by something else) is dropped.
fn adopt_row(state: &mut State, dir: &Path, mut row: IndexRow) {
    if state.slots.contains_key(&row.hash) {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(dir.join(&row.file)) else {
        return;
    };
    if !meta.is_file() || row.file != entry_file_name(&row.hash) {
        return;
    }
    for entry in &mut row.entries {
        // Rows written before arguments were bounded hold them whole.
        if entry.args_digest.is_empty() {
            entry.args_digest = args_digest(&entry.tool_args);
            entry.tool_args = bounded_args(&entry.tool_args);
        }
    }
    state.clock = state.clock.max(row.last_used_ms);
    state.slots.insert(
        row.hash,
        Slot {
            rows: row.entries,
            bytes: meta.len(),
            last_used: row.last_used_ms,
            mem: None,
        },
    );
}

/// For every disk-backed slot except `except`, compare the entry file's size
/// with what the slot recorded; when another process rewrote it, rebuild the
/// slot's rows from the file so a following index write keeps them.
fn refresh_changed_slots(state: &mut State, dir: &Path, except: &str, max_file_bytes: u64) {
    let hashes: Vec<String> = state
        .slots
        .iter()
        .filter(|(hash, slot)| slot.mem.is_none() && hash.as_str() != except)
        .map(|(hash, _)| hash.clone())
        .collect();
    for hash in hashes {
        let path = dir.join(entry_file_name(&hash));
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Another process cleared this entry file: stop listing it.
                state.slots.remove(&hash);
                continue;
            }
            Err(_) => continue,
        };
        let unchanged = state
            .slots
            .get(&hash)
            .is_none_or(|slot| slot.bytes == meta.len());
        if unchanged || !meta.is_file() || meta.len() > max_file_bytes {
            continue;
        }
        let Ok(bytes) = read_private(&path, max_file_bytes) else {
            continue;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<CacheEntry>>(&bytes) else {
            continue;
        };
        if entries.is_empty() || entries.iter().any(|entry| entry.file_hash != hash) {
            continue;
        }
        if let Some(slot) = state.slots.get_mut(&hash) {
            slot.rows = entries.iter().map(summary_of).collect();
            slot.bytes = meta.len();
        }
    }
}

/// Adopt the entry files the index does not list: another process using the
/// same directory may have written them after this one read the index, or an
/// older version left them. Without this nothing would ever count or remove
/// them. Only files that parse as entries of the hash their name says are taken.
fn adopt_unlisted_files(state: &mut State, dir: &Path, max_file_bytes: u64) {
    let Ok(listing) = fs::read_dir(dir) else {
        return;
    };
    let known: std::collections::HashSet<String> = state
        .slots
        .keys()
        .map(|hash| entry_file_name(hash))
        .collect();
    for item in listing.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name == INDEX_FILE || name.starts_with('.') {
            continue;
        }
        if known.contains(&name) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(item.path()) else {
            continue;
        };
        if !meta.is_file() || meta.len() > max_file_bytes {
            continue;
        }
        let Ok(bytes) = read_private(&item.path(), max_file_bytes) else {
            continue;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<CacheEntry>>(&bytes) else {
            continue;
        };
        let Some(first) = entries.first() else {
            continue;
        };
        let hash = first.file_hash.clone();
        if entry_file_name(&hash) != name
            || entries.iter().any(|entry| entry.file_hash != hash)
            || state.slots.contains_key(&hash)
        {
            continue;
        }
        let tick = {
            state.clock = now_ms().max(state.clock + 1);
            state.clock
        };
        state.slots.insert(
            hash,
            Slot {
                rows: entries.iter().map(summary_of).collect(),
                bytes: meta.len(),
                last_used: tick,
                mem: None,
            },
        );
    }
}

/// Read the index (not the entries) into `state`, then adopt entry files it
/// does not list.
fn load_index(state: &mut State, dir: &Path, max_file_bytes: u64) {
    for row in read_index(dir) {
        adopt_row(state, dir, row);
    }
    adopt_unlisted_files(state, dir, max_file_bytes);
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CacheSearchQuery {
    pub tool_name: Option<String>,
    pub file_path_pattern: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub min_file_size: Option<u64>,
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatistics {
    pub tool_counts: HashMap<String, usize>,
    pub file_type_counts: HashMap<String, usize>,
    pub total_analyses: usize,
    pub unique_files: usize,
    pub avg_execution_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tempfile::TempDir;

    fn create_test_entry(file_hash: &str, tool_name: &str, file_path: &str) -> CacheEntry {
        CacheEntry {
            file_path: file_path.to_string(),
            file_hash: file_hash.to_string(),
            tool_name: tool_name.to_string(),
            tool_args: [("test_arg".to_string(), serde_json::json!("value"))]
                .iter()
                .cloned()
                .collect(),
            result: serde_json::json!({"result": "test"}),
            timestamp: Utc::now(),
            file_size: 1024,
            execution_time_ms: 100,
        }
    }

    #[tokio::test]
    async fn test_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let metadata = cache.get_metadata().await;
        assert_eq!(metadata.total_entries, 0);
        assert_eq!(metadata.total_unique_files, 0);
    }

    #[tokio::test]
    async fn test_add_and_get_entry() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry = create_test_entry("hash123", "test_tool", "/test/file.bin");
        cache.add_entry(entry.clone()).await.unwrap();

        let entries = cache.get_entries("hash123").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool_name, "test_tool");
        assert_eq!(entries[0].file_path, "/test/file.bin");
        assert_eq!(entries[0].file_hash, "hash123");
        assert_eq!(entries[0].file_size, 1024);
        assert_eq!(entries[0].execution_time_ms, 100);
    }

    #[tokio::test]
    async fn test_multiple_entries_same_file() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash123", "tool1", "/test/file.bin");
        let entry2 = create_test_entry("hash123", "tool2", "/test/file.bin");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();

        let entries = cache.get_entries("hash123").await.unwrap();
        assert_eq!(entries.len(), 2);

        let tool_names: Vec<_> = entries.iter().map(|e| &e.tool_name).collect();
        assert!(tool_names.contains(&&"tool1".to_string()));
        assert!(tool_names.contains(&&"tool2".to_string()));
    }

    #[tokio::test]
    async fn test_get_latest_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let now = Utc::now();
        let mut entry1 = create_test_entry("hash123", "test_tool", "/test/file.bin");
        entry1.timestamp = now - Duration::hours(1);

        let mut entry2 = create_test_entry("hash123", "test_tool", "/test/file.bin");
        entry2.timestamp = now;

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();

        let latest = cache
            .get_latest_analysis("hash123", "test_tool")
            .await
            .unwrap();
        assert_eq!(latest.timestamp, now);
    }

    #[tokio::test]
    async fn test_get_latest_analysis_different_tools() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash123", "tool1", "/test/file.bin");
        let entry2 = create_test_entry("hash123", "tool2", "/test/file.bin");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();

        let latest_tool1 = cache.get_latest_analysis("hash123", "tool1").await;
        let latest_tool2 = cache.get_latest_analysis("hash123", "tool2").await;
        let latest_nonexistent = cache.get_latest_analysis("hash123", "tool3").await;

        assert!(latest_tool1.is_some());
        assert!(latest_tool2.is_some());
        assert!(latest_nonexistent.is_none());
    }

    #[tokio::test]
    async fn test_get_all_entries() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash1", "tool1", "/test/file1.bin");
        let entry2 = create_test_entry("hash2", "tool2", "/test/file2.bin");
        let entry3 = create_test_entry("hash1", "tool2", "/test/file1.bin");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let all_entries = cache.get_all_entries().await;
        assert_eq!(all_entries.len(), 3);
    }

    #[tokio::test]
    async fn test_get_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash1", "tool1", "/test/file1.bin");
        let entry2 = create_test_entry("hash2", "tool2", "/test/file2.bin");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();

        let metadata = cache.get_metadata().await;
        assert_eq!(metadata.total_entries, 2);
        assert_eq!(metadata.total_unique_files, 2);
        assert!(metadata.cache_size_bytes > 0);
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry = create_test_entry("hash123", "test_tool", "/test/file.bin");
        cache.add_entry(entry).await.unwrap();

        let metadata_before = cache.get_metadata().await;
        assert_eq!(metadata_before.total_entries, 1);

        cache.clear().await.unwrap();

        let metadata_after = cache.get_metadata().await;
        assert_eq!(metadata_after.total_entries, 0);
        assert_eq!(metadata_after.total_unique_files, 0);
    }

    #[tokio::test]
    async fn test_search_by_tool_name() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash1", "hash_tool", "/test/file1.bin");
        let entry2 = create_test_entry("hash2", "string_tool", "/test/file2.bin");
        let entry3 = create_test_entry("hash3", "hash_tool", "/test/file3.bin");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let query = CacheSearchQuery {
            tool_name: Some("hash_tool".to_string()),
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.tool_name == "hash_tool"));
    }

    #[tokio::test]
    async fn test_search_by_file_path_pattern() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash1", "tool", "/bin/ls");
        let entry2 = create_test_entry("hash2", "tool", "/usr/bin/cat");
        let entry3 = create_test_entry("hash3", "tool", "/home/user/file.txt");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: Some("bin".to_string()),
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.file_path.contains("bin")));
    }

    #[tokio::test]
    async fn test_search_by_time_range() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let two_hours_ago = now - Duration::hours(2);

        let mut entry1 = create_test_entry("hash1", "tool", "/test/file1.bin");
        entry1.timestamp = two_hours_ago;

        let mut entry2 = create_test_entry("hash2", "tool", "/test/file2.bin");
        entry2.timestamp = hour_ago;

        let mut entry3 = create_test_entry("hash3", "tool", "/test/file3.bin");
        entry3.timestamp = now;

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: Some(hour_ago - Duration::minutes(30)),
            end_time: Some(now + Duration::minutes(30)),
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query).await;
        assert_eq!(results.len(), 2); // Should exclude the entry from 2 hours ago
    }

    #[tokio::test]
    async fn test_search_by_file_size() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let mut entry1 = create_test_entry("hash1", "tool", "/test/small.bin");
        entry1.file_size = 100;

        let mut entry2 = create_test_entry("hash2", "tool", "/test/medium.bin");
        entry2.file_size = 1000;

        let mut entry3 = create_test_entry("hash3", "tool", "/test/large.bin");
        entry3.file_size = 10000;

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: Some(500),
            max_file_size: Some(5000),
        };

        let results = cache.search_entries(&query).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_size, 1000);
    }

    #[tokio::test]
    async fn test_search_combined_criteria() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let entry1 = create_test_entry("hash1", "hash_tool", "/bin/ls");
        let entry2 = create_test_entry("hash2", "string_tool", "/bin/cat");
        let entry3 = create_test_entry("hash3", "hash_tool", "/usr/bin/grep");

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let query = CacheSearchQuery {
            tool_name: Some("hash_tool".to_string()),
            file_path_pattern: Some("bin".to_string()),
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&query).await;
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|e| e.tool_name == "hash_tool" && e.file_path.contains("bin")));
    }

    #[tokio::test]
    async fn test_get_statistics() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        let mut entry1 = create_test_entry("hash1", "hash_tool", "/test/file.exe");
        entry1.execution_time_ms = 100;

        let mut entry2 = create_test_entry("hash2", "string_tool", "/test/file.dll");
        entry2.execution_time_ms = 200;

        let mut entry3 = create_test_entry("hash3", "hash_tool", "/test/file.txt");
        entry3.execution_time_ms = 150;

        cache.add_entry(entry1).await.unwrap();
        cache.add_entry(entry2).await.unwrap();
        cache.add_entry(entry3).await.unwrap();

        let stats = cache.get_statistics().await;
        assert_eq!(stats.total_analyses, 3);
        assert_eq!(stats.unique_files, 3);
        assert_eq!(stats.avg_execution_time_ms, 150); // (100 + 200 + 150) / 3

        assert_eq!(stats.tool_counts["hash_tool"], 2);
        assert_eq!(stats.tool_counts["string_tool"], 1);

        assert_eq!(stats.file_type_counts["exe"], 1);
        assert_eq!(stats.file_type_counts["dll"], 1);
        assert_eq!(stats.file_type_counts["txt"], 1);
    }

    #[tokio::test]
    async fn test_max_entries_per_file_limit() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = AnalysisCache::new(temp_dir.path()).unwrap();
        cache.max_entries_per_file = 3; // Set a low limit for testing

        // Add more entries than the limit
        for i in 0..5 {
            let entry = create_test_entry("hash123", &format!("tool{i}"), "/test/file.bin");
            cache.add_entry(entry).await.unwrap();
        }

        let entries = cache.get_entries("hash123").await.unwrap();
        assert_eq!(entries.len(), 3); // Should be limited
    }

    #[tokio::test]
    async fn test_cache_entry_serialization() {
        let entry = CacheEntry {
            file_path: "/test/file.bin".to_string(),
            file_hash: "abc123".to_string(),
            tool_name: "test_tool".to_string(),
            tool_args: [("arg1".to_string(), serde_json::json!("value1"))]
                .iter()
                .cloned()
                .collect(),
            result: serde_json::json!({"result": "success"}),
            timestamp: Utc::now(),
            file_size: 2048,
            execution_time_ms: 250,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: CacheEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.file_path, entry.file_path);
        assert_eq!(deserialized.file_hash, entry.file_hash);
        assert_eq!(deserialized.tool_name, entry.tool_name);
        assert_eq!(deserialized.file_size, entry.file_size);
        assert_eq!(deserialized.execution_time_ms, entry.execution_time_ms);
    }

    #[tokio::test]
    async fn test_cache_metadata_serialization() {
        let metadata = CacheMetadata {
            total_entries: 10,
            total_unique_files: 5,
            cache_size_bytes: 1024,
            last_updated: Utc::now(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: CacheMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_entries, metadata.total_entries);
        assert_eq!(deserialized.total_unique_files, metadata.total_unique_files);
        assert_eq!(deserialized.cache_size_bytes, metadata.cache_size_bytes);
    }

    #[tokio::test]
    async fn test_cache_search_query_serialization() {
        let query = CacheSearchQuery {
            tool_name: Some("test_tool".to_string()),
            file_path_pattern: Some("/test/".to_string()),
            start_time: Some(Utc::now()),
            end_time: Some(Utc::now()),
            min_file_size: Some(100),
            max_file_size: Some(1000),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&query).unwrap();
        let deserialized: CacheSearchQuery = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tool_name, query.tool_name);
        assert_eq!(deserialized.file_path_pattern, query.file_path_pattern);
        assert_eq!(deserialized.min_file_size, query.min_file_size);
        assert_eq!(deserialized.max_file_size, query.max_file_size);
    }

    #[tokio::test]
    async fn test_cache_statistics_serialization() {
        let stats = CacheStatistics {
            tool_counts: [("tool1".to_string(), 5), ("tool2".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            file_type_counts: [("exe".to_string(), 2), ("dll".to_string(), 1)]
                .iter()
                .cloned()
                .collect(),
            total_analyses: 8,
            unique_files: 6,
            avg_execution_time_ms: 150,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: CacheStatistics = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_analyses, stats.total_analyses);
        assert_eq!(deserialized.unique_files, stats.unique_files);
        assert_eq!(
            deserialized.avg_execution_time_ms,
            stats.avg_execution_time_ms
        );
        assert_eq!(deserialized.tool_counts, stats.tool_counts);
        assert_eq!(deserialized.file_type_counts, stats.file_type_counts);
    }

    #[tokio::test]
    async fn test_empty_cache_operations() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(temp_dir.path()).unwrap();

        // Test operations on empty cache
        assert!(cache.get_entries("nonexistent").await.is_none());
        assert!(cache
            .get_latest_analysis("nonexistent", "tool")
            .await
            .is_none());

        let all_entries = cache.get_all_entries().await;
        assert!(all_entries.is_empty());

        let empty_query = CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        };

        let results = cache.search_entries(&empty_query).await;
        assert!(results.is_empty());

        let stats = cache.get_statistics().await;
        assert_eq!(stats.total_analyses, 0);
        assert_eq!(stats.unique_files, 0);
        assert_eq!(stats.avg_execution_time_ms, 0);
    }

    #[tokio::test]
    async fn test_cache_persistence() {
        let temp_dir = TempDir::new().unwrap();

        {
            let cache = AnalysisCache::new(temp_dir.path()).unwrap();
            let entry = create_test_entry("persistent_hash", "test_tool", "/test/file.bin");
            cache.add_entry(entry).await.unwrap();
        }

        // Create new cache instance to test loading
        let cache2 = AnalysisCache::new(temp_dir.path()).unwrap();
        let entries = cache2.get_entries("persistent_hash").await;

        // add_entry is complete on return, so the second instance finds it.
        let entries = entries.expect("the entry persisted by the first instance");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_path, "/test/file.bin");
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use tempfile::TempDir;

    fn entry(hash: &str, tool: &str, path: &str, result: Value) -> CacheEntry {
        CacheEntry {
            file_path: path.to_string(),
            file_hash: hash.to_string(),
            tool_name: tool.to_string(),
            tool_args: HashMap::new(),
            result,
            timestamp: Utc::now(),
            file_size: 10,
            execution_time_ms: 1,
        }
    }

    fn any_query() -> CacheSearchQuery {
        CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        }
    }

    /// A string that does not compress away and is `len` bytes long.
    fn blob(len: usize) -> Value {
        Value::String("x".repeat(len))
    }

    #[tokio::test]
    async fn an_entry_is_complete_on_disk_when_add_entry_returns() {
        // CS12: the process may exit right after the call; nothing is pending.
        let dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        cache
            .add_entry(entry(
                "abc",
                "analyze_file",
                "/f",
                serde_json::json!({"k": 1}),
            ))
            .await
            .unwrap();
        let on_disk: Vec<CacheEntry> =
            serde_json::from_slice(&fs::read(dir.path().join("abc.json")).unwrap()).unwrap();
        assert_eq!(on_disk.len(), 1);
        // No temporary files are left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[tokio::test]
    async fn adding_for_one_hash_rewrites_only_that_hash() {
        let dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        cache
            .add_entry(entry("one", "t", "/a", blob(100)))
            .await
            .unwrap();
        let before = fs::metadata(dir.path().join("one.json"))
            .unwrap()
            .modified()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        cache
            .add_entry(entry("two", "t", "/b", blob(100)))
            .await
            .unwrap();
        let after = fs::metadata(dir.path().join("one.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(before, after, "an unrelated entry file is not rewritten");
    }

    #[tokio::test]
    async fn start_up_reads_the_index_not_the_results() {
        let dir = TempDir::new().unwrap();
        {
            let cache = AnalysisCache::new(dir.path()).unwrap();
            cache
                .add_entry(entry("h1", "t", "/a", blob(2000)))
                .await
                .unwrap();
            cache
                .add_entry(entry("h2", "t", "/b", blob(2000)))
                .await
                .unwrap();
        }
        // Corrupt a result file: the listing (from the index) does not notice,
        // so nothing parsed it; asking for that hash's results does.
        fs::write(dir.path().join("h1.json"), "not json at all").unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        let rows = cache.list_summaries(&CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        });
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.result_bytes > 2000));
        assert!(cache.get_entries("h2").await.is_some());
        assert!(cache.get_entries("h1").await.is_none());
        assert_eq!(cache.get_metadata().await.total_unique_files, 1);
    }

    #[tokio::test]
    async fn the_cache_is_bounded_in_bytes_and_evicts_least_recently_used() {
        let dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(dir.path())
            .unwrap()
            .with_limits(12_000, 100);
        for i in 0..3 {
            cache
                .add_entry(entry(&format!("h{i}"), "t", "/f", blob(3_000)))
                .await
                .unwrap();
        }
        // Touch h0 so h1 is the least recently used.
        assert!(cache.get_entries("h0").await.is_some());
        cache
            .add_entry(entry("h3", "t", "/f", blob(3_000)))
            .await
            .unwrap();
        cache
            .add_entry(entry("h4", "t", "/f", blob(3_000)))
            .await
            .unwrap();
        let total: u64 = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with('h'))
            .map(|e| e.metadata().unwrap().len())
            .sum();
        assert!(total <= 12_000, "{total} bytes on disk");
        assert!(
            cache.get_entries("h4").await.is_some(),
            "the newest survives"
        );
        assert!(
            cache.get_entries("h0").await.is_some(),
            "a recently used one survives"
        );
        assert!(
            cache.get_entries("h1").await.is_none(),
            "the least recently used goes first"
        );
        assert!(!dir.path().join("h1.json").exists(), "its file is deleted");
    }

    #[tokio::test]
    async fn the_entry_count_is_bounded() {
        let cache = AnalysisCache::memory_only().with_limits(u64::MAX, 3);
        for i in 0..6 {
            cache
                .add_entry(entry(&format!("h{i}"), "t", "/f", Value::Null))
                .await
                .unwrap();
        }
        assert_eq!(cache.get_metadata().await.total_entries, 3);
        assert!(cache.get_entries("h5").await.is_some());
        assert!(cache.get_entries("h0").await.is_none());
    }

    #[tokio::test]
    async fn an_oversized_result_is_replaced_by_a_note() {
        // CS13: one noisy YARA scan stored 79 MB.
        let cache = AnalysisCache::memory_only();
        cache
            .add_entry(entry(
                "big",
                "yara_scan_file",
                "/d",
                blob(DEFAULT_MAX_ENTRY_RESULT_BYTES + 10),
            ))
            .await
            .unwrap();
        let stored = cache.get_entries("big").await.unwrap();
        assert!(stored[0].result["omitted"].is_string());
        assert!(
            stored[0].result["result_bytes"].as_u64().unwrap()
                > DEFAULT_MAX_ENTRY_RESULT_BYTES as u64
        );
    }

    #[tokio::test]
    async fn a_lookup_is_validated_by_size_and_mtime_and_falls_back_to_the_hash() {
        let cache = AnalysisCache::memory_only();
        let mut args = HashMap::new();
        args.insert("hashes".to_string(), Value::Bool(true));
        let mut e = entry("h", "analyze_file", "/f", serde_json::json!({"v": 1}));
        e.tool_args = args.clone();
        cache.add_entry_with_mtime(e, Some(1_000)).await.unwrap();
        // Unchanged (same size, same mtime): served without hashing.
        assert!(cache
            .find_valid("/f", "analyze_file", &args, 10, 1_000)
            .await
            .is_some());
        // Modified or resized: not served by stamp.
        assert!(cache
            .find_valid("/f", "analyze_file", &args, 10, 2_000)
            .await
            .is_none());
        assert!(cache
            .find_valid("/f", "analyze_file", &args, 11, 1_000)
            .await
            .is_none());
        // Other arguments or another tool: not served.
        assert!(cache
            .find_valid("/f", "analyze_file", &HashMap::new(), 10, 1_000)
            .await
            .is_none());
        // The caller hashed the file instead: same content still hits.
        assert!(cache
            .find_by_hash("h", "analyze_file", &args)
            .await
            .is_some());
        assert!(cache
            .find_by_hash("other", "analyze_file", &args)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn an_unusable_directory_degrades_to_memory_with_one_line() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bad = Arc::new(CacheDir::new(file.path().join("cache")));
        let cache = AnalysisCache::lazy(Arc::clone(&bad));
        assert!(!cache.is_persistent());
        cache
            .add_entry(entry("h", "t", "/f", Value::Null))
            .await
            .unwrap();
        assert!(cache.get_entries("h").await.is_some());
        assert!(AnalysisCache::new(file.path().join("cache")).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_in_place_of_an_entry_file_is_not_followed() {
        // TS10: a planted metadata.json symlink got its target overwritten.
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("victim.txt");
        fs::write(&target, "keep me").unwrap();
        let cache_dir = dir.path().join("cache");
        let cache = AnalysisCache::new(&cache_dir).unwrap();
        std::os::unix::fs::symlink(&target, cache_dir.join("metadata.json")).unwrap();
        std::os::unix::fs::symlink(&target, cache_dir.join("planted.json")).unwrap();
        cache
            .add_entry(entry("planted", "t", "/f", Value::Null))
            .await
            .unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep me");
        // The entries are readable again through the real files.
        assert!(cache.get_entries("planted").await.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_of_another_user_is_refused() {
        // The decision itself: a directory owned by someone else is refused
        // with a message that names the owner and the way out.
        assert!(check_owner(501, 501).is_ok());
        let refused = check_owner(0, 501).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        let text = refused.to_string();
        assert!(text.contains("another user (uid 0)"), "{text}");
        assert!(text.contains("--cache-dir"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_of_ours_passes_the_owner_check_for_real() {
        let dir = TempDir::new().unwrap();
        create_private_dir(&dir.path().join("mine")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_looser_directory_of_ours_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let loose = dir.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();
        create_private_dir(&loose).unwrap();
        assert_eq!(
            fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[tokio::test]
    async fn two_caches_on_one_directory_keep_each_others_entries() {
        let dir = TempDir::new().unwrap();
        let a = AnalysisCache::new(dir.path()).unwrap();
        let b = AnalysisCache::new(dir.path()).unwrap();
        // Both read the (empty) index before either writes.
        assert!(a.get_entries("none").await.is_none());
        assert!(b.get_entries("none").await.is_none());
        a.add_entry(entry("hash-a", "t", "/a", Value::Null))
            .await
            .unwrap();
        b.add_entry(entry("hash-b", "t", "/b", Value::Null))
            .await
            .unwrap();
        a.add_entry(entry("hash-c", "t", "/c", Value::Null))
            .await
            .unwrap();
        let later = AnalysisCache::new(dir.path()).unwrap();
        let mut hashes: Vec<String> = later
            .list_summaries(&any_query())
            .into_iter()
            .map(|row| row.file_hash)
            .collect();
        hashes.sort();
        assert_eq!(hashes, ["hash-a", "hash-b", "hash-c"]);
    }

    #[tokio::test]
    async fn a_row_the_other_cache_added_to_a_held_hash_survives_our_next_write() {
        let dir = TempDir::new().unwrap();
        let a = AnalysisCache::new(dir.path()).unwrap();
        let b = AnalysisCache::new(dir.path()).unwrap();
        a.add_entry(entry("shared", "t1", "/f", Value::Null))
            .await
            .unwrap();
        // B adopts the hash and adds a second entry; A still holds one row.
        b.add_entry(entry("shared", "t2", "/f", Value::Null))
            .await
            .unwrap();
        // A writes a different hash.
        a.add_entry(entry("other", "t3", "/g", Value::Null))
            .await
            .unwrap();
        let later = AnalysisCache::new(dir.path()).unwrap();
        let rows = later.list_summaries(&any_query());
        assert_eq!(
            rows.iter().filter(|row| row.file_hash == "shared").count(),
            2,
            "{rows:?}"
        );
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn a_row_whose_entry_file_another_cache_removed_is_dropped_at_our_next_write() {
        let dir = TempDir::new().unwrap();
        let a = AnalysisCache::new(dir.path()).unwrap();
        let b = AnalysisCache::new(dir.path()).unwrap();
        a.add_entry(entry("gone", "t1", "/f", Value::Null))
            .await
            .unwrap();
        a.add_entry(entry("gone2", "t2", "/f2", Value::Null))
            .await
            .unwrap();
        // B adopts the rows from disk, then clears the directory.
        let _ = b.list_summaries(&any_query());
        b.clear().await.unwrap();
        a.add_entry(entry("kept", "t3", "/g", Value::Null))
            .await
            .unwrap();
        let hashes: Vec<String> = a
            .list_summaries(&any_query())
            .into_iter()
            .map(|row| row.file_hash)
            .collect();
        assert_eq!(hashes, ["kept"], "{hashes:?}");
        let later = AnalysisCache::new(dir.path()).unwrap();
        assert_eq!(later.list_summaries(&any_query()).len(), 1);
    }

    #[tokio::test]
    async fn entry_files_the_index_does_not_list_are_adopted_and_cleared() {
        let dir = TempDir::new().unwrap();
        {
            let writer = AnalysisCache::new(dir.path()).unwrap();
            writer
                .add_entry(entry("orphan", "t", "/o", Value::Null))
                .await
                .unwrap();
        }
        // The index is lost (for example overwritten by another process).
        fs::remove_file(dir.path().join("metadata.json")).unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        assert_eq!(
            cache.list_summaries(&any_query()).len(),
            1,
            "the orphan is counted"
        );
        cache.clear().await.unwrap();
        assert!(!dir.path().join("orphan.json").exists());
    }

    #[tokio::test]
    async fn long_arguments_are_bounded_in_the_index_and_lookups_still_work() {
        let dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        let mut item = entry("big-args", "yara_scan_file", "/f", Value::Null);
        let rule = "rule x { condition: true } ".repeat(5000);
        item.tool_args
            .insert("yara_rule".to_string(), Value::String(rule));
        item.tool_args
            .insert("list".to_string(), serde_json::json!(vec![1; 1000]));
        item.tool_args
            .insert("short".to_string(), serde_json::json!("keep"));
        let args = item.tool_args.clone();
        cache.add_entry_with_mtime(item, Some(5)).await.unwrap();

        let rows = cache.list_summaries(&any_query());
        let shown = serde_json::to_string(&rows[0].tool_args).unwrap();
        assert!(shown.len() < 1000, "{} bytes", shown.len());
        assert!(shown.contains("characters in all"));
        assert_eq!(rows[0].tool_args["short"], "keep");
        let index = fs::metadata(dir.path().join("metadata.json"))
            .unwrap()
            .len();
        assert!(index < 4000, "index is {index} bytes");
        // The entry file keeps them whole, and the lookup compares the full arguments.
        let found = cache.find_valid("/f", "yara_scan_file", &args, 10, 5).await;
        assert_eq!(found.unwrap().tool_args, args);
        let mut other = args.clone();
        other.insert("short".to_string(), serde_json::json!("changed"));
        assert!(cache
            .find_valid("/f", "yara_scan_file", &other, 10, 5)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn clear_removes_only_the_files_the_cache_wrote() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("notes.json"), "{}").unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        cache
            .add_entry(entry("h", "t", "/f", Value::Null))
            .await
            .unwrap();
        cache.clear().await.unwrap();
        assert!(!dir.path().join("h.json").exists());
        assert!(!dir.path().join("metadata.json").exists());
        assert!(dir.path().join("notes.json").exists(), "foreign files stay");
    }

    #[tokio::test]
    async fn awkward_hashes_get_safe_file_names() {
        let dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        for hash in ["../escape", "a/b", "metadata", ""] {
            cache
                .add_entry(entry(hash, "t", "/f", Value::Null))
                .await
                .unwrap();
            assert!(cache.get_entries(hash).await.is_some(), "{hash:?}");
        }
        assert!(!dir.path().parent().unwrap().join("escape.json").exists());
        let index: IndexFile =
            serde_json::from_slice(&fs::read(dir.path().join("metadata.json")).unwrap()).unwrap();
        assert_eq!(
            index.index.len(),
            4,
            "the index file was not clobbered by 'metadata'"
        );
    }

    #[test]
    fn concurrent_adds_keep_every_entry() {
        let dir = TempDir::new().unwrap();
        let cache = AnalysisCache::new(dir.path()).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let cache = cache.clone();
                std::thread::spawn(move || {
                    for i in 0..10 {
                        cache.add_entry_sync(
                            entry(&format!("h{t}"), "t", &format!("/f{i}"), Value::Null),
                            None,
                        );
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let reopened = AnalysisCache::new(dir.path()).unwrap();
        let rows = reopened.list_summaries(&CacheSearchQuery {
            tool_name: None,
            file_path_pattern: None,
            start_time: None,
            end_time: None,
            min_file_size: None,
            max_file_size: None,
        });
        assert_eq!(rows.len(), 80);
    }

    #[test]
    fn a_second_cache_on_one_directory_keeps_the_first_ones_entry_for_the_same_hash() {
        let dir = TempDir::new().unwrap();
        let a = AnalysisCache::new(dir.path()).unwrap();
        let b = AnalysisCache::new(dir.path()).unwrap();
        a.add_entry_sync(entry("samehash", "analyze_file", "/f", Value::Null), None);
        b.add_entry_sync(entry("samehash", "yara_scan_file", "/f", Value::Null), None);
        let fresh = AnalysisCache::new(dir.path()).unwrap();
        let rows = fresh.list_summaries(&any_query());
        assert_eq!(rows.len(), 2, "{rows:?}");
    }
}
