//! Opt-in analysis isolation (#316): `--isolation bwrap`.
//!
//! By default (`--isolation none`) every analysis runs inside the server
//! process. With `--isolation bwrap` (Linux only) the server runs exactly one
//! analysis in a sandbox, the `metadata` section of `analyze_file`, and refuses
//! every other analysis request with a tool error before it reads the file
//! (`FileScannerMcp::isolation_refusal`). Nothing falls back to in-process
//! analysis. The control tools that read only the server's own caches
//! (`cache_status`, `cache_clear`, `string_details`, and `search_strings`
//! without `file_path`) keep working.
//!
//! Admission ([`Sandbox::admit`]): the profile needs allow-roots. Each root is
//! opened once at start-up; a call's file is opened with ONE `openat2` beneath
//! the root it is spelled under (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, so
//! `..`, absolute links and `/proc` links cannot leave it), non-blocking and
//! without a controlling terminal, then `fstat` must show a regular file
//! within [`MAX_INPUT_BYTES`]. That one descriptor is all the call uses: the
//! server never reopens the path and never reads the content itself.
//!
//! The worker is this same executable (`WORKER_ARG`) under bubblewrap (a
//! verified, root-owned absolute path), with the admitted descriptor as its
//! stdin and only input. It runs in fresh user, PID, network, IPC, UTS and
//! cgroup namespaces, with no network, a read-only root that holds only
//! read-only binds of `/usr`, the library directories, `/etc/ld.so.cache` and
//! the worker binary, no `/proc`, `/dev` or `/tmp`, an empty environment, no
//! capabilities and no descriptor other than stdin, stdout and stderr. Each of
//! its processes (bubblewrap and the worker) gets the address-space limit; the
//! call has a wall-clock deadline. The worker hashes at most
//! [`MAX_INPUT_BYTES`] and returns the MIME type and the hashes; the server
//! takes the stat fields from its own `fstat` of the descriptor, before and
//! after, and refuses the answer when the file changed in between.
//!
//! Cache provenance: an isolated result is stored only under its own key
//! ([`METADATA_PROVENANCE`]), never under the in-process `metadata` key, and is
//! looked up only by a SHA-256 that a worker reported for the same unchanged
//! file (device, inode, size, modification and change time) in this process.

use std::{
    collections::HashMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::hash::Hashes;

/// Environment variable that selects the profile (`--isolation` wins).
pub const ISOLATION_ENV: &str = "FILE_SCANNER_ISOLATION";
/// First argument that turns the executable into the sandboxed worker. It is
/// handled in `main` before the async runtime or the argument parser start.
pub const WORKER_ARG: &str = "__isolated-metadata-worker";
/// The only places bubblewrap is taken from. No `PATH` lookup.
pub const BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/bin/bwrap"];
/// Wall-clock deadline of one sandboxed analysis.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(120);
/// Address-space limit (`RLIMIT_AS`) of bubblewrap and the worker. It counts
/// the mapped worker executable (this whole binary), so it cannot be tight.
pub const DEFAULT_MEMORY_BYTES: u64 = 1024 * MIB;
/// Largest file the metadata worker reads. A bigger file is refused at
/// admission; the worker itself stops one byte past it.
pub const MAX_INPUT_BYTES: u64 = 2048 * MIB;
/// Revision of the sandboxed metadata result. Its cache key starts with
/// `metadata:<this>:`, a namespace only the sandboxed path writes.
pub const METADATA_PROVENANCE: &str = "bwrap-v1";

const MIB: u64 = 1024 * 1024;
/// Files whose worker-reported SHA-256 is remembered at once (the table is
/// emptied when full).
const PROVENANCE_LIMIT: usize = 4096;
/// A file modified this recently is not remembered by its stat identity.
const RACY_WINDOW: Duration = Duration::from_secs(2);
/// Largest answer read from a worker; a real one is under 400 bytes.
const MAX_WORKER_STDOUT: usize = 4096;
/// Largest diagnostic read from bubblewrap or the worker.
const MAX_WORKER_STDERR: usize = 2048;
/// Header bytes the MIME check looks at (as `FileMetadata` does in-process).
const HEADER_BYTES: usize = 512;
/// Where the worker binary is mounted inside the sandbox.
const WORKER_IN_SANDBOX: &str = "/file-scanner-worker";
/// SHA-256 of no bytes: what the start-up probe must get back.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The isolation an operator asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum IsolationProfile {
    /// Every analysis runs inside the server process (the default).
    #[default]
    None,
    /// Linux: the metadata section of analyze_file runs in a bubblewrap
    /// sandbox; every other analysis is refused
    Bwrap,
}

impl IsolationProfile {
    /// The name used on the command line and in the environment variable.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bwrap => "bwrap",
        }
    }
}

impl std::fmt::Display for IsolationProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why `--isolation bwrap` cannot be used. Raised at start-up, before any
/// transport accepts a call; the server then does not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IsolationError {
    #[error(
        "--isolation bwrap is available on Linux only (this build is for {os}). The server did \
         not start; it never falls back to in-process analysis. Use --isolation none"
    )]
    UnsupportedPlatform { os: &'static str },
    #[error(
        "--isolation bwrap needs at least one --allow-root (or FILE_SCANNER_ALLOWED_ROOTS): files \
         are opened only beneath roots opened at start-up. The server did not start"
    )]
    NoAllowRoots,
    #[error("--isolation bwrap cannot open the allowed root {root} ({reason}). The server did not start")]
    RootUnusable { root: String, reason: String },
    #[error(
        "--isolation bwrap needs openat2 with RESOLVE_BENEATH (Linux 5.6 or later) to open files \
         beneath the allowed roots ({detail}). The server did not start; it never falls back to \
         in-process analysis"
    )]
    SafeOpenUnavailable { detail: String },
    #[error(
        "--isolation bwrap needs bubblewrap installed by root at /usr/bin/bwrap or /bin/bwrap \
         ({reason}). The server did not start; it never falls back to in-process analysis"
    )]
    BwrapUnavailable { reason: String },
    #[error(
        "--isolation bwrap cannot use {path} as the sandboxed worker ({reason}). The server did \
         not start"
    )]
    WorkerExecutable { path: String, reason: String },
    #[error(
        "--isolation bwrap: bubblewrap at {bwrap} could not run the sandboxed worker on this host \
         ({detail}). Unprivileged user namespaces and Linux 5.11 or later are required. The \
         server did not start; it never falls back to in-process analysis"
    )]
    ProbeFailed { bwrap: String, detail: String },
}

/// Why one sandboxed analysis produced no result. Every variant is a tool
/// error of that call only; the server keeps answering.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkerError {
    #[error(
        "the sandboxed metadata worker did not finish within its {} s deadline and was killed",
        .deadline.as_secs_f64()
    )]
    Deadline { deadline: Duration },
    #[error(
        "the sandboxed metadata worker ran out of memory under its {} MiB memory limit and was \
         stopped",
        .memory_bytes / MIB
    )]
    Memory { memory_bytes: u64 },
    #[error(
        "startup memory refusal: the sandboxed metadata worker was not started because its {} \
         MiB memory limit is below the {} MiB its executable needs to load",
        .memory_bytes / MIB,
        .startup_bytes.div_ceil(MIB)
    )]
    MemoryBelowStartup {
        memory_bytes: u64,
        startup_bytes: u64,
    },
    #[error(
        "the sandboxed metadata worker failed ({status}) under its {} MiB memory limit and {} s \
         deadline: {detail}",
        .memory_bytes / MIB,
        .deadline.as_secs_f64()
    )]
    Failed {
        status: String,
        memory_bytes: u64,
        deadline: Duration,
        detail: String,
    },
    #[error("cannot start the sandbox: {0}")]
    Launch(String),
    #[error("the sandboxed metadata worker returned an unusable answer: {0}")]
    BadAnswer(String),
}

/// Why a sandboxed metadata call produced no result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
}

/// Why a file was not admitted to the sandbox, or why its answer was
/// refused. No variant has read a byte of the file in the server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error(
        "{path} is not spelled under an allowed root ({roots}). Under --isolation bwrap pass an \
         absolute path that starts with one of them"
    )]
    NotUnderRoot { path: String, roots: String },
    #[error(
        "{path} leaves the allowed root through `..`, an absolute link or a /proc link; copy the \
         file under the root"
    )]
    Escapes { path: String },
    #[error("{path} does not exist")]
    NotFound { path: String },
    #[error("{path} is a {kind}, not a regular file")]
    NotRegular { path: String, kind: &'static str },
    #[error("{path} is {size} bytes; the sandboxed metadata worker reads at most {cap} bytes")]
    TooLarge { path: String, size: u64, cap: u64 },
    #[error("cannot open {path}: {reason}")]
    Open { path: String, reason: String },
    #[error("{path} changed while it was being analyzed; call analyze_file again")]
    Changed { path: String },
}

/// One allowed root, opened at start-up. Paths are matched against both
/// spellings; the open always starts from `dir`.
#[derive(Debug)]
struct AuthorizedRoot {
    /// The configured spelling (`~` expanded) and the canonical one.
    spellings: Vec<PathBuf>,
    dir: std::fs::File,
}

/// A file admitted for one sandboxed call: one descriptor opened beneath an
/// authorized root, `fstat` showing a regular file within the byte cap.
#[derive(Debug)]
pub struct AdmittedFile {
    file: std::fs::File,
    stat: std::fs::Metadata,
    path: PathBuf,
}

impl AdmittedFile {
    /// The path as the caller spelled it (`~` expanded).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `fstat` taken at admission.
    pub const fn stat(&self) -> &std::fs::Metadata {
        &self.stat
    }
}

/// What identifies an unchanged file without reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Identity {
    device: u64,
    inode: u64,
    len: u64,
    modified_ns: i128,
    changed_ns: i128,
}

#[cfg(unix)]
fn identity(stat: &std::fs::Metadata) -> Option<Identity> {
    use std::os::unix::fs::MetadataExt;
    let ns = |secs: i64, nanos: i64| i128::from(secs) * 1_000_000_000 + i128::from(nanos);
    Some(Identity {
        device: stat.dev(),
        inode: stat.ino(),
        len: stat.len(),
        modified_ns: ns(stat.mtime(), stat.mtime_nsec()),
        changed_ns: ns(stat.ctime(), stat.ctime_nsec()),
    })
}

#[cfg(not(unix))]
fn identity(_stat: &std::fs::Metadata) -> Option<Identity> {
    None
}

/// SHA-256 values a worker reported, by the identity of the file it read.
#[derive(Debug, Default)]
struct Provenance(Mutex<HashMap<Identity, String>>);

impl Provenance {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Identity, String>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The text of the tool error that refuses `what` under `--isolation bwrap`.
pub fn refusal_text(what: &str) -> String {
    format!(
        "{what} is refused: this server runs with --isolation bwrap, which runs only analyze_file \
         with sections: [\"metadata\"] (or metadata: true) on one file, inside its sandbox, and \
         refuses every other analysis instead of running it in the server process. cache_status, \
         cache_clear, string_details and search_strings without file_path still work. Start the \
         server without --isolation for the full tool set."
    )
}

/// What the worker sends back: one compact JSON object on stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAnswer {
    pub mime_type: String,
    pub hashes: Hashes,
}

impl WorkerAnswer {
    /// Accept only what an honest worker can produce: a MIME type from the
    /// fixed list and lowercase hex digests of the right lengths.
    fn check(&self) -> Result<(), WorkerError> {
        if !crate::metadata::MIME_TYPES.contains(&self.mime_type.as_str()) {
            return Err(WorkerError::BadAnswer("unknown MIME type".to_string()));
        }
        let hashes = &self.hashes;
        for (name, value, len) in [
            ("md5", &hashes.md5, 32),
            ("sha256", &hashes.sha256, 64),
            ("sha512", &hashes.sha512, 128),
            ("blake3", &hashes.blake3, 64),
        ] {
            let hex = value.len() == len
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !hex {
                return Err(WorkerError::BadAnswer(format!("malformed {name} digest")));
            }
        }
        Ok(())
    }
}

/// The worker: hash at most [`MAX_INPUT_BYTES`] of stdin in one pass,
/// classify its first bytes, print the answer. Returns the process exit code.
/// Reads nothing but stdin.
pub fn worker_main() -> i32 {
    let mut head = Vec::with_capacity(HEADER_BYTES);
    let mut input = std::io::stdin().lock().take(MAX_INPUT_BYTES + 1);
    let hashes = match crate::hash::hash_reader(&mut input, &mut head, HEADER_BYTES) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!("cannot read the input: {error}");
            return 2;
        }
    };
    if input.limit() == 0 {
        eprintln!("the input is larger than {MAX_INPUT_BYTES} bytes");
        return 4;
    }
    let answer = WorkerAnswer {
        mime_type: crate::metadata::mime_type_of(&head).to_string(),
        hashes,
    };
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer(&mut out, &answer).is_err() || out.flush().is_err() {
        return 3;
    }
    0
}

/// One read-only mount of the sandbox's minimal runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeMount {
    /// `--ro-bind path path`
    Bind(PathBuf),
    /// `--ro-bind-try path path`
    BindIfPresent(PathBuf),
    /// `--symlink target at` (a merged-`/usr` link such as `/lib -> usr/lib`)
    Symlink { target: PathBuf, at: PathBuf },
}

/// A verified bubblewrap launcher for the metadata worker.
#[derive(Debug, Clone)]
pub struct Sandbox {
    bwrap: PathBuf,
    worker_exe: PathBuf,
    runtime: Vec<RuntimeMount>,
    deadline: Duration,
    memory_bytes: u64,
    roots: Arc<Vec<AuthorizedRoot>>,
    provenance: Arc<Provenance>,
    /// Address space the worker needs to start: its loadable segments plus
    /// [`STARTUP_MARGIN`] (0 when the executable's headers are not ELF64 LE).
    startup_bytes: u64,
}

/// Address space for the loader, libc, the stack and the heap of a starting
/// worker, on top of the executable's loadable segments.
const STARTUP_MARGIN: u64 = 48 * MIB;

/// The span of the PT_LOAD segments of a little-endian ELF64 executable, from
/// its first bytes; `None` for anything else.
fn elf_load_span(head: &[u8]) -> Option<u64> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(head.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(head.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(head.get(at..at + 8)?.try_into().ok()?));
    if head.get(..6)? != b"\x7FELF\x02\x01" {
        return None;
    }
    let phoff = usize::try_from(u64_at(0x20)?).ok()?;
    let phentsize = usize::from(u16_at(0x36)?);
    let phnum = usize::from(u16_at(0x38)?);
    let (mut low, mut high) = (u64::MAX, 0_u64);
    for index in 0..phnum {
        let at = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if u32_at(at)? != 1 {
            continue; // not PT_LOAD
        }
        let vaddr = u64_at(at + 0x10)?;
        let memsz = u64_at(at + 0x28)?;
        low = low.min(vaddr);
        high = high.max(vaddr.checked_add(memsz)?);
    }
    (high > low).then(|| high - low)
}

/// What the worker executable needs to start, from its program headers.
fn startup_bytes(worker_exe: &Path) -> u64 {
    let mut head = Vec::new();
    let read = std::fs::File::open(worker_exe)
        .and_then(|file| file.take(64 * 1024).read_to_end(&mut head));
    read.ok()
        .and_then(|_| elf_load_span(&head))
        .map_or(0, |span| span.saturating_add(STARTUP_MARGIN))
}

impl Sandbox {
    /// Open the allowed roots and prove `openat2` beneath them, verify
    /// bubblewrap and the worker executable, then run the worker once on an
    /// empty input to prove the sandbox starts on this host. Any failure is a
    /// typed error; nothing is returned that was not proven.
    pub async fn detect(
        worker_exe: &Path,
        allow_roots: &[PathBuf],
    ) -> Result<Self, IsolationError> {
        if !cfg!(target_os = "linux") {
            return Err(IsolationError::UnsupportedPlatform {
                os: std::env::consts::OS,
            });
        }
        let roots = open_roots(allow_roots)?;
        let bwrap = verify_bwrap()?;
        let worker_exe = verify_worker(worker_exe)?;
        let sandbox = Self {
            bwrap,
            startup_bytes: startup_bytes(&worker_exe),
            worker_exe,
            runtime: runtime_mounts(),
            deadline: DEFAULT_DEADLINE,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            roots: Arc::new(roots),
            provenance: Arc::default(),
        };
        let probe_failed = |detail: String| IsolationError::ProbeFailed {
            bwrap: sandbox.bwrap.display().to_string(),
            detail,
        };
        let empty = std::fs::File::open("/dev/null")
            .map_err(|error| probe_failed(format!("cannot open /dev/null: {error}")))?;
        let answer = sandbox
            .run_metadata(empty)
            .await
            .map_err(|error| probe_failed(error.to_string()))?;
        if answer.hashes.sha256 != EMPTY_SHA256 {
            return Err(probe_failed(
                "the worker answered for input it was not given".to_string(),
            ));
        }
        Ok(sandbox)
    }

    /// Unit tests of the refusal gate only: a sandbox whose launcher is
    /// `bwrap` as given, unverified and never probed, so any worker start
    /// fails with [`WorkerError::Launch`]. Not compiled outside tests.
    /// `root` is opened as the one allowed root where the platform allows
    /// (Linux); elsewhere there is none and every admission is refused.
    #[cfg(test)]
    pub(crate) fn unverified_for_tests(bwrap: PathBuf, root: &Path) -> Self {
        Self {
            bwrap,
            worker_exe: PathBuf::from("/nonexistent/file-scanner"),
            runtime: Vec::new(),
            deadline: DEFAULT_DEADLINE,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            roots: Arc::new(open_roots(&[root.to_path_buf()]).unwrap_or_default()),
            provenance: Arc::default(),
            startup_bytes: 0,
        }
    }

    /// Admit the file `raw` names: ONE `openat2` beneath the allowed root it
    /// is spelled under, then `fstat`. Nothing is read. A FIFO or device is
    /// opened non-blocking and refused by its type.
    pub fn admit(&self, raw: &str) -> Result<AdmittedFile, AdmissionError> {
        let path =
            crate::mcp_server::paths::expand_tilde(raw).map_err(|reason| AdmissionError::Open {
                path: raw.to_string(),
                reason,
            })?;
        let shown = path.display().to_string();
        let found = self.roots.iter().find_map(|root| {
            root.spellings
                .iter()
                .find_map(|spelling| path.strip_prefix(spelling).ok())
                .map(|relative| (root, relative))
        });
        let Some((root, relative)) = found.filter(|_| path.is_absolute()) else {
            return Err(self.not_under_root(shown));
        };
        if relative.as_os_str().is_empty() {
            return Err(AdmissionError::NotRegular {
                path: shown,
                kind: "directory",
            });
        }
        let file =
            open_beneath(&root.dir, relative).map_err(|error| match error.raw_os_error() {
                Some(code) if is_escape(code) => AdmissionError::Escapes {
                    path: shown.clone(),
                },
                _ if error.kind() == std::io::ErrorKind::NotFound => AdmissionError::NotFound {
                    path: shown.clone(),
                },
                _ => AdmissionError::Open {
                    path: shown.clone(),
                    reason: error.to_string(),
                },
            })?;
        self.finish_admission(file, path, shown)
    }

    fn not_under_root(&self, shown: String) -> AdmissionError {
        let roots = self
            .roots
            .iter()
            .filter_map(|root| root.spellings.first())
            .map(|spelling| spelling.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        AdmissionError::NotUnderRoot { path: shown, roots }
    }

    /// The type and size checks on the one admitted descriptor.
    fn finish_admission(
        &self,
        file: std::fs::File,
        path: PathBuf,
        shown: String,
    ) -> Result<AdmittedFile, AdmissionError> {
        let stat = file.metadata().map_err(|error| AdmissionError::Open {
            path: shown.clone(),
            reason: error.to_string(),
        })?;
        let kind = stat.file_type();
        if !kind.is_file() {
            let kind = if kind.is_dir() {
                "directory"
            } else {
                "special file (FIFO, socket or device)"
            };
            return Err(AdmissionError::NotRegular { path: shown, kind });
        }
        if stat.len() > MAX_INPUT_BYTES {
            return Err(AdmissionError::TooLarge {
                path: shown,
                size: stat.len(),
                cap: MAX_INPUT_BYTES,
            });
        }
        Ok(AdmittedFile { file, stat, path })
    }

    /// The SHA-256 a worker reported in this process for this same unchanged
    /// file, if any. Only such a value may select a cached isolated result.
    pub fn known_sha256(&self, admitted: &AdmittedFile) -> Option<String> {
        let identity = identity(&admitted.stat)?;
        self.provenance.lock().get(&identity).cloned()
    }

    /// Run the worker on the admitted descriptor and check, by a second
    /// `fstat` of the same descriptor, that the file did not change while it
    /// was read. Returns the answer and the admission `fstat`.
    pub async fn metadata_of(
        &self,
        admitted: AdmittedFile,
    ) -> Result<(WorkerAnswer, std::fs::Metadata), MetadataError> {
        let AdmittedFile { file, stat, path } = admitted;
        let changed = || {
            MetadataError::Admission(AdmissionError::Changed {
                path: path.display().to_string(),
            })
        };
        // A duplicate of the same open file description: only for `fstat`.
        let watch = file.try_clone().map_err(|error| {
            MetadataError::Admission(AdmissionError::Open {
                path: path.display().to_string(),
                reason: error.to_string(),
            })
        })?;
        let answer = self
            .run_metadata(file)
            .await
            .map_err(MetadataError::Worker)?;
        let after = watch.metadata().map_err(|_| changed())?;
        let before_id = identity(&stat);
        if before_id != identity(&after) {
            return Err(changed());
        }
        let racy = stat
            .modified()
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_none_or(|age| age < RACY_WINDOW);
        if let (Some(id), false) = (before_id, racy) {
            let mut known = self.provenance.lock();
            if known.len() >= PROVENANCE_LIMIT {
                known.clear();
            }
            known.insert(id, answer.hashes.sha256.clone());
        }
        Ok((answer, stat))
    }

    /// The same sandbox with another deadline and address-space limit (at
    /// least 1 ms and 1 MiB).
    #[must_use]
    pub fn with_limits(mut self, deadline: Duration, memory_bytes: u64) -> Self {
        self.deadline = deadline.max(Duration::from_millis(1));
        self.memory_bytes = memory_bytes.max(MIB);
        self
    }

    /// The verified bubblewrap executable.
    pub fn bwrap_path(&self) -> &Path {
        &self.bwrap
    }

    /// The deadline of one analysis.
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The address-space limit of one analysis, in bytes.
    pub const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    /// The bubblewrap command line (without the executable).
    fn arguments(&self) -> Vec<std::ffi::OsString> {
        let mut args: Vec<std::ffi::OsString> = [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
        ]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect();
        for mount in &self.runtime {
            match mount {
                RuntimeMount::Bind(path) => {
                    args.extend(["--ro-bind".into(), path.into(), path.into()]);
                }
                RuntimeMount::BindIfPresent(path) => {
                    args.extend(["--ro-bind-try".into(), path.into(), path.into()]);
                }
                RuntimeMount::Symlink { target, at } => {
                    args.extend(["--symlink".into(), target.into(), at.into()]);
                }
            }
        }
        args.extend([
            "--ro-bind".into(),
            self.worker_exe.clone().into(),
            WORKER_IN_SANDBOX.into(),
            // The root tmpfs bubblewrap builds would otherwise stay writable.
            "--remount-ro".into(),
            "/".into(),
            "--chdir".into(),
            "/".into(),
            "--".into(),
            WORKER_IN_SANDBOX.into(),
            WORKER_ARG.into(),
        ]);
        args
    }

    /// Run the worker on `input`: an admitted descriptor, or `/dev/null` for
    /// the start-up probe. The child is killed and reaped at the deadline, and
    /// killed when the returned future is dropped (a cancelled call or a
    /// server shutting down).
    async fn run_metadata(&self, input: std::fs::File) -> Result<WorkerAnswer, WorkerError> {
        // Deterministic: a limit the executable cannot even load under would
        // fail inside the kernel or the loader with no reliable signal.
        if self.memory_bytes < self.startup_bytes {
            return Err(WorkerError::MemoryBelowStartup {
                memory_bytes: self.memory_bytes,
                startup_bytes: self.startup_bytes,
            });
        }
        #[cfg(target_os = "linux")]
        {
            self.run_linux(input).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            drop(input);
            Err(WorkerError::Launch(
                "the bubblewrap sandbox needs Linux".to_string(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    async fn run_linux(&self, input: std::fs::File) -> Result<WorkerAnswer, WorkerError> {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::process::Stdio;

        let mut command = std::process::Command::new(&self.bwrap);
        command
            .args(self.arguments())
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let memory = self.memory_bytes;
        let cpu_seconds = self.deadline.as_secs().saturating_add(1);
        // SAFETY: the closure runs in the child between fork and exec. It
        // calls only setrlimit and close_range (async-signal-safe system
        // calls), allocates nothing and touches no lock.
        unsafe {
            command.pre_exec(move || limit_child(memory, cpu_seconds));
        }
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| {
            // exec of bubblewrap under the address-space limit
            if error.raw_os_error() == Some(libc::ENOMEM) {
                WorkerError::Memory {
                    memory_bytes: self.memory_bytes,
                }
            } else {
                WorkerError::Launch(format!("{}: {error}", self.bwrap.display()))
            }
        })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let finished = tokio::time::timeout(self.deadline, async {
            let (out, err) = tokio::join!(
                read_bounded(stdout, MAX_WORKER_STDOUT + 1),
                read_bounded(stderr, MAX_WORKER_STDERR)
            );
            (out, err, child.wait().await)
        })
        .await;
        let Ok((out, err, status)) = finished else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(WorkerError::Deadline {
                deadline: self.deadline,
            });
        };
        let status = status.map_err(|error| WorkerError::Launch(error.to_string()))?;
        let detail = printable(&err);
        if !status.success() {
            if status.signal() == Some(libc::SIGXCPU) {
                return Err(WorkerError::Deadline {
                    deadline: self.deadline,
                });
            }
            if out_of_memory(&detail, status.signal()) {
                return Err(WorkerError::Memory {
                    memory_bytes: self.memory_bytes,
                });
            }
            return Err(WorkerError::Failed {
                status: status.to_string(),
                memory_bytes: self.memory_bytes,
                deadline: self.deadline,
                detail,
            });
        }
        if out.len() > MAX_WORKER_STDOUT {
            return Err(WorkerError::BadAnswer(format!(
                "more than {MAX_WORKER_STDOUT} bytes"
            )));
        }
        let answer: WorkerAnswer = serde_json::from_slice(&out)
            .map_err(|error| WorkerError::BadAnswer(error.to_string()))?;
        answer.check()?;
        Ok(answer)
    }
}

/// Between fork and exec: the address-space, CPU-time and core limits, then
/// every descriptor above stderr marked close-on-exec, so bubblewrap and the
/// worker inherit stdin, stdout and stderr only.
#[cfg(target_os = "linux")]
fn limit_child(memory: u64, cpu_seconds: u64) -> std::io::Result<()> {
    const FIRST_EXTRA_FD: libc::c_uint = 3;
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    let set = |resource, value: u64| {
        let limit = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        // SAFETY: a plain system call on a stack value.
        if unsafe { libc::setrlimit(resource, &limit) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    set(libc::RLIMIT_AS, memory)?;
    set(libc::RLIMIT_CPU, cpu_seconds)?;
    set(libc::RLIMIT_CORE, 0)?;
    // SAFETY: close_range(2) with constant arguments; no Rust object owns
    // these descriptors in the child, which is about to exec.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_EXTRA_FD,
            libc::c_uint::MAX,
            CLOSE_RANGE_CLOEXEC,
        )
    };
    if marked == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(reader: Option<R>, limit: usize) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut buffer = Vec::new();
    if let Some(reader) = reader {
        // The pipe is closed when this returns, so a worker writing past the
        // limit gets an error instead of blocking until the deadline.
        let _ = reader.take(limit as u64).read_to_end(&mut buffer).await;
    }
    buffer
}

/// Diagnostic bytes as one printable line.
fn printable(bytes: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let text = text.trim();
    if text.is_empty() {
        "no diagnostic".to_string()
    } else {
        text.to_string()
    }
}

/// Whether a failed worker ran out of address space: an allocation failure
/// (Rust aborts with this text), or an exec or loader that could not map.
fn out_of_memory(detail: &str, signal: Option<i32>) -> bool {
    let detail = detail.to_ascii_lowercase();
    [
        "memory allocation of",
        "cannot allocate memory",
        "out of memory",
        "failed to map segment",
    ]
    .iter()
    .any(|needle| detail.contains(needle))
        || (signal == Some(6) && detail.contains("memory"))
}

/// Open every allowed root once, as a directory, and prove `openat2` works
/// beneath the first one. At least one root is required.
fn open_roots(allow_roots: &[PathBuf]) -> Result<Vec<AuthorizedRoot>, IsolationError> {
    if allow_roots.is_empty() {
        return Err(IsolationError::NoAllowRoots);
    }
    let mut roots = Vec::new();
    for configured in allow_roots {
        let unusable = |reason: String| IsolationError::RootUnusable {
            root: configured.display().to_string(),
            reason,
        };
        let expanded = crate::mcp_server::paths::expand_tilde(&configured.to_string_lossy())
            .map_err(&unusable)?;
        let canonical = std::fs::canonicalize(&expanded).map_err(|e| unusable(e.to_string()))?;
        let dir = open_directory(&canonical).map_err(|e| unusable(e.to_string()))?;
        let mut spellings = vec![canonical];
        if expanded.is_absolute() && !spellings.contains(&expanded) {
            spellings.push(expanded);
        }
        roots.push(AuthorizedRoot { spellings, dir });
    }
    if let Some(first) = roots.first() {
        open_beneath(&first.dir, Path::new(".")).map_err(|error| {
            IsolationError::SafeOpenUnavailable {
                detail: error.to_string(),
            }
        })?;
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_directory(_path: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::other(
        "allowed roots are opened on Linux only",
    ))
}

/// `openat2(dir, relative, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC)`
/// with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`: the result is beneath
/// `dir` or the call fails (`EXDEV`, `ELOOP`). `O_NONBLOCK` keeps a FIFO or
/// device from blocking the open; the caller refuses it by type.
#[cfg(target_os = "linux")]
fn open_beneath(dir: &std::fs::File, relative: &Path) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    /// `struct open_how` of openat2(2).
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;

    let name = std::ffi::CString::new(relative.as_os_str().as_bytes())?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: openat2(2) with a live directory descriptor, a NUL-terminated
    // name and a correctly sized `open_how` that outlive the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd as std::os::fd::RawFd) })
}

#[cfg(not(target_os = "linux"))]
fn open_beneath(_dir: &std::fs::File, _relative: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::other("openat2 is Linux only"))
}

/// Errors of `openat2` that mean the path tried to leave the root.
#[cfg(target_os = "linux")]
const fn is_escape(code: i32) -> bool {
    code == libc::EXDEV || code == libc::ELOOP
}

#[cfg(not(target_os = "linux"))]
const fn is_escape(_code: i32) -> bool {
    false
}

/// The first of [`BWRAP_PATHS`] that is a root-owned executable no one else
/// can replace: the file and every directory above it owned by root and not
/// writable by group or others. Returns the resolved absolute path.
fn verify_bwrap() -> Result<PathBuf, IsolationError> {
    let mut reasons = Vec::new();
    for candidate in BWRAP_PATHS {
        match root_owned_executable(Path::new(candidate)) {
            Ok(path) => return Ok(path),
            Err(reason) => reasons.push(format!("{candidate}: {reason}")),
        }
    }
    Err(IsolationError::BwrapUnavailable {
        reason: reasons.join("; "),
    })
}

#[cfg(unix)]
fn root_owned_executable(path: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    let resolved = std::fs::canonicalize(path).map_err(|error| error.to_string())?;
    let meta = std::fs::metadata(&resolved).map_err(|error| error.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    if meta.mode() & 0o111 == 0 {
        return Err("not executable".to_string());
    }
    for (index, item) in resolved.ancestors().enumerate() {
        let meta = std::fs::metadata(item).map_err(|error| error.to_string())?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            let what = if index == 0 {
                "the file"
            } else {
                "a parent directory"
            };
            return Err(format!(
                "{what} {} is not root-owned or is writable by others",
                item.display()
            ));
        }
    }
    Ok(resolved)
}

#[cfg(not(unix))]
fn root_owned_executable(_path: &Path) -> Result<PathBuf, String> {
    Err("not a Unix system".to_string())
}

/// The worker executable: an absolute, existing regular file.
fn verify_worker(path: &Path) -> Result<PathBuf, IsolationError> {
    let failed = |reason: String| IsolationError::WorkerExecutable {
        path: path.display().to_string(),
        reason,
    };
    let resolved = std::fs::canonicalize(path).map_err(|error| failed(error.to_string()))?;
    let meta = std::fs::metadata(&resolved).map_err(|error| failed(error.to_string()))?;
    if !meta.is_file() {
        return Err(failed("not a regular file".to_string()));
    }
    Ok(resolved)
}

/// The read-only runtime the worker needs to start: `/usr`, the library
/// directories (as links when `/usr` is merged) and the loader cache.
fn runtime_mounts() -> Vec<RuntimeMount> {
    let mut mounts = vec![RuntimeMount::Bind(PathBuf::from("/usr"))];
    for name in ["/lib", "/lib64", "/lib32"] {
        let path = PathBuf::from(name);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            if let Ok(target) = std::fs::read_link(&path) {
                mounts.push(RuntimeMount::Symlink { target, at: path });
            }
        } else if meta.is_dir() {
            mounts.push(RuntimeMount::Bind(path));
        }
    }
    mounts.push(RuntimeMount::BindIfPresent(PathBuf::from(
        "/etc/ld.so.cache",
    )));
    mounts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> Sandbox {
        Sandbox {
            bwrap: PathBuf::from("/usr/bin/bwrap"),
            worker_exe: PathBuf::from("/opt/fs/file-scanner"),
            runtime: vec![
                RuntimeMount::Bind(PathBuf::from("/usr")),
                RuntimeMount::Symlink {
                    target: PathBuf::from("usr/lib"),
                    at: PathBuf::from("/lib"),
                },
                RuntimeMount::BindIfPresent(PathBuf::from("/etc/ld.so.cache")),
            ],
            deadline: DEFAULT_DEADLINE,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            roots: Arc::default(),
            provenance: Arc::default(),
            startup_bytes: 0,
        }
    }

    #[test]
    fn the_startup_footprint_is_read_from_the_program_headers() {
        // A minimal ELF64 LE header with two PT_LOAD entries at 0x40.
        let mut head = vec![0_u8; 0x40 + 2 * 0x38];
        head[..6].copy_from_slice(b"\x7FELF\x02\x01");
        head[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        head[0x36..0x38].copy_from_slice(&0x38_u16.to_le_bytes());
        head[0x38..0x3A].copy_from_slice(&2_u16.to_le_bytes());
        for (index, (vaddr, memsz)) in [(0x1000_u64, 0x2000_u64), (0x10_0000, 0x500)]
            .into_iter()
            .enumerate()
        {
            let at = 0x40 + index * 0x38;
            head[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
            head[at + 0x10..at + 0x18].copy_from_slice(&vaddr.to_le_bytes());
            head[at + 0x28..at + 0x30].copy_from_slice(&memsz.to_le_bytes());
        }
        assert_eq!(elf_load_span(&head), Some(0x10_0500 - 0x1000));
        assert_eq!(elf_load_span(b"MZ not an ELF"), None);
        assert_eq!(elf_load_span(&head[..0x50]), None);
    }

    #[tokio::test]
    async fn a_limit_below_the_startup_footprint_is_refused_before_launch() {
        let mut tight = sandbox().with_limits(Duration::from_secs(1), 16 * MIB);
        tight.startup_bytes = 200 * MIB;
        let error = tight
            .run_metadata(tempfile::tempfile().unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, WorkerError::MemoryBelowStartup { .. }),
            "{error}"
        );
        assert!(error.to_string().starts_with("startup memory refusal"));
    }

    #[test]
    fn the_command_line_isolates_and_mounts_only_the_allowlist() {
        let args: Vec<String> = sandbox()
            .arguments()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(joined.starts_with(
            "--unshare-all --die-with-parent --new-session --clearenv --cap-drop ALL "
        ));
        for flag in [
            "--share-net",
            "--bind ",
            "--dev-bind",
            "--proc",
            "--dev ",
            "--tmpfs",
        ] {
            assert!(!joined.contains(flag), "{flag} in {joined}");
        }
        let mounted: Vec<&str> = args
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" || w[0] == "--ro-bind-try")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            mounted,
            ["/usr", "/etc/ld.so.cache", "/opt/fs/file-scanner"],
            "{joined}"
        );
        assert!(joined.contains("--symlink usr/lib /lib"), "{joined}");
        assert!(joined.contains("--remount-ro /"), "{joined}");
        assert!(joined.ends_with(&format!("-- {WORKER_IN_SANDBOX} {WORKER_ARG}")));
    }

    #[test]
    fn limits_have_a_floor() {
        let tight = sandbox().with_limits(Duration::ZERO, 0);
        assert_eq!(tight.deadline(), Duration::from_millis(1));
        assert_eq!(tight.memory_bytes(), MIB);
    }

    #[test]
    fn answers_are_checked_before_use() {
        let good = WorkerAnswer {
            mime_type: "application/x-elf".to_string(),
            hashes: Hashes {
                md5: "0".repeat(32),
                sha256: EMPTY_SHA256.to_string(),
                sha512: "a".repeat(128),
                blake3: "f".repeat(64),
            },
        };
        assert!(good.check().is_ok());
        let mut bad = good.clone();
        bad.mime_type = "text/html; <script>".to_string();
        assert!(matches!(bad.check(), Err(WorkerError::BadAnswer(_))));
        let mut bad = good.clone();
        bad.hashes.sha256 = EMPTY_SHA256.to_uppercase();
        assert!(matches!(bad.check(), Err(WorkerError::BadAnswer(_))));
        let mut bad = good;
        bad.hashes.md5.push('0');
        assert!(matches!(bad.check(), Err(WorkerError::BadAnswer(_))));
        let extra = r#"{"mime_type":"application/pdf","hashes":{"md5":"","sha256":"","sha512":"","blake3":""},"path":"/etc/passwd"}"#;
        assert!(serde_json::from_str::<WorkerAnswer>(extra).is_err());
    }

    #[test]
    fn failures_name_the_limit() {
        let deadline = WorkerError::Deadline {
            deadline: Duration::from_millis(1500),
        };
        assert!(
            deadline.to_string().contains("1.5 s deadline"),
            "{deadline}"
        );
        let memory = WorkerError::Memory {
            memory_bytes: 16 * MIB,
        };
        assert!(
            memory.to_string().contains("16 MiB memory limit"),
            "{memory}"
        );
        let failed = WorkerError::Failed {
            status: "exit status: 1".to_string(),
            memory_bytes: 16 * MIB,
            deadline: Duration::from_secs(2),
            detail: printable(b"bwrap: \x1b[31msetting up uid map\n"),
        };
        let text = failed.to_string();
        assert!(
            text.contains("16 MiB memory limit") && text.contains("2 s"),
            "{text}"
        );
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }

    #[test]
    fn out_of_memory_is_recognised_from_the_diagnostic() {
        assert!(out_of_memory(
            "memory allocation of 1048576 bytes failed",
            Some(6)
        ));
        assert!(out_of_memory(
            "bwrap: execvp /file-scanner-worker: Cannot allocate memory",
            None
        ));
        assert!(!out_of_memory(
            "bwrap: No permissions to create new namespace",
            None
        ));
    }

    #[test]
    fn the_refusal_names_the_supported_request_and_the_fix() {
        let text = refusal_text("disassemble");
        assert!(text.starts_with("disassemble is refused"));
        assert!(text.contains("sections: [\"metadata\"]"));
        assert!(text.contains("without --isolation"));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn bwrap_is_refused_off_linux() {
        let error = Sandbox::detect(Path::new("/bin/sh"), &[PathBuf::from("/tmp")])
            .await
            .unwrap_err();
        assert!(matches!(error, IsolationError::UnsupportedPlatform { .. }));
    }

    #[test]
    fn no_allow_roots_is_refused() {
        assert_eq!(open_roots(&[]).unwrap_err(), IsolationError::NoAllowRoots);
    }

    /// Admission on benign fixtures: one `openat2` beneath the root, no
    /// escape by `..`, links or a rename, no blocking on a FIFO, and a
    /// descriptor that stays bound to the file it opened.
    #[cfg(target_os = "linux")]
    mod admission {
        use super::*;
        use std::io::Read as _;
        use std::os::unix::{ffi::OsStrExt, fs::symlink};

        const INSIDE: &[u8] = b"\x7FELF benign inside bytes";

        struct Fixture {
            _dir: tempfile::TempDir,
            root: PathBuf,
            outside: PathBuf,
            sandbox: Sandbox,
        }

        fn fixture() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("root");
            std::fs::create_dir(&root).unwrap();
            let outside = dir.path().join("outside.txt");
            std::fs::write(&outside, b"benign outside bytes").unwrap();
            std::fs::write(root.join("inside.bin"), INSIDE).unwrap();
            let sandbox = Sandbox::unverified_for_tests(PathBuf::from("/nonexistent/bwrap"), &root);
            Fixture {
                _dir: dir,
                root,
                outside,
                sandbox,
            }
        }

        fn raw(path: &Path) -> String {
            path.to_string_lossy().into_owned()
        }

        #[test]
        fn a_regular_file_beneath_the_root_is_admitted_by_one_descriptor() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            let mut admitted = f.sandbox.admit(&raw(&path)).unwrap();
            assert_eq!(admitted.path(), path);
            assert_eq!(admitted.stat().len(), INSIDE.len() as u64);
            let mut bytes = Vec::new();
            admitted.file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, INSIDE);
        }

        #[test]
        fn paths_outside_or_leaving_the_root_are_refused() {
            let f = fixture();
            let refused = |path: String| f.sandbox.admit(&path).unwrap_err();
            assert!(matches!(
                refused(raw(&f.outside)),
                AdmissionError::NotUnderRoot { .. }
            ));
            assert!(matches!(
                refused("inside.bin".into()),
                AdmissionError::NotUnderRoot { .. }
            ));
            let dotdot = format!("{}/../outside.txt", raw(&f.root));
            assert!(matches!(refused(dotdot), AdmissionError::Escapes { .. }));
            assert!(matches!(
                refused(raw(&f.root.join("missing.bin"))),
                AdmissionError::NotFound { .. }
            ));
        }

        #[test]
        fn links_that_leave_the_root_are_refused_and_links_inside_are_followed() {
            let f = fixture();
            symlink(&f.outside, f.root.join("absolute.lnk")).unwrap();
            symlink("../outside.txt", f.root.join("relative.lnk")).unwrap();
            symlink("inside.bin", f.root.join("inside.lnk")).unwrap();
            for name in ["absolute.lnk", "relative.lnk"] {
                let error = f.sandbox.admit(&raw(&f.root.join(name))).unwrap_err();
                assert!(
                    matches!(error, AdmissionError::Escapes { .. }),
                    "{name}: {error}"
                );
            }
            let followed = f.sandbox.admit(&raw(&f.root.join("inside.lnk"))).unwrap();
            assert_eq!(followed.stat().len(), INSIDE.len() as u64);
        }

        #[test]
        fn a_rename_cannot_substitute_the_file() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            // Admitted first, then replaced: the descriptor still reads the
            // file that was admitted, never the replacement.
            let mut admitted = f.sandbox.admit(&raw(&path)).unwrap();
            std::fs::write(f.root.join("swap.bin"), b"benign replacement").unwrap();
            std::fs::rename(f.root.join("swap.bin"), &path).unwrap();
            let mut bytes = Vec::new();
            admitted.file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, INSIDE);
            // Replaced by a link to a file outside before admission: refused.
            symlink(&f.outside, f.root.join("evil.lnk")).unwrap();
            std::fs::rename(f.root.join("evil.lnk"), &path).unwrap();
            let error = f.sandbox.admit(&raw(&path)).unwrap_err();
            assert!(matches!(error, AdmissionError::Escapes { .. }), "{error}");
        }

        #[test]
        fn special_files_and_directories_are_refused_without_blocking() {
            let f = fixture();
            let fifo = f.root.join("pipe");
            let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
            // SAFETY: mkfifo(3) on a NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            // Nothing writes to the FIFO: a blocking open would hang here.
            let error = f.sandbox.admit(&raw(&fifo)).unwrap_err();
            assert!(
                matches!(error, AdmissionError::NotRegular { .. }),
                "{error}"
            );
            std::fs::create_dir(f.root.join("sub")).unwrap();
            for dir in [f.root.join("sub"), f.root.clone()] {
                let error = f.sandbox.admit(&raw(&dir)).unwrap_err();
                assert!(
                    matches!(
                        error,
                        AdmissionError::NotRegular {
                            kind: "directory",
                            ..
                        }
                    ),
                    "{error}"
                );
            }
        }

        #[test]
        fn a_file_over_the_byte_cap_is_refused_before_any_read() {
            let f = fixture();
            let big = f.root.join("big.bin");
            std::fs::File::create(&big)
                .unwrap()
                .set_len(MAX_INPUT_BYTES + 1)
                .unwrap();
            let error = f.sandbox.admit(&raw(&big)).unwrap_err();
            assert!(matches!(error, AdmissionError::TooLarge { .. }), "{error}");
        }

        #[test]
        fn a_remembered_hash_selects_only_the_same_unchanged_file() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            let admitted = f.sandbox.admit(&raw(&path)).unwrap();
            assert_eq!(f.sandbox.known_sha256(&admitted), None);
            let sha = "ab".repeat(32);
            f.sandbox
                .provenance
                .lock()
                .insert(identity(admitted.stat()).unwrap(), sha.clone());
            assert_eq!(f.sandbox.known_sha256(&admitted), Some(sha));
            std::fs::write(&path, b"benign, rewritten and longer").unwrap();
            let again = f.sandbox.admit(&raw(&path)).unwrap();
            assert_eq!(f.sandbox.known_sha256(&again), None);
        }
    }
}
