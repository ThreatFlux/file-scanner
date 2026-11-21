//! Execution: the verified bubblewrap launcher, the sandbox command line, one
//! run of the worker (spawn, read under the deadline, classify the exit,
//! check the answer) and the worker's own entry point.
//!
//! The worker is this same executable under bubblewrap (a verified,
//! root-owned absolute path), with the admitted descriptor as its stdin and
//! only input. It runs in fresh user, PID, network, IPC, UTS and cgroup
//! namespaces, with no network, a read-only root that holds only read-only
//! binds of `/usr`, the library directories, `/etc/ld.so.cache` and the worker
//! binary, no `/proc`, `/dev` or `/tmp`, an empty environment, no capabilities
//! and no descriptor other than stdin, stdout and stderr.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use super::{
    limits, IsolationError, DEFAULT_DEADLINE, DEFAULT_MEMORY_BYTES, MAX_INPUT_BYTES, MIB,
    WORKER_ARG,
};
use crate::hash::Hashes;

/// The only places bubblewrap is taken from. No `PATH` lookup.
pub const BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/bin/bwrap"];

/// Largest answer read from a worker; a real one is under 400 bytes.
const MAX_WORKER_STDOUT: usize = 4096;
/// Largest diagnostic read from bubblewrap or the worker.
const MAX_WORKER_STDERR: usize = 2048;
/// Header bytes the MIME check looks at (as `FileMetadata` does in-process).
const HEADER_BYTES: usize = crate::metadata::MIME_HEADER_BYTES;
/// Where the worker binary is mounted inside the sandbox.
const WORKER_IN_SANDBOX: &str = "/file-scanner-worker";
/// SHA-256 of no bytes: what the start-up probe must get back.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

/// Resolve the running executable's pathname from `/proc/self/exe`.
/// Bubblewrap mounts this pathname from the scanner installation.
pub fn running_executable() -> std::io::Result<PathBuf> {
    if cfg!(target_os = "linux") {
        std::fs::read_link("/proc/self/exe")
    } else {
        Err(std::io::Error::other(
            "the sandboxed worker exists on Linux only",
        ))
    }
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

impl RuntimeMount {
    /// The bubblewrap arguments of this mount.
    fn arguments(&self) -> [std::ffi::OsString; 3] {
        match self {
            Self::Bind(path) => ["--ro-bind".into(), path.into(), path.into()],
            Self::BindIfPresent(path) => ["--ro-bind-try".into(), path.into(), path.into()],
            Self::Symlink { target, at } => ["--symlink".into(), target.into(), at.into()],
        }
    }
}

/// A verified bubblewrap launcher for the metadata worker, with its limits.
#[derive(Debug, Clone)]
pub(super) struct Launcher {
    bwrap: PathBuf,
    worker_exe: PathBuf,
    runtime: Vec<RuntimeMount>,
    deadline: Duration,
    memory_bytes: u64,
    /// Address space the worker needs to start (see `limits::startup_bytes`).
    startup_bytes: u64,
}

impl Launcher {
    /// Verify bubblewrap and the worker executable.
    pub(super) fn verify(worker_exe: &Path) -> Result<Self, IsolationError> {
        let bwrap = verify_bwrap()?;
        let worker_exe = verify_worker(worker_exe)?;
        Ok(Self {
            bwrap,
            startup_bytes: limits::startup_bytes(&worker_exe),
            worker_exe,
            runtime: runtime_mounts(),
            deadline: DEFAULT_DEADLINE,
            memory_bytes: DEFAULT_MEMORY_BYTES,
        })
    }

    /// A launcher that was never verified (`bwrap` as given); tests only.
    #[cfg(test)]
    pub(super) fn unverified(bwrap: PathBuf) -> Self {
        Self {
            bwrap,
            worker_exe: PathBuf::from("/nonexistent/file-scanner"),
            runtime: Vec::new(),
            deadline: DEFAULT_DEADLINE,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            startup_bytes: 0,
        }
    }

    /// Run the worker once on an empty input to prove the sandbox starts on
    /// this host and answers for what it was given.
    pub(super) async fn probe(&self) -> Result<(), IsolationError> {
        let failed = |detail: String| IsolationError::ProbeFailed {
            bwrap: self.bwrap.display().to_string(),
            detail,
        };
        let empty = std::fs::File::open("/dev/null")
            .map_err(|error| failed(format!("cannot open /dev/null: {error}")))?;
        let answer = self
            .run(empty)
            .await
            .map_err(|error| failed(error.to_string()))?;
        if answer.hashes.sha256 == EMPTY_SHA256 {
            Ok(())
        } else {
            Err(failed(
                "the worker answered for input it was not given".to_string(),
            ))
        }
    }

    /// The same launcher with another deadline and address-space limit (at
    /// least 1 ms and 1 MiB).
    #[must_use]
    pub(super) fn with_limits(mut self, deadline: Duration, memory_bytes: u64) -> Self {
        self.deadline = deadline.max(Duration::from_millis(1));
        self.memory_bytes = memory_bytes.max(MIB);
        self
    }

    pub(super) fn bwrap_path(&self) -> &Path {
        &self.bwrap
    }

    pub(super) const fn deadline(&self) -> Duration {
        self.deadline
    }

    pub(super) const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    /// The bubblewrap command line (without the executable).
    fn arguments(&self) -> Vec<std::ffi::OsString> {
        let isolation = [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
        ]
        .map(std::ffi::OsString::from);
        let worker: [std::ffi::OsString; 9] = [
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
        ];
        isolation
            .into_iter()
            .chain(self.runtime.iter().flat_map(RuntimeMount::arguments))
            .chain(worker)
            .chain([WORKER_ARG.into()])
            .collect()
    }

    /// Run the worker on `input`: an admitted descriptor, or `/dev/null` for
    /// the start-up probe. The child is killed and reaped at the deadline, and
    /// killed when the returned future is dropped (a cancelled call or a
    /// server shutting down).
    pub(super) async fn run(&self, input: std::fs::File) -> Result<WorkerAnswer, WorkerError> {
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
            let child = self.spawn(input)?;
            let (out, err, status) = self.collect(child).await?;
            self.classify_exit(status, &err)?;
            parse_answer(&out)
        }
        #[cfg(not(target_os = "linux"))]
        {
            drop(input);
            Err(WorkerError::Launch(
                "the bubblewrap sandbox needs Linux".to_string(),
            ))
        }
    }

    /// Phase 1: start bubblewrap with the limits applied between fork and
    /// exec, an empty environment, `input` as stdin and piped output.
    #[cfg(target_os = "linux")]
    fn spawn(&self, input: std::fs::File) -> Result<tokio::process::Child, WorkerError> {
        use std::os::unix::process::CommandExt;
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
        // SAFETY: `pre_exec` closures run in the forked child before exec.
        // This one captures two integers and calls `limits::limit_child`,
        // which makes only async-signal-safe system calls (setrlimit,
        // close_range), allocates nothing and takes no lock.
        unsafe {
            command.pre_exec(move || limits::limit_child(memory, cpu_seconds));
        }
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        command.spawn().map_err(|error| {
            // exec of bubblewrap itself failed under the address-space limit
            if error.raw_os_error() == Some(libc::ENOMEM) {
                WorkerError::Memory {
                    memory_bytes: self.memory_bytes,
                }
            } else {
                WorkerError::Launch(format!("{}: {error}", self.bwrap.display()))
            }
        })
    }

    /// Phase 2: read bounded stdout and stderr and wait for the exit, all
    /// within the deadline; past it the child is killed and reaped.
    #[cfg(target_os = "linux")]
    async fn collect(
        &self,
        mut child: tokio::process::Child,
    ) -> Result<(Vec<u8>, Vec<u8>, std::process::ExitStatus), WorkerError> {
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
        Ok((out, err, status))
    }

    /// Phase 3: a non-zero exit becomes the limit it hit, or a failure with
    /// its printable diagnostic.
    #[cfg(target_os = "linux")]
    fn classify_exit(
        &self,
        status: std::process::ExitStatus,
        err: &[u8],
    ) -> Result<(), WorkerError> {
        use std::os::unix::process::ExitStatusExt;
        if status.success() {
            return Ok(());
        }
        let detail = printable(err);
        if status.signal() == Some(libc::SIGXCPU) {
            return Err(WorkerError::Deadline {
                deadline: self.deadline,
            });
        }
        if limits::out_of_memory(&detail, status.signal()) {
            return Err(WorkerError::Memory {
                memory_bytes: self.memory_bytes,
            });
        }
        Err(WorkerError::Failed {
            status: status.to_string(),
            memory_bytes: self.memory_bytes,
            deadline: self.deadline,
            detail,
        })
    }
}

/// Phase 4: the bounded answer, parsed and checked.
fn parse_answer(out: &[u8]) -> Result<WorkerAnswer, WorkerError> {
    if out.len() > MAX_WORKER_STDOUT {
        return Err(WorkerError::BadAnswer(format!(
            "more than {MAX_WORKER_STDOUT} bytes"
        )));
    }
    let answer: WorkerAnswer =
        serde_json::from_slice(out).map_err(|error| WorkerError::BadAnswer(error.to_string()))?;
    answer.check()?;
    Ok(answer)
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
    let libraries = ["/lib", "/lib64", "/lib32"]
        .into_iter()
        .filter_map(|name| library_mount(PathBuf::from(name)));
    std::iter::once(RuntimeMount::Bind(PathBuf::from("/usr")))
        .chain(libraries)
        .chain([RuntimeMount::BindIfPresent(PathBuf::from(
            "/etc/ld.so.cache",
        ))])
        .collect()
}

/// A library directory as a link (merged `/usr`) or a bind; `None` if absent.
fn library_mount(path: PathBuf) -> Option<RuntimeMount> {
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&path).ok()?;
        Some(RuntimeMount::Symlink { target, at: path })
    } else {
        meta.is_dir().then_some(RuntimeMount::Bind(path))
    }
}

#[cfg(test)]
mod tests;
