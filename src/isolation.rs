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
//! The parts:
//!
//! - `admission`: the allowed roots, opened at start-up; ONE `openat2`
//!   descriptor per call beneath them, checked to be a regular file within
//!   [`MAX_INPUT_BYTES`]; the provenance table of worker-reported hashes.
//! - `launch`: the verified bubblewrap launcher, the sandbox command line, one
//!   run of the worker under its deadline, and the worker's entry point.
//! - `limits`: the worker's startup footprint, the resource limits and
//!   descriptor control applied between fork and exec, and the reading of an
//!   out-of-memory failure.
//!
//! Each process of a run (bubblewrap and the worker) gets the address-space
//! limit; the call has a wall-clock deadline. The worker hashes at most
//! [`MAX_INPUT_BYTES`] of the admitted descriptor and returns the MIME type and
//! the hashes; the server takes the stat fields from its own `fstat` of the
//! descriptor, before and after, and refuses the answer when the file changed
//! in between.
//!
//! Cache provenance: an isolated result is stored only under its own key
//! ([`METADATA_PROVENANCE`]), never under the in-process `metadata` key, and is
//! looked up only by a SHA-256 that a worker reported for the same unchanged
//! file in this process.

mod admission;
mod launch;
mod limits;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub use admission::{AdmissionError, AdmittedFile};
pub use launch::{running_executable, worker_main, WorkerAnswer, WorkerError};

/// Environment variable that selects the profile (`--isolation` wins).
pub const ISOLATION_ENV: &str = "FILE_SCANNER_ISOLATION";
/// The hidden subcommand that turns the executable into the sandboxed worker.
pub const WORKER_ARG: &str = "__isolated-metadata-worker";
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

/// Why a sandboxed metadata call produced no result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
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

/// The sandbox exists on Linux only.
fn require_linux() -> Result<(), IsolationError> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(IsolationError::UnsupportedPlatform {
            os: std::env::consts::OS,
        })
    }
}

/// A verified sandbox for the metadata worker: admission (roots, provenance)
/// and execution (launcher, limits).
#[derive(Debug, Clone)]
pub struct Sandbox {
    launcher: launch::Launcher,
    admission: Arc<admission::Admission>,
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
        require_linux()?;
        let admission = admission::Admission::open(allow_roots)?;
        let launcher = launch::Launcher::verify(worker_exe)?;
        launcher.probe().await?;
        Ok(Self {
            launcher,
            admission: Arc::new(admission),
        })
    }

    /// [`Sandbox::detect`] with the executable the kernel is running (this
    /// server's own image, see [`running_executable`]) as the worker.
    pub async fn detect_running(allow_roots: &[PathBuf]) -> Result<Self, IsolationError> {
        require_linux()?;
        let worker = running_executable().map_err(|error| IsolationError::WorkerExecutable {
            path: "/proc/self/exe".to_string(),
            reason: error.to_string(),
        })?;
        Self::detect(&worker, allow_roots).await
    }

    /// Unit tests of the refusal gate only: a sandbox whose launcher is
    /// `bwrap` as given, unverified and never probed, so any worker start
    /// fails with [`WorkerError::Launch`]. Not compiled outside tests.
    /// `root` is opened as the one allowed root where the platform allows
    /// (Linux); elsewhere there is none and every admission is refused.
    #[cfg(test)]
    pub(crate) fn unverified_for_tests(bwrap: PathBuf, root: &Path) -> Self {
        Self {
            launcher: launch::Launcher::unverified(bwrap),
            admission: Arc::new(
                admission::Admission::open(&[root.to_path_buf()]).unwrap_or_default(),
            ),
        }
    }

    /// Admit the file `raw` names (see the `admission` module): one
    /// descriptor, nothing read.
    pub fn admit(&self, raw: &str) -> Result<AdmittedFile, AdmissionError> {
        self.admission.admit(raw)
    }

    /// The SHA-256 a worker reported in this process for this same unchanged
    /// file, if any. Only such a value may select a cached isolated result.
    pub fn known_sha256(&self, admitted: &AdmittedFile) -> Option<String> {
        self.admission.known_sha256(admitted.stat())
    }

    /// Run the worker on the admitted descriptor and check, by a second
    /// `fstat` of the same descriptor, that the file did not change while it
    /// was read. Returns the answer and the admission `fstat`.
    pub async fn metadata_of(
        &self,
        admitted: AdmittedFile,
    ) -> Result<(WorkerAnswer, std::fs::Metadata), MetadataError> {
        let (file, stat, path) = admitted.into_parts();
        // A duplicate of the same open file description: only for `fstat`.
        let watch = file.try_clone().map_err(|error| AdmissionError::Open {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        let answer = self.launcher.run(file).await?;
        let after = watch.metadata().map_err(|_| AdmissionError::Changed {
            path: path.display().to_string(),
        })?;
        admission::check_unchanged(&stat, &after, &path)?;
        self.admission.remember(&stat, &answer.hashes.sha256);
        Ok((answer, stat))
    }

    /// The same sandbox with another deadline and address-space limit (at
    /// least 1 ms and 1 MiB).
    #[must_use]
    pub fn with_limits(mut self, deadline: Duration, memory_bytes: u64) -> Self {
        self.launcher = self.launcher.with_limits(deadline, memory_bytes);
        self
    }

    /// The verified bubblewrap executable.
    pub fn bwrap_path(&self) -> &Path {
        self.launcher.bwrap_path()
    }

    /// The deadline of one analysis.
    pub const fn deadline(&self) -> Duration {
        self.launcher.deadline()
    }

    /// The address-space limit of each process of one analysis, in bytes.
    pub const fn memory_bytes(&self) -> u64 {
        self.launcher.memory_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusal_names_the_supported_request_and_the_fix() {
        let text = refusal_text("disassemble");
        assert!(text.starts_with("disassemble is refused"));
        assert!(text.contains("sections: [\"metadata\"]"));
        assert!(text.contains("without --isolation"));
    }

    #[test]
    fn profile_names_match_the_command_line() {
        assert_eq!(IsolationProfile::default(), IsolationProfile::None);
        assert_eq!(IsolationProfile::None.to_string(), "none");
        assert_eq!(IsolationProfile::Bwrap.to_string(), "bwrap");
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn bwrap_is_refused_off_linux() {
        let error = Sandbox::detect(Path::new("/bin/sh"), &[PathBuf::from("/tmp")])
            .await
            .unwrap_err();
        assert!(matches!(error, IsolationError::UnsupportedPlatform { .. }));
    }
}
