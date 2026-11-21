//! Admission: which file a sandboxed call may read, opened exactly once.
//!
//! Each allowed root is opened at start-up. A call's file is opened with ONE
//! `openat2` beneath the root it is spelled under (`RESOLVE_BENEATH |
//! RESOLVE_NO_MAGICLINKS`, so `..`, absolute links and `/proc` links cannot
//! leave it), non-blocking and without a controlling terminal; then `fstat`
//! must show a regular file within [`MAX_INPUT_BYTES`]. That one descriptor is
//! all the call uses: the server never reopens the path and never reads the
//! content itself.
//!
//! The provenance table remembers, per unchanged file (device, inode, size,
//! modification and change time), the SHA-256 a worker reported in this
//! process; only such a value may select a cached sandboxed result.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, SystemTime},
};

use super::{IsolationError, MAX_INPUT_BYTES};

/// Files whose worker-reported SHA-256 is remembered at once (the table is
/// emptied when full).
const PROVENANCE_LIMIT: usize = 4096;
/// A file modified this recently is not remembered by its stat identity.
const RACY_WINDOW: Duration = Duration::from_secs(2);

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

    /// The descriptor, its admission `fstat` and the path, for the run.
    pub(super) fn into_parts(self) -> (std::fs::File, std::fs::Metadata, PathBuf) {
        (self.file, self.stat, self.path)
    }
}

/// One allowed root, opened at start-up. Paths are matched against both
/// spellings; the open always starts from `dir`.
#[derive(Debug)]
struct AuthorizedRoot {
    /// The canonical spelling and, when it differs, the configured one.
    spellings: Vec<PathBuf>,
    dir: std::fs::File,
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

/// The allowed roots and the provenance table of one sandbox.
#[derive(Debug, Default)]
pub(super) struct Admission {
    roots: Vec<AuthorizedRoot>,
    provenance: Mutex<HashMap<Identity, String>>,
}

impl Admission {
    /// Open every allowed root once, as a directory, and prove `openat2`
    /// works beneath the first one. At least one root is required.
    pub(super) fn open(allow_roots: &[PathBuf]) -> Result<Self, IsolationError> {
        if allow_roots.is_empty() {
            return Err(IsolationError::NoAllowRoots);
        }
        let roots = allow_roots
            .iter()
            .map(|configured| open_root(configured))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(first) = roots.first() {
            open_beneath(&first.dir, Path::new(".")).map_err(|error| {
                IsolationError::SafeOpenUnavailable {
                    detail: error.to_string(),
                }
            })?;
        }
        Ok(Self {
            roots,
            provenance: Mutex::default(),
        })
    }

    /// Admit the file `raw` names: ONE `openat2` beneath the allowed root it
    /// is spelled under, then `fstat`. Nothing is read. A FIFO or device is
    /// opened non-blocking and refused by its type.
    pub(super) fn admit(&self, raw: &str) -> Result<AdmittedFile, AdmissionError> {
        let path =
            crate::mcp_server::paths::expand_tilde(raw).map_err(|reason| AdmissionError::Open {
                path: raw.to_string(),
                reason,
            })?;
        let shown = path.display().to_string();
        let Some((root, relative)) = self.locate(&path) else {
            return Err(self.not_under_root(shown));
        };
        if relative.as_os_str().is_empty() {
            return Err(AdmissionError::NotRegular {
                path: shown,
                kind: "directory",
            });
        }
        let file = open_beneath(&root.dir, relative).map_err(|error| open_error(&error, &shown))?;
        check_regular(file, path, shown)
    }

    /// The root an absolute `path` is spelled under, and the rest of it.
    fn locate<'a>(&'a self, path: &'a Path) -> Option<(&'a AuthorizedRoot, &'a Path)> {
        if !path.is_absolute() {
            return None;
        }
        self.roots.iter().find_map(|root| {
            root.spellings
                .iter()
                .find_map(|spelling| path.strip_prefix(spelling).ok())
                .map(|relative| (root, relative))
        })
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

    fn provenance(&self) -> MutexGuard<'_, HashMap<Identity, String>> {
        self.provenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The SHA-256 a worker reported in this process for this same unchanged
    /// file, if any.
    pub(super) fn known_sha256(&self, stat: &std::fs::Metadata) -> Option<String> {
        let identity = identity(stat)?;
        self.provenance().get(&identity).cloned()
    }

    /// Remember the SHA-256 a worker reported for the file with admission
    /// `fstat` `stat`, unless it was modified too recently to be told apart
    /// by its stat identity.
    pub(super) fn remember(&self, stat: &std::fs::Metadata, sha256: &str) {
        let Some(identity) = identity(stat) else {
            return;
        };
        let settled = stat
            .modified()
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age >= RACY_WINDOW);
        if !settled {
            return;
        }
        let mut known = self.provenance();
        if known.len() >= PROVENANCE_LIMIT {
            known.clear();
        }
        known.insert(identity, sha256.to_string());
    }
}

/// Refuse an answer when a second `fstat` of the same descriptor shows the
/// file changed while the worker read it.
pub(super) fn check_unchanged(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    path: &Path,
) -> Result<(), AdmissionError> {
    if identity(before) == identity(after) {
        Ok(())
    } else {
        Err(AdmissionError::Changed {
            path: path.display().to_string(),
        })
    }
}

/// One allowed root: `~` expanded, canonical, opened as a directory.
fn open_root(configured: &Path) -> Result<AuthorizedRoot, IsolationError> {
    let unusable = |reason: String| IsolationError::RootUnusable {
        root: configured.display().to_string(),
        reason,
    };
    let expanded =
        crate::mcp_server::paths::expand_tilde(&configured.to_string_lossy()).map_err(&unusable)?;
    let canonical = std::fs::canonicalize(&expanded).map_err(|e| unusable(e.to_string()))?;
    let dir = open_directory(&canonical).map_err(|e| unusable(e.to_string()))?;
    let mut spellings = vec![canonical];
    if expanded.is_absolute() && !spellings.contains(&expanded) {
        spellings.push(expanded);
    }
    Ok(AuthorizedRoot { spellings, dir })
}

/// The admission error for a failed `openat2`.
fn open_error(error: &std::io::Error, shown: &str) -> AdmissionError {
    let path = shown.to_string();
    match error.raw_os_error() {
        Some(code) if is_escape(code) => AdmissionError::Escapes { path },
        _ if error.kind() == std::io::ErrorKind::NotFound => AdmissionError::NotFound { path },
        _ => AdmissionError::Open {
            path,
            reason: error.to_string(),
        },
    }
}

/// The type and size checks on the one admitted descriptor.
fn check_regular(
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

/// `struct open_how` of openat2(2), as the kernel lays it out.
#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `openat2(dir, relative, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC)`
/// with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`: the result is beneath
/// `dir` or the call fails (`EXDEV`, `ELOOP`). `O_NONBLOCK` keeps a FIFO or
/// device from blocking the open; the caller refuses it by type.
#[cfg(target_os = "linux")]
fn open_beneath(dir: &std::fs::File, relative: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    let name = std::ffi::CString::new(relative.as_os_str().as_bytes())?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    openat2(dir, &name, &how).map(std::fs::File::from)
}

/// The openat2(2) system call (no safe wrapper exists in the standard
/// library or in this crate's direct dependencies).
#[cfg(target_os = "linux")]
fn openat2(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    how: &OpenHow,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    // SAFETY: `dir` is an open descriptor borrowed for the call, `name` is a
    // NUL-terminated string and `how` a `repr(C)` `open_how` whose exact size
    // is passed; all three outlive the call and the kernel only reads them.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            name.as_ptr(),
            std::ptr::from_ref(how),
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = RawFd::try_from(fd).map_err(|_| std::io::Error::other("descriptor out of range"))?;
    // SAFETY: the kernel just returned `fd` as a new open descriptor; nothing
    // else in this process owns it, so `OwnedFd` may take sole ownership.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_allow_roots_is_refused() {
        assert_eq!(
            Admission::open(&[]).unwrap_err(),
            IsolationError::NoAllowRoots
        );
    }

    /// Admission on benign fixtures: one `openat2` beneath the root, no
    /// escape by `..`, links or a rename, no blocking on a FIFO, and a
    /// descriptor that stays bound to the file it opened.
    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::io::Read as _;
        use std::os::unix::fs::symlink;

        const INSIDE: &[u8] = b"\x7FELF benign inside bytes";

        struct Fixture {
            _dir: tempfile::TempDir,
            root: PathBuf,
            outside: PathBuf,
            admission: Admission,
        }

        fn fixture() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("root");
            std::fs::create_dir(&root).unwrap();
            let outside = dir.path().join("outside.txt");
            std::fs::write(&outside, b"benign outside bytes").unwrap();
            std::fs::write(root.join("inside.bin"), INSIDE).unwrap();
            let admission = Admission::open(&[root.clone()]).unwrap();
            Fixture {
                _dir: dir,
                root,
                outside,
                admission,
            }
        }

        fn raw(path: &Path) -> String {
            path.to_string_lossy().into_owned()
        }

        fn read_all(admitted: AdmittedFile) -> Vec<u8> {
            let (mut file, _, _) = admitted.into_parts();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        }

        #[test]
        fn a_regular_file_beneath_the_root_is_admitted_by_one_descriptor() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            let admitted = f.admission.admit(&raw(&path)).unwrap();
            assert_eq!(admitted.path(), path);
            assert_eq!(admitted.stat().len(), INSIDE.len() as u64);
            assert_eq!(read_all(admitted), INSIDE);
        }

        #[test]
        fn paths_outside_or_leaving_the_root_are_refused() {
            let f = fixture();
            let refused = |path: String| f.admission.admit(&path).unwrap_err();
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
                let error = f.admission.admit(&raw(&f.root.join(name))).unwrap_err();
                assert!(
                    matches!(error, AdmissionError::Escapes { .. }),
                    "{name}: {error}"
                );
            }
            let followed = f.admission.admit(&raw(&f.root.join("inside.lnk"))).unwrap();
            assert_eq!(followed.stat().len(), INSIDE.len() as u64);
        }

        #[test]
        fn a_rename_cannot_substitute_the_file() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            // Admitted first, then replaced: the descriptor still reads the
            // file that was admitted, never the replacement.
            let admitted = f.admission.admit(&raw(&path)).unwrap();
            std::fs::write(f.root.join("swap.bin"), b"benign replacement").unwrap();
            std::fs::rename(f.root.join("swap.bin"), &path).unwrap();
            assert_eq!(read_all(admitted), INSIDE);
            // Replaced by a link to a file outside before admission: refused.
            symlink(&f.outside, f.root.join("evil.lnk")).unwrap();
            std::fs::rename(f.root.join("evil.lnk"), &path).unwrap();
            let error = f.admission.admit(&raw(&path)).unwrap_err();
            assert!(matches!(error, AdmissionError::Escapes { .. }), "{error}");
        }

        #[test]
        fn special_files_and_directories_are_refused_without_blocking() {
            let f = fixture();
            let fifo = f.root.join("pipe");
            let made = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(made.success());
            // Nothing writes to the FIFO: a blocking open would hang here.
            let error = f.admission.admit(&raw(&fifo)).unwrap_err();
            assert!(
                matches!(error, AdmissionError::NotRegular { .. }),
                "{error}"
            );
            std::fs::create_dir(f.root.join("sub")).unwrap();
            for dir in [f.root.join("sub"), f.root.clone()] {
                let error = f.admission.admit(&raw(&dir)).unwrap_err();
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
            let error = f.admission.admit(&raw(&big)).unwrap_err();
            assert!(matches!(error, AdmissionError::TooLarge { .. }), "{error}");
        }

        #[test]
        fn a_remembered_hash_selects_only_the_same_unchanged_file() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            // Settled: modified long ago, so its stat identity is trusted.
            filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(1_600_000_000, 0))
                .unwrap();
            let admitted = f.admission.admit(&raw(&path)).unwrap();
            assert_eq!(f.admission.known_sha256(admitted.stat()), None);
            let sha = "ab".repeat(32);
            f.admission.remember(admitted.stat(), &sha);
            assert_eq!(f.admission.known_sha256(admitted.stat()), Some(sha));
            std::fs::write(&path, b"benign, rewritten and longer").unwrap();
            let again = f.admission.admit(&raw(&path)).unwrap();
            assert_eq!(f.admission.known_sha256(again.stat()), None);
            // Just modified: not remembered at all.
            f.admission.remember(again.stat(), &"cd".repeat(32));
            assert_eq!(f.admission.known_sha256(again.stat()), None);
        }

        #[test]
        fn a_changed_file_is_detected_by_a_second_fstat() {
            let f = fixture();
            let path = f.root.join("inside.bin");
            let admitted = f.admission.admit(&raw(&path)).unwrap();
            let (file, before, _) = admitted.into_parts();
            assert!(check_unchanged(&before, &file.metadata().unwrap(), &path).is_ok());
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .set_len(1)
                .unwrap();
            let error = check_unchanged(&before, &file.metadata().unwrap(), &path).unwrap_err();
            assert!(matches!(error, AdmissionError::Changed { .. }), "{error}");
        }
    }
}
