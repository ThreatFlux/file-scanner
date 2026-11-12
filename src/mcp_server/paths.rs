//! Path handling shared by every tool: `~` expansion, allow-roots, file kinds.
//!
//! Errors name the problem and the fix, because the reader is a model that
//! can only correct its next call from the message.

use std::path::{Path, PathBuf};

/// What a tool needs the path to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A regular file.
    File,
    /// A regular file or a directory.
    FileOrDir,
}

/// The file-system scope of the server.
#[derive(Debug, Clone, Default)]
pub struct PathPolicy {
    /// Canonical directories every path must be under. Empty means no limit.
    allow_roots: Vec<PathBuf>,
    /// Home directory for `~`; the environment's when `None`.
    home: Option<PathBuf>,
}

impl PathPolicy {
    /// A policy limited to `roots` (empty: unrestricted). Roots are canonicalized
    /// when they exist; a root that does not exist yet is kept as written.
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        let allow_roots = roots
            .into_iter()
            .map(|root| expand_tilde(&root.to_string_lossy()).unwrap_or(root))
            .map(|root| std::fs::canonicalize(&root).unwrap_or(root))
            .collect();
        Self {
            allow_roots,
            home: None,
        }
    }

    /// Use `home` for `~` instead of the environment's (tests).
    #[must_use]
    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    /// The configured roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.allow_roots
    }

    /// Resolve a path argument.
    ///
    /// `noun` is the word used in "does not exist" errors (`File` or `Path`).
    /// On success the returned path is ready to open: `~` is expanded and, when
    /// roots are configured, the path is canonical and inside a root.
    pub fn resolve(&self, raw: &str, noun: &str, expect: Expect) -> Result<PathBuf, String> {
        if raw.trim().is_empty() {
            return Err(format!(
                "{noun} path is empty. Pass the absolute path of the {}.",
                if expect == Expect::File {
                    "file"
                } else {
                    "file or directory"
                }
            ));
        }
        let expanded = expand_tilde_with(raw, self.home.as_deref())?;

        let metadata = match std::fs::metadata(&expanded) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Outside the roots, say nothing about what exists: "not found"
                // versus "outside" would let a caller probe the file system.
                if !self.allow_roots.is_empty() && !self.could_be_inside_a_root(&expanded) {
                    return Err(self.outside_error(raw));
                }
                return Err(not_found(raw, &expanded, noun));
            }
            Err(error) => {
                return Err(format!(
                    "Cannot access {raw}: {error}. Check that the path is readable by the \
                     server process."
                ));
            }
        };

        let resolved = if self.allow_roots.is_empty() {
            expanded
        } else {
            let canonical = std::fs::canonicalize(&expanded).map_err(|error| {
                format!("Cannot resolve {raw}: {error}. Pass an absolute path to an existing item.")
            })?;
            if !self.is_inside_a_root(&canonical) {
                return Err(self.outside_error(raw));
            }
            canonical
        };

        check_kind(raw, &metadata, expect)?;
        Ok(resolved)
    }

    /// Check what a directory argument contains, before a tool reads it.
    ///
    /// [`Self::resolve`] vets only the path it is given. A directory can hold
    /// symlinks to files elsewhere and special files that block a reader, so
    /// the tools that read inside a directory call this too. Without following
    /// links it fails on: a FIFO, socket or device (always), and, when roots are
    /// set, a symlink whose target is outside every root. `recursive: false`
    /// looks at the direct members only. A file argument passes.
    pub fn check_tree(&self, dir: &Path, recursive: bool) -> Result<(), String> {
        if !dir.is_dir() {
            return Ok(());
        }
        let mut walker = walkdir::WalkDir::new(dir).follow_links(false).min_depth(1);
        if !recursive {
            walker = walker.max_depth(1);
        }
        for entry in walker.into_iter().filter_map(Result::ok) {
            self.check_entry(
                dir,
                entry.path(),
                entry.file_type(),
                entry.path_is_symlink(),
            )?;
        }
        Ok(())
    }

    /// Vet one entry found under `dir` by a walk that does not follow links
    /// (what [`Self::check_tree`] does for every entry). For a caller that
    /// walks lazily and stops early, so a huge tree is not read to the end
    /// before the work starts: call this on each entry before opening it.
    ///
    /// `file_type` is the entry's own type (not its target's) and `is_symlink`
    /// says whether the entry is a link. Fails on a FIFO, socket or device, and,
    /// when roots are set, on a symlink whose target is outside every root.
    pub fn check_entry(
        &self,
        dir: &Path,
        path: &Path,
        file_type: std::fs::FileType,
        is_symlink: bool,
    ) -> Result<(), String> {
        let shown = path.strip_prefix(dir).unwrap_or(path);
        if is_symlink {
            if self.allow_roots.is_empty() {
                return Ok(());
            }
            // A link that cannot be resolved cannot be read either.
            let Ok(target) = std::fs::canonicalize(path) else {
                return Ok(());
            };
            if !self.is_inside_a_root(&target) {
                return Err(format!(
                    "{} contains the symlink {}, which points outside the directories this \
                     server may read ({}). Remove the link, or start the server with \
                     --allow-root <dir> for its target.",
                    dir.display(),
                    shown.display(),
                    self.roots_text()
                ));
            }
            if let Ok(metadata) = std::fs::metadata(&target) {
                if let Some(kind) = special_kind(&metadata) {
                    return Err(special_in_tree(dir, shown, kind));
                }
            }
        } else if let Some(kind) = special_kind_of(file_type) {
            return Err(special_in_tree(dir, shown, kind));
        }
        Ok(())
    }

    fn is_inside_a_root(&self, canonical: &Path) -> bool {
        self.allow_roots
            .iter()
            .any(|root| canonical.starts_with(root))
    }

    /// Whether a path that does not exist could sit under a root: its nearest
    /// existing ancestor must canonicalize under one, and it must not use `..`.
    fn could_be_inside_a_root(&self, expanded: &Path) -> bool {
        use std::path::Component;
        let absolute = if expanded.is_relative() {
            match std::env::current_dir() {
                Ok(cwd) => cwd.join(expanded),
                Err(_) => return false,
            }
        } else {
            expanded.to_path_buf()
        };
        if absolute
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        {
            return false;
        }
        absolute
            .ancestors()
            .find_map(|ancestor| std::fs::canonicalize(ancestor).ok())
            .is_some_and(|ancestor| self.is_inside_a_root(&ancestor))
    }

    fn roots_text(&self) -> String {
        self.allow_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn outside_error(&self, raw: &str) -> String {
        format!(
            "Path {raw} is outside the directories this server may read ({}). Pass a path under \
             one of them, or start the server with --allow-root <dir> to allow another.",
            self.roots_text()
        )
    }
}

fn special_in_tree(dir: &Path, shown: &Path, kind: &str) -> String {
    format!(
        "{} contains {}, which is {kind}; reading it could block forever. Remove it or pass a \
         directory without special files.",
        dir.display(),
        shown.display()
    )
}

#[cfg(unix)]
fn special_kind_of(file_type: std::fs::FileType) -> Option<&'static str> {
    use std::os::unix::fs::FileTypeExt;
    if file_type.is_fifo() {
        Some("a named pipe (FIFO)")
    } else if file_type.is_socket() {
        Some("a socket")
    } else if file_type.is_block_device() || file_type.is_char_device() {
        Some("a device file")
    } else {
        None
    }
}

#[cfg(not(unix))]
fn special_kind_of(_file_type: std::fs::FileType) -> Option<&'static str> {
    None
}

fn special_kind(metadata: &std::fs::Metadata) -> Option<&'static str> {
    special_kind_of(metadata.file_type())
}

fn not_found(raw: &str, expanded: &Path, noun: &str) -> String {
    let mut message = format!("{noun} does not exist: {raw}");
    if expanded.is_relative() {
        match std::env::current_dir() {
            Ok(cwd) => message.push_str(&format!(
                " (a relative path is resolved against the server's working directory {}; pass \
                 an absolute path)",
                cwd.display()
            )),
            Err(_) => message.push_str(" (pass an absolute path)"),
        }
    }
    message
}

fn check_kind(raw: &str, metadata: &std::fs::Metadata, expect: Expect) -> Result<(), String> {
    if let Some(kind) = special_kind(metadata) {
        return Err(format!(
            "{raw} is {kind}, which cannot be analyzed (reading it could block forever). \
             Pass a regular file."
        ));
    }
    if expect == Expect::File && metadata.is_dir() {
        return Err(format!(
            "{raw} is a directory, but this tool analyzes a single file. Pass the path of a \
             file inside it."
        ));
    }
    Ok(())
}

/// Expand a leading `~` or `~/` to the home directory.
pub fn expand_tilde(raw: &str) -> Result<PathBuf, String> {
    expand_tilde_with(raw, None)
}

/// [`expand_tilde`] with an explicit home directory.
fn expand_tilde_with(raw: &str, home: Option<&Path>) -> Result<PathBuf, String> {
    if raw == "~" || raw.starts_with("~/") {
        let home = home
            .map(Path::to_path_buf)
            .or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(PathBuf::from)
            })
            .filter(|home| home.is_absolute())
            .ok_or_else(|| {
                format!("Cannot expand ~ in {raw}: the server has no home directory. Pass an absolute path.")
            })?;
        Ok(if raw == "~" {
            home
        } else {
            home.join(&raw[2..])
        })
    } else {
        Ok(PathBuf::from(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_file_keeps_the_old_wording() {
        let policy = PathPolicy::default();
        let error = policy
            .resolve("/definitely/not/here.bin", "File", Expect::File)
            .unwrap_err();
        assert_eq!(error, "File does not exist: /definitely/not/here.bin");
        let error = policy
            .resolve("/definitely/not/here", "Path", Expect::FileOrDir)
            .unwrap_err();
        assert!(error.starts_with("Path does not exist: "));
    }

    #[test]
    fn relative_not_found_names_the_working_directory() {
        let error = PathPolicy::default()
            .resolve("no_such_relative_file", "File", Expect::File)
            .unwrap_err();
        assert!(error.contains("working directory"), "{error}");
        assert!(error.contains("absolute path"), "{error}");
    }

    #[test]
    fn directories_need_the_right_expectation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_string_lossy().to_string();
        let policy = PathPolicy::default();
        let error = policy.resolve(&path, "File", Expect::File).unwrap_err();
        assert!(error.contains("is a directory"), "{error}");
        assert!(policy.resolve(&path, "Path", Expect::FileOrDir).is_ok());
    }

    #[test]
    fn empty_path_is_rejected() {
        let error = PathPolicy::default()
            .resolve("  ", "File", Expect::File)
            .unwrap_err();
        assert!(error.contains("empty"));
    }

    #[cfg(unix)]
    #[test]
    fn fifos_are_rejected_instead_of_hanging() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let error = PathPolicy::default()
            .resolve(&fifo.to_string_lossy(), "File", Expect::File)
            .unwrap_err();
        assert!(error.contains("named pipe"), "{error}");
    }

    #[test]
    fn allow_roots_confine_paths_including_symlink_escapes() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let inside_file = root.path().join("ok.bin");
        std::fs::write(&inside_file, b"x").unwrap();
        let outside_file = outside.path().join("secret.bin");
        std::fs::write(&outside_file, b"x").unwrap();
        let policy = PathPolicy::new([root.path().to_path_buf()]);

        let resolved = policy
            .resolve(&inside_file.to_string_lossy(), "File", Expect::File)
            .unwrap();
        assert!(resolved.ends_with("ok.bin"));

        let error = policy
            .resolve(&outside_file.to_string_lossy(), "File", Expect::File)
            .unwrap_err();
        assert!(error.contains("outside the directories"), "{error}");
        assert!(error.contains("--allow-root"), "{error}");

        #[cfg(unix)]
        {
            let link = root.path().join("link.bin");
            std::os::unix::fs::symlink(&outside_file, &link).unwrap();
            let error = policy
                .resolve(&link.to_string_lossy(), "File", Expect::File)
                .unwrap_err();
            assert!(error.contains("outside the directories"), "{error}");
        }

        // `..` cannot climb out either.
        let sneaky = format!("{}/../{}/secret.bin", root.path().display(), {
            outside.path().file_name().unwrap().to_string_lossy()
        });
        assert!(policy.resolve(&sneaky, "File", Expect::File).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn check_entry_vets_one_entry_the_way_check_tree_does() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("x"), b"x").unwrap();
        std::fs::write(root.path().join("f"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path().join("x"), root.path().join("l")).unwrap();
        let policy = PathPolicy::new([root.path().to_path_buf()]);
        let dir = root.path().canonicalize().unwrap();
        let check = |name: &str| {
            let path = dir.join(name);
            let meta = std::fs::symlink_metadata(&path).unwrap();
            policy.check_entry(&dir, &path, meta.file_type(), meta.file_type().is_symlink())
        };
        assert!(check("f").is_ok());
        assert!(check("l").unwrap_err().contains("points outside"));
        assert!(policy.check_tree(&dir, false).is_err());
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("mkfifo");
        assert!(status.success());
    }

    #[cfg(unix)]
    #[test]
    fn check_tree_rejects_symlinks_that_leave_the_roots() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"x").unwrap();
        std::fs::write(root.path().join("own.txt"), b"x").unwrap();
        let policy = PathPolicy::new([root.path().to_path_buf()]);
        let dir = root.path().canonicalize().unwrap();
        assert!(policy.check_tree(&dir, true).is_ok());

        // An in-root link is fine.
        std::os::unix::fs::symlink(dir.join("own.txt"), dir.join("inner")).unwrap();
        assert!(policy.check_tree(&dir, true).is_ok());

        let nested = dir.join("sub");
        std::fs::create_dir(&nested).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), nested.join("link")).unwrap();
        // Only the nested member is outside, so a shallow check passes and a deep one fails.
        assert!(policy.check_tree(&dir, false).is_ok());
        let error = policy.check_tree(&dir, true).unwrap_err();
        assert!(error.contains("sub/link"), "{error}");
        assert!(error.contains("outside the directories"), "{error}");
        assert!(error.contains("--allow-root"), "{error}");

        // Without roots a link is not an escape.
        assert!(PathPolicy::default().check_tree(&dir, true).is_ok());
        // A file argument has no members.
        assert!(policy.check_tree(&dir.join("own.txt"), true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn check_tree_rejects_special_files_with_or_without_roots() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().canonicalize().unwrap();
        mkfifo(&path.join("package.json"));
        for policy in [
            PathPolicy::default(),
            PathPolicy::new([dir.path().to_path_buf()]),
        ] {
            let error = policy.check_tree(&path, true).unwrap_err();
            assert!(error.contains("package.json"), "{error}");
            assert!(error.contains("named pipe"), "{error}");
        }
        // A link to a FIFO that sits in another allowed root is caught too.
        let linked = TempDir::new().unwrap();
        let pipes = TempDir::new().unwrap();
        let linked_path = linked.path().canonicalize().unwrap();
        let pipes_path = pipes.path().canonicalize().unwrap();
        mkfifo(&pipes_path.join("pipe"));
        std::os::unix::fs::symlink(pipes_path.join("pipe"), linked_path.join("alias")).unwrap();
        let both = PathPolicy::new([linked_path.clone(), pipes_path]);
        let error = both.check_tree(&linked_path, true).unwrap_err();
        assert!(
            error.contains("alias") && error.contains("named pipe"),
            "{error}"
        );
    }

    #[test]
    fn outside_the_roots_a_missing_path_looks_like_an_existing_one() {
        let root = TempDir::new().unwrap();
        let policy = PathPolicy::new([root.path().to_path_buf()]);
        let missing = policy
            .resolve("/etc/no-such-file-zz", "File", Expect::File)
            .unwrap_err();
        let present = policy
            .resolve("/etc/hosts", "File", Expect::File)
            .unwrap_err();
        assert!(missing.contains("outside the directories"), "{missing}");
        assert!(present.contains("outside the directories"), "{present}");
        assert!(!missing.contains("does not exist"), "{missing}");
        // `..` out of a root does not get a "not found" either.
        let climb = format!("{}/../nothing-here", root.path().display());
        assert!(policy
            .resolve(&climb, "File", Expect::File)
            .unwrap_err()
            .contains("outside the directories"));
        // Under a root, a missing file is reported as missing.
        let inside = root.path().join("absent.bin");
        let error = policy
            .resolve(&inside.to_string_lossy(), "File", Expect::File)
            .unwrap_err();
        assert!(error.contains("does not exist"), "{error}");
    }

    #[test]
    fn resolve_expands_tilde_and_still_applies_the_roots() {
        let home = TempDir::new().unwrap();
        std::fs::write(home.path().join("sample.bin"), b"x").unwrap();
        let home_path = home.path().canonicalize().unwrap();

        let open = PathPolicy::default().with_home(home_path.clone());
        let resolved = open.resolve("~/sample.bin", "File", Expect::File).unwrap();
        assert_eq!(resolved, home_path.join("sample.bin"));

        // With a root other than home, `~/...` is outside it, and so is `~/../..`.
        let elsewhere = TempDir::new().unwrap();
        let confined =
            PathPolicy::new([elsewhere.path().to_path_buf()]).with_home(home_path.clone());
        let error = confined
            .resolve("~/sample.bin", "File", Expect::File)
            .unwrap_err();
        assert!(error.contains("outside the directories"), "{error}");

        // With home as the root, `~/..` cannot climb out.
        let rooted = PathPolicy::new([home_path.clone()]).with_home(home_path);
        assert!(rooted.resolve("~/sample.bin", "File", Expect::File).is_ok());
        assert!(rooted
            .resolve("~/../sample.bin", "File", Expect::File)
            .is_err());
    }

    #[test]
    fn a_relative_tilde_without_home_is_an_error_that_names_the_fix() {
        let error = expand_tilde_with("~/x", Some(Path::new("relative-home"))).unwrap_err();
        assert!(error.contains("Pass an absolute path"), "{error}");
    }

    #[test]
    fn tilde_is_expanded_from_home() {
        if let Some(home) = std::env::var_os("HOME") {
            let expanded = expand_tilde("~/x/y").unwrap();
            assert_eq!(expanded, PathBuf::from(home).join("x/y"));
        }
        assert_eq!(expand_tilde("~other/x").unwrap(), PathBuf::from("~other/x"));
    }
}
