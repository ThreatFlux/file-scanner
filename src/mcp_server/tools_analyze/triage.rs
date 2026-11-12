//! Directory triage: one paged row per file instead of one call per file.

use std::{io::Read, path::Path};

use serde_json::{json, Value};

use crate::{hash::calculate_sha256_only, mcp_server::tools_formats::detect_file_kind};

/// Files listed when the caller passes no `max_files`.
pub(super) const DEFAULT_MAX_FILES: usize = 1000;
/// Largest `max_files`.
pub(super) const MAX_FILES_CEILING: usize = 10_000;
/// Bytes read to estimate a file's entropy.
const ENTROPY_SAMPLE: u64 = 1 << 20;
/// Entropy (bits per byte) above which a file is flagged.
const HIGH_ENTROPY: f64 = 7.2;

/// Shannon entropy of `bytes`, bits per byte.
fn byte_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// The per-file row: path, size, type, sha256 and headline flags.
fn row(root: &Path, path: &Path, runtime: &tokio::runtime::Handle) -> Value {
    let shown = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    let mut out = json!({"path": shown});
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            out["error"] = format!("cannot read: {e}").into();
            return out;
        }
    };
    out["size"] = meta.len().into();
    let mut flags: Vec<&str> = Vec::new();
    if meta.len() == 0 {
        flags.push("empty");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 != 0 {
            flags.push("executable");
        }
    }
    match detect_file_kind(path) {
        Ok(kind) => {
            out["type"] = kind.label.into();
            out["kind"] = kind.kind.into();
            out["mime"] = kind.mime.into();
        }
        Err(e) => out["error"] = format!("cannot read: {e}").into(),
    }
    match runtime.block_on(calculate_sha256_only(path)) {
        Ok(sha) => out["sha256"] = sha.into(),
        Err(e) => out["error"] = format!("cannot hash: {e:#}").into(),
    }
    if let Ok(file) = std::fs::File::open(path) {
        let mut sample = Vec::new();
        if file.take(ENTROPY_SAMPLE).read_to_end(&mut sample).is_ok() {
            let entropy = byte_entropy(&sample);
            out["entropy"] = ((entropy * 100.0).round() / 100.0).into();
            if entropy > HIGH_ENTROPY && sample.len() >= 256 {
                flags.push("high-entropy");
            }
        }
    }
    out["flags"] = flags.into();
    out
}

/// The paged triage table of the files under `root`.
/// Directory entries one triage walk looks at before it stops.
const MAX_ENTRIES_WALKED: usize = 200_000;
/// Time one triage walk may spend listing entries (not counting the rows).
const WALK_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// `vet` checks the path policy on one entry that is a symlink or a special
/// file, as the walk reaches it, so a huge tree is not read to the end before
/// the first row (an `Err` fails the whole table, naming the entry).
pub(super) fn table(
    root: &Path,
    file_path: &str,
    recursive: bool,
    max_files: usize,
    (offset, limit): (usize, usize),
    runtime: &tokio::runtime::Handle,
    budget: usize,
    vet: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<Value, String> {
    let mut walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .sort_by_file_name();
    if !recursive {
        walker = walker.max_depth(1);
    }
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut more_than_max = false;
    let mut subdirectories = 0usize;
    let mut examined = 0usize;
    let mut walk_cut = false;
    let mut links_skipped = 0usize;
    let started = std::time::Instant::now();
    for entry in walker.into_iter().filter_map(Result::ok) {
        // A tree of millions of directories and few files is walked for a
        // bounded number of entries.
        examined += 1;
        if examined > MAX_ENTRIES_WALKED
            || (examined.is_multiple_of(256) && started.elapsed() > WALK_BUDGET)
        {
            walk_cut = true;
            break;
        }
        if entry.path_is_symlink() || !(entry.file_type().is_file() || entry.file_type().is_dir()) {
            vet(entry.path()).map_err(|reason| {
                let shown = entry.path().strip_prefix(root).unwrap_or(entry.path());
                format!(
                    "{} contains {}, which this server may not read: {reason}",
                    root.display(),
                    shown.display()
                )
            })?;
        }
        if entry.path_is_symlink() {
            links_skipped += 1;
        }
        if entry.file_type().is_dir() {
            subdirectories += 1;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if files.len() >= max_files {
            more_than_max = true;
            break;
        }
        files.push(entry.into_path());
    }
    let limit = limit.clamp(1, 200);
    let start = offset.min(files.len());
    let end = start.saturating_add(limit).min(files.len());
    let rows: Vec<Value> = files[start..end]
        .iter()
        .map(|path| row(root, path, runtime))
        .collect();
    // The fields around the rows are added after the rows are fitted: when
    // they push the answer over the budget, fit again with more room kept.
    let build = |reserve: usize| -> Value {
        let mut out = json!({
            "view": "directory",
            "file_path": file_path,
            "recursive": recursive,
            "total": files.len(),
            "returned": rows.len(),
            "offset": offset,
            "files": rows.clone(),
        });
        if end < files.len() {
            out["next_offset"] = end.into();
        }
        // next_steps and the notes below take a few hundred bytes more.
        crate::mcp_server::output::fit_rows(
            &mut out,
            "files",
            budget.saturating_sub(reserve),
            offset,
            files.len(),
        );
        let end = out
            .get("next_offset")
            .and_then(Value::as_u64)
            .map_or(files.len(), |n| n as usize);
        if walk_cut {
            out["walk_note"] = format!(
                "The walk stopped after {examined} directory entries (at most {MAX_ENTRIES_WALKED} \
                 entries or {} seconds); triage a subdirectory to see the rest.",
                WALK_BUDGET.as_secs()
            )
            .into();
        }
        if links_skipped > 0 {
            out["links_skipped"] = format!(
                "{links_skipped} symbolic link{} {} left out of this table: links are never \
                 followed or listed.",
                if links_skipped == 1 { "" } else { "s" },
                if links_skipped == 1 { "was" } else { "were" }
            )
            .into();
        }
        if more_than_max {
            out["truncated_listing"] = format!(
                "Only the first {max_files} files (sorted by name) are listed; there are more. \
                 Raise max_files (ceiling {MAX_FILES_CEILING}) or triage a subdirectory."
            )
            .into();
        }
        if !recursive && subdirectories > 0 {
            out["not_entered"] = format!(
                "{subdirectories} subdirector{} not entered (recursive is false); their files are \
                 not in this table.",
                if subdirectories == 1 {
                    "y was"
                } else {
                    "ies were"
                }
            )
            .into();
        }
        let mut steps: Vec<Value> = Vec::new();
        // A package directory has a specialist tool.
        let has =
            |name: &str| std::fs::symlink_metadata(root.join(name)).is_ok_and(|m| m.is_file());
        if has("package.json") {
            steps.push(json!({
                "tool": "analyze_npm_package",
                "arguments": {"package_path": file_path},
                "why": "this directory is an npm package: lifecycle scripts, dependencies, findings",
            }));
        }
        if has("setup.py") || has("pyproject.toml") || has("requirements.txt") {
            steps.push(json!({
                "tool": "analyze_python_package",
                "arguments": {"package_path": file_path},
                "why": "this directory is a Python package: install hooks, dependencies, findings",
            }));
        }
        steps.push(json!({
            "tool": "analyze_file",
            "arguments": {"file_path": "<directory>/<path of a row>"},
            "gives": "the overview of one file, with the sections it offers",
        }));
        if end < files.len() {
            steps.push(json!({
                "tool": "analyze_file",
                "arguments": {"file_path": file_path, "recursive": recursive, "offset": end},
                "gives": "the next page of this table",
            }));
        }
        if !recursive && subdirectories > 0 {
            steps.push(json!({
                "tool": "analyze_file",
                "arguments": {"file_path": file_path, "recursive": true},
                "gives": "the table including the files in subdirectories",
            }));
        }
        out["next_steps"] = steps.into();
        out
    };
    let mut reserve = 1200 + 2 * file_path.len();
    loop {
        let out = build(reserve);
        let size = serde_json::to_vec(&out).map_or(0, |v| v.len());
        let kept = out["files"].as_array().map_or(0, Vec::len);
        if size <= budget || kept <= 1 {
            return Ok(out);
        }
        reserve += size - budget + 16;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// The walk stops at `max_files` and checks only the entries that need it
    /// (links and special files), not every entry of the tree up front.
    #[test]
    fn the_walk_is_lazy_and_vets_links_as_it_meets_them() {
        let dir = tempfile::TempDir::new().unwrap();
        for i in 0..300 {
            std::fs::write(dir.path().join(format!("f{i:03}.txt")), b"x").unwrap();
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let calls = Cell::new(0usize);
        let table_of = |vet: &dyn Fn(&Path) -> Result<(), String>| {
            table(
                dir.path(),
                "d",
                true,
                5,
                (0, 50),
                runtime.handle(),
                80_000,
                vet,
            )
        };
        let counting = |_: &Path| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let value = table_of(&counting).unwrap();
        assert_eq!(value["total"], 5);
        assert_eq!(calls.get(), 0, "regular files need no policy check");
        assert!(value["truncated_listing"].is_string());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", dir.path().join("a-link")).unwrap();
            let refusing = |p: &Path| Err(format!("no: {}", p.display()));
            let error = table_of(&refusing).unwrap_err();
            assert!(error.contains("a-link"), "{error}");
        }
    }
}
