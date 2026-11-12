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
pub(super) fn table(
    root: &Path,
    file_path: &str,
    recursive: bool,
    max_files: usize,
    offset: usize,
    limit: usize,
    runtime: &tokio::runtime::Handle,
    budget: usize,
) -> Value {
    let mut walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .sort_by_file_name();
    if !recursive {
        walker = walker.max_depth(1);
    }
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut more_than_max = false;
    for entry in walker.into_iter().filter_map(Result::ok) {
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
    let mut out = json!({
        "view": "directory",
        "file_path": file_path,
        "recursive": recursive,
        "total": files.len(),
        "returned": rows.len(),
        "offset": offset,
        "files": rows,
    });
    if end < files.len() {
        out["next_offset"] = end.into();
    }
    // next_steps and the notes below take a few hundred bytes more.
    crate::mcp_server::output::fit_rows(
        &mut out,
        "files",
        budget.saturating_sub(1200),
        offset,
        files.len(),
    );
    let end = out
        .get("next_offset")
        .and_then(Value::as_u64)
        .map_or(files.len(), |n| n as usize);
    if more_than_max {
        out["truncated_listing"] = format!(
            "Only the first {max_files} files (sorted by name) are listed; there are more. \
             Raise max_files (ceiling {MAX_FILES_CEILING}) or triage a subdirectory."
        )
        .into();
    }
    let mut steps = vec![json!({
        "tool": "analyze_file",
        "arguments": {"file_path": "<directory>/<path of a row>"},
        "gives": "the overview of one file, with the sections it offers",
    })];
    if end < files.len() {
        steps.push(json!({
            "tool": "analyze_file",
            "arguments": {"file_path": file_path, "recursive": recursive, "offset": end},
            "gives": "the next page of this table",
        }));
    }
    out["next_steps"] = steps.into();
    out
}
