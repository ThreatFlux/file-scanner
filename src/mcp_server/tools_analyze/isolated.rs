//! `analyze_file` under `--isolation bwrap`: the `metadata` section is computed
//! by the sandboxed worker; every other form of the call is refused before the
//! file is opened.
//!
//! One descriptor per call: after an analysis slot is taken, the file is
//! admitted by `Sandbox::admit` (one `openat2` beneath a preopened allowed
//! root, non-blocking, then `fstat`: a regular file within the byte cap). The
//! server never reopens the path and never reads the content; the worker
//! hashes that same descriptor inside the sandbox under its deadline. The stat
//! fields come from the server's `fstat` of the descriptor.
//!
//! Cache provenance: the result is stored under `metadata:bwrap-v1:<path>:<mtime>`
//! only, a key the in-process path never writes, and is looked up only with a
//! SHA-256 a worker reported for the same unchanged file in this process. An
//! in-process `metadata` result is never served here, so `isolation.profile`
//! and `cache: hit` always describe a sandboxed computation.

use std::{path::Path, sync::Arc, time::Instant};

use rmcp::model::{CallToolResult, JsonObject};
use serde_json::{json, Value};

use super::{mtime_ns_of, sections};
use crate::{
    isolation::{
        refusal_text, AdmissionError, AdmittedFile, MetadataError, Sandbox, METADATA_PROVENANCE,
    },
    mcp_server::{
        output::{render, respond_text, tool_error},
        FileScannerMcp,
    },
    metadata::FileMetadata,
};

/// A metadata section ready to answer, and where it came from.
struct Section {
    sha256: String,
    value: Arc<Value>,
    /// The admission `fstat` of the descriptor; the history records it.
    stat: std::fs::Metadata,
    cache: &'static str,
}

impl FileScannerMcp {
    /// The `analyze_file` body when the server has a sandbox. `raw_path` is
    /// the caller's path, not yet touched; `names` the requested sections.
    pub(super) async fn run_isolated_analyze_file(
        &self,
        raw_path: &str,
        names: &[&'static str],
        budget: usize,
        raw_args: &JsonObject,
        started: Instant,
    ) -> CallToolResult {
        let Some(sandbox) = self.state.sandbox().map(Arc::clone) else {
            return tool_error("analyze_file: no sandbox is configured".to_string());
        };
        if let Some(refused) = refuse_unsupported(names) {
            return refused;
        }
        // The admission slot bounds how many files are open and how many
        // workers run at once.
        let _slot = self.state.analysis_slot().await;
        let admitted = match sandbox.admit(raw_path) {
            Ok(admitted) => admitted,
            Err(refused) => return tool_error(admission_text(&refused)),
        };
        let file_path = admitted.path().to_string_lossy().into_owned();
        let key = cache_key(&file_path, &admitted);
        let section = match self.cached_section(&sandbox, &admitted, &key) {
            Some(hit) => hit,
            None => match self
                .computed_section(&sandbox, admitted, &file_path, &key)
                .await
            {
                Ok(section) => section,
                Err(failed) => return tool_error(failed),
            },
        };
        let value = answer(&sandbox, &file_path, &section);
        let entry = value.clone();
        let text = render(value, budget);
        self.state
            .record_analyze_file(
                raw_args,
                raw_path,
                None,
                entry,
                &section.sha256,
                (section.stat.len(), Some(&section.stat)),
                started,
            )
            .await;
        respond_text(text)
    }

    /// A sandboxed result already stored for this same unchanged file, found
    /// only through the SHA-256 a worker reported for it in this process.
    fn cached_section(
        &self,
        sandbox: &Sandbox,
        admitted: &AdmittedFile,
        key: &str,
    ) -> Option<Section> {
        let sha256 = sandbox.known_sha256(admitted)?;
        let value = self.state.section_cache().get(&sha256, key)?;
        Some(Section {
            sha256,
            value,
            stat: admitted.stat().clone(),
            cache: "hit",
        })
    }

    /// Run the worker on the admitted descriptor, build the section from its
    /// answer and the server's `fstat`, and store it under the isolated key.
    async fn computed_section(
        &self,
        sandbox: &Sandbox,
        admitted: AdmittedFile,
        file_path: &str,
        key: &str,
    ) -> Result<Section, String> {
        let (answer, stat) = sandbox
            .metadata_of(admitted)
            .await
            .map_err(|error| failure_text(file_path, &error))?;
        let sha256 = answer.hashes.sha256.clone();
        let mut metadata =
            FileMetadata::new(Path::new(file_path)).map_err(|error| format!("{error:#}"))?;
        metadata.apply_stat(&stat);
        metadata.mime_type = Some(answer.mime_type);
        metadata.hashes = Some(answer.hashes);
        let value = serde_json::to_value(&metadata).map_err(|error| error.to_string())?;
        let _ = self.state.section_cache().put(&sha256, key, &value);
        Ok(Section {
            sha256,
            value: Arc::new(value),
            stat,
            cache: "miss",
        })
    }
}

/// The tool error for every request this sandbox does not run, or `None`
/// for `sections: ["metadata"]`.
fn refuse_unsupported(names: &[&'static str]) -> Option<CallToolResult> {
    if names == ["metadata"] {
        return None;
    }
    let what = if names.is_empty() {
        "analyze_file without sections (the overview)".to_string()
    } else {
        format!("analyze_file with sections {}", names.join(", "))
    };
    Some(tool_error(refusal_text(&what)))
}

/// Format the admission failure. A directory gets the isolation refusal.
fn admission_text(error: &AdmissionError) -> String {
    match error {
        AdmissionError::NotRegular {
            kind: "directory", ..
        } => refusal_text("analyze_file on a directory"),
        error => format!("{error}."),
    }
}

/// The isolated section key: its own namespace, the path and the mtime.
fn cache_key(file_path: &str, admitted: &AdmittedFile) -> String {
    format!(
        "metadata:{METADATA_PROVENANCE}:{file_path}:{}",
        mtime_ns_of(admitted.stat())
    )
}

/// The tool error text of a failed sandboxed call.
fn failure_text(file_path: &str, error: &MetadataError) -> String {
    match error {
        MetadataError::Admission(error) => format!("{error}."),
        MetadataError::Worker(error) => {
            format!("analyze_file metadata of {file_path}: {error}. The server is still running.")
        }
    }
}

/// The answer: the section summary, where it came from and the limits.
fn answer(sandbox: &Sandbox, file_path: &str, section: &Section) -> Value {
    json!({
        "file_path": file_path,
        "sha256": section.sha256,
        "metadata": sections::summarize("metadata", &section.value),
        "cache": section.cache,
        "isolation": {
            "profile": "bwrap",
            "provenance": METADATA_PROVENANCE,
            "memory_mb_per_process": sandbox.memory_bytes() / (1024 * 1024),
            "deadline_seconds": sandbox.deadline().as_secs_f64(),
        },
    })
}
