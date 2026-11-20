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
use serde_json::json;

use super::{mtime_ns_of, sections};
use crate::{
    isolation::{refusal_text, AdmissionError, MetadataError, METADATA_PROVENANCE},
    mcp_server::{
        output::{render, respond_text, tool_error},
        FileScannerMcp,
    },
    metadata::FileMetadata,
};

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
        if names != ["metadata"] {
            let what = if names.is_empty() {
                "analyze_file without sections (the overview)".to_string()
            } else {
                format!("analyze_file with sections {}", names.join(", "))
            };
            return tool_error(refusal_text(&what));
        }
        // The admission slot bounds how many files are open and how many
        // workers run at once.
        let _slot = self.state.analysis_slot().await;
        let admitted = match sandbox.admit(raw_path) {
            Ok(admitted) => admitted,
            Err(AdmissionError::NotRegular {
                kind: "directory", ..
            }) => return tool_error(refusal_text("analyze_file on a directory")),
            Err(error) => return tool_error(format!("{error}.")),
        };
        let file_path = admitted.path().to_string_lossy().into_owned();
        let key = format!(
            "metadata:{METADATA_PROVENANCE}:{file_path}:{}",
            mtime_ns_of(admitted.stat())
        );
        let admitted_stat = admitted.stat().clone();
        let cache = self.state.section_cache();
        let hit = sandbox
            .known_sha256(&admitted)
            .and_then(|sha256| cache.get(&sha256, &key).map(|value| (sha256, value)));
        let (sha256, section, file_size, cache_state) = if let Some((sha256, value)) = hit {
            let size = admitted.stat().len();
            (sha256, value, size, "hit")
        } else {
            let (answer, stat) = match sandbox.metadata_of(admitted).await {
                Ok(done) => done,
                Err(MetadataError::Admission(error)) => return tool_error(format!("{error}.")),
                Err(MetadataError::Worker(error)) => {
                    return tool_error(format!(
                        "analyze_file metadata of {file_path}: {error}. The server is still \
                         running."
                    ))
                }
            };
            let sha256 = answer.hashes.sha256.clone();
            let mut metadata = match FileMetadata::new(Path::new(&file_path)) {
                Ok(metadata) => metadata,
                Err(error) => return tool_error(format!("{error:#}")),
            };
            metadata.apply_stat(&stat);
            metadata.mime_type = Some(answer.mime_type);
            metadata.hashes = Some(answer.hashes);
            let value = match serde_json::to_value(&metadata) {
                Ok(value) => value,
                Err(error) => return tool_error(error.to_string()),
            };
            let _ = cache.put(&sha256, &key, &value);
            (sha256, Arc::new(value), stat.len(), "miss")
        };
        let value = json!({
            "file_path": file_path,
            "sha256": sha256,
            "metadata": sections::summarize("metadata", &section),
            "cache": cache_state,
            "isolation": {
                "profile": "bwrap",
                "provenance": METADATA_PROVENANCE,
                "memory_mb_per_process": sandbox.memory_bytes() / (1024 * 1024),
                "deadline_seconds": sandbox.deadline().as_secs_f64(),
            },
        });
        let entry = value.clone();
        let text = render(value, budget);
        self.state
            .record_analyze_file(
                raw_args,
                raw_path,
                None,
                entry,
                &sha256,
                (file_size, Some(&admitted_stat)),
                started,
            )
            .await;
        respond_text(text)
    }
}
