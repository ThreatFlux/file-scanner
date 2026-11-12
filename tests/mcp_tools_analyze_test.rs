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
        let cache = TempDir::new().unwrap();
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: cache.path().to_path_buf(),
            ..StateConfig::default()
        }));
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
    assert!(page["items"][0]["instructions_count"].as_u64().unwrap() > 0);
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
                json!({"file_path": file, "section": "vulnerabilities", "limit": 500,
                       "offset": offset, "max_output_bytes": 20_000}),
            )
            .await;
        assert!(size <= 20_000, "{size}");
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
    for name in ["strings", "entropy", "binary_info", "symbols"] {
        let note = value["notes"][name].as_str().unwrap_or_default();
        assert!(note.contains("sections"), "{name}: {value}");
    }
    assert!(value.get("counts").is_some());
}
