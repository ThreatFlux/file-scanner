#![allow(
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

//! `disassemble`, `read_hex`, `llm_analyze_file` and `compare_files` driven
//! through the real server with the SDK client, in process.
//!
//! The byte budget is asserted on the repository's test binaries and on
//! `/bin/ls`; after `all: true` a `disassemble` call is answered from the cache.

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

/// A 100-byte file whose byte at position `i` is `i`.
fn counting_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("counting.bin");
    std::fs::write(&path, (0..100u8).collect::<Vec<_>>()).unwrap();
    path
}

/// A text file with a repeated string.
fn repeated_strings_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("repeated.txt");
    let mut text = String::new();
    for _ in 0..6 {
        text.push_str("http://repeated.example.com/path\n");
        text.push_str("duplicate marker string here\n");
    }
    text.push_str("another distinct marker line\n");
    std::fs::write(&path, text).unwrap();
    path
}

// ---------------------------------------------------------------------------
// read_hex
// ---------------------------------------------------------------------------

/// CB22: the footer, without knowing the file's size, and no "(truncated)"
/// text when the dump reaches the end of the file.
#[tokio::test]
async fn read_hex_reads_the_footer_and_knows_where_the_file_ends() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = counting_file(&dir);
    let (tail, _) = harness
        .ok(
            "read_hex",
            json!({"file_path": file, "offset": -32, "length": 32}),
        )
        .await;
    assert_eq!(tail["offset"], 68);
    assert_eq!(tail["length"], 32);
    assert_eq!(tail["total_bytes"], 100);
    assert_eq!(tail["end_of_file"], true);
    assert!(tail.get("next_offset").is_none());
    assert_eq!(tail["previous_offset"], 36);
    let lines = tail["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].as_str().unwrap().starts_with("00000044  44 45 46"));
    assert!(!tail.to_string().contains("truncated"));

    // A page in the middle says where the next one starts.
    let (middle, _) = harness
        .ok(
            "read_hex",
            json!({"file_path": file, "offset": 16, "length": 32}),
        )
        .await;
    assert_eq!(middle["end_of_file"], false);
    assert_eq!(middle["next_offset"], 48);
    assert_eq!(middle["previous_offset"], 0);

    // The default length is 256 bytes (the whole 100-byte file here).
    let (all, _) = harness.ok("read_hex", json!({"file_path": file})).await;
    assert_eq!(all["length"], 100);
    assert_eq!(all["end_of_file"], true);

    // A negative offset before the start is clamped and says so.
    let (clamped, _) = harness
        .ok(
            "read_hex",
            json!({"file_path": file, "offset": -5000, "length": 16}),
        )
        .await;
    assert_eq!(clamped["offset"], 0);
    assert!(clamped["note"].as_str().unwrap().contains("starts at 0"));
}

#[tokio::test]
async fn read_hex_failures_are_errors_a_model_can_act_on() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = counting_file(&dir);
    let past = harness
        .err("read_hex", json!({"file_path": file, "offset": 100}))
        .await;
    assert!(
        past.contains("100 bytes long") && past.contains("negative offset"),
        "{past}"
    );
    let zero = harness
        .err("read_hex", json!({"file_path": file, "length": 0}))
        .await;
    assert!(zero.contains("1 to 4096"), "{zero}");
    let big = harness
        .err("read_hex", json!({"file_path": file, "length": 4097}))
        .await;
    assert!(big.contains("1 to 4096"), "{big}");
    let unknown = harness
        .err("read_hex", json!({"file_path": file, "size": 16}))
        .await;
    assert!(unknown.contains("unknown field"), "{unknown}");
    let missing = harness
        .err("read_hex", json!({"file_path": "/nonexistent/file.bin"}))
        .await;
    assert!(!missing.is_empty());
}

#[tokio::test]
async fn read_hex_stays_within_the_budget_on_real_binaries() {
    let harness = Harness::new().await;
    for file in [sample("go_test_binary"), "/bin/ls".to_string()] {
        for offset in [0i64, -4096, 1000] {
            let (dump, size) = harness
                .ok(
                    "read_hex",
                    json!({"file_path": file, "offset": offset, "length": 4096}),
                )
                .await;
            assert!(size <= BUDGET, "{file} {offset}: {size}");
            assert_eq!(dump["length"], 4096);
            assert!(dump.get("truncated").is_none(), "{file} {offset}");
        }
    }
}

/// CB22 / UC16 on analyze_file too: a negative `hex_dump_offset` is the footer.
#[tokio::test]
async fn analyze_file_hex_dump_accepts_a_negative_offset() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = counting_file(&dir);
    let (result, _) = harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "hex_dump": true, "hex_dump_size": 32,
                   "hex_dump_offset": -32}),
        )
        .await;
    assert_eq!(result["hex_dump"]["offset"], 68, "{result}");
    assert!(!result.to_string().contains("(truncated)"));
}

// ---------------------------------------------------------------------------
// disassemble
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disassemble_lists_functions_then_one_function_within_the_cap() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let (table, size) = harness
        .ok("disassemble", json!({"file_path": file, "limit": 10}))
        .await;
    assert!(size <= BUDGET);
    assert_eq!(table["view"], "functions");
    assert_eq!(table["cache"], "miss");
    assert_eq!(table["returned"], 10);
    assert!(table["total"].as_u64().unwrap() > 10);
    assert!(table["next_steps"][0]["tool"] == "disassemble");

    // The second call is answered from the cache.
    let (one, size) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "beacon_home", "max_instructions": 5}),
        )
        .await;
    assert_eq!(one["cache"], "hit");
    assert!(size < 5_000, "{size}");
    assert_eq!(one["function"]["name"], "beacon_home");
    assert_eq!(one["returned"], 5);
    assert_eq!(one["more"], true);
    let listing = one["listing"].as_str().unwrap();
    assert_eq!(listing.lines().count(), 5);
    assert!(listing.starts_with("0x"), "{listing}");
    let next = one["next_address"].as_str().unwrap().to_string();

    // The continuation starts where the first page stopped.
    let (more, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "address": next, "max_instructions": 3}),
        )
        .await;
    assert_eq!(more["start_address"], next.as_str());
    assert_eq!(more["function"]["name"], "beacon_home");
    assert_eq!(more["returned"], 3);

    // An address as a number, and a function given by its address.
    let start = u64::from_str_radix(
        one["function"]["address"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let (by_number, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "address": start, "max_instructions": 2}),
        )
        .await;
    assert_eq!(by_number["function"]["name"], "beacon_home");
    let (by_text, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": format!("0x{start:x}"), "max_instructions": 2}),
        )
        .await;
    assert_eq!(by_text["listing"], by_number["listing"]);

    // The default is 200 instructions and the cap is 1000: nothing returns a whole binary.
    let (default, size) = harness
        .ok("disassemble", json!({"file_path": file, "address": start}))
        .await;
    assert!(default["returned"].as_u64().unwrap() <= 200);
    assert!(size <= BUDGET);
    let (capped, size) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "address": start, "max_instructions": 100_000}),
        )
        .await;
    assert!(capped["returned"].as_u64().unwrap() <= 1000);
    assert!(
        capped["note"].as_str().unwrap().contains("1000"),
        "{capped}"
    );
    assert!(size <= BUDGET, "{size}");
    assert!(capped.get("truncated").is_none_or(|t| t == true));
}

#[tokio::test]
async fn disassemble_errors_say_what_to_do() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let unknown = harness
        .err(
            "disassemble",
            json!({"file_path": file, "function": "no_such_function_xyz"}),
        )
        .await;
    assert!(
        unknown.contains("No function named") && unknown.contains("filter"),
        "{unknown}"
    );
    let ambiguous = harness
        .err("disassemble", json!({"file_path": file, "function": "a"}))
        .await;
    assert!(
        ambiguous.contains("matches") && ambiguous.contains("exact name"),
        "{ambiguous}"
    );
    let both = harness
        .err(
            "disassemble",
            json!({"file_path": file, "function": "main", "address": 4096}),
        )
        .await;
    assert!(both.contains("not both"), "{both}");
    let bad = harness
        .err("disassemble", json!({"file_path": file, "address": "main"}))
        .await;
    assert!(bad.contains("is not an address"), "{bad}");
    let nowhere = harness
        .err("disassemble", json!({"file_path": file, "address": 16}))
        .await;
    assert!(nowhere.contains("No instruction at 0x10"), "{nowhere}");
    let zero = harness
        .err(
            "disassemble",
            json!({"file_path": file, "function": "main", "max_instructions": 0}),
        )
        .await;
    assert!(zero.contains("at least 1"), "{zero}");

    let dir = TempDir::new().unwrap();
    let text = repeated_strings_file(&dir);
    let not_code = harness.err("disassemble", json!({"file_path": text})).await;
    assert!(not_code.contains("analyze_file"), "{not_code}");
    let directory = harness
        .err("disassemble", json!({"file_path": dir.path()}))
        .await;
    assert!(!directory.is_empty());
}

/// The maintainer's rule: after `all: true` a `disassemble` call is a cache hit
/// (on the Go binary and on `/bin/ls`, a fat Mach-O on macOS and ELF elsewhere).
#[tokio::test]
async fn disassemble_after_all_is_a_cache_hit() {
    for file in [sample("go_test_binary"), "/bin/ls".to_string()] {
        let harness = Harness::new().await;
        let (all, _) = harness
            .ok("analyze_file", json!({"file_path": file, "all": true}))
            .await;
        if all.get("disassembly").is_none() {
            // Not disassemblable here (a universal Mach-O): the reason is an error.
            let message = harness.err("disassemble", json!({"file_path": file})).await;
            assert!(
                message.to_lowercase().contains("disassembl"),
                "{file}: {message}"
            );
            continue;
        }
        let (table, size) = harness
            .ok("disassemble", json!({"file_path": file, "limit": 5}))
            .await;
        assert_eq!(table["cache"], "hit", "{file}: {}", table["cache_note"]);
        assert!(size <= BUDGET);
        // A stripped binary (the system /bin/ls) has no function names: the
        // table says so and names an address to list from instead.
        let arguments = match table["items"][0]["name"].as_str() {
            Some(name) => json!({"file_path": file, "function": name}),
            None => {
                assert!(table["note"]
                    .as_str()
                    .unwrap()
                    .contains("no function symbols"));
                let address = table["next_steps"][0]["arguments"]["address"].clone();
                json!({"file_path": file, "address": address})
            }
        };
        let (listing, size) = harness.ok("disassemble", arguments).await;
        assert_eq!(listing["cache"], "hit", "{file}");
        assert!(size <= BUDGET, "{file}: {size}");
        assert!(listing["returned"].as_u64().unwrap() >= 1);
    }
}

#[tokio::test]
async fn disassemble_stays_within_the_budget_on_every_test_binary() {
    let harness = Harness::new().await;
    for name in [
        "c_advanced_binary",
        "cpp_test_binary",
        "nim_test_binary",
        "rust_test_binary",
    ] {
        let file = sample(name);
        let (table, size) = harness
            .ok("disassemble", json!({"file_path": file, "limit": 500}))
            .await;
        assert!(size <= BUDGET, "{name}: {size}");
        let first = table["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["instructions"].as_u64().unwrap_or(0) > 0)
            .unwrap_or_else(|| panic!("{name}: no function with instructions"));
        let (listing, size) = harness
            .ok(
                "disassemble",
                json!({"file_path": file, "address": first["address"], "max_instructions": 1000}),
            )
            .await;
        assert!(size <= BUDGET, "{name}: {size}");
        assert!(listing["returned"].as_u64().unwrap() >= 1);
    }
}

// ---------------------------------------------------------------------------
// llm_analyze_file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn llm_digest_names_the_file_and_has_no_duplicate_strings() {
    let harness = Harness::new().await;
    for file in [
        sample("c_advanced_binary"),
        sample("go_test_binary"),
        "/bin/ls".to_string(),
    ] {
        let (digest, size) = harness
            .ok("llm_analyze_file", json!({"file_path": file}))
            .await;
        assert!(size <= 25_000, "{file}: {size}");
        assert_eq!(digest["sha256"].as_str().unwrap().len(), 64, "{file}");
        assert_eq!(digest["md5"].as_str().unwrap().len(), 32);
        assert!(digest["file_type"].is_string(), "{file}: {digest}");
        assert!(digest["architecture"].is_string(), "{file}");
        assert!(digest["entropy"].is_f64());
        let strings: Vec<&str> = digest["key_strings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let unique: std::collections::BTreeSet<_> = strings.iter().collect();
        assert_eq!(strings.len(), unique.len(), "{file}: duplicate key strings");
        assert!(
            digest.get("truncated").is_none(),
            "{file}: {}",
            digest["truncated"]
        );
    }
    // The ELF test binaries have an entry point: opcodes are the instructions there.
    let (elf, _) = harness
        .ok(
            "llm_analyze_file",
            json!({"file_path": sample("c_advanced_binary")}),
        )
        .await;
    let opcodes = elf["opcodes"].as_array().unwrap();
    assert!(!opcodes.is_empty(), "{elf}");
    assert!(opcodes[0]
        .as_str()
        .unwrap()
        .split(' ')
        .all(|b| b.len() == 2));
    assert!(elf["notes"].to_string().contains("entry point"));
}

#[tokio::test]
async fn llm_digest_dedupes_repeated_strings_from_a_text_file() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let file = repeated_strings_file(&dir);
    let (digest, _) = harness
        .ok(
            "llm_analyze_file",
            json!({"file_path": file, "min_string_length": 6}),
        )
        .await;
    let strings = digest["key_strings"].as_array().unwrap();
    let count = |needle: &str| {
        strings
            .iter()
            .filter(|s| s.as_str().unwrap().contains(needle))
            .count()
    };
    assert_eq!(count("repeated.example.com"), 1, "{strings:?}");
    assert_eq!(count("duplicate marker"), 1, "{strings:?}");
    // The URL, a categorized string, comes first.
    assert!(strings[0].as_str().unwrap().contains("http://repeated"));
}

/// PF18 / LS18: `token_limit` is an output budget the answer obeys, and the
/// answer says what it cut.
#[tokio::test]
async fn llm_token_limit_is_honored_and_the_cut_is_reported() {
    let harness = Harness::new().await;
    let file = sample("rust_test_binary");
    for limit in [20_000usize, 6_000, 2_500, 1_500] {
        let (digest, size) = harness
            .ok(
                "llm_analyze_file",
                json!({"file_path": file, "token_limit": limit, "max_strings": 500,
                       "max_imports": 200}),
            )
            .await;
        assert!(size <= limit, "token_limit {limit}: {size} bytes");
        if limit <= 6_000 {
            let cut = &digest["truncated"];
            assert!(
                cut["cut"]["key_strings"]["dropped"].as_u64().unwrap() > 0,
                "{cut}"
            );
            assert!(cut["how"].as_str().unwrap().contains("token_limit"));
        }
    }
    // Asking for less than the identity needs is an error that says what is needed.
    let tiny = harness
        .err(
            "llm_analyze_file",
            json!({"file_path": file, "token_limit": 50}),
        )
        .await;
    assert!(tiny.contains("smaller than the smallest digest"), "{tiny}");
    // The tool's own output cap lowers the limit too.
    let (capped, size) = harness
        .ok(
            "llm_analyze_file",
            json!({"file_path": file, "max_strings": 500, "max_output_bytes": 4_000}),
        )
        .await;
    assert!(size <= 4_000, "{size}");
    assert!(capped.get("truncated").is_some());
}

/// LS19: a degenerate size is an error, not a crash.
#[tokio::test]
async fn llm_degenerate_arguments_are_rejected_with_a_reason() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let zero = harness
        .err(
            "llm_analyze_file",
            json!({"file_path": file, "hex_pattern_size": 0}),
        )
        .await;
    assert!(
        zero.contains("hex_pattern_size 0") && zero.contains("1 to 1024"),
        "{zero}"
    );
    let huge = harness
        .err(
            "llm_analyze_file",
            json!({"file_path": file, "hex_pattern_size": 100_000}),
        )
        .await;
    assert!(huge.contains("1 to 1024"), "{huge}");
    let min = harness
        .err(
            "llm_analyze_file",
            json!({"file_path": file, "min_string_length": 0}),
        )
        .await;
    assert!(min.contains("at least 1"), "{min}");
    // The server is still there, and the other zero-valued options still work.
    let (digest, _) = harness
        .ok(
            "llm_analyze_file",
            json!({"file_path": file, "max_strings": 0, "max_imports": 0, "max_opcodes": 0}),
        )
        .await;
    assert_eq!(digest["key_strings"].as_array().unwrap().len(), 0);
    assert!(digest
        .get("opcodes")
        .is_none_or(|o| o.as_array().unwrap().is_empty()));
}

// ---------------------------------------------------------------------------
// compare_files
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compare_files_says_identical_for_the_same_content() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let copy = dir.path().join("copy_of_c_advanced");
    std::fs::copy(sample("c_advanced_binary"), &copy).unwrap();
    let (result, _) = harness
        .ok(
            "compare_files",
            json!({"file_a": sample("c_advanced_binary"), "file_b": copy}),
        )
        .await;
    assert_eq!(result["identical"], true);
    assert_eq!(result["sha256"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn compare_files_lists_what_two_binaries_share_and_what_differs() {
    let harness = Harness::new().await;
    let (result, size) = harness
        .ok(
            "compare_files",
            json!({"file_a": sample("c_advanced_binary"), "file_b": sample("cpp_test_binary")}),
        )
        .await;
    assert!(size <= BUDGET, "{size}");
    assert_eq!(result["identical"], false);
    assert_eq!(result["file_a"]["format"], "ELF");
    assert!(result["size_delta"].as_i64().unwrap() > 0);
    assert!(result["entropy_delta"].is_f64());
    for group in ["imports", "sections", "categorized_strings"] {
        let g = &result[group];
        let (a, b) = (g["a"].as_u64().unwrap(), g["b"].as_u64().unwrap());
        let common = g["common"].as_u64().unwrap();
        assert_eq!(common + g["only_in_a"].as_u64().unwrap(), a, "{group}");
        assert_eq!(common + g["only_in_b"].as_u64().unwrap(), b, "{group}");
        for list in ["common_items", "only_in_a_items", "only_in_b_items"] {
            assert!(g[list].as_array().unwrap().len() <= 20, "{group} {list}");
        }
    }
    assert!(result["sections"]["common"].as_u64().unwrap() > 5);
    // A cap is announced, and lowering it shortens the lists.
    let (small, _) = harness
        .ok(
            "compare_files",
            json!({"file_a": sample("c_advanced_binary"), "file_b": sample("cpp_test_binary"),
                   "max_items": 2}),
        )
        .await;
    assert_eq!(
        small["sections"]["common_items"].as_array().unwrap().len(),
        2
    );
    assert!(small["sections"]["lists_capped"].is_string());
    // Both files were analyzed once; a later query on either is a hit.
    assert_eq!(small["cache"], "hit");
    let (page, _) = harness
        .ok(
            "query_analysis",
            json!({"file_path": sample("cpp_test_binary"), "section": "strings", "limit": 3}),
        )
        .await;
    assert_eq!(page["cache"], "hit");
}

#[tokio::test]
async fn compare_files_copes_with_text_and_with_big_binaries() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let text = repeated_strings_file(&dir);
    let (result, size) = harness
        .ok(
            "compare_files",
            json!({"file_a": text, "file_b": sample("go_test_binary")}),
        )
        .await;
    assert!(size <= BUDGET, "{size}");
    // The text file is not an executable: said under notes, not silently empty.
    assert!(
        result["notes"].to_string().contains("file_a: binary_info"),
        "{result}"
    );
    assert_eq!(result["categorized_strings"]["common"], 0);
    // The placeholder section of a raw file is not counted as a section.
    assert_eq!(result["sections"]["a"], 0, "{result}");
    assert_eq!(result["sections"]["common"], 0, "{result}");

    let (big, size) = harness
        .ok(
            "compare_files",
            json!({"file_a": sample("rust_test_binary"), "file_b": sample("go_test_binary"),
                   "max_items": 200}),
        )
        .await;
    assert!(size <= BUDGET, "{size}");
    assert!(big["imports"]["a"].is_u64());
    let missing = harness
        .err(
            "compare_files",
            json!({"file_a": "/nonexistent/a.bin", "file_b": sample("go_test_binary")}),
        )
        .await;
    assert!(!missing.is_empty());
    let extra = harness
        .err(
            "compare_files",
            json!({"file_a": text, "file_b": text, "compare_with": "x"}),
        )
        .await;
    assert!(extra.contains("unknown field"), "{extra}");
}

// ---------------------------------------------------------------------------
// The tool list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_new_tools_are_listed_with_descriptions_that_say_what_to_call_first() {
    let harness = Harness::new().await;
    let tools = harness.client.list_all_tools().await.unwrap();
    for (name, needle) in [
        ("disassemble", "analyze_file"),
        ("read_hex", "analyze_file"),
        ("compare_files", "analyze_file"),
        ("llm_analyze_file", "analyze_file"),
    ] {
        let tool = tools
            .iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("{name}"));
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(description.contains(needle), "{name}: {description}");
        assert!(tool.input_schema.get("properties").is_some());
    }
    let llm = tools.iter().find(|t| t.name == "llm_analyze_file").unwrap();
    let description = llm.description.as_deref().unwrap();
    assert!(
        description.contains("Choose it over analyze_file"),
        "{description}"
    );
}

#[tokio::test]
async fn read_hex_cut_by_the_budget_continues_where_it_stopped() {
    let harness = Harness::new().await;
    let file = sample("go_test_binary");
    let (page, size) = harness
        .ok(
            "read_hex",
            json!({"file_path": file, "offset": 4096, "length": 4096, "max_output_bytes": 4000}),
        )
        .await;
    assert!(size <= 4000, "{size}");
    let lines = page["lines"].as_array().unwrap().len();
    assert!(lines < 256, "the budget should cut the dump");
    assert_eq!(page["length"], json!(lines * 16));
    assert_eq!(page["next_offset"], json!(4096 + lines * 16));
    assert_eq!(page["end_of_file"], json!(false));
}

#[tokio::test]
async fn disassemble_without_function_names_points_at_an_address() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("code.bin");
    std::fs::write(&path, [0x90u8; 64]).unwrap();
    let message = harness
        .err(
            "disassemble",
            json!({"file_path": path.to_string_lossy(), "address": -1}),
        )
        .await;
    assert!(message.contains("0x401136"), "{message}");
}

/// A listing cut by a small budget reports the lines it sent and continues at
/// the first line it did not send.
#[tokio::test]
async fn a_listing_cut_by_the_budget_continues_where_it_stopped() {
    let harness = Harness::new().await;
    let file = sample("c_advanced_binary");
    let (uncut, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": file, "function": "main", "max_instructions": 1000,
                   "max_output_bytes": 400000}),
        )
        .await;
    let all_lines: Vec<String> = uncut["listing"]
        .as_str()
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert!(all_lines.len() > 60, "{}", all_lines.len());

    let mut walked: Vec<String> = Vec::new();
    let mut request = json!({"file_path": file, "function": "main", "max_instructions": 1000,
                             "max_output_bytes": 4000});
    for _ in 0..40 {
        let (page, size) = harness.ok("disassemble", request.clone()).await;
        assert!(size <= 4000, "{size}");
        let lines: Vec<String> = page["listing"]
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(page["returned"], json!(lines.len()), "{page}");
        assert!(page.get("truncated").is_none(), "{page}");
        walked.extend(lines);
        let Some(next) = page["next_address"].as_str() else {
            break;
        };
        assert_eq!(
            page["next_steps"][0]["arguments"]["address"], next,
            "{page}"
        );
        request = json!({"file_path": file, "address": next, "max_instructions": 1000,
                         "max_output_bytes": 4000});
    }
    // Following next_address at a small budget reads the code the cut left out.
    assert!(walked.len() >= 90, "{}", walked.len());
    assert_eq!(walked[..60], all_lines[..60]);
}

/// A call or jump to an address that is a function is shown with its name.
#[tokio::test]
async fn direct_calls_are_named_in_the_listing() {
    let harness = Harness::new().await;
    let (page, _) = harness
        .ok(
            "disassemble",
            json!({"file_path": sample("c_advanced_binary"), "function": "main",
                   "max_instructions": 300}),
        )
        .await;
    let listing = page["listing"].as_str().unwrap();
    assert!(
        listing
            .lines()
            .any(|l| l.contains(" call 0x") && l.contains("; -> ")),
        "{listing}"
    );
}
