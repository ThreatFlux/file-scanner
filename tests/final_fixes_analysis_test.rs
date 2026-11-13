#![allow(clippy::too_many_lines, clippy::missing_panics_doc)]

//! Last fixes of the final verification of the analysis tools: `disassemble`
//! with a part of a function name, the section cache and the class of a file's
//! name, and the numeric `format` keys of the tool input schemas.

use std::{io::Write, path::Path, sync::Arc};

use file_scanner::mcp_server::{FileScannerMcp, ServerState, StateConfig};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};
use tempfile::TempDir;

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

    /// The answer as text and whether it is an error.
    async fn text(&self, tool: &str, args: Value) -> (bool, String) {
        let result = self.raw(tool, args).await;
        (
            result.is_error == Some(true),
            result.content[0].as_text().unwrap().text.clone(),
        )
    }

    async fn ok(&self, tool: &str, args: Value) -> Value {
        let (is_error, text) = self.text(tool, args.clone()).await;
        assert!(!is_error, "{tool} {args}: {text}");
        serde_json::from_str(&text).expect("compact JSON")
    }
}

fn go_binary() -> String {
    format!(
        "{}/test_programs/go_test_binary",
        env!("CARGO_MANIFEST_DIR")
    )
}

// ---------------------------------------------------------------------------
// Item 2: a part of a function name searches what the functions view filters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_partial_function_name_matches_what_the_filter_lists() {
    let harness = Harness::new().await;
    let file = go_binary();
    // "main." matches two grouped functions and `main.main`, which is only in
    // the symbol table.
    let listed = harness
        .ok("disassemble", json!({"file_path": file, "filter": "main."}))
        .await;
    let names: Vec<String> = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.iter().any(|n| n == "main.main"), "{names:?}");
    assert!(names.len() >= 3, "{names:?}");

    let (is_error, message) = harness
        .text(
            "disassemble",
            json!({"file_path": file, "function": "main."}),
        )
        .await;
    assert!(is_error, "{message}");
    assert!(
        message.contains(&format!("'main.' matches {} functions", names.len())),
        "{message}"
    );
    for name in &names {
        assert!(message.contains(name.as_str()), "{name} in {message}");
    }

    // The exact name keeps working, in any case.
    for name in ["main.main", "MAIN.MAIN"] {
        let answer = harness
            .ok(
                "disassemble",
                json!({"file_path": file, "function": name, "limit": 3}),
            )
            .await;
        assert_eq!(answer["function"]["name"], "main.main", "{name}");
    }

    // A part that only one function has, a symbol-table-only one, is
    // disassembled; so is one that only a grouped function has.
    for (part, name) in [
        ("main.ma", "main.main"),
        ("runtime.main.func1", "runtime.main.func1"),
    ] {
        let one = harness
            .ok("disassemble", json!({"file_path": file, "filter": part}))
            .await;
        assert_eq!(one["total"], 1, "{part}: {one}");
        let answer = harness
            .ok("disassemble", json!({"file_path": file, "function": part}))
            .await;
        assert_eq!(answer["function"]["name"], name, "{part}");
    }

    // The count in the message follows the filter for other parts too.
    for part in ["runtime.", "main"] {
        let listed = harness
            .ok("disassemble", json!({"file_path": file, "filter": part}))
            .await;
        let total = listed["total"].as_u64().unwrap();
        let (is_error, message) = harness
            .text("disassemble", json!({"file_path": file, "function": part}))
            .await;
        if total > 1 {
            assert!(is_error, "{part}: {message}");
            assert!(
                message.contains(&format!("'{part}' matches {total} functions")),
                "{part} ({total}): {message}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Item 3: the answer of `disassemble` does not depend on the file's name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disassemble_answers_the_same_under_java_archive_names() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let real = dir.path().join("sample.bin");
    std::fs::copy(go_binary(), &real).unwrap();
    let strip = |mut value: Value| {
        value.as_object_mut().unwrap().remove("file_path");
        value.as_object_mut().unwrap().remove("next_steps");
        value.as_object_mut().unwrap().remove("cache");
        value.as_object_mut().unwrap().remove("cache_note");
        value
    };
    let expected = strip(
        harness
            .ok("disassemble", json!({"file_path": real, "limit": 5}))
            .await,
    );
    assert!(expected["total"].as_u64().unwrap() > 0);
    for ext in ["jar", "war", "ear", "apk", "aar"] {
        let copy = dir.path().join(format!("sample.{ext}"));
        std::fs::copy(go_binary(), &copy).unwrap();
        let answer = strip(
            harness
                .ok("disassemble", json!({"file_path": copy, "limit": 5}))
                .await,
        );
        assert_eq!(answer, expected, ".{ext}");
    }
}

// ---------------------------------------------------------------------------
// Item 4: a cached answer is shared only between names of one class
// ---------------------------------------------------------------------------

fn plain_zip(path: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("notes.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"just a text file in a plain archive")
        .unwrap();
    zip.finish().unwrap();
}

async fn section(harness: &Harness, file: &Path, section: &str) -> Value {
    harness
        .ok(
            "analyze_file",
            json!({"file_path": file, "sections": [section]}),
        )
        .await
}

#[tokio::test]
async fn names_of_different_classes_never_share_a_cached_answer() {
    let dir = TempDir::new().unwrap();
    for (first, second) in [("war", "zip"), ("zip", "war"), ("bin", "jar")] {
        // A fresh server, so a stored answer of an earlier pair cannot help.
        let harness = Harness::new().await;
        let a = dir.path().join(format!("a_{first}_{second}.{first}"));
        let b = dir.path().join(format!("b_{first}_{second}.{second}"));
        plain_zip(&a);
        std::fs::copy(&a, &b).unwrap();
        for name in ["binary_info", "yara_indicators"] {
            let one = section(&harness, &a, name).await;
            assert_eq!(one["cache"], "miss", "{name} {first}");
            let two = section(&harness, &b, name).await;
            assert_eq!(
                two["cache"], "miss",
                "{name}: .{first} then .{second} must not share an answer"
            );
        }
    }
}

#[tokio::test]
async fn names_of_one_class_share_a_cached_answer() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    // `.war` and `.JAR` are one class (Java archives), `.zip` and `.bin` another.
    let pairs = [("war", "JAR"), ("zip", "bin")];
    for (first, second) in pairs {
        let a = dir.path().join(format!("a.{first}"));
        let b = dir.path().join(format!("b.{second}"));
        plain_zip(&a);
        std::fs::copy(&a, &b).unwrap();
        for name in ["binary_info", "yara_indicators"] {
            assert_eq!(section(&harness, &a, name).await["cache"], "miss");
            assert_eq!(
                section(&harness, &b, name).await["cache"],
                "hit",
                "{name}: .{first} and .{second}"
            );
        }
    }
}

#[tokio::test]
async fn the_name_decides_binary_info_of_the_same_bytes() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let war = dir.path().join("plain.war");
    let zip = dir.path().join("plain.zip");
    plain_zip(&war);
    std::fs::copy(&war, &zip).unwrap();
    let as_war = section(&harness, &war, "binary_info").await;
    let as_zip = section(&harness, &zip, "binary_info").await;
    assert_eq!(as_war["binary_info"]["format"], "Java Archive");
    assert_ne!(as_zip["binary_info"]["format"], "Java Archive", "{as_zip}");
}

#[tokio::test]
async fn taint_answers_carry_the_path_of_the_file_asked_about() {
    let harness = Harness::new().await;
    let dir = TempDir::new().unwrap();
    let first = dir.path().join("first.py");
    let second = dir.path().join("second.txt");
    std::fs::write(
        &first,
        "import os\nimport sys\nimport subprocess\n\ndef run():\n    cmd = input()\n    os.system(cmd)\n    subprocess.call(sys.argv[1])\n",
    )
    .unwrap();
    std::fs::copy(&first, &second).unwrap();
    let a = section(&harness, &first, "taint").await;
    assert_eq!(a["cache"], "miss");
    let b = section(&harness, &second, "taint").await;
    assert_eq!(b["cache"], "miss", "{b}");
    let first_path = first.to_string_lossy().to_string();
    let second_path = second.to_string_lossy().to_string();
    for list in ["sources", "sinks"] {
        let rows = harness
            .ok(
                "query_analysis",
                json!({"file_path": second, "section": "taint", "list": list}),
            )
            .await;
        let text = rows.to_string();
        assert!(text.contains(&second_path), "{list}: {text}");
        assert!(!text.contains(&first_path), "{list}: {text}");
    }
}

// ---------------------------------------------------------------------------
// Item 5: no `format` on an integer or number in a tool input schema
// ---------------------------------------------------------------------------

fn numeric_formats(node: &Value, path: &str, found: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            let numeric = match map.get("type") {
                Some(Value::String(t)) => t == "integer" || t == "number",
                Some(Value::Array(types)) => types
                    .iter()
                    .any(|t| matches!(t.as_str(), Some("integer" | "number"))),
                _ => false,
            };
            if numeric && map.contains_key("format") {
                found.push(format!("{path}: {}", map["format"]));
            }
            for (key, value) in map {
                numeric_formats(value, &format!("{path}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().enumerate() {
                numeric_formats(value, &format!("{path}/{i}"), found);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn no_tool_schema_carries_a_format_on_an_integer_or_number() {
    let harness = Harness::new().await;
    let tools = harness.client.list_all_tools().await.unwrap();
    assert!(tools.len() >= 17, "{} tools", tools.len());
    let mut found = Vec::new();
    for tool in &tools {
        let schema = Value::Object((*tool.input_schema).clone());
        numeric_formats(&schema, &tool.name, &mut found);
    }
    assert!(found.is_empty(), "{found:#?}");

    // Everything else of the schemas stays: an unsigned integer keeps its bound.
    let disassemble = tools.iter().find(|t| t.name == "disassemble").unwrap();
    let limit = &disassemble.input_schema["properties"]["limit"];
    assert!(limit["type"].to_string().contains("integer"), "{limit}");
    assert_eq!(limit["minimum"], 0, "{limit}");

    // The same definitions, as the REST listing builds them.
    let definitions = FileScannerMcp::new().tool_definitions();
    let mut found = Vec::new();
    for tool in &definitions {
        numeric_formats(&serde_json::to_value(tool).unwrap(), &tool.name, &mut found);
    }
    assert!(found.is_empty(), "{found:#?}");
}
