#![allow(clippy::too_many_lines)]

//! Findings of the review of pull request 315: a content hash remembered for a
//! path must not outlive an in-place rewrite, a package source that could not
//! be read must not count as scanned, and the signature answer must depend on
//! the detached signature files of the path it was asked for.

use std::io::Write as _;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use file_scanner::npm_analysis::{analyze_npm_package, RiskLevel as NpmRisk};
use file_scanner::{
    mcp_server::FileScannerMcp,
    python_analysis::{analyze_python_package, RiskLevel as PyRisk},
};
use rmcp::{model::CallToolRequestParams, ServiceExt};
use serde_json::{json, Value};
use tempfile::TempDir;

async fn client() -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(service) = FileScannerMcp::new().serve(server_io).await {
            let _ = service.waiting().await;
        }
    });
    ().serve(client_io).await.expect("handshake")
}

async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> Value {
    let Value::Object(map) = args else {
        panic!("object")
    };
    let result = client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map))
        .await
        .expect("protocol");
    let text = result
        .content
        .first()
        .and_then(|b| b.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default();
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str(&text).unwrap_or(Value::String(text))
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, bytes).unwrap();
    path
}

// ---------------------------------------------------------------------------
// 1. A rewrite in place with the modification time put back
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn a_same_length_rewrite_with_the_mtime_restored_is_not_answered_from_the_old_hash() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "a.bin", b"hello_alpha_string_one\n");
    let old = filetime::FileTime::from_unix_time(1_000_000, 0);
    filetime::set_file_mtime(&path, old).unwrap();
    let client = client().await;
    let ask = || json!({"file_path": path, "query": "_string_", "min_length": 6});

    let first = call(&client, "search_strings", ask()).await;
    assert!(first.to_string().contains("hello_alpha_string_one"));
    let first_sha = first["sha256"].as_str().unwrap().to_string();

    // Same length, written in place, modification time put back.
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(b"world_omega_string_two\n").unwrap();
    }
    filetime::set_file_mtime(&path, old).unwrap();

    let second = call(&client, "search_strings", ask()).await;
    assert_ne!(second["sha256"].as_str().unwrap(), first_sha, "{second}");
    assert!(second.to_string().contains("world_omega_string_two"));
    assert!(!second.to_string().contains("hello_alpha_string_one"));
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// 2. Sources that could not be read are not counted as scanned
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn evil_js() -> String {
    let pool = ["stratum", "+tcp://pool.example.invalid:3333"].concat();
    format!(
        "const pool = '{pool}';\nrequire('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');\n"
    )
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_source_is_not_counted_and_the_package_is_not_safe() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "package.json",
        br#"{"name":"demo-pkg","version":"1.0.0"}"#,
    );
    write(dir.path(), "ok.js", b"module.exports = 1;\n");
    let hidden = write(dir.path(), "lib/hidden.js", evil_js().as_bytes());

    // Fully readable: every source is counted, nothing is skipped.
    let full = analyze_npm_package(dir.path()).unwrap();
    assert_eq!(full.input.files_skipped, 0);
    assert_eq!(full.input.files_scanned, 2);
    let full_bytes = full.input.bytes_scanned;

    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&hidden).is_ok() {
        // Root reads anything: the case cannot be built here.
        return;
    }
    let analysis = analyze_npm_package(dir.path()).unwrap();
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(analysis.input.files_scanned, 1, "{:?}", analysis.input);
    assert!(analysis.input.bytes_scanned < full_bytes);
    assert_eq!(analysis.input.files_skipped, 1);
    assert!(
        analysis
            .input
            .notes
            .iter()
            .any(|n| n.starts_with("1 source files could not be read: lib/hidden.js")),
        "{:?}",
        analysis.input.notes
    );
    let reason = analysis.input.incomplete_reason().unwrap();
    assert!(
        reason.contains("1 source file(s) were not scanned"),
        "{reason}"
    );
    assert!(!matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::Safe
    ));
}

#[test]
fn a_zip_member_with_damaged_data_is_not_counted_and_the_package_is_not_safe() {
    let metadata = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\nbody\n";
    let build = |damage: bool| {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("demo/ok.py", stored).unwrap();
        writer.write_all(b"x = 1\n").unwrap();
        writer.start_file("demo/bad.py", stored).unwrap();
        writer
            .write_all(b"import os\nos.system('echo hello world')\n")
            .unwrap();
        writer
            .start_file("demo-1.0.dist-info/METADATA", stored)
            .unwrap();
        writer.write_all(metadata.as_bytes()).unwrap();
        let mut bytes = writer.finish().unwrap().into_inner();
        if damage {
            // Flip a byte of the stored data of demo/bad.py: its CRC no longer fits.
            let needle = b"os.system";
            let at = bytes
                .windows(needle.len())
                .position(|w| w == needle)
                .unwrap();
            bytes[at] ^= 0x20;
        }
        bytes
    };
    let dir = TempDir::new().unwrap();
    let good = write(dir.path(), "good-1.0-py3-none-any.whl", &build(false));
    let broken = write(dir.path(), "demo-1.0-py3-none-any.whl", &build(true));

    let full = analyze_python_package(&good).unwrap();
    assert_eq!(full.input.files_skipped, 0, "{:?}", full.input);
    assert_eq!(full.input.files_scanned, 2);

    let analysis = analyze_python_package(&broken).unwrap();
    assert_eq!(analysis.input.files_scanned, 1, "{:?}", analysis.input);
    assert!(analysis.input.bytes_scanned < full.input.bytes_scanned);
    assert_eq!(analysis.input.files_skipped, 1);
    assert!(
        analysis
            .input
            .notes
            .iter()
            .any(|n| n.starts_with("1 source files could not be read: demo/bad.py")),
        "{:?}",
        analysis.input.notes
    );
    assert!(analysis.input.incomplete_reason().is_some());
    assert_ne!(analysis.malicious_indicators.risk_level, PyRisk::Safe);
}

// ---------------------------------------------------------------------------
// 3. The signature answer depends on the side files of this path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_signature_answer_follows_the_detached_signature_files_of_the_path() {
    let dir = TempDir::new().unwrap();
    let payload = b"same payload bytes\n".repeat(10);
    let x = write(dir.path(), "x/p.bin", &payload);
    let y = write(dir.path(), "y/p.bin", &payload);
    let client = client().await;
    let status = |value: &Value| {
        value["signatures"]["verification_status"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    let ask = |path: &Path| json!({"file_path": path, "signatures": true});

    let first = call(&client, "analyze_file", ask(&x)).await;
    assert_eq!(status(&first), "No signature found", "{first}");

    // Adding the detached signature changes the answer for this path.
    let side = write(
        dir.path(),
        "x/p.bin.sig",
        b"-----BEGIN PGP SIGNATURE-----\nbogus\n-----END PGP SIGNATURE-----\n",
    );
    let second = call(&client, "analyze_file", ask(&x)).await;
    assert_ne!(status(&second), "No signature found", "{second}");
    assert!(
        second["signatures"]["signature_type"] == "GPG"
            || status(&second).to_lowercase().contains("detached"),
        "{second}"
    );

    // The identical payload at another path has no side file: not shared.
    let other = call(&client, "analyze_file", ask(&y)).await;
    assert_eq!(status(&other), "No signature found", "{other}");

    // Removing the side file gives "no signature" again.
    std::fs::remove_file(side).unwrap();
    let third = call(&client, "analyze_file", ask(&x)).await;
    assert_eq!(status(&third), "No signature found", "{third}");
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// 4. A detached signature file is read only from inside the allowed roots
// ---------------------------------------------------------------------------

#[cfg(unix)]
const SECRET_LINE: &str = "TOPSECRET_LINE_42";
#[cfg(unix)]
const REFUSED_WORDS: &str = "was not read because it is a link that leads to";

async fn rooted_client(root: &Path) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    use file_scanner::mcp_server::{ServerState, StateConfig};
    let cache = TempDir::new().unwrap();
    let state = std::sync::Arc::new(ServerState::new(StateConfig {
        cache_dir: cache.path().to_path_buf(),
        allow_roots: vec![root.to_path_buf()],
        ..StateConfig::default()
    }));
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _keep = cache;
        if let Ok(service) = FileScannerMcp::with_state(state).serve(server_io).await {
            let _ = service.waiting().await;
        }
    });
    ().serve(client_io).await.expect("handshake")
}

fn armor_with(line: &str) -> Vec<u8> {
    format!("-----BEGIN PGP SIGNATURE-----\n{line}\n\nxx\n-----END PGP SIGNATURE-----\n")
        .into_bytes()
}

#[cfg(unix)]
#[tokio::test]
async fn a_signature_link_leading_outside_the_roots_is_not_read() {
    for suffix in ["sig", "asc"] {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let secret = write(outside.path(), "secret.txt", &armor_with(SECRET_LINE));
        let file = write(&root_path, "a.bin", b"payload bytes\n");
        std::os::unix::fs::symlink(&secret, root_path.join(format!("a.bin.{suffix}"))).unwrap();
        let client = rooted_client(&root_path).await;
        let outside_dir = outside.path().canonicalize().unwrap();

        // The cache is on: the answer must be computed again every call.
        for args in [
            json!({"file_path": file, "signatures": true}),
            json!({"file_path": file, "all": true}),
            json!({"file_path": file}),
            json!({"file_path": file, "signatures": true}),
            json!({"file_path": file, "sections": ["signatures"]}),
        ] {
            let answer = call(&client, "analyze_file", args).await.to_string();
            assert!(!answer.contains(SECRET_LINE), "{suffix}: {answer}");
            assert!(
                !answer.contains(outside_dir.to_str().unwrap()) && !answer.contains("secret.txt"),
                "{suffix}: {answer}"
            );
            if answer.contains("verification_status") {
                assert!(answer.contains(REFUSED_WORDS), "{suffix}: {answer}");
                assert!(answer.contains("<outside the allowed roots>"), "{suffix}");
            }
        }
        // Removing the link gives the plain answer again (nothing stale).
        std::fs::remove_file(root_path.join(format!("a.bin.{suffix}"))).unwrap();
        let after = call(
            &client,
            "analyze_file",
            json!({"file_path": file, "signatures": true}),
        )
        .await;
        assert_eq!(
            after["signatures"]["verification_status"], "No signature found",
            "{after}"
        );
        client.cancel().await.unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_signature_link_to_another_file_inside_the_roots_is_still_used() {
    let root = TempDir::new().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let real = write(&root_path, "store/real.dat", &armor_with("INSIDE_LINE_7"));
    let file = write(&root_path, "a.bin", b"payload bytes\n");
    std::os::unix::fs::symlink(&real, root_path.join("a.bin.sig")).unwrap();
    let client = rooted_client(&root_path).await;
    let answer = call(
        &client,
        "analyze_file",
        json!({"file_path": file, "signatures": true}),
    )
    .await;
    let status = answer["signatures"]["verification_status"]
        .as_str()
        .unwrap_or_default();
    assert!(!status.contains(REFUSED_WORDS), "{answer}");
    assert_ne!(status, "No signature found", "{answer}");
    client.cancel().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn without_roots_a_signature_link_is_followed_as_before() {
    let dir = TempDir::new().unwrap();
    let other = TempDir::new().unwrap();
    let secret = write(other.path(), "s.txt", &armor_with(SECRET_LINE));
    let file = write(dir.path(), "a.bin", b"payload bytes\n");
    std::os::unix::fs::symlink(&secret, dir.path().join("a.bin.sig")).unwrap();
    let client = client().await;
    let answer = call(
        &client,
        "analyze_file",
        json!({"file_path": file, "signatures": true}),
    )
    .await;
    let status = answer["signatures"]["verification_status"]
        .as_str()
        .unwrap_or_default();
    assert!(!status.contains(REFUSED_WORDS), "{answer}");
    assert_ne!(status, "No signature found", "{answer}");
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// 5. A side file that is not a regular file is never opened
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn make_fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo");
    assert!(status.success());
}

/// Ask for the signature section with a client-side deadline, so a call that
/// would block on a pipe fails the test instead of hanging it.
async fn signature_answer(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    file: &Path,
) -> Value {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        call(
            client,
            "analyze_file",
            json!({"file_path": file, "sections": ["signatures"]}),
        ),
    )
    .await
    .expect("the signature section must answer, not block on the side file")
}

#[cfg(unix)]
#[tokio::test]
async fn a_named_pipe_or_directory_as_a_side_file_is_not_opened_and_is_said_so() {
    for rooted in [false, true] {
        for (kind, words) in [
            ("fifo", "is a named pipe (FIFO)"),
            ("dir", "is a directory"),
        ] {
            for suffix in ["sig", "asc"] {
                let root = TempDir::new().unwrap();
                let root_path = root.path().canonicalize().unwrap();
                let file = write(&root_path, "a.bin", b"payload bytes\n");
                let side = root_path.join(format!("a.bin.{suffix}"));
                if kind == "fifo" {
                    make_fifo(&side);
                } else {
                    std::fs::create_dir(&side).unwrap();
                }
                let client = if rooted {
                    rooted_client(&root_path).await
                } else {
                    client().await
                };
                let answer = signature_answer(&client, &file).await.to_string();
                assert!(
                    answer.contains("exists beside the file but")
                        && answer.contains(words)
                        && answer.contains("was not read"),
                    "{kind} {suffix} rooted={rooted}: {answer}"
                );
                assert!(!answer.contains("Detached signature present"), "{answer}");
                client.cancel().await.unwrap();
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_link_to_a_named_pipe_inside_the_roots_is_not_opened_either() {
    let root = TempDir::new().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let file = write(&root_path, "a.bin", b"payload bytes\n");
    let pipe = root_path.join("pipe");
    make_fifo(&pipe);
    std::os::unix::fs::symlink(&pipe, root_path.join("a.bin.sig")).unwrap();
    let client = rooted_client(&root_path).await;
    let answer = signature_answer(&client, &file).await.to_string();
    assert!(answer.contains("is a named pipe (FIFO)"), "{answer}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn an_ordinary_side_file_is_still_used() {
    let root = TempDir::new().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let file = write(&root_path, "a.bin", b"payload bytes\n");
    write(&root_path, "a.bin.sig", &armor_with("PLAIN_SIDE"));
    let client = rooted_client(&root_path).await;
    let answer = signature_answer(&client, &file).await;
    let status = answer["signatures"]["verification_status"]
        .as_str()
        .unwrap_or_default();
    assert!(!status.contains("was not read"), "{answer}");
    assert_ne!(status, "No signature found", "{answer}");
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// 6. The library entry points obey the roots of a rooted state
// ---------------------------------------------------------------------------

#[cfg(unix)]
async fn tool_error_text(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> String {
    let Value::Object(map) = args else {
        panic!("object")
    };
    let result = client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map))
        .await
        .expect("protocol");
    assert_eq!(result.is_error, Some(true), "{result:?}");
    result
        .content
        .first()
        .and_then(|b| b.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default()
}

#[cfg(unix)]
#[tokio::test]
async fn the_library_entry_points_refuse_what_the_registered_tools_refuse() {
    use file_scanner::mcp_server::{
        NpmAnalysisRequest, PythonAnalysisRequest, ServerState, StateConfig, YaraScanRequest,
    };
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let outside_path = outside.path().canonicalize().unwrap();
    let cache = TempDir::new().unwrap();
    let state = std::sync::Arc::new(ServerState::new(StateConfig {
        cache_dir: cache.path().to_path_buf(),
        allow_roots: vec![root_path.clone()],
        ..StateConfig::default()
    }));
    let server = FileScannerMcp::with_state(std::sync::Arc::clone(&state));
    let client = rooted_client(&root_path).await;

    // Targets: a file outside, and a link inside that leads outside.
    let secret = write(&outside_path, "secret.bin", b"SECRET_BYTES\n");
    let secret_dir = outside_path.join("pkg");
    write(
        &secret_dir,
        "package.json",
        br#"{"name":"x","version":"1.0.0"}"#,
    );
    write(&secret_dir, "setup.py", b"print('x')\n");
    let inside_file = write(&root_path, "ok.bin", b"inside\n");
    let link_file = root_path.join("link.bin");
    std::os::unix::fs::symlink(&secret, &link_file).unwrap();
    let link_dir = root_path.join("linkdir");
    std::os::unix::fs::symlink(&secret_dir, &link_dir).unwrap();
    let rules = write(&outside_path, "rules/r.yar", b"rule r { condition: true }");

    for target in [&secret, &link_file] {
        let raw = target.to_string_lossy().into_owned();
        let request: file_scanner::mcp_server::FileAnalysisRequest =
            serde_json::from_value(json!({"file_path": raw, "signatures": true})).unwrap();
        let library = server.analyze_file(request).await.err().expect("refused");
        let tool = tool_error_text(&client, "analyze_file", json!({"file_path": raw})).await;
        assert_eq!(library, tool);

        let request: YaraScanRequest =
            serde_json::from_value(json!({"path": raw, "yara_rule": "rule a { condition: true }"}))
                .unwrap();
        let library = server.yara_scan_file(request).await.err().expect("refused");
        let tool = tool_error_text(
            &client,
            "yara_scan_file",
            json!({"path": raw, "yara_rule": "rule a { condition: true }"}),
        )
        .await;
        assert_eq!(library, tool);
    }

    // A rule path outside, with a scan path inside.
    for rule in [rules.clone(), {
        let link = root_path.join("rules-link");
        std::os::unix::fs::symlink(outside_path.join("rules"), &link).unwrap();
        link
    }] {
        let raw = rule.to_string_lossy().into_owned();
        let request: YaraScanRequest =
            serde_json::from_value(json!({"path": inside_file, "yara_rule": "", "rule_path": raw}))
                .unwrap();
        let library = server.yara_scan_file(request).await.err().expect("refused");
        let tool = tool_error_text(
            &client,
            "yara_scan_file",
            json!({"path": inside_file, "rule_path": raw}),
        )
        .await;
        assert_eq!(library, tool);
    }

    for target in [&secret_dir, &link_dir] {
        let raw = target.to_string_lossy().into_owned();
        let request: NpmAnalysisRequest =
            serde_json::from_value(json!({"package_path": raw})).unwrap();
        let library = server
            .analyze_npm_package(request)
            .await
            .err()
            .expect("refused");
        let tool =
            tool_error_text(&client, "analyze_npm_package", json!({"package_path": raw})).await;
        assert_eq!(library, tool);

        let request: PythonAnalysisRequest =
            serde_json::from_value(json!({"package_path": raw})).unwrap();
        let library = server
            .analyze_python_package(request)
            .await
            .err()
            .expect("refused");
        let tool = tool_error_text(
            &client,
            "analyze_python_package",
            json!({"package_path": raw}),
        )
        .await;
        assert_eq!(library, tool);
    }

    // What is inside the root still works.
    let request: file_scanner::mcp_server::FileAnalysisRequest =
        serde_json::from_value(json!({"file_path": inside_file, "hashes": true})).unwrap();
    assert!(server.analyze_file(request).await.is_ok());
    client.cancel().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn the_last_library_entry_points_refuse_what_the_registered_tools_refuse() {
    use file_scanner::mcp_server::{
        JavaAnalysisRequest, LlmFileAnalysisRequest, ServerState, StateConfig,
    };
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let outside_path = outside.path().canonicalize().unwrap();
    let cache = TempDir::new().unwrap();
    let state = std::sync::Arc::new(ServerState::new(StateConfig {
        cache_dir: cache.path().to_path_buf(),
        allow_roots: vec![root_path.clone()],
        ..StateConfig::default()
    }));
    let server = FileScannerMcp::with_state(std::sync::Arc::clone(&state));
    let client = rooted_client(&root_path).await;

    let secret = write(&outside_path, "secret.bin", b"SECRET_BYTES and more text\n");
    let inside_file = write(&root_path, "ok.bin", b"inside file with some text\n");
    let link_file = root_path.join("link.bin");
    std::os::unix::fs::symlink(&secret, &link_file).unwrap();

    for target in [&secret, &link_file] {
        let raw = target.to_string_lossy().into_owned();

        let request: LlmFileAnalysisRequest =
            serde_json::from_value(json!({"file_path": raw})).unwrap();
        let library = server
            .llm_analyze_file(request)
            .await
            .err()
            .expect("refused");
        let tool = tool_error_text(&client, "llm_analyze_file", json!({"file_path": raw})).await;
        assert_eq!(library, tool);

        let request: JavaAnalysisRequest =
            serde_json::from_value(json!({"file_path": raw})).unwrap();
        let library = server
            .analyze_java_file(request)
            .await
            .err()
            .expect("refused");
        let tool = tool_error_text(&client, "analyze_java_file", json!({"file_path": raw})).await;
        assert_eq!(library, tool);

        // The hash primitive of the state refuses the same way.
        let library = state.file_sha256(target).await.expect_err("refused");
        let tool = tool_error_text(&client, "analyze_file", json!({"file_path": raw})).await;
        assert_eq!(library, tool);
    }

    // Inside the root both still work (a text file is not a Java file, but
    // the refusal is the Java parser's, not the roots').
    let request: LlmFileAnalysisRequest =
        serde_json::from_value(json!({"file_path": inside_file})).unwrap();
    let digest = server
        .llm_analyze_file(request)
        .await
        .expect("inside works");
    assert_eq!(digest.0.file_size, 27);
    let request: JavaAnalysisRequest =
        serde_json::from_value(json!({"file_path": inside_file})).unwrap();
    if let Err(message) = server.analyze_java_file(request).await {
        assert!(!message.contains("allowed roots"), "{message}");
    }
    assert_eq!(state.file_sha256(&inside_file).await.unwrap().len(), 64);

    // Without roots nothing changes: the outside file is read.
    let open = FileScannerMcp::new();
    let request: LlmFileAnalysisRequest =
        serde_json::from_value(json!({"file_path": secret})).unwrap();
    assert!(open.llm_analyze_file(request).await.is_ok());
    let unrooted = ServerState::new(StateConfig {
        cache_dir: cache.path().to_path_buf(),
        ..StateConfig::default()
    });
    assert_eq!(unrooted.file_sha256(&secret).await.unwrap().len(), 64);
    client.cancel().await.unwrap();
}
