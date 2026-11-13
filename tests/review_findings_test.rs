#![allow(clippy::too_many_lines)]

//! Findings of the review of pull request 315: a content hash remembered for a
//! path must not outlive an in-place rewrite, a package source that could not
//! be read must not count as scanned, and the signature answer must depend on
//! the detached signature files of the path it was asked for.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use file_scanner::{
    mcp_server::FileScannerMcp,
    npm_analysis::{analyze_npm_package, RiskLevel as NpmRisk},
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

const SECRET_LINE: &str = "TOPSECRET_LINE_42";
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
