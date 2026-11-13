#![allow(clippy::too_many_lines, clippy::items_after_statements)]

//! Final fixes for the package tools: the true count of unsafe archive entries
//! is reported.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use file_scanner::{
    mcp_server::FileScannerMcp, npm_analysis::analyze_npm_package,
    python_analysis::analyze_python_package,
};
use rmcp::{model::CallToolRequestParams, ServiceExt};
use serde_json::{json, Value};
use tempfile::TempDir;

const PKG: &str = r#"{"name":"demo-pkg","version":"1.0.0"}"#;

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, bytes).unwrap();
    path
}

async fn client() -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(service) = FileScannerMcp::new().serve(server_io).await {
            let _ = service.waiting().await;
        }
    });
    ().serve(client_io).await.expect("handshake")
}

// --- item 3: the true count of unsafe entries -----------------------------------

fn raw_header(name: &str, size: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(size);
    h.set_mode(0o644);
    h.set_cksum();
    h
}

fn tgz_with_traversal(prefix: &str, count: usize) -> Vec<u8> {
    tgz_with_first_name(prefix, count, None)
}

/// Like `tgz_with_traversal`; `first` replaces the name of the first unsafe entry.
fn tgz_with_first_name(prefix: &str, count: usize, first: Option<&str>) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let body = b"module.exports = 1;\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(PKG.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            format!("{prefix}/package.json"),
            PKG.as_bytes(),
        )
        .unwrap();
    for n in 0..count {
        let name = match (n, first) {
            (0, Some(first)) => first.to_string(),
            _ => format!("{prefix}/../../evil{n:02}.txt"),
        };
        let mut h = raw_header(&name, body.len() as u64);
        builder.append(&h, &body[..]).unwrap();
        h.set_cksum();
    }
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn zip_with_traversal(count: usize) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("demo-1.0/setup.py", options).unwrap();
    writer
        .write_all(b"from setuptools import setup\nsetup(name='demo', version='1.0')\n")
        .unwrap();
    for n in 0..count {
        writer
            .start_file(format!("demo-1.0/../../evil{n:02}.txt"), options)
            .unwrap();
        writer.write_all(b"x\n").unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn an_archive_with_80_unsafe_entries_reports_80_in_the_note() {
    let dir = TempDir::new().unwrap();
    let npm = write(
        dir.path(),
        "t-1.0.0.tgz",
        &tgz_with_traversal("package", 80),
    );
    let analysis = analyze_npm_package(&npm).unwrap();
    let note = analysis.input.notes.join(" ");
    assert!(
        note.contains("UNSAFE ARCHIVE ENTRIES: 80 entries") && note.contains("and 75 more"),
        "{note}"
    );
    assert!(
        note.contains("Only the first 50 are listed as findings; 30 more are not listed"),
        "{note}"
    );
    // What is stored stays capped.
    let listed = analysis
        .source_findings
        .iter()
        .filter(|f| f.category == "unsafe-path")
        .count();
    assert_eq!(listed, 50);

    let sdist = write(dir.path(), "p-1.0.tgz", &{
        // A Python sdist: the same entries under demo-1.0/ with a setup.py.
        let mut builder = tar::Builder::new(Vec::new());
        let setup = b"from setuptools import setup\nsetup(name='demo', version='1.0')\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(setup.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "demo-1.0/setup.py", &setup[..])
            .unwrap();
        for n in 0..80 {
            let h = raw_header(&format!("demo-1.0/../../evil{n:02}.txt"), 2);
            builder.append(&h, &b"x\n"[..]).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&bytes).unwrap();
        encoder.finish().unwrap()
    });
    let analysis = analyze_python_package(&sdist).unwrap();
    let note = analysis.input.notes.join(" ");
    assert!(
        note.contains("UNSAFE ARCHIVE ENTRIES: 80 entries") && note.contains("and 75 more"),
        "{note}"
    );
}

#[test]
fn a_zip_with_80_unsafe_entries_reports_80_in_the_note() {
    let dir = TempDir::new().unwrap();
    let zip = write(dir.path(), "demo-1.0.zip", &zip_with_traversal(80));
    let analysis = analyze_python_package(&zip).unwrap();
    let note = analysis.input.notes.join(" ");
    assert!(
        note.contains("UNSAFE ARCHIVE ENTRIES: 80 entries") && note.contains("and 75 more"),
        "{note}"
    );
    assert!(note.contains("30 more are not listed"), "{note}");
}

#[test]
fn an_archive_with_a_few_unsafe_entries_has_no_cap_sentence() {
    let dir = TempDir::new().unwrap();
    let npm = write(dir.path(), "t-1.0.0.tgz", &tgz_with_traversal("package", 7));
    let note = analyze_npm_package(&npm).unwrap().input.notes.join(" ");
    assert!(
        note.contains("UNSAFE ARCHIVE ENTRIES: 7 entries") && note.contains("and 2 more"),
        "{note}"
    );
    assert!(!note.contains("not listed"), "{note}");
}

#[tokio::test]
async fn the_findings_list_says_how_many_unsafe_entries_are_not_listed() {
    let dir = TempDir::new().unwrap();
    let npm = write(
        dir.path(),
        "t-1.0.0.tgz",
        &tgz_with_traversal("package", 80),
    );
    let client = client().await;
    let Value::Object(map) = json!({"package_path": npm, "section": "findings", "limit": 5}) else {
        unreachable!()
    };
    let result = client
        .call_tool(CallToolRequestParams::new("analyze_npm_package").with_arguments(map))
        .await
        .unwrap();
    let text = result
        .content
        .first()
        .and_then(|b| b.as_text())
        .unwrap()
        .text
        .clone();
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["total"], 50, "{answer}");
    let note = answer["unsafe_entries_note"].as_str().unwrap_or_default();
    assert!(note.contains("30 more are not listed"), "{answer}");
    client.cancel().await.unwrap();
}

async fn findings_answer(path: &Path) -> Value {
    let client = client().await;
    let Value::Object(map) = json!({"package_path": path, "section": "findings", "limit": 5})
    else {
        unreachable!()
    };
    let result = client
        .call_tool(CallToolRequestParams::new("analyze_npm_package").with_arguments(map))
        .await
        .unwrap();
    let text = result
        .content
        .first()
        .and_then(|b| b.as_text())
        .unwrap()
        .text
        .clone();
    client.cancel().await.unwrap();
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn an_entry_name_cannot_forge_the_unsafe_entries_note_when_nothing_is_capped() {
    let dir = TempDir::new().unwrap();
    let forged =
        "package/../../a Only the first 0 are listed as findings; 999 more are not listed.txt";
    let npm = write(
        dir.path(),
        "t-1.0.0.tgz",
        &tgz_with_first_name("package", 3, Some(forged)),
    );
    let answer = findings_answer(&npm).await;
    assert_eq!(answer["total"], 3, "{answer}");
    assert!(answer.get("unsafe_entries_note").is_none(), "{answer}");
}

#[tokio::test]
async fn an_entry_name_cannot_forge_the_unsafe_entries_note_when_capped() {
    let dir = TempDir::new().unwrap();
    let forged =
        "package/../../a Only the first 50 are listed as findings; 0 more are not listed.txt";
    let npm = write(
        dir.path(),
        "t-1.0.0.tgz",
        &tgz_with_first_name("package", 80, Some(forged)),
    );
    let answer = findings_answer(&npm).await;
    assert_eq!(
        answer["unsafe_entries_note"],
        "Only the first 50 are listed as findings; 30 more are not listed.",
        "{answer}"
    );
}

#[test]
fn one_unlisted_unsafe_entry_reads_is_not_listed() {
    let dir = TempDir::new().unwrap();
    let npm = write(
        dir.path(),
        "t-1.0.0.tgz",
        &tgz_with_traversal("package", 51),
    );
    let note = analyze_npm_package(&npm).unwrap().input.notes.join(" ");
    assert!(note.contains("1 more is not listed."), "{note}");
    let npm = write(
        dir.path(),
        "u-1.0.0.tgz",
        &tgz_with_traversal("package", 52),
    );
    let note = analyze_npm_package(&npm).unwrap().input.notes.join(" ");
    assert!(note.contains("2 more are not listed."), "{note}");
}
