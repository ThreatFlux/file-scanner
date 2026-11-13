//! `inspect_archive` and archive analysis, driven through the real MCP service.

use std::io::Write;

use file_scanner::mcp_server::FileScannerMcp;
use rmcp::{model::CallToolRequestParams, ServiceExt};
use serde_json::{json, Value};

async fn call_all(tool: &str, calls: Vec<Value>) -> Vec<(bool, String)> {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(service) = FileScannerMcp::new().serve(server_io).await {
            let _ = service.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("handshake");
    let mut out = Vec::new();
    for args in calls {
        let result = client
            .call_tool(
                CallToolRequestParams::new(tool.to_string())
                    .with_arguments(args.as_object().unwrap().clone()),
            )
            .await
            .expect("answered");
        let text = result.content[0].as_text().unwrap().text.clone();
        out.push((result.is_error == Some(true), text));
    }
    client.cancel().await.unwrap();
    out
}

fn ok(result: &(bool, String)) -> Value {
    assert!(!result.0, "tool error: {}", result.1);
    serde_json::from_str(&result.1).expect("compact JSON")
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        for (name, data) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    buf.into_inner()
}

#[tokio::test]
async fn inspect_archive_is_listed_and_pages_a_zip() {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..120).map(|i| format!("data/file{i:03}.txt")).collect();
    let mut entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
    entries.push(("../../etc/cron.d/evil", b"x"));
    entries.push(("tools/setup.exe", b"MZ"));
    let path = dir.path().join("sample.zip");
    std::fs::write(&path, zip_bytes(&entries)).unwrap();
    let p = path.to_str().unwrap();

    let results = call_all(
        "inspect_archive",
        vec![
            json!({"file_path": p}),
            json!({"file_path": p, "offset": 50, "limit": 50}),
            json!({"file_path": p, "filter": "FILE00"}),
            json!({"file_path": p, "risky_only": true}),
        ],
    )
    .await;

    let first = ok(&results[0]);
    assert_eq!(first["cache"], "miss");
    assert_eq!(first["summary"]["entries"], 122);
    assert_eq!(first["summary"]["risk"], "critical");
    assert_eq!(first["summary"]["unsafe_paths"], 1);
    assert_eq!(first["entries"]["returned"], 50);
    assert_eq!(first["entries"]["total"], 122);
    assert_eq!(first["entries"]["next_offset"], 50);
    let step = &first["next_steps"][0];
    assert_eq!(step["tool"], "inspect_archive");
    assert_eq!(step["arguments"]["offset"], 50);
    assert!(step["gives"].is_string());

    let second = ok(&results[1]);
    assert_eq!(second["cache"], "hit", "paging is served from the cache");
    assert_eq!(second["entries"]["items"][0]["path"], "data/file050.txt");

    let filtered = ok(&results[2]);
    assert_eq!(filtered["entries"]["total"], 10);

    let risky = ok(&results[3]);
    let paths: Vec<&str> = risky["entries"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["../../etc/cron.d/evil", "tools/setup.exe"]);
    assert!(risky["entries"]["items"][0]["risks"][0]
        .as_str()
        .unwrap()
        .starts_with("PathTraversal (critical)"));
}

#[tokio::test]
async fn inspect_archive_reads_tar_gz_and_names_its_limits() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o4755);
    builder
        .append_data(&mut header, "bin/tool", &b"data"[..])
        .unwrap();
    let tar = builder.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    let gz_path = dir.path().join("release.tgz");
    std::fs::write(&gz_path, gz.finish().unwrap()).unwrap();

    // RAR 4 with a header that is not listable, and a 7z with a compressed header.
    let rar_path = dir.path().join("locked.rar");
    let mut rar = b"Rar!\x1a\x07\x00".to_vec();
    rar.extend([0, 0, 0x73, 0x80, 0, 13, 0]);
    rar.extend([0u8; 6]);
    std::fs::write(&rar_path, rar).unwrap();
    let pdf_path = dir.path().join("doc.pdf");
    std::fs::write(&pdf_path, b"%PDF-1.4\n").unwrap();

    let results = call_all(
        "inspect_archive",
        vec![
            json!({"file_path": gz_path}),
            json!({"file_path": rar_path}),
            json!({"file_path": pdf_path}),
            json!({"file_path": gz_path, "bogus": 1}),
            json!({"file_path": dir.path().join("missing.zip")}),
        ],
    )
    .await;

    let tgz = ok(&results[0]);
    assert_eq!(tgz["summary"]["entries"], 1);
    assert_eq!(tgz["entries"]["items"][0]["path"], "bin/tool");
    assert_eq!(tgz["entries"]["items"][0]["mode"], "4755");
    assert!(tgz["entries"]["items"][0]["risks"][0]
        .as_str()
        .unwrap()
        .starts_with("Setuid"));

    let rar = ok(&results[1]);
    assert!(rar["summary"]["entries"].is_null(), "unknown, not zero");
    assert_eq!(rar["summary"]["listed_entries"], 0);
    assert_eq!(rar["summary"]["encrypted"], true);
    assert!(rar["summary"]["notes"][0]
        .as_str()
        .unwrap()
        .contains("headers are encrypted"));

    assert!(results[2].0, "a PDF is not an archive");
    assert!(
        results[2].1.contains("analyze_document"),
        "{}",
        results[2].1
    );
    assert!(
        results[3].0 && results[3].1.contains("bogus"),
        "{}",
        results[3].1
    );
    assert!(
        results[4].0 && results[4].1.contains("does not exist"),
        "{}",
        results[4].1
    );
}

#[test]
fn zip_checks_use_path_components_and_size_thresholds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("names.zip");
    std::fs::write(
        &path,
        zip_bytes(&[
            ("notes..txt", b"a"),
            ("a/b..c/d.txt", b"a"),
            ("operation/elaborate.txt", b"a"),
        ]),
    )
    .unwrap();
    let analysis = file_scanner::archive_analysis::analyze_zip(&path).unwrap();
    assert!(!analysis.suspicious_indicators.has_path_traversal);
    assert!(!analysis.suspicious_indicators.has_suspicious_names);
    assert!(
        !analysis
            .security_analysis
            .zip_bomb_indicators
            .is_potential_bomb
    );

    // A tiny, highly compressible file is not a bomb; a 20 MiB one at 1000:1 is.
    let path = dir.path().join("zeros.zip");
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("small.bin", options).unwrap();
        zip.write_all(&vec![0u8; 50_000]).unwrap();
        zip.start_file("big.bin", options).unwrap();
        zip.write_all(&vec![0u8; 20 * 1024 * 1024]).unwrap();
        zip.finish().unwrap();
    }
    std::fs::write(&path, buf.into_inner()).unwrap();
    let analysis = file_scanner::archive_analysis::analyze_zip(&path).unwrap();
    let bomb = &analysis.security_analysis.zip_bomb_indicators;
    assert!(bomb.is_potential_bomb);
    assert_eq!(bomb.recursive_entries, ["big.bin"]);
}

/// Offsets of every central-directory header in `zip`.
fn central_headers(zip: &[u8]) -> Vec<usize> {
    (0..zip.len().saturating_sub(4))
        .filter(|&i| &zip[i..i + 4] == b"PK\x01\x02")
        .collect()
}

#[test]
fn encrypted_zip_entries_are_flagged_and_symlink_targets_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.zip");
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let plain = zip::write::SimpleFileOptions::default();
        zip.start_file("a.txt", plain).unwrap();
        zip.write_all(b"a").unwrap();
        zip.start_file("secret.bin", plain).unwrap();
        zip.write_all(b"s").unwrap();
        zip.start_file("suid", plain).unwrap();
        zip.write_all(b"s").unwrap();
        zip.add_symlink("link", "/etc/passwd", plain).unwrap();
        zip.add_symlink("ok.lnk", "a.txt", plain).unwrap();
        zip.finish().unwrap();
    }
    let mut bytes = buf.into_inner();
    let heads = central_headers(&bytes);
    // secret.bin: set the "encrypted" general-purpose flag bit.
    bytes[heads[1] + 8] |= 1;
    // suid: unix mode 0o104755 in the external attributes.
    let attr = (0o104_755u32 << 16).to_le_bytes();
    bytes[heads[2] + 38..heads[2] + 42].copy_from_slice(&attr);
    std::fs::write(&path, &bytes).unwrap();

    let analysis = file_scanner::archive_analysis::analyze_zip(&path).unwrap();
    let by = |name: &str| analysis.entries.iter().find(|e| e.path == name).unwrap();
    assert!(by("secret.bin").is_encrypted);
    assert!(!by("a.txt").is_encrypted);
    assert!(analysis.metadata.has_encryption);
    assert_eq!(by("suid").permissions, Some(0o4755));
    assert!(by("suid")
        .risk_indicators
        .iter()
        .any(|r| r.indicator_type == "Setuid"));
    assert_eq!(by("link").link_target.as_deref(), Some("/etc/passwd"));
    assert!(by("link")
        .risk_indicators
        .iter()
        .any(|r| r.indicator_type == "LinkEscape"));
    assert_eq!(by("ok.lnk").link_target.as_deref(), Some("a.txt"));
    assert!(!by("ok.lnk")
        .risk_indicators
        .iter()
        .any(|r| r.indicator_type == "LinkEscape"));
    // Modes carry permission bits only, not file-type bits.
    assert!(analysis
        .entries
        .iter()
        .all(|e| e.permissions.is_none_or(|m| m <= 0o7777)));
}

/// A stored ZIP whose two entries declare 2^63 bytes each through ZIP64 fields.
fn overflow_zip() -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    let extra = |size: u64| {
        let mut e = 1u16.to_le_bytes().to_vec();
        e.extend(16u16.to_le_bytes());
        e.extend(size.to_le_bytes()); // uncompressed
        e.extend(size.to_le_bytes()); // compressed
        e
    };
    for name in ["a", "b"] {
        offsets.push(out.len() as u32);
        out.extend(b"PK\x03\x04");
        out.extend(45u16.to_le_bytes());
        out.extend([0u8; 2 + 2 + 2]); // flags, method, time
        out.extend(0x21u16.to_le_bytes()); // date
        out.extend(0u32.to_le_bytes()); // crc
        out.extend(u32::MAX.to_le_bytes());
        out.extend(u32::MAX.to_le_bytes());
        out.extend(1u16.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(extra(1 << 63));
    }
    let cd_start = out.len();
    for (name, offset) in ["a", "b"].iter().zip(&offsets) {
        out.extend(b"PK\x01\x02");
        out.extend(0x032du16.to_le_bytes());
        out.extend(45u16.to_le_bytes());
        out.extend([0u8; 2 + 2 + 2]);
        out.extend(0x21u16.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(u32::MAX.to_le_bytes());
        out.extend(u32::MAX.to_le_bytes());
        out.extend(1u16.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        out.extend([0u8; 2 + 2 + 2 + 4]);
        out.extend(offset.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(extra(1 << 63));
    }
    let cd_size = (out.len() - cd_start) as u32;
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    out.extend(2u16.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(cd_size.to_le_bytes());
    out.extend((cd_start as u32).to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

#[test]
fn entry_sizes_that_overflow_do_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overflow.zip");
    std::fs::write(&path, overflow_zip()).unwrap();
    let analysis = file_scanner::archive_analysis::analyze_zip(&path).unwrap();
    assert_eq!(analysis.metadata.total_entries, 2);
    assert_eq!(analysis.metadata.total_size_uncompressed, u64::MAX);
    assert!((0.0..=1.0).contains(&analysis.metadata.compression_ratio));
}

#[test]
fn a_single_inner_zip_is_not_a_bomb_and_ratios_are_never_negative() {
    let dir = tempfile::tempdir().unwrap();
    let inner = zip_bytes(&[("x.txt", b"hello")]);
    let zip = dir.path().join("one_inner.zip");
    std::fs::write(&zip, zip_bytes(&[("inner.zip", &inner)])).unwrap();
    let analysis = file_scanner::archive_analysis::analyze_zip(&zip).unwrap();
    let bomb = &analysis.security_analysis.zip_bomb_indicators;
    assert!(!bomb.is_potential_bomb && !bomb.quine_detection);
    assert_eq!(analysis.nested_archives.len(), 1);
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        file_scanner::archive_analysis::RiskLevel::Low
    ));
    assert!(analysis.entries.iter().all(|e| e.compression_ratio >= 0.0));
    assert!(analysis.metadata.compression_ratio >= 0.0);

    let mut b = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(inner.len() as u64);
    header.set_mode(0o644);
    b.append_data(&mut header, "inner.zip", &inner[..]).unwrap();
    let tar_path = dir.path().join("one_inner.tar");
    std::fs::write(&tar_path, b.into_inner().unwrap()).unwrap();
    let analysis = file_scanner::tar_analysis::analyze_tar(&tar_path).unwrap();
    assert!(
        !analysis
            .security_analysis
            .zip_bomb_indicators
            .is_potential_bomb
    );
}

#[test]
fn a_long_archive_comment_is_capped() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = zip_bytes(&[("a.txt", b"a")]);
    let len = bytes.len();
    bytes[len - 2..].copy_from_slice(&60_000u16.to_le_bytes());
    bytes.extend(vec![b'c'; 60_000]);
    let path = dir.path().join("comment.zip");
    std::fs::write(&path, &bytes).unwrap();
    let analysis = file_scanner::archive_analysis::analyze_zip(&path).unwrap();
    let comment = analysis.metadata.comment.unwrap();
    assert!(comment.len() < 600, "{}", comment.len());
    assert!(comment.contains("60000 bytes in all"));
}

#[tokio::test]
async fn results_do_not_depend_on_the_file_name_and_unknown_counts_are_null() {
    let dir = tempfile::tempdir().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(b"just some text\n").unwrap();
    let gz = gz.finish().unwrap();
    let (a, b) = (dir.path().join("c1.gz"), dir.path().join("c1.tar.gz"));
    std::fs::write(&a, &gz).unwrap();
    std::fs::write(&b, &gz).unwrap();
    let bz = dir.path().join("a.tar.bz2");
    std::fs::write(&bz, b"BZh91AY&SY....").unwrap();
    let results = call_all(
        "inspect_archive",
        vec![
            json!({"file_path": b.to_str().unwrap()}),
            json!({"file_path": a.to_str().unwrap()}),
            json!({"file_path": bz.to_str().unwrap()}),
        ],
    )
    .await;
    // Same bytes, same answer, in either order, and no raw bytes in the error.
    assert!(results[0].0 && results[1].0, "{:?}", results);
    assert!(!results[0].1.contains("just some text"));
    let summary = &ok(&results[2])["summary"];
    assert!(summary["entries"].is_null(), "{summary}");
    assert!(summary["uncompressed_bytes"].is_null());
    assert!(summary["compression_ratio"].is_null());
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(bytes).unwrap();
    gz.finish().unwrap()
}

/// A tar.gz of symlinks with 200-character names and 4,000-character targets
/// uses a bounded amount of text once the archive-wide name budget is spent,
/// paging and filtering still work from the cache, and the long traversal
/// examples are short.
#[tokio::test]
async fn long_names_share_an_archive_wide_budget_and_examples_stay_short() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    for i in 0..2500 {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        let name = format!("{i:05}{}", "n".repeat(200));
        let target = format!("{}{}", "../".repeat(1300), i);
        builder.append_link(&mut header, name, target).unwrap();
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    builder
        .append_data(&mut header, "x".repeat(4000) + "/../../etc/evil", &b"x"[..])
        .unwrap();
    let path = dir.path().join("names.tar.gz");
    std::fs::write(&path, gz(&builder.into_inner().unwrap())).unwrap();
    let p = path.to_str().unwrap();

    let results = call_all(
        "inspect_archive",
        vec![
            json!({"file_path": p, "offset": 2490, "limit": 10}),
            json!({"file_path": p, "filter": "02499", "limit": 5}),
            json!({"file_path": p, "risky_only": true, "limit": 1}),
        ],
    )
    .await;
    let first = ok(&results[0]);
    let notes = first["summary"]["notes"].to_string();
    assert!(notes.contains("very long"), "{notes}");
    let rows = first["entries"]["items"].as_array().unwrap();
    assert!(!rows.is_empty());
    for row in rows {
        // The names near the end were cut to 255 characters plus the marker.
        let len = row["path"].as_str().unwrap().len();
        assert!(len < 300, "{len}");
        let target = row["link_target"].as_str().unwrap_or_default().len();
        assert!(target < 300, "{target}");
    }
    for example in first["summary"]["unsafe_path_examples"].as_array().unwrap() {
        assert!(example["entry_path"].as_str().unwrap().len() < 300);
        assert!(example["resolved_path"].as_str().unwrap().len() < 300);
    }
    let filtered = ok(&results[1]);
    assert_eq!(filtered["cache"], "hit");
    assert_eq!(filtered["entries"]["total"], 1);
    let risky = ok(&results[2]);
    assert!(risky["entries"]["total"].as_u64().unwrap() >= 1);
    assert!(risky["entries"]["items"][0].get("risky").is_none());
}
