use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("file-scanner"))
        .stdout(predicate::str::contains("analyze-npm"))
        .stdout(predicate::str::contains("analyze-python"));
}

#[test]
fn test_cli_version() {
    // The CLI doesn't have a --version flag, skip this test
    // or test with --help which shows the binary name
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("file-scanner"));
}

#[test]
fn test_cli_basic_file_scan() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "Hello, World!")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("file_name"))
        .stdout(predicate::str::contains("test.txt"))
        .stdout(predicate::str::contains("file_size"));

    Ok(())
}

#[test]
fn test_cli_json_format() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "test content")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"file_name\":\"test.txt\""));

    Ok(())
}

#[test]
fn test_cli_yaml_format() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "test content")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--format")
        .arg("yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("file_name: test.txt"));

    Ok(())
}

#[test]
fn test_cli_with_strings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(
        &test_file,
        "Hello World\nThis is a test string\nAnother line here",
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--strings")
        .assert()
        .success()
        .stdout(predicate::str::contains("extracted_strings"));

    Ok(())
}

#[test]
fn test_cli_with_hex_dump() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.bin");
    fs::write(&test_file, b"ABCDEFGHIJKLMNOP")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--hex-dump")
        .assert()
        .success()
        .stdout(predicate::str::contains("hex_dump"))
        .stdout(predicate::str::contains("41 42 43 44")); // ABCD in hex

    Ok(())
}

#[test]
fn test_cli_npm_analysis_with_package_json() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let package_json = temp_dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
        "name": "test-package",
        "version": "1.0.0",
        "description": "Test package for CLI testing",
        "dependencies": {
            "express": "^4.18.0"
        }
    }"#,
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd.arg("analyze-npm").arg(&package_json).assert().success();
    let analysis: serde_json::Value = serde_json::from_slice(&assertion.get_output().stdout)?;
    assert_eq!(analysis["package_info"]["name"], "test-package");
    assert_eq!(analysis["package_info"]["version"], "1.0.0");
    assert!(analysis.get("security_analysis").is_some());

    Ok(())
}

#[test]
fn test_cli_npm_analysis_with_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let package_json = temp_dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
        "name": "dir-package",
        "version": "2.0.0",
        "license": "MIT"
    }"#,
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd
        .arg("analyze-npm")
        .arg(temp_dir.path())
        .assert()
        .success();
    let analysis: serde_json::Value = serde_json::from_slice(&assertion.get_output().stdout)?;
    assert_eq!(analysis["package_info"]["name"], "dir-package");
    assert_eq!(analysis["package_info"]["version"], "2.0.0");
    assert_eq!(analysis["package_info"]["license"], "MIT");

    Ok(())
}

#[test]
fn test_cli_python_analysis_with_setup_py() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let setup_py = temp_dir.path().join("setup.py");
    fs::write(
        &setup_py,
        r#"
from setuptools import setup

setup(
    name="test-python-package",
    version="1.0.0",
    author="Test Author",
    install_requires=["requests>=2.25.0"],
)
"#,
    )?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd
        .arg("analyze-python")
        .arg(temp_dir.path())
        .assert()
        .success();
    let analysis: serde_json::Value = serde_json::from_slice(&assertion.get_output().stdout)?;
    assert_eq!(analysis["package_info"]["name"], "test-python-package");
    assert_eq!(analysis["package_info"]["version"], "1.0.0");
    assert!(analysis.get("setup_analysis").is_some());

    Ok(())
}

#[test]
fn test_cli_combined_options() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "Test content with strings")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--strings")
        .arg("--hex-dump")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("extracted_strings"))
        .stdout(predicate::str::contains("hex_dump"));

    Ok(())
}

#[test]
fn test_cli_nonexistent_file() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg("/nonexistent/file.txt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_cli_no_arguments() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_cli_mcp_stdio_command() {
    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 17,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "file-scanner-test", "version": "1.0" }
        }
    });
    let cache_home = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd
        .arg("mcp-stdio")
        .env("FILE_SCANNER_CACHE_DIR", cache_home.path())
        .write_stdin(format!("{initialize}\n"))
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .success();
    let response: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stdout).unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 17);
    assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
    assert!(response.get("error").is_none());
}

#[test]
fn test_cli_mcp_stdio_with_no_input_exits_cleanly() {
    // The Docker workflows run exactly this: stdin closed before any message.
    let cache_home = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd
        .arg("mcp-stdio")
        .env("FILE_SCANNER_CACHE_DIR", cache_home.path())
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .success();
    assert!(assertion.get_output().stdout.is_empty());
}

#[test]
fn test_cli_mcp_stdio_stdout_is_only_json_rpc() {
    let lines = [
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": { "name": "file-scanner-test", "version": "1.0" }
            }
        }),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
    ];
    let input: String = lines.iter().map(|line| format!("{line}\n")).collect();
    let cache_home = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd
        .arg("mcp-stdio")
        .env("FILE_SCANNER_CACHE_DIR", cache_home.path())
        .write_stdin(input)
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    let messages: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("every stdout line is JSON"))
        .collect();
    // Three requests, three replies; the notification is not answered.
    assert_eq!(messages.len(), 3, "{stdout}");
    assert!(messages
        .iter()
        .all(|m| m["jsonrpc"] == "2.0" && m["id"].is_number()));
    let list = messages.iter().find(|m| m["id"] == 3).unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    for name in [
        "analyze_file",
        "analyze_java_file",
        "analyze_npm_package",
        "analyze_python_package",
        "llm_analyze_file",
        "yara_scan_file",
    ] {
        assert!(tools.iter().any(|t| t["name"] == name), "missing {name}");
    }
}

#[test]
fn test_cli_mcp_reports_partial_string_indexing() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("bounded-strings.bin");
    let mut content = vec![b'a'; 1_048_577];
    content.extend_from_slice(b"\0malware_token\0");
    fs::write(&test_file, content)?;
    let initialize = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": { "name": "file-scanner-test", "version": "1.0" }
        }
    });
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 23, "method": "tools/call",
        "params": {
            "name": "analyze_file",
            "arguments": { "file_path": test_file, "strings": true }
        }
    });
    let query = serde_json::json!({
        "jsonrpc": "2.0", "id": 24, "method": "tools/call",
        "params": {
            "name": "query_analysis",
            "arguments": { "file_path": test_file, "section": "strings", "filter": "malware_token" }
        }
    });
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let assertion = cmd
        .arg("mcp-stdio")
        // A cache of its own: a disk cache shared with other runs or builds
        // could answer with sections stored by different code.
        .env("FILE_SCANNER_CACHE_DIR", temp_dir.path().join("cache"))
        .write_stdin(format!("{initialize}\n{call}\n{query}\n"))
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "String indexing skipped values outside tracker bounds",
        ));
    let stdout = String::from_utf8(assertion.get_output().stdout.clone())?;
    let response: serde_json::Value = stdout
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|message| message["id"] == 23)
        .expect("a reply to the tools/call");
    assert_ne!(response["result"]["isError"], serde_json::json!(true));
    let analysis: serde_json::Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())?;
    // analyze_file answers a summary of the strings; the counts include both.
    assert!(analysis["strings"]["total_count"].as_u64().unwrap() >= 2);
    // The string past the tracker's bounds is still found, by the filter.
    let reply: serde_json::Value = stdout
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|message| message["id"] == 24)
        .expect("a reply to the query");
    assert_ne!(
        reply["result"]["isError"],
        serde_json::json!(true),
        "{reply}"
    );
    let found: serde_json::Value =
        serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(found["items"][0]["value"], "malware_token", "{found}");
    Ok(())
}

#[test]
fn test_cli_mcp_http_command() {
    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    let cache_home = TempDir::new().unwrap();
    cmd.arg("mcp-http")
        .env("FILE_SCANNER_CACHE_DIR", cache_home.path())
        .arg("--port")
        .arg("0") // Use port 0 to let OS assign
        .timeout(std::time::Duration::from_secs(1))
        .assert()
        .interrupted();
}

#[test]
fn test_cli_custom_string_length() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "ab\nabcde\nabcdefgh\nabcdefghijk")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--strings")
        .arg("--min-string-len")
        .arg("8")
        .arg("--format")
        .arg("json")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_cli_hex_dump_with_size() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.bin");
    fs::write(&test_file, vec![0u8; 1024])?; // 1KB of zeros

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--hex-dump")
        .arg("--hex-dump-size")
        .arg("64")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"total_bytes\":1024"));

    Ok(())
}

#[test]
fn test_cli_hex_dump_with_offset() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.bin");
    fs::write(&test_file, b"HEADER_DATA_MIDDLE_DATA_FOOTER")?;

    let mut cmd = Command::cargo_bin("file-scanner").unwrap();
    cmd.arg(test_file.to_str().unwrap())
        .arg("--hex-dump")
        .arg("--hex-dump-offset")
        .arg("-6") // Last 6 bytes (FOOTER)
        .arg("--hex-dump-size")
        .arg("6")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("FOOTER"));

    Ok(())
}
