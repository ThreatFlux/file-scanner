use file_scanner::mcp_server::{FileAnalysisRequest, FileScannerMcp, LlmFileAnalysisRequest};
use rmcp::ServerHandler;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

async fn create_test_server() -> FileScannerMcp {
    FileScannerMcp
}

fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

#[tokio::test]
async fn test_analyze_file_metadata_only() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let test_file = create_test_file(&temp_dir, "test.txt", b"Hello, World!");

    let params = FileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };

    let result = server.analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper

    // Check metadata is present since we requested it
    assert!(response.metadata.is_some());
    let metadata = response.metadata.unwrap();
    assert_eq!(metadata.file_size, 13);
}

#[tokio::test]
async fn test_analyze_file_with_hashes() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let test_file = create_test_file(&temp_dir, "test.bin", b"Test content");

    let params = FileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };

    let result = server.analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper
    assert!(response.hashes.is_some());
    let hashes = response.hashes.unwrap();
    assert!(!hashes.md5.is_empty());
    assert!(!hashes.sha256.is_empty());
    assert!(!hashes.sha512.is_empty());
    assert!(!hashes.blake3.is_empty());
}

#[tokio::test]
async fn test_analyze_file_with_strings() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let content = b"Hello World\x00\x01\x02This is a test string\x00More text";
    let test_file = create_test_file(&temp_dir, "strings.bin", content);

    let params = FileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: None,
        hashes: None,
        strings: Some(true),
        min_string_length: Some(5),
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };

    let result = server.analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper
    assert!(response.strings.is_some());
    let strings = response.strings.unwrap();
    assert!(!strings.is_empty()); // Should contain some extracted strings
}

#[tokio::test]
async fn test_analyze_file_with_hex_dump() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();
    let test_file = create_test_file(&temp_dir, "hex.bin", b"ABCDEFGHIJKLMNOP");

    let params = FileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: None,
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: Some(true),
        hex_dump_size: Some(8),
        hex_dump_offset: Some(4),
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };

    let result = server.analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper
    assert!(response.hex_dump.is_some());
    let hex_dump = response.hex_dump.unwrap();
    // Check that hex dump contains the expected content starting at offset 4 (EFGH)
    assert!(hex_dump.contains("45 46 47 48")); // EFGH in hex
}

#[tokio::test]
async fn test_analyze_file_nonexistent() {
    let server = create_test_server().await;

    let params = FileAnalysisRequest {
        file_path: "/nonexistent/file/path".to_string(),
        metadata: Some(true),
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };

    let result = server.analyze_file(params).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_llm_analyze_file() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();

    // Create a test file with various content
    let mut content = Vec::new();
    content.extend_from_slice(b"MZ"); // PE header
    content.extend_from_slice(&[0x90; 60]); // Padding
    content.extend_from_slice(b"This is a test string");
    content.extend_from_slice(&[0x00; 10]);
    content.extend_from_slice(b"CreateProcess");
    content.extend_from_slice(&[0x00; 10]);
    content.extend_from_slice(b"kernel32.dll");

    let test_file = create_test_file(&temp_dir, "malware_test.exe", &content);

    let params = LlmFileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        token_limit: Some(10000),
        min_string_length: Some(4),
        max_strings: Some(20),
        max_imports: Some(10),
        max_opcodes: Some(5),
        hex_pattern_size: Some(16),
        suggest_yara_rule: Some(true),
    };

    let result = server.llm_analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper
    assert!(!response.md5.is_empty());
    assert!(response.file_size > 0);
    assert!(!response.key_strings.is_empty());
    assert!(!response.hex_patterns.is_empty());

    // Check if YARA rule suggestion is included
    if let Some(yara_rule) = &response.yara_rule_suggestion {
        assert!(yara_rule.contains("rule"));
        assert!(yara_rule.contains("strings:"));
        assert!(yara_rule.contains("condition:"));
    }
}

#[tokio::test]
async fn test_llm_analyze_file_token_limit() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();

    // Create a large file with many strings
    let mut content = Vec::new();
    for i in 0..1000 {
        content.extend_from_slice(format!("String number {}\x00", i).as_bytes());
    }

    let test_file = create_test_file(&temp_dir, "large_file.bin", &content);

    let params = LlmFileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        token_limit: Some(1000), // Very small limit
        min_string_length: Some(4),
        max_strings: Some(10), // Limit strings
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: Some(false),
    };

    let result = server.llm_analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper
    let response_str = serde_json::to_string(&response).unwrap();
    assert!(response_str.len() <= 1500); // Allow some overhead

    // Check that strings are limited
    assert!(response.key_strings.len() <= 10);
}

#[tokio::test]
async fn test_mcp_tool_registration() {
    let server = create_test_server().await;

    // This test checks that the server can be instantiated and has the expected structure
    // Test the server info to verify it's properly configured
    let info = server.get_info();
    assert_eq!(info.server_info.name, "file-scanner");
    assert_eq!(info.server_info.version, "0.1.0");
    assert!(info.instructions.is_some());
    assert!(info.capabilities.tools.is_some());
}

#[tokio::test]
async fn test_analyze_file_all_options() {
    let server = create_test_server().await;
    let temp_dir = TempDir::new().unwrap();

    // Create an ELF-like file
    let mut content = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    content.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]); // 64-bit, little endian
    content.extend_from_slice(&[0x00; 100]); // Padding
    content.extend_from_slice(b"Test string in ELF");

    let test_file = create_test_file(&temp_dir, "test.elf", &content);

    let params = FileAnalysisRequest {
        file_path: test_file.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: Some(true),
        min_string_length: Some(4),
        hex_dump: Some(true),
        hex_dump_size: Some(32),
        hex_dump_offset: Some(0),
        binary_info: Some(true),
        signatures: Some(true),
        symbols: Some(true),
        control_flow: Some(true),
        vulnerabilities: Some(true),
        code_quality: Some(true),
        dependencies: Some(true),
        entropy: Some(true),
        disassembly: Some(true),
        threats: Some(true),
        behavioral: Some(true),
        yara_indicators: Some(true),
    };

    let result = server.analyze_file(params).await;
    assert!(result.is_ok());

    let response = result.unwrap().0; // Access the inner value from Json wrapper

    // Check all requested fields are present
    assert_eq!(response.file_path, test_file.to_str().unwrap());
    assert!(response.metadata.is_some());
    assert!(response.hashes.is_some());
    assert!(response.strings.is_some());
    assert!(response.hex_dump.is_some());
    assert!(response.binary_info.is_some());

    // Binary info should detect ELF
    if let Some(binary_info) = &response.binary_info {
        assert_eq!(binary_info.format, "ELF");
    }
}

#[test]
fn test_analyze_file_params_defaults() {
    let params = FileAnalysisRequest {
        file_path: "/test/path".to_string(),
        metadata: None,
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: None,
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: None,
        signatures: None,
        symbols: None,
        control_flow: None,
        vulnerabilities: None,
        code_quality: None,
        dependencies: None,
        entropy: None,
        disassembly: None,
        threats: None,
        behavioral: None,
        yara_indicators: None,
    };

    // All options should be None by default
    assert!(params.metadata.is_none());
    assert!(params.hashes.is_none());
    assert!(params.strings.is_none());
}

#[test]
fn test_llm_analyze_file_params_defaults() {
    let params = LlmFileAnalysisRequest {
        file_path: "/test/path".to_string(),
        token_limit: None,
        min_string_length: None,
        max_strings: None,
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: None,
    };

    // Check that defaults will be applied in the implementation
    assert!(params.token_limit.is_none());
    assert!(params.min_string_length.is_none());
    assert!(params.max_strings.is_none());
}
