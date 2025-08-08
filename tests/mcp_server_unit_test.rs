use file_scanner::mcp_server::{FileAnalysisRequest, FileScannerMcp, LlmFileAnalysisRequest};
use rmcp::ServerHandler;
use serde_json::Value;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn create_test_file(content: &[u8]) -> anyhow::Result<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("test_file");
    let mut file = fs::File::create(&file_path)?;
    file.write_all(content)?;
    Ok((temp_dir, file_path))
}

#[test]
fn test_file_scanner_mcp_creation() {
    let mcp = FileScannerMcp::new();

    // Test that we can create the MCP server
    let info = mcp.get_info();
    assert_eq!(info.server_info.name, "file-scanner");
    assert_eq!(info.server_info.version, "0.1.0");
    assert!(info.instructions.is_some());
    assert!(info.capabilities.tools.is_some());
}

#[test]
fn test_mcp_server_info_structure() {
    let mcp = FileScannerMcp::new();
    let info = mcp.get_info();

    // Verify server info fields
    assert!(!info.server_info.name.is_empty());
    assert!(!info.server_info.version.is_empty());

    // Check instructions
    if let Some(instructions) = &info.instructions {
        assert!(!instructions.is_empty());
        assert!(
            instructions.contains("file")
                || instructions.contains("analysis")
                || instructions.contains("scanner")
        );
    }

    // Check capabilities
    assert!(info.capabilities.tools.is_some());
}

#[tokio::test]
async fn test_file_analysis_request_validation() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"test content").unwrap();

    // Test valid request
    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_analysis_request_invalid_path() {
    let mcp = FileScannerMcp::new();

    let request = FileAnalysisRequest {
        all: None,
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_llm_file_analysis_request_validation() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"test content for LLM analysis").unwrap();

    let request = LlmFileAnalysisRequest {
        file_path: file_path.to_str().unwrap().to_string(),
        token_limit: Some(1000),
        min_string_length: Some(4),
        max_strings: Some(10),
        max_imports: Some(5),
        max_opcodes: Some(3),
        hex_pattern_size: Some(16),
        suggest_yara_rule: Some(true),
    };

    let result = mcp.llm_analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(!response.md5.is_empty());
    assert!(response.file_size > 0);
}

#[tokio::test]
async fn test_llm_file_analysis_with_defaults() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"default analysis test").unwrap();

    let request = LlmFileAnalysisRequest {
        file_path: file_path.to_str().unwrap().to_string(),
        token_limit: None,
        min_string_length: None,
        max_strings: None,
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: None,
    };

    let result = mcp.llm_analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(!response.md5.is_empty());
    assert!(response.file_size > 0);
    // Default should suggest YARA rule
    assert!(response.yara_rule_suggestion.is_some());
}

#[tokio::test]
async fn test_file_analysis_metadata_only() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"metadata test content").unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.metadata.is_some());
    assert!(response.hashes.is_none());
    assert!(response.strings.is_none());
    assert!(response.hex_dump.is_none());
    assert!(response.binary_info.is_none());
}

#[tokio::test]
async fn test_file_analysis_hashes_only() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"hash test content").unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: None,
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.metadata.is_none());
    assert!(response.hashes.is_some());

    let hashes = response.hashes.unwrap();
    assert!(!hashes.md5.is_empty());
    assert!(!hashes.sha256.is_empty());
    assert!(!hashes.sha512.is_empty());
    assert!(!hashes.blake3.is_empty());
}

#[tokio::test]
async fn test_file_analysis_strings_with_parameters() {
    let mcp = FileScannerMcp::new();
    let content = b"Short\x00LongerString\x00VeryLongStringForTesting\x00";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: None,
        hashes: None,
        strings: Some(true),
        min_string_length: Some(10), // Filter short strings
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.strings.is_some());

    let strings = response.strings.unwrap();
    // Should not contain "Short" due to min_string_length filter
    assert!(!strings.contains(&"Short".to_string()));
    // Should contain longer strings
    assert!(strings.iter().any(|s| s.contains("LongerString")));
}

#[tokio::test]
async fn test_file_analysis_hex_dump_with_parameters() {
    let mcp = FileScannerMcp::new();
    let content = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: None,
        hashes: None,
        strings: None,
        min_string_length: None,
        hex_dump: Some(true),
        hex_dump_size: Some(10),
        hex_dump_offset: Some(5),
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.hex_dump.is_some());

    let hex_dump = response.hex_dump.unwrap();
    // Should contain hex dump text with offset information
    assert!(hex_dump.contains("offset"));
    // Should contain the content starting from offset 5 ('56789')
    assert!(hex_dump.contains("56789"));
}

#[tokio::test]
async fn test_file_analysis_request_all_options_false() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"test").unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: Some(false),
        hashes: Some(false),
        strings: Some(false),
        min_string_length: None,
        hex_dump: Some(false),
        hex_dump_size: None,
        hex_dump_offset: None,
        binary_info: Some(false),
        signatures: Some(false),
        symbols: Some(false),
        control_flow: Some(false),
        vulnerabilities: Some(false),
        code_quality: Some(false),
        dependencies: Some(false),
        entropy: Some(false),
        disassembly: Some(false),
        threats: Some(false),
        behavioral: Some(false),
        yara_indicators: Some(false),
    };

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.metadata.is_none());
    assert!(response.hashes.is_none());
    assert!(response.strings.is_none());
    assert!(response.hex_dump.is_none());
    assert!(response.binary_info.is_none());
}

#[tokio::test]
async fn test_file_analysis_binary_file() {
    let mcp = FileScannerMcp::new();

    // Create a minimal ELF-like file
    let mut content = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    content.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]); // 64-bit, little endian
    content.extend_from_slice(&[0x00; 100]); // Padding
    content.extend_from_slice(b"embedded string");

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: Some(true),
        min_string_length: Some(4),
        hex_dump: Some(true),
        hex_dump_size: Some(32),
        hex_dump_offset: Some(0),
        binary_info: Some(true),
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.metadata.is_some());
    assert!(response.hashes.is_some());
    assert!(response.strings.is_some());
    assert!(response.hex_dump.is_some());
    assert!(response.binary_info.is_some());

    // Check that strings were extracted
    let strings = response.strings.unwrap();
    assert!(strings.iter().any(|s| s.contains("embedded")));

    // Check that hex dump starts with ELF magic
    let hex_dump = response.hex_dump.unwrap();
    assert!(hex_dump.contains("7f 45 4c 46"));
}

#[tokio::test]
async fn test_llm_analysis_token_limit_enforcement() {
    let mcp = FileScannerMcp::new();

    // Create a file with many strings
    let mut content = Vec::new();
    for i in 0..1000 {
        content
            .extend_from_slice(format!("String number {} with additional text\x00", i).as_bytes());
    }

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let request = LlmFileAnalysisRequest {
        file_path: file_path.to_str().unwrap().to_string(),
        token_limit: Some(500), // Very small limit
        min_string_length: Some(4),
        max_strings: Some(5), // Limit strings
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: Some(false),
    };

    let result = mcp.llm_analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;

    // Check that token limit is respected (approximately)
    let response_str = serde_json::to_string(&response).unwrap();
    assert!(response_str.len() <= 800); // Allow some overhead

    // Check that strings are limited
    assert!(response.key_strings.len() <= 5);
}

#[test]
fn test_file_analysis_request_structure() {
    let request = FileAnalysisRequest {
        all: None,
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

    // Test serialization/deserialization
    let json = serde_json::to_string(&request).unwrap();
    let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.file_path, request.file_path);
    assert_eq!(deserialized.metadata, request.metadata);
    assert_eq!(deserialized.hashes, request.hashes);
}

#[test]
fn test_llm_file_analysis_request_structure() {
    let request = LlmFileAnalysisRequest {
        file_path: "/test/path".to_string(),
        token_limit: Some(1000),
        min_string_length: Some(6),
        max_strings: Some(20),
        max_imports: Some(10),
        max_opcodes: Some(5),
        hex_pattern_size: Some(32),
        suggest_yara_rule: Some(true),
    };

    // Test serialization/deserialization
    let json = serde_json::to_string(&request).unwrap();
    let deserialized: LlmFileAnalysisRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.file_path, request.file_path);
    assert_eq!(deserialized.token_limit, request.token_limit);
    assert_eq!(deserialized.min_string_length, request.min_string_length);
    assert_eq!(deserialized.max_strings, request.max_strings);
    assert_eq!(deserialized.max_imports, request.max_imports);
    assert_eq!(deserialized.max_opcodes, request.max_opcodes);
    assert_eq!(deserialized.hex_pattern_size, request.hex_pattern_size);
    assert_eq!(deserialized.suggest_yara_rule, request.suggest_yara_rule);
}

#[tokio::test]
async fn test_file_analysis_empty_file() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"").unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: Some(true),
        min_string_length: Some(4),
        hex_dump: Some(true),
        hex_dump_size: Some(100),
        hex_dump_offset: Some(0),
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(response.metadata.is_some());
    assert!(response.hashes.is_some());

    let metadata = response.metadata.unwrap();
    assert_eq!(metadata.file_size, 0);

    // Empty file should still have hashes
    let hashes = response.hashes.unwrap();
    assert!(!hashes.md5.is_empty());

    // Strings should be empty
    if let Some(strings) = response.strings {
        assert!(strings.is_empty());
    }

    // Hex dump should indicate empty file
    if let Some(hex_dump) = response.hex_dump {
        assert!(hex_dump.contains("0 bytes") || hex_dump.is_empty());
    }
}

#[tokio::test]
async fn test_llm_analysis_empty_file() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"").unwrap();

    let request = LlmFileAnalysisRequest {
        file_path: file_path.to_str().unwrap().to_string(),
        token_limit: Some(1000),
        min_string_length: Some(4),
        max_strings: Some(10),
        max_imports: Some(5),
        max_opcodes: Some(3),
        hex_pattern_size: Some(16),
        suggest_yara_rule: Some(true),
    };

    let result = mcp.llm_analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;
    assert!(!response.md5.is_empty());
    assert_eq!(response.file_size, 0);
    assert!(response.key_strings.is_empty());
    assert!(response.hex_patterns.is_empty());
    assert!(response.imports.is_empty());
    assert!(response.opcodes.is_empty());
}

#[tokio::test]
async fn test_file_analysis_permission_error() {
    let mcp = FileScannerMcp::new();

    // Try to analyze a system file that might not be readable
    let request = FileAnalysisRequest {
        all: None,
        file_path: "/root/.ssh/id_rsa".to_string(), // Typically not readable
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

    let result = mcp.analyze_file(request).await;
    // Should handle permission errors gracefully
    assert!(result.is_err());
}

#[tokio::test]
async fn test_file_analysis_response_structure() {
    let mcp = FileScannerMcp::new();
    let (_temp_dir, file_path) = create_test_file(b"response structure test").unwrap();

    let request = FileAnalysisRequest {
        all: None,
        file_path: file_path.to_str().unwrap().to_string(),
        metadata: Some(true),
        hashes: Some(true),
        strings: Some(true),
        min_string_length: Some(4),
        hex_dump: Some(true),
        hex_dump_size: Some(50),
        hex_dump_offset: Some(0),
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

    let result = mcp.analyze_file(request).await;
    assert!(result.is_ok());

    let response = result.unwrap().0;

    // Check response structure
    assert_eq!(response.file_path, file_path.to_str().unwrap());
    assert!(response.metadata.is_some());
    assert!(response.hashes.is_some());
    assert!(response.strings.is_some());
    assert!(response.hex_dump.is_some());
    assert!(response.binary_info.is_none()); // Not requested

    // Test serialization
    let json = serde_json::to_string(&response).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();

    assert!(parsed.get("file_path").is_some());
    assert!(parsed.get("metadata").is_some());
    assert!(parsed.get("hashes").is_some());
    assert!(parsed.get("strings").is_some());
    assert!(parsed.get("hex_dump").is_some());
}
