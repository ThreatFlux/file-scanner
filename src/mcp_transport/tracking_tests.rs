use super::*;

#[tokio::test]
async fn test_analyze_file_indexes_valid_strings_after_oversized_input() {
    let cache_dir = tempfile::tempdir().unwrap();
    let server = McpTransportServer {
        handler: FileScannerMcp::new(),
        cache: Arc::new(AnalysisCache::new(cache_dir.path()).unwrap()),
        string_tracker: Arc::new(StringTracker::new()),
    };
    let test_file = tempfile::NamedTempFile::new().unwrap();
    let mut content = vec![b'a'; 1_048_577];
    content.extend_from_slice(b"\0malware_token\0");
    std::fs::write(&test_file, content).unwrap();
    let params = ToolCallParams {
        name: "analyze_file".into(),
        arguments: HashMap::from([
            ("file_path".into(), json!(test_file.path())),
            ("strings".into(), json!(true)),
        ]),
    };
    let result = server.handle_tool_call(params).await;
    let text = result["content"][0]["text"].as_str().unwrap();
    let analysis: Value = serde_json::from_str(text).unwrap();
    assert!(analysis["strings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "malware_token"));
    assert!(server
        .string_tracker
        .get_string_details("malware_token")
        .is_some());
    assert_eq!(
        server
            .string_tracker
            .search_strings("malware_token", 10)
            .len(),
        1
    );
}
