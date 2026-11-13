//! Tools that exist only in unit-test builds of the library.

use rmcp::{
    model::{CallToolResult, ContentBlock},
    tool, tool_router, ErrorData,
};

use super::{state::mark_section, FileScannerMcp};

#[tool_router(router = test_support_router, vis = "pub(crate)")]
impl FileScannerMcp {
    /// Panics inside blocking work, the way a buggy analyzer would.
    #[tool(
        name = "test_panic",
        description = "Test only: panic inside an analyzer"
    )]
    async fn test_panic_tool(&self) -> Result<CallToolResult, ErrorData> {
        let outcome = self
            .state
            .run_blocking("test_panic", || -> u32 {
                mark_section("parser");
                panic!("simulated analyzer bug")
            })
            .await;
        Ok(match outcome {
            Ok(_) => CallToolResult::success(vec![ContentBlock::text("unreachable")]),
            Err(message) => super::output::tool_error(message),
        })
    }
}

#[cfg(test)]
mod tests {
    use rmcp::{model::CallToolRequestParams, ServiceExt};

    use super::super::FileScannerMcp;

    /// PF06 through the real service: a panic in analysis becomes a tool error
    /// naming the section, the request is answered, and the server keeps going.
    #[tokio::test]
    async fn a_panicking_analysis_is_a_tool_error_and_the_server_survives() {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            if let Ok(service) = FileScannerMcp::new().serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        let client = ().serve(client_io).await.expect("handshake");

        let crashed = client
            .call_tool(CallToolRequestParams::new("test_panic"))
            .await
            .expect("the request is answered");
        assert_eq!(crashed.is_error, Some(true));
        let text = crashed.content[0].as_text().unwrap().text.clone();
        assert!(
            text.contains("test_panic crashed in section 'parser': simulated analyzer bug"),
            "{text}"
        );

        // Same connection, next request, and a second crash is contained as well.
        assert!(!client.list_all_tools().await.unwrap().is_empty());
        let again = client
            .call_tool(CallToolRequestParams::new("test_panic"))
            .await
            .unwrap();
        assert_eq!(again.is_error, Some(true));
        client.cancel().await.unwrap();
    }
}
