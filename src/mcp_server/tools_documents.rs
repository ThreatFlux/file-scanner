//! Document and script analyzers (`analyze_document`, `analyze_script`).
//! Owned by a later package; this router is empty so it only adds functions.

use rmcp::tool_router;

use super::FileScannerMcp;

#[tool_router(router = documents_router, vis = "pub(crate)", allow_empty)]
impl FileScannerMcp {}
