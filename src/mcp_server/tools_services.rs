//! Search over tracked strings and cache management tools. Owned by a later
//! package; this router is empty so it only adds functions.

use rmcp::tool_router;

use super::FileScannerMcp;

#[tool_router(router = services_router, vis = "pub(crate)", allow_empty)]
impl FileScannerMcp {}
