//! Product-neutral service plumbing: the MCP protocol layer, OAuth client
//! registration checks and (on Workers) the D1 adapter. Products inject tools.
#[cfg(all(feature = "cloudflare", target_arch = "wasm32"))]
pub(crate) mod cloudflare;
pub(crate) mod mcp;
pub(crate) mod oauth_client;
