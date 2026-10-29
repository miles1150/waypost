//! Stateless Streamable HTTP MCP protocol layer. It knows nothing about any
//! product's tools or principals: callers inject the catalog and authentication.
use crate::{
    error::Result,
    http::{Request, Response},
    json::fields,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) const VERSIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];

pub(crate) struct ServerInfo {
    pub name: &'static str,
    pub instructions: &'static str,
}

pub(crate) struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub read_only: bool,
}

/// A product's MCP surface. Authentication runs before any protocol parsing so
/// unauthenticated callers learn nothing beyond the OAuth challenge.
#[allow(async_fn_in_trait)]
pub(crate) trait ToolCatalog {
    type Principal;
    fn server(&self) -> ServerInfo;
    fn tools(&self) -> Vec<ToolSpec>;
    async fn authenticate(&self, request: &Request) -> Result<Self::Principal>;
    async fn call(&self, principal: &Self::Principal, name: &str, args: Value) -> Result<Value>;
}

pub(crate) fn schema(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn rpc_error(status: u16, id: Value, code: i32, message: &str) -> Response {
    Response::json(
        status,
        json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
    )
}

fn listed(tools: Vec<ToolSpec>) -> Vec<Value> {
    tools.into_iter().map(|t| json!({"name":t.name,"description":t.description,"inputSchema":t.input_schema,"annotations":{"readOnlyHint":t.read_only,"destructiveHint":!t.read_only,"idempotentHint":true,"openWorldHint":false}})).collect()
}

pub(crate) async fn serve<C: ToolCatalog>(
    catalog: &C,
    public_origin: &str,
    max_json_bytes: usize,
    request: &Request,
) -> Response {
    if request
        .headers
        .get("origin")
        .is_some_and(|o| o != public_origin)
    {
        return rpc_error(403, Value::Null, -32001, "Invalid Origin.");
    }
    let principal = match catalog.authenticate(request).await {
        Ok(p) => p,
        Err(e) => return rpc_error(e.status(), Value::Null, -32001, &e.message),
    };
    if request.method != "POST" {
        let mut response = rpc_error(
            405,
            Value::Null,
            -32600,
            "This stateless endpoint accepts POST only.",
        );
        response.headers.insert("allow".into(), "POST".into());
        return response;
    }
    if request
        .headers
        .get("mcp-protocol-version")
        .is_some_and(|v| !VERSIONS.contains(&v.as_str()))
    {
        return rpc_error(
            400,
            Value::Null,
            -32600,
            "Unsupported MCP-Protocol-Version.",
        );
    }
    let value = match crate::json::parse(&request.body, max_json_bytes) {
        Ok(v) => v,
        Err(_) => return rpc_error(400, Value::Null, -32700, "Invalid JSON."),
    };
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    if !value.is_object()
        || value["jsonrpc"] != "2.0"
        || !value.get("method").is_some_and(Value::is_string)
        || (value.get("id").is_some() && !id.is_string() && !id.is_number())
        || fields(&value, &["jsonrpc", "id", "method", "params"]).is_err()
    {
        return rpc_error(
            400,
            Value::Null,
            -32600,
            "Expected one JSON-RPC request or notification.",
        );
    }
    let method = value["method"].as_str().unwrap_or_default();
    let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
    if !params.is_object() {
        return rpc_error(400, id, -32602, "Parameters must be an object.");
    }
    if value.get("id").is_none() {
        return Response {
            status: 202,
            headers: BTreeMap::new(),
            body: vec![],
        };
    }
    let result = match method {
        "initialize" => {
            let Some(version) = params.get("protocolVersion").and_then(Value::as_str) else {
                return rpc_error(200, id, -32602, "protocolVersion is required.");
            };
            let version = if VERSIONS.contains(&version) {
                version
            } else {
                VERSIONS[0]
            };
            let server = catalog.server();
            json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":server.name,"version":env!("CARGO_PKG_VERSION")},"instructions":server.instructions})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":listed(catalog.tools())}),
        "tools/call" => {
            if fields(&params, &["name", "arguments", "_meta"]).is_err() {
                return rpc_error(200, id, -32602, "Invalid tools/call parameters.");
            }
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return rpc_error(200, id, -32602, "Tool name is required.");
            };
            if !catalog.tools().iter().any(|t| t.name == name) {
                return rpc_error(200, id, -32602, "Unknown tool.");
            }
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let outcome = catalog.call(&principal, name, arguments).await;
            let envelope = match outcome {
                Ok(data) => json!({"ok":true,"data":data}),
                Err(e) => json!({"ok":false,"error":e.value()}),
            };
            json!({"content":[{"type":"text","text":envelope.to_string()}],"structuredContent":envelope,"isError":envelope["ok"]!=true})
        }
        _ => return rpc_error(200, id, -32601, "Method not found."),
    };
    Response::json(200, json!({"jsonrpc":"2.0","id":id,"result":result}))
}
