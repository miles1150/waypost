use super::*;
use crate::gateway::mcp::{ServerInfo, ToolCatalog, ToolSpec, schema};
use crate::json::{fields, required};
/// Waypost's tool catalog behind the shared MCP gateway.
pub(super) struct WaypostTools<'a, D, O>(pub(super) &'a App<D, O>);
impl<D: Database, O: ObjectStore> ToolCatalog for WaypostTools<'_, D, O> {
    type Principal = Principal;
    fn server(&self) -> ServerInfo {
        ServerInfo {
            name: "waypost",
            instructions: "Use waypost_describe first. Persist stable request IDs before writes and persist inbox content before acknowledging. Blob bytes use authenticated HTTP PUT/GET URLs returned by the tools.",
        }
    }
    fn tools(&self) -> Vec<ToolSpec> {
        tools()
    }
    async fn authenticate(&self, request: &Request) -> Result<Principal> {
        self.0.authenticate(request).await
    }
    async fn call(&self, p: &Principal, name: &str, args: Value) -> Result<Value> {
        self.0.call_tool(p, name, args).await
    }
}
impl<D: Database, O: ObjectStore> App<D, O> {
    async fn call_tool(&self, p: &Principal, name: &str, args: Value) -> Result<Value> {
        match name {
            "waypost_describe" => {
                fields(&args, &[])?;
                self.describe(p).await
            }
            "waypost_send" => self.send(p, args).await,
            "waypost_message_get" => {
                fields(&args, &["message_id"])?;
                self.message(p, &required(&args, "message_id")?).await
            }
            "waypost_inbox" => self.inbox(p, args).await,
            "waypost_ack" => self.ack(p, args).await,
            "waypost_status" => self.status(p, args).await,
            "waypost_blob_prepare" => self.blob_prepare(p, args).await,
            "waypost_blob_commit" => {
                self.blob_commit(p, &required(&args, "upload_id")?, args)
                    .await
            }
            "waypost_blob_get" => {
                fields(&args, &["blob_id"])?;
                self.blob_get(p, &required(&args, "blob_id")?).await
            }
            "waypost_memory_publish" => {
                self.memory_publish(p, &required(&args, "collection_id")?, args)
                    .await
            }
            "waypost_memory_read" => {
                self.memory_read(p, &required(&args, "collection_id")?, args)
                    .await
            }
            _ => Err(Error::not_found()),
        }
    }
}
fn tools() -> Vec<ToolSpec> {
    let s = json!({"type":"string"});
    let strings = json!({"type":"array","items":{"type":"string"}});
    let n = json!({"type":"integer","minimum":0});
    let nullable = json!({"type":["string","null"]});
    let item = schema(
        json!({"item_id":s,"blob_id":s,"path":s,"metadata":{"type":"object"}}),
        &["item_id", "blob_id", "path"],
    );
    let definitions = vec![
        (
            "waypost_describe",
            "Inspect Space identity, default destination, limits and supported capabilities.",
            schema(json!({}), &[]),
            true,
        ),
        (
            "waypost_send",
            "Durably send an immutable message with a stable request ID.",
            schema(
                json!({"request_id":s,"recipient_ids":strings,"thread_id":nullable,"in_reply_to":nullable,"kind":{"type":"string","enum":["info","result","question","todo_suggestion","memory_notice","processing_result"]},"subject":s,"body":schema(json!({"text":s,"options":{"type":"array","items":{"type":"string"}}}),&["text"]),"source":schema(json!({"native_thread_id":nullable,"native_message_id":nullable,"url":nullable}),&[]),"attachment_ids":strings,"metadata":{"type":"object"}}),
                &["request_id", "kind", "subject", "body"],
            ),
            false,
        ),
        (
            "waypost_message_get",
            "Read a message currently visible to this Actor.",
            schema(json!({"message_id":s}), &["message_id"]),
            true,
        ),
        (
            "waypost_inbox",
            "Read a Consumer feed page without acknowledging it.",
            schema(
                json!({"consumer_id":s,"cursor":nullable,"limit":n}),
                &["consumer_id"],
            ),
            true,
        ),
        (
            "waypost_ack",
            "Confirm inputs only after local durable storage; stages are monotonic.",
            schema(
                json!({"request_id":s,"consumer_id":s,"checkpoint_cursor":nullable,"items":{"type":"array","items":schema(json!({"item_id":s,"stage":{"type":"string","enum":["received","processed"]}}),&["item_id","stage"])}}),
                &["request_id", "consumer_id"],
            ),
            false,
        ),
        (
            "waypost_status",
            "Recover the original outcome of an Actor-stable submission.",
            schema(
                json!({"operation":s,"request_id":s}),
                &["operation", "request_id"],
            ),
            true,
        ),
        (
            "waypost_blob_prepare",
            "Reserve a create-only upload. Upload exact bytes to upload_url before commit.",
            schema(
                json!({"request_id":s,"content_type":s,"size_bytes":n,"sha256":s,"filename":nullable}),
                &["request_id", "content_type", "size_bytes", "sha256"],
            ),
            false,
        ),
        (
            "waypost_blob_commit",
            "Seal verified uploaded bytes; preserve this request ID on retries.",
            schema(
                json!({"request_id":s,"upload_id":s}),
                &["request_id", "upload_id"],
            ),
            false,
        ),
        (
            "waypost_blob_get",
            "Get authorized Blob metadata and an authenticated download URL.",
            schema(json!({"blob_id":s}), &["blob_id"]),
            true,
        ),
        (
            "waypost_memory_publish",
            "Publish a full snapshot or partial delta using expected_revision. Never use snapshot for a partial export.",
            schema(
                json!({"request_id":s,"collection_id":s,"expected_revision":n,"mode":{"type":"string","enum":["snapshot","delta"]},"items":{"type":"array","items":item},"delete_ids":strings,"manifest_blob_id":s}),
                &["request_id", "collection_id", "expected_revision", "mode"],
            ),
            false,
        ),
        (
            "waypost_memory_read",
            "Read a fixed memory revision; retain next_cursor for stable pagination and export.",
            schema(
                json!({"collection_id":s,"revision":{"type":["integer","null"],"minimum":0},"limit":n,"cursor":nullable,"include_tombstones":{"type":"boolean"}}),
                &["collection_id"],
            ),
            true,
        ),
    ];
    definitions
        .into_iter()
        .map(|(name, description, input_schema, read_only)| ToolSpec {
            name,
            description,
            input_schema,
            read_only,
        })
        .collect()
}
