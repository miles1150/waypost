use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route<'a> {
    PublicAsset,
    Health,
    Ready,
    AdminSession,
    Admin,
    Mcp,
    Describe,
    UploadPrepare,
    UploadContent(&'a str),
    UploadCommit(&'a str),
    BlobMetadata(&'a str),
    BlobContent(&'a str),
    MessageSend,
    MessageGet(&'a str),
    Receipts,
    Inbox,
    SubmissionStatus,
    MemoryPublish(&'a str),
    MemoryRead(&'a str),
    Unknown,
}
pub(crate) fn classify<'a>(method: &str, path: &'a str) -> Route<'a> {
    use Route::*;
    match (method, path) {
        (
            "GET",
            "/"
            | "/dashboard"
            | "/dashboard/"
            | "/dashboard/app.js"
            | "/dashboard/i18n.js"
            | "/dashboard/style.css"
            | "/dashboard/memory.js"
            | "/dashboard/locales/en.json"
            | "/dashboard/locales/zh.json",
        ) => return PublicAsset,
        ("GET", "/health") => return Health,
        ("GET", "/ready") => return Ready,
        (_, "/admin/session" | "/admin/invitation" | "/admin/access-request") => {
            return AdminSession;
        }
        (_, path) if (path.starts_with("/account/") || path.starts_with("/oauth/")) => {
            return AdminSession;
        }
        (_, "/mcp") => return Mcp,
        ("GET", "/v0/describe") => return Describe,
        ("POST", "/v0/uploads") => return UploadPrepare,
        ("POST", "/v0/messages") => return MessageSend,
        ("POST", "/v0/receipts") => return Receipts,
        ("POST", "/v0/inbox/read") => return Inbox,
        ("POST", "/v0/submissions/status") => return SubmissionStatus,
        (_, path) if path.starts_with("/admin/v0/") => return Admin,
        _ => {}
    }
    let parts = path.split('/').collect::<Vec<_>>();
    match (method, parts.as_slice()) {
        ("PUT", ["", "v0", "uploads", id, "content"]) if !id.is_empty() => UploadContent(id),
        ("POST", ["", "v0", "uploads", id, "commit"]) if !id.is_empty() => UploadCommit(id),
        ("GET", ["", "v0", "blobs", id, "content"]) if !id.is_empty() => BlobContent(id),
        ("GET", ["", "v0", "blobs", id]) if !id.is_empty() => BlobMetadata(id),
        ("GET", ["", "v0", "messages", id]) if !id.is_empty() => MessageGet(id),
        ("POST", ["", "v0", "memory", "collections", id, "revisions"]) if !id.is_empty() => {
            MemoryPublish(id)
        }
        ("POST", ["", "v0", "memory", "collections", id, "read"]) if !id.is_empty() => {
            MemoryRead(id)
        }
        _ => Unknown,
    }
}

#[cfg(any(test, all(feature = "cloudflare", target_arch = "wasm32")))]
const ROUTE_WORDS: &[&str] = &[
    ".well-known",
    "access-request",
    "access-requests",
    "account",
    "actors",
    "admin",
    "app.css",
    "app.js",
    "audit",
    "authorize",
    "blobs",
    "callback",
    "cleanup",
    "clients",
    "collections",
    "commit",
    "connection-status",
    "consent",
    "consumers",
    "content",
    "dashboard",
    "describe",
    "device_authorization",
    "device_consent",
    "disable",
    "edit",
    "encrypt",
    "grants",
    "health",
    "inbox",
    "inspect",
    "invitation",
    "invitations",
    "keyenv-remote.json",
    "keys",
    "locales",
    "login",
    "maintenance",
    "mcp",
    "memory",
    "messages",
    "oauth",
    "oauth-authorization-server",
    "oauth-protected-resource",
    "owner-credential",
    "prepare",
    "preview",
    "primary-assistant",
    "privacy",
    "read",
    "ready",
    "receipts",
    "register",
    "registry",
    "revisions",
    "revoke",
    "session",
    "spaces",
    "status",
    "submissions",
    "token",
    "tokens",
    "uploads",
    "v0",
];

/// Stable route for logs. Resource ids are replaced with `:id`.
#[cfg(any(test, all(feature = "cloudflare", target_arch = "wasm32")))]
pub(crate) fn route_label(method: &str, path: &str) -> String {
    let verb = match method {
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => method,
        _ => "UNKNOWN",
    };
    let pattern = match classify(method, path) {
        Route::PublicAsset => match path {
            "/" => "/",
            "/dashboard" | "/dashboard/" => "/dashboard",
            "/dashboard/app.js" => "/dashboard/app.js",
            "/dashboard/i18n.js" => "/dashboard/i18n.js",
            "/dashboard/memory.js" => "/dashboard/memory.js",
            "/dashboard/style.css" => "/dashboard/style.css",
            "/dashboard/locales/en.json" => "/dashboard/locales/en.json",
            "/dashboard/locales/zh.json" => "/dashboard/locales/zh.json",
            _ => "/dashboard",
        }
        .to_owned(),
        _ => templated_path(path),
    };
    format!("{verb} {pattern}")
}

#[cfg(any(test, all(feature = "cloudflare", target_arch = "wasm32")))]
fn templated_path(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    if !path.starts_with('/') || path.len() > 512 {
        return "/unknown".into();
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() || segments.len() > 12 {
        return "/unknown".into();
    }
    let templated = segments
        .into_iter()
        .map(|segment| {
            if ROUTE_WORDS.contains(&segment) {
                segment
            } else {
                ":id"
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    format!("/{templated}")
}

#[derive(Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn json(method: &str, path: &str, token: &str, value: Value) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: BTreeMap::from([
                ("authorization".into(), format!("Bearer {token}")),
                ("content-type".into(), "application/json".into()),
            ]),
            body: serde_json::to_vec(&value).expect("JSON value serializes"),
        }
    }
}

pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            headers: BTreeMap::from([
                ("content-type".into(), "application/json".into()),
                ("cache-control".into(), "no-store".into()),
                ("x-content-type-options".into(), "nosniff".into()),
            ]),
            body: serde_json::to_vec(&value).expect("JSON value serializes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::route_label;

    #[test]
    fn route_label_keeps_patterns_and_drops_ids() {
        assert_eq!(route_label("GET", "/health"), "GET /health");
        assert_eq!(
            route_label("GET", "/dashboard/app.js"),
            "GET /dashboard/app.js"
        );
        assert_eq!(
            route_label("GET", "/v0/messages/msg_123"),
            "GET /v0/messages/:id"
        );
        assert_eq!(
            route_label("POST", "/admin/v0/spaces/space_1/memory/col_2/read"),
            "POST /admin/v0/spaces/:id/memory/:id/read"
        );
        let hidden = route_label("GET", "/v0/blobs/secret-token-value");
        assert_eq!(hidden, "GET /v0/blobs/:id");
        assert!(!hidden.contains("secret"));
        assert_eq!(route_label("TRACE", "/health"), "UNKNOWN /health");
        assert_eq!(route_label("GET", "/not-a-route"), "GET /:id");
        for (method, path) in [
            ("POST", "/oauth/register"),
            ("GET", "/oauth/clients/keyenv-remote.json"),
            ("GET", "/.well-known/oauth-protected-resource/mcp"),
            ("POST", "/account/keys/grants/revoke"),
        ] {
            assert_eq!(route_label(method, path), format!("{method} {path}"));
        }
        // Keys entry names never appear in paths; anything unexpected is masked.
        assert_eq!(
            route_label("GET", "/account/keys/github-token"),
            "GET /account/keys/:id"
        );
    }
}
