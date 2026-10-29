use crate::storage::queries::guarded_inserts as push_rows;
use crate::{
    domain::{FeedFilter, Principal},
    error::{Error, Result},
    http::{Request, Response},
    storage::{
        ObjectStore,
        driver::{Database, Row, Statement, Value as Sql, blob, integer, text},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, rc::Rc};
mod account_devices;
mod account_management;
mod accounts;
pub mod accounts_oidc;
mod admin;
mod blobs;
mod dashboard;
mod dashboard_memory;
mod encryption;
mod invitations;
pub mod keys;
mod mailbox;
mod maintenance;
mod mcp;
mod memory;
pub mod oauth;
mod oauth_authorization;
mod oauth_tokens;
mod onboarding;
#[cfg(all(test, feature = "native"))]
mod operator_retirement_tests;
mod privacy;
mod receipts;
mod token_routing;
#[cfg(all(test, feature = "native"))]
mod token_routing_tests;

#[derive(Clone)]
pub struct Config {
    pub admin_secret: String,
    pub public_origin: String,
}
#[derive(Clone, serde::Serialize)]
pub struct Limits {
    pub max_json_bytes: usize,
    pub max_blob_bytes: u64,
    pub max_message_attachments: usize,
    pub max_inline_memory_changes: usize,
    pub max_manifest_memory_changes: usize,
    pub max_collection_items: usize,
    pub max_page_size: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_json_bytes: 65536,
            max_blob_bytes: 8 * 1024 * 1024,
            max_message_attachments: 16,
            max_inline_memory_changes: 500,
            max_manifest_memory_changes: 10000,
            max_collection_items: 10000,
            max_page_size: 100,
        }
    }
}
pub trait Clock {
    fn now_ms(&self) -> i64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        }
        #[cfg(target_arch = "wasm32")]
        {
            js_sys::Date::now() as i64
        }
    }
}
pub struct App<D, O> {
    pub(crate) db: D,
    pub(crate) objects: O,
    pub(crate) config: Config,
    pub(crate) clock: Rc<dyn Clock>,
    pub(crate) limits: Limits,
    cursor_key: [u8; 32],
    csrf_key: [u8; 32],
    explicit_cursor_secret: Option<[u8; 32]>,
    explicit_csrf_secret: Option<[u8; 32]>,
    pub(crate) operator_enabled: bool,
    pub(crate) encryption: Option<encryption::Encryption>,
    pub(crate) oidc: Option<accounts_oidc::OidcConfig>,
    pub(crate) account_signup_limit: usize,
    pub(crate) oauth: Option<oauth::OAuthConfig>,
    pub(crate) invitations_enabled: bool,
    pub(crate) oidc_exchange: Option<Rc<dyn accounts_oidc::OidcCodeExchange>>,
    pub(crate) client_fetcher: Option<Rc<dyn crate::gateway::oauth_client::ClientMetadataFetch>>,
    /// Set when this App serves the keys product instead of Waypost.
    pub(crate) keys: Option<keys::KeysConfig>,
}
// SQL execution is sealed inside this crate; callers use supported runtimes and domain HTTP/MCP operations.
#[allow(private_bounds)]
impl<D: Database, O: ObjectStore> App<D, O> {
    pub fn new(db: D, objects: O, config: Config) -> Self {
        Self {
            cursor_key: derive_key(&config.admin_secret, b"waypost-cursor-v2"),
            csrf_key: derive_key(&config.admin_secret, b"waypost-admin-csrf-v2"),
            explicit_cursor_secret: None,
            explicit_csrf_secret: None,
            operator_enabled: true,
            encryption: None,
            oidc: None,
            account_signup_limit: 0,
            oauth: None,
            invitations_enabled: true,
            oidc_exchange: None,
            client_fetcher: None,
            keys: None,
            db,
            objects,
            config,
            clock: Rc::new(SystemClock),
            limits: Limits::default(),
        }
    }
    /// Retirement is opt-in and requires the replacement account path. Data is
    /// retained so rollback can restore the legacy workflow without a down migration.
    pub fn with_onboarding_mode(mut self, mode: &str) -> Result<Self> {
        self.invitations_enabled = match mode {
            "legacy" => true,
            "accounts" if self.oidc.is_some() => false,
            "accounts" => {
                return Err(Error::invalid(
                    "Account onboarding requires configured OIDC.",
                ));
            }
            _ => {
                return Err(Error::invalid(
                    "Onboarding mode must be legacy or accounts.",
                ));
            }
        };
        Ok(self)
    }
    /// Separate browser CSRF authentication from the retireable operator credential.
    pub fn with_csrf_secret(mut self, secret: &str) -> Result<Self> {
        if secret.len() < 32 {
            return Err(Error::invalid(
                "CSRF secret must contain at least 32 bytes.",
            ));
        }
        self.csrf_key = derive_key(secret, b"waypost-admin-csrf-v2");
        self.explicit_csrf_secret = Some(Sha256::digest(secret.as_bytes()).into());
        Ok(self)
    }
    /// Opt-in operator retirement validates configuration, not identity-provider
    /// availability. Losing the external account can make account access unrecoverable.
    pub fn with_operator_mode(mut self, mode: &str) -> Result<Self> {
        self.operator_enabled = match mode {
            "enabled" => true,
            "disabled" => false,
            _ => return Err(Error::invalid("Operator mode must be enabled or disabled.")),
        };
        self.validate_runtime_auth()?;
        Ok(self)
    }
    pub fn validate_runtime_auth(&self) -> Result<()> {
        if self.operator_enabled {
            if self.config.admin_secret.len() < 32 {
                return Err(Error::invalid(
                    "Admin secret must contain at least 32 bytes.",
                ));
            }
            return Ok(());
        }
        if self.oidc.is_none() || self.oidc_exchange.is_none() {
            return Err(Error::invalid(
                "Disabled operator requires configured OIDC account authentication.",
            ));
        }
        let (Some(cursor), Some(csrf)) = (self.explicit_cursor_secret, self.explicit_csrf_secret)
        else {
            return Err(Error::invalid(
                "Disabled operator requires explicit cursor and CSRF secrets.",
            ));
        };
        let admin: [u8; 32] = Sha256::digest(self.config.admin_secret.as_bytes()).into();
        if cursor == csrf
            || (!self.config.admin_secret.is_empty() && (cursor == admin || csrf == admin))
        {
            return Err(Error::invalid(
                "Cursor, CSRF and operator secrets must be independent.",
            ));
        }
        Ok(())
    }
    pub fn with_cursor_secret(mut self, secret: &str) -> Result<Self> {
        if secret.len() < 32 {
            return Err(Error::invalid(
                "Cursor secret must contain at least 32 bytes.",
            ));
        }
        self.cursor_key = derive_key(secret, b"waypost-cursor-v2");
        self.explicit_cursor_secret = Some(Sha256::digest(secret.as_bytes()).into());
        Ok(self)
    }
    pub fn with_clock(mut self, clock: Rc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
    pub async fn handle(&self, request: Request) -> Response {
        if self.keys.is_some() {
            return self.keys_handle(request).await;
        }
        if request.path == "/onboarding" && request.method == "GET" {
            return Response::json(
                200,
                json!({"ok":true,"data":{
                    "invitations_enabled":self.invitations_enabled,
                    "accounts_enabled":self.oidc.is_some(),
                    "account_url":if self.oidc.is_some() {Some("/account")} else {None}
                }}),
            );
        }
        let parts: Vec<_> = request.path.split('/').collect();
        let invitation_route = matches!(
            request.path.as_str(),
            "/admin/access-request" | "/admin/invitation" | "/admin/v0/access-requests"
        ) || (parts.len() >= 5
            && parts[..4] == ["", "admin", "v0", "spaces"]
            && parts.get(5) == Some(&"invitations"));
        if !self.invitations_enabled && invitation_route {
            return Response::json(
                410,
                json!({"ok":false,"error":{
                    "code":"INVITATIONS_RETIRED","message":"Invitation onboarding is retired. Use account sign-in or existing space recovery.","details":{"account_url":"/account"}}
                }),
            );
        }
        if request.path.starts_with("/oauth/") || request.path.starts_with("/.well-known/oauth-") {
            return self.oauth_handle(&request).await;
        }
        if request.path == "/account" || request.path.starts_with("/account/") {
            return self.account_handle(&request).await;
        }
        if let Some(response) = self.dashboard_asset(&request) {
            return response;
        }
        if request.path == "/admin/access-request" {
            return self.access_request(&request).await;
        }
        if request.path == "/admin/invitation" {
            return self.redeem_invitation(&request).await;
        }
        if request.path == "/admin/session" {
            return self.admin_session(&request).await;
        }
        if request.path == "/mcp" {
            let mut response = crate::gateway::mcp::serve(
                &mcp::WaypostTools(self),
                &self.config.public_origin,
                self.limits.max_json_bytes,
                &request,
            )
            .await;
            self.oauth_challenge(&mut response);
            return response;
        }
        let trace = match random_id("req") {
            Ok(v) => v,
            Err(e) => {
                return Response::json(
                    e.status(),
                    json!({"ok":false,"request_id":"unavailable","error":e.value()}),
                );
            }
        };
        let request_id = crate::json::parse(&request.body, self.limits.max_json_bytes)
            .ok()
            .and_then(|v| {
                v.get("request_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or(trace);
        if Self::dashboard_blob_request(&request) {
            return match self.dashboard_blob_content(&request).await {
                Ok(response) => response,
                Err(error) => Response::json(
                    error.status(),
                    json!({"ok":false,"request_id":request_id,"error":error.value()}),
                ),
            };
        }
        if matches!(
            crate::http::classify(&request.method, &request.path),
            crate::http::Route::BlobContent(_)
        ) {
            match self.blob_content(&request).await {
                Ok(response) => return response,
                Err(error) => {
                    return Response::json(
                        error.status(),
                        json!({"ok":false,"request_id":request_id,"error":error.value()}),
                    );
                }
            }
        }
        let result = self.route(&request).await;
        match result {
            Ok(data) => Response::json(200, json!({"ok":true,"request_id":request_id,"data":data})),
            Err(error) => Response::json(
                error.status(),
                json!({"ok":false,"request_id":request_id,"error":error.value()}),
            ),
        }
    }
    async fn route(&self, request: &Request) -> Result<Value> {
        if request.path == "/health" && request.method == "GET" {
            return Ok(json!({"status":"ok","api_version":"0.1"}));
        }
        if let Some(origin) = request.headers.get("origin")
            && origin != &self.config.public_origin
        {
            return Err(Error::forbidden());
        }
        if request.path.starts_with("/admin/v0/") {
            let scope = self.admin_access(request).await?;
            let value = crate::json::parse(&request.body, self.limits.max_json_bytes)?;
            if let Some(space) = scope {
                return self.user_admin(request, value, &space).await;
            }
            return self.admin(request, value).await;
        }
        let principal = self.authenticate(request).await?;
        use crate::http::{Route, classify};
        let route = classify(&request.method, &request.path);
        if let Route::UploadContent(id) = route {
            return self.blob_put(&principal, id, request).await;
        }
        let value = crate::json::parse(&request.body, self.limits.max_json_bytes)?;
        match route {
            Route::Describe => self.describe(&principal).await,
            Route::UploadPrepare => self.blob_prepare(&principal, value).await,
            Route::UploadCommit(id) => self.blob_commit(&principal, id, value).await,
            Route::BlobMetadata(id) => self.blob_get(&principal, id).await,
            Route::MessageSend => self.send(&principal, value).await,
            Route::MessageGet(id) => self.message(&principal, id).await,
            Route::Receipts => self.ack(&principal, value).await,
            Route::Inbox => self.inbox(&principal, value).await,
            Route::SubmissionStatus => self.status(&principal, value).await,
            Route::MemoryPublish(id) => self.memory_publish(&principal, id, value).await,
            Route::MemoryRead(id) => self.memory_read(&principal, id, value).await,
            _ => Err(Error::not_found()),
        }
    }

    pub(crate) fn admin_auth(&self, request: &Request) -> Result<()> {
        if !self.operator_enabled {
            return Err(Error::unauthenticated());
        }
        let supplied = bearer(request)?;
        if self.config.admin_secret.len() < 32 {
            return Err(Error::internal("invalid admin secret configuration"));
        }
        let expected = Sha256::digest(self.config.admin_secret.as_bytes());
        let actual = Sha256::digest(supplied.as_bytes());
        let mut difference = 0u8;
        for (a, b) in expected.iter().zip(actual.iter()) {
            difference |= a ^ b;
        }
        if difference == 0 {
            Ok(())
        } else {
            Err(Error::unauthenticated())
        }
    }
    pub(crate) async fn authenticate(&self, request: &Request) -> Result<Principal> {
        let token = bearer(request)?;
        let digest = Sha256::digest(token.as_bytes()).to_vec();
        let now = self.clock.now_ms();
        let (oauth_guard, oauth_parameters) = self.oauth_authority_guard(now);
        let mut parameters = vec![digest.into(), now.into()];
        parameters.extend(oauth_parameters);
        let rows = self
            .db
            .query(Statement::new(
                format!(
                    "{} AND {oauth_guard}",
                    crate::storage::queries::AUTHENTICATE
                ),
                parameters,
            ))
            .await?;
        let row = rows.first().ok_or_else(Error::unauthenticated)?;
        fn decoded<T: serde::de::DeserializeOwned>(row: &Row, key: &str) -> Result<T> {
            serde_json::from_str(&text(row, key)?)
                .map_err(|_| Error::internal("decode authentication filters"))
        }
        #[derive(serde::Deserialize)]
        struct FilterEntry {
            dimension: String,
            value: String,
        }
        let token_id = text(row, "token_id")?;
        let space_id = text(row, "space_id")?;
        let consumer_id = text(row, "consumer_id")?;
        let mut filter = FeedFilter::default();
        for entry in decoded::<Vec<FilterEntry>>(row, "filters_json")? {
            match entry.dimension.as_str() {
                "producer_ids" => filter.producer_ids.push(entry.value),
                "thread_ids" => filter.thread_ids.push(entry.value),
                "item_types" => filter.item_types.push(entry.value),
                "collection_ids" => filter.collection_ids.push(entry.value),
                _ => return Err(Error::internal("decode filter dimension")),
            }
        }
        let filter_fingerprint =
            fingerprint(&serde_json::to_value(&filter).map_err(|_| Error::storage())?)?;
        Ok(Principal {
            owner_authority: None,
            space_id,
            consumer_id,
            token_id,
            actor_id: text(row, "actor_id")?,
            actor_version: integer(row, "actor_version")?,
            credential_version: integer(row, "credential_version")?,
            view_revision: integer(row, "view_revision")?,
            default_actor_id: text(row, "default_actor_id")?,
            default_recipient_id: text(row, "default_recipient_id")?,
            view: text(row, "view")?,
            filter,
            filter_fingerprint,
        })
    }
    // Both the initial authentication SELECT and final mutation guard use this
    // predicate against token alias t. No separate ownership lookup can go stale.
    fn oauth_authority_guard(&self, now: i64) -> (String, Vec<Sql>) {
        if self.oauth.is_none() {
            return ("t.credential_kind='legacy'".into(), vec![]);
        }
        let (clients, client_parameters) = self.client_guard("ofa.client_id");
        let mut parameters = vec![self.oauth_resource().into()];
        parameters.extend(client_parameters);
        parameters.push(now.into());
        (
            format!(
                "(t.credential_kind='legacy' OR (t.credential_kind='oauth' AND EXISTS(SELECT 1 FROM oauth_access_tokens oat JOIN oauth_families ofa ON ofa.family_id=oat.family_id JOIN accounts oac ON oac.account_id=ofa.account_id JOIN account_spaces oas ON oas.account_id=ofa.account_id AND oas.space_id=ofa.space_id WHERE oat.token_id=t.token_id AND ofa.space_id=t.space_id AND ofa.actor_id=t.actor_id AND ofa.consumer_id=t.consumer_id AND ofa.scope='waypost' AND ofa.resource=? AND {clients} AND ofa.revoked_at IS NULL AND ofa.expires_at>? AND oac.disabled=0 AND c.view='inbox')))"
            ),
            parameters,
        )
    }
    pub(crate) fn authority_guard(&self, p: &Principal) -> (String, Vec<Sql>) {
        if p.owner_authority.is_some() {
            return self.owner_authority_guard(p);
        }
        let now = self.clock.now_ms();
        let (oauth_guard, oauth_parameters) = self.oauth_authority_guard(now);
        let mut parameters = vec![
            p.token_id.clone().into(),
            p.credential_version.into(),
            p.actor_version.into(),
            p.view_revision.into(),
            now.into(),
        ];
        parameters.extend(oauth_parameters);
        (
            format!(
                "EXISTS(SELECT 1 FROM tokens t JOIN actors a ON a.space_id=t.space_id AND a.actor_id=t.actor_id JOIN consumers c ON c.space_id=t.space_id AND c.consumer_id=t.consumer_id AND c.actor_id=t.actor_id WHERE t.token_id=? AND t.authority_version=? AND a.authority_version=? AND c.view_revision=? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>?) AND a.disabled=0 AND c.disabled=0 AND (NOT EXISTS(SELECT 1 FROM account_devices ad WHERE ad.token_id=t.token_id) OR EXISTS(SELECT 1 FROM account_devices ad JOIN accounts ac ON ac.account_id=ad.account_id JOIN account_spaces asp ON asp.account_id=ac.account_id AND asp.space_id=ad.space_id WHERE ad.token_id=t.token_id AND ad.state='consumed' AND ac.disabled=0 AND ad.space_id=t.space_id)) AND {oauth_guard})"
            ),
            parameters,
        )
    }
    pub(crate) async fn current(&self, p: &Principal) -> Result<()> {
        let (guard, parameters) = self.authority_guard(p);
        let r = self
            .db
            .query(Statement::new(
                format!("SELECT 1 AS valid WHERE {guard}"),
                parameters,
            ))
            .await?;
        if r.is_empty() {
            Err(Error::unauthenticated())
        } else {
            Ok(())
        }
    }
    pub(crate) async fn describe(&self, p: &Principal) -> Result<Value> {
        self.current(p).await?;
        let mut collections = vec![];
        let rows=self.db.query(Statement::new("SELECT c.* FROM memory_collections c WHERE c.space_id=? ORDER BY c.created_at,c.collection_id LIMIT ?",vec![p.space_id.clone().into(),((self.limits.max_page_size+1) as i64).into()])).await?;
        let more = rows.len() > self.limits.max_page_size;
        for row in rows.iter().take(self.limits.max_page_size) {
            collections.push(json!({"collection_id":text(row,"collection_id")?,"source_actor_id":text(row,"source_actor_id")?,"scope":text(row,"scope")?,"display_name":text(row,"display_name")?,"current_revision":integer(row,"current_revision")?,"can_read":true,"can_write":true}));
        }
        self.current(p).await?;
        Ok(
            json!({"api_version":"0.1","space_id":p.space_id,"actor_id":p.actor_id,"consumer_id":p.consumer_id,"view_revision":p.view_revision,"default_recipient_id":p.default_recipient_id,"access_model":"space_membership","memory_collections":collections,"memory_collections_has_more":more,"limits":self.limits,"capabilities":{"privacy_filtering":true,"mailbox":true,"receipts":true,"blob_upload":true,"memory_snapshot":true,"memory_delta":true,"webhook_events":false,"oauth":self.oauth.is_some(),"server_export":false}}),
        )
    }
    pub(crate) fn sign_cursor(&self, payload: &str) -> Result<String> {
        let mut m =
            Hmac::<Sha256>::new_from_slice(&self.cursor_key).map_err(|_| Error::storage())?;
        m.update(payload.as_bytes());
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
        ))
    }
    pub(crate) fn verify_cursor(&self, cursor: &str) -> Result<String> {
        let (body, tag) = cursor
            .split_once('.')
            .ok_or_else(|| Error::new("INVALID_CURSOR", "Invalid cursor."))?;
        let body = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Error::new("INVALID_CURSOR", "Invalid cursor."))?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| Error::new("INVALID_CURSOR", "Invalid cursor."))?;
        let mut m =
            Hmac::<Sha256>::new_from_slice(&self.cursor_key).map_err(|_| Error::storage())?;
        m.update(&body);
        m.verify_slice(&tag)
            .map_err(|_| Error::new("INVALID_CURSOR", "Invalid cursor."))?;
        String::from_utf8(body).map_err(|_| Error::new("INVALID_CURSOR", "Invalid cursor."))
    }
}
pub(crate) fn bearer(request: &Request) -> Result<String> {
    request
        .headers
        .get("authorization")
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .map(str::to_owned)
        .ok_or_else(Error::unauthenticated)
}
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::getrandom(&mut b).map_err(|_| Error::internal("random identifier generation"))?;
    Ok(b)
}
pub(crate) fn random_id(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}_{}", hex::encode(random_bytes::<16>()?)))
}
pub(crate) fn fingerprint(v: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(crate::json::canonical(v)?)))
}
pub(crate) fn stamp(ms: i64) -> Result<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .ok_or_else(Error::storage)
}
pub(crate) fn uuid_uri() -> Result<String> {
    let mut b = random_bytes::<16>()?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = hex::encode(b);
    Ok(format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

fn derive_key(secret: &str, label: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any size. Labels isolate cursor and CSRF protocols.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts arbitrary keys");
    mac.update(label);
    mac.finalize().into_bytes().into()
}
