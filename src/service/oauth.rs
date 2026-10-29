//! OAuth authorization server for the MCP resource. Clients are preregistered,
//! identified by a Client ID Metadata Document, or dynamically registered; the
//! authorization grant itself is bound by the active product profile.
use super::*;
use crate::gateway::oauth_client::{
    self as registry, ClientDocument, ClientMetadataFetch, HttpMetadataFetcher,
};
use serde::Deserialize;
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub allow_loopback_port_variation: bool,
}
impl OAuthClient {
    pub(super) fn accepts_redirect(&self, candidate: &str) -> bool {
        if self.redirect_uris.iter().any(|r| r == candidate) {
            return true;
        }
        if !self.allow_loopback_port_variation {
            return false;
        }
        let Ok(mut requested) = Url::parse(candidate) else {
            return false;
        };
        if requested.as_str() != candidate
            || requested.scheme() != "http"
            || !matches!(requested.host_str(), Some("127.0.0.1" | "[::1]"))
            || requested.port().is_none_or(|p| p == 0)
            || requested.query().is_some()
            || requested.fragment().is_some()
            || !requested.username().is_empty()
            || requested.password().is_some()
        {
            return false;
        }
        self.redirect_uris.iter().any(|registered| {
            let Ok(expected) = Url::parse(registered) else {
                return false;
            };
            if expected.scheme() != "http"
                || expected.host_str() != requested.host_str()
                || expected.port().is_none_or(|p| p == 0)
            {
                return false;
            }
            if requested.set_port(expected.port()).is_err() {
                return false;
            }
            requested.as_str() == registered
        })
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    #[serde(default)]
    pub clients: Vec<OAuthClient>,
    /// Accept HTTPS URL client IDs resolved from Client ID Metadata Documents.
    #[serde(default)]
    pub client_id_metadata_documents: bool,
    /// Expose an RFC 7591 registration endpoint for public clients.
    #[serde(default)]
    pub dynamic_registration: bool,
}

/// How the server learned a client's identity and callbacks.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum ClientKind {
    Preregistered,
    MetadataDocument,
    Dynamic,
}
impl ClientKind {
    fn label(self) -> &'static str {
        match self {
            Self::Preregistered => "preregistered",
            Self::MetadataDocument => "metadata_document",
            Self::Dynamic => "dynamic_registration",
        }
    }
}
pub(crate) struct ResolvedClient {
    pub client_id: String,
    pub name: String,
    pub kind: ClientKind,
    preregistered: Option<OAuthClient>,
    redirect_uris: Vec<String>,
}
impl ResolvedClient {
    pub(crate) fn accepts_redirect(&self, candidate: &str) -> bool {
        match &self.preregistered {
            Some(client) => client.accepts_redirect(candidate),
            None => self
                .redirect_uris
                .iter()
                .any(|r| registry::redirect_matches(r, candidate)),
        }
    }
    /// What the consent page must show (MCP 2025-11-25: display the redirect
    /// host; warn about loopback-only clients, which any local process can impersonate).
    pub(crate) fn consent_view(&self, redirect: Option<&str>) -> Value {
        let declared = match &self.preregistered {
            Some(c) => c.redirect_uris.clone(),
            None => self.redirect_uris.clone(),
        };
        let mut warnings = vec![];
        if self.kind == ClientKind::Dynamic {
            warnings.push("The client name was supplied by the client itself and is not verified.");
        }
        if self.kind != ClientKind::Preregistered && registry::loopback_only(&declared) {
            warnings.push("This client only receives codes on this computer (loopback). Approve only if you started this sign-in yourself.");
        }
        json!({
            "client_id": self.client_id,
            "client_name": self.name,
            "client_kind": self.kind.label(),
            "client_host": if self.kind == ClientKind::MetadataDocument {registry::display_host(&self.client_id)} else {String::new()},
            "redirect_host": redirect.map(registry::display_host),
            "client_warnings": warnings,
        })
    }
}

/// Resource, scope and grant features of the product served by this App.
pub(crate) struct OAuthProfile {
    pub scopes: &'static [&'static str],
    pub default_scope: &'static str,
    pub resource_name: &'static str,
    pub device_grant: bool,
}
const WAYPOST_PROFILE: OAuthProfile = OAuthProfile {
    scopes: &["waypost"],
    default_scope: "waypost",
    resource_name: "Waypost Space",
    device_grant: true,
};
pub(crate) const KEYS_PROFILE: OAuthProfile = OAuthProfile {
    scopes: &["keys:read", "keys:write"],
    default_scope: "keys:read keys:write",
    resource_name: "keyenv-remote secrets",
    device_grant: false,
};

pub(super) fn oauth_error(code: &'static str) -> Error {
    Error::new(code, "OAuth request could not be completed.")
}
/// Edge throttling happens before App dispatch, but OAuth clients still need the
/// protocol error shape and an explicit retry delay (never the API envelope).
#[cfg(any(test, all(feature = "cloudflare", target_arch = "wasm32")))]
pub(crate) fn rate_limited_response() -> Response {
    let mut response = Response::json(429, json!({"error":"temporarily_unavailable"}));
    response
        .headers
        .insert("cache-control".into(), "no-store".into());
    response.headers.insert("pragma".into(), "no-cache".into());
    response.headers.insert("retry-after".into(), "60".into());
    response
}

pub(super) fn parse_params(raw: &str) -> Result<BTreeMap<String, String>> {
    if raw.len() > 16384 {
        return Err(oauth_error("invalid_request"));
    }
    // Reject malformed percent encoding rather than normalizing ambiguous parameters.
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return Err(oauth_error("invalid_request"));
            }
            i += 2;
        }
        i += 1;
    }
    let mut out = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if k.contains('\u{fffd}') || v.contains('\u{fffd}') {
            return Err(oauth_error("invalid_request"));
        }
        if let Some(previous) = out.get(k.as_ref()) {
            // RFC 8707 permits repeated resource parameters. This server has
            // one audience: collapse identical copies, never choose one of
            // conflicting targets. Other repeated parameters stay invalid.
            if k != "resource" || previous != v.as_ref() {
                return Err(oauth_error("invalid_request"));
            }
        } else {
            out.insert(k.into_owned(), v.into_owned());
        }
    }
    Ok(out)
}
impl<D: Database, O: ObjectStore> App<D, O> {
    pub fn with_oauth(mut self, config: OAuthConfig) -> Result<Self> {
        let open_registration = config.client_id_metadata_documents || config.dynamic_registration;
        if self.oidc.is_none()
            || (config.clients.is_empty() && !open_registration)
            || config.clients.len() > 32
        {
            return Err(Error::invalid(
                "OAuth requires accounts and 1–32 pre-registered clients, metadata documents or dynamic registration.",
            ));
        }
        let origin = Url::parse(&self.config.public_origin)
            .map_err(|_| Error::invalid("Invalid OAuth issuer."))?;
        if origin.origin().ascii_serialization() != self.config.public_origin
            || (origin.scheme() != "https"
                && !(origin.scheme() == "http" && origin.host_str() == Some("127.0.0.1")))
        {
            return Err(Error::invalid(
                "OAuth requires HTTPS or literal loopback development origin.",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for c in &config.clients {
            if c.client_id.is_empty()
                || c.client_id.len() > 200
                || c.client_id.chars().any(char::is_control)
                || c.client_id.starts_with("https://")
                || c.client_id.starts_with("dcr_")
                || !ids.insert(c.client_id.clone())
                || c.name.is_empty()
                || c.name.len() > 200
                || c.name.chars().any(char::is_control)
                || c.redirect_uris.len() > 8
            {
                return Err(Error::invalid("Invalid OAuth client configuration."));
            }
            for r in &c.redirect_uris {
                let u = Url::parse(r).map_err(|_| Error::invalid("Invalid OAuth redirect."))?;
                if u.fragment().is_some()
                    || u.query().is_some()
                    || !u.username().is_empty()
                    || u.password().is_some()
                    || u.host_str().is_none()
                    || u.as_str() != r
                    || r.len() > 2048
                    || !(u.scheme() == "https"
                        || (u.scheme() == "http"
                            && matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))))
                {
                    return Err(Error::invalid(
                        "Redirect must be a registered HTTPS or loopback URL without query/fragment.",
                    ));
                }
            }
        }
        if config.client_id_metadata_documents && self.client_fetcher.is_none() {
            self.client_fetcher = Some(Rc::new(HttpMetadataFetcher));
        }
        self.oauth = Some(config);
        Ok(self)
    }
    /// Replace the metadata-document transport (tests and pinned deployments).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_client_fetcher(mut self, fetcher: Rc<dyn ClientMetadataFetch>) -> Self {
        self.client_fetcher = Some(fetcher);
        self
    }
    pub(super) fn oauth_profile(&self) -> &'static OAuthProfile {
        if self.keys.is_some() {
            &KEYS_PROFILE
        } else {
            &WAYPOST_PROFILE
        }
    }
    /// Canonical scope string: known, non-repeated values in profile order.
    pub(super) fn normalize_scope(&self, raw: Option<&str>) -> Result<String> {
        let profile = self.oauth_profile();
        let Some(raw) = raw else {
            return Ok(profile.default_scope.into());
        };
        let requested: Vec<_> = raw.split(' ').collect();
        if requested.iter().any(|s| !profile.scopes.contains(s))
            || (1..requested.len()).any(|i| requested[..i].contains(&requested[i]))
        {
            return Err(oauth_error("invalid_scope"));
        }
        Ok(profile
            .scopes
            .iter()
            .filter(|s| requested.contains(s))
            .copied()
            .collect::<Vec<_>>()
            .join(" "))
    }
    /// SQL predicate: this client ID is still authorized by current configuration.
    /// Removing a preregistered client, disabling metadata documents or disabling
    /// a dynamic registration stops its existing grants on the next request.
    pub(super) fn client_guard(&self, column: &str) -> (String, Vec<Sql>) {
        let config = self.oauth.as_ref();
        let cimd = config.is_some_and(|c| c.client_id_metadata_documents);
        let mut ids: Vec<String> = config
            .map(|c| c.clients.iter().map(|c| c.client_id.clone()).collect())
            .unwrap_or_default();
        if cimd {
            ids.extend(self.hosted_client_id());
        }
        let ids = json!(ids).to_string();
        let dcr = config.is_some_and(|c| c.dynamic_registration);
        (
            format!(
                "({column} IN(SELECT value FROM json_each(?)) OR (?=1 AND substr({column},1,8)='https://') OR (?=1 AND EXISTS(SELECT 1 FROM oauth_registered_clients orc WHERE orc.client_id={column} AND orc.disabled=0)))"
            ),
            vec![ids.into(), i64::from(cimd).into(), i64::from(dcr).into()],
        )
    }
    /// Cheap check for refresh, revocation and polling: no document fetch.
    pub(super) async fn client_allowed(&self, id: &str) -> Result<()> {
        let config = self
            .oauth
            .as_ref()
            .ok_or_else(|| oauth_error("invalid_client"))?;
        if config.clients.iter().any(|c| c.client_id == id)
            || (config.client_id_metadata_documents
                && (registry::metadata_document_url(id).is_some()
                    || self.hosted_client_document(id).is_some()))
        {
            return Ok(());
        }
        if config.dynamic_registration && id.starts_with("dcr_") {
            let rows = self
                .db
                .query(Statement::new(
                    "SELECT 1 AS ok FROM oauth_registered_clients WHERE client_id=? AND disabled=0",
                    vec![id.into()],
                ))
                .await?;
            if !rows.is_empty() {
                return Ok(());
            }
        }
        Err(oauth_error("invalid_client"))
    }
    /// Full client identity with redirect URIs, fetching a metadata document if needed.
    pub(super) async fn resolve_client(&self, id: &str) -> Result<ResolvedClient> {
        let config = self
            .oauth
            .as_ref()
            .ok_or_else(|| oauth_error("invalid_client"))?;
        if let Some(c) = config.clients.iter().find(|c| c.client_id == id) {
            return Ok(ResolvedClient {
                client_id: c.client_id.clone(),
                name: c.name.clone(),
                kind: ClientKind::Preregistered,
                preregistered: Some(c.clone()),
                redirect_uris: vec![],
            });
        }
        if config.client_id_metadata_documents
            && (id.starts_with("https://") || self.hosted_client_document(id).is_some())
        {
            let document = self.metadata_document(id).await?;
            return Ok(ResolvedClient {
                client_id: id.into(),
                name: document.client_name,
                kind: ClientKind::MetadataDocument,
                preregistered: None,
                redirect_uris: document.redirect_uris,
            });
        }
        if config.dynamic_registration && id.starts_with("dcr_") && id.len() <= 64 {
            let rows = self.db.query(Statement::new("SELECT client_name,redirect_uris FROM oauth_registered_clients WHERE client_id=? AND disabled=0",vec![id.into()])).await?;
            let row = rows.first().ok_or_else(|| oauth_error("invalid_client"))?;
            return Ok(ResolvedClient {
                client_id: id.into(),
                name: text(row, "client_name")?,
                kind: ClientKind::Dynamic,
                preregistered: None,
                redirect_uris: serde_json::from_str(&text(row, "redirect_uris")?)
                    .map_err(|_| Error::internal("decode registered redirects"))?,
            });
        }
        Err(oauth_error("invalid_client"))
    }
    async fn metadata_document(&self, id: &str) -> Result<ClientDocument> {
        // A document this deployment hosts itself is resolved without a
        // subrequest to its own origin (plain HTTP in local development).
        if let Some(document) = self.hosted_client_document(id) {
            return Ok(document);
        }
        let url =
            registry::metadata_document_url(id).ok_or_else(|| oauth_error("invalid_client"))?;
        let now = self.clock.now_ms();
        let cached = self.db.query(Statement::new("SELECT client_name,redirect_uris FROM oauth_client_documents WHERE client_id=? AND expires_at>?",vec![id.into(),now.into()])).await?;
        if let Some(row) = cached.first() {
            return Ok(ClientDocument {
                client_name: text(row, "client_name")?,
                redirect_uris: serde_json::from_str(&text(row, "redirect_uris")?)
                    .map_err(|_| Error::internal("decode cached redirects"))?,
            });
        }
        let fetcher = self
            .client_fetcher
            .as_ref()
            .ok_or_else(|| oauth_error("invalid_client"))?;
        // Unreachable, slow, oversized or redirected documents all mean: unknown client.
        let fetched = fetcher
            .fetch(&url)
            .await
            .map_err(|_| oauth_error("invalid_client"))?;
        let document = registry::parse_document(id, &fetched)?;
        let now = self.clock.now_ms();
        let expires = now + registry::cache_ttl_ms(fetched.cache_control.as_deref());
        let redirects = serde_json::to_string(&document.redirect_uris)
            .map_err(|_| Error::internal("encode redirects"))?;
        // Bounded cache; when full, the document is used once without caching.
        self.db.batch(vec![
            Statement::new("DELETE FROM oauth_client_documents WHERE expires_at<=?",vec![now.into()]),
            Statement::new("INSERT INTO oauth_client_documents(client_id,client_name,redirect_uris,fetched_at,expires_at) SELECT ?,?,?,?,? WHERE (SELECT count(*) FROM oauth_client_documents)<1000 ON CONFLICT(client_id) DO UPDATE SET client_name=excluded.client_name,redirect_uris=excluded.redirect_uris,fetched_at=excluded.fetched_at,expires_at=excluded.expires_at",vec![id.into(),document.client_name.clone().into(),redirects.into(),now.into(),expires.into()]),
        ]).await?;
        Ok(document)
    }
    async fn register_client(&self, r: &Request) -> Result<Response> {
        let config = self.oauth.as_ref().ok_or_else(Error::not_found)?;
        if !config.dynamic_registration {
            return Err(Error::not_found());
        }
        if r.headers
            .get("content-type")
            .and_then(|s| s.split(';').next())
            .map(str::trim)
            != Some("application/json")
            || r.headers.contains_key("authorization")
        {
            return Ok(Response::json(
                400,
                json!({"error":"invalid_client_metadata"}),
            ));
        }
        let body = match crate::json::parse(&r.body, 16384) {
            Ok(body) => body,
            Err(_) => {
                return Ok(Response::json(
                    400,
                    json!({"error":"invalid_client_metadata"}),
                ));
            }
        };
        let registration = match registry::parse_registration(&body) {
            Ok(r) => r,
            Err(code) => return Ok(Response::json(400, json!({"error":code}))),
        };
        let now = self.clock.now_ms();
        let id = random_id("dcr")?;
        let redirects = serde_json::to_string(&registration.redirect_uris)
            .map_err(|_| Error::internal("encode redirects"))?;
        let grants = serde_json::to_string(&registration.grant_types)
            .map_err(|_| Error::internal("encode grants"))?;
        // Registrations never used for an approved grant expire after a day; the
        // live total is capped so anonymous registration cannot grow storage.
        let rows = self.db.batch(vec![
            Statement::new("DELETE FROM oauth_registered_clients WHERE created_at<? AND NOT EXISTS(SELECT 1 FROM oauth_requests q WHERE q.client_id=oauth_registered_clients.client_id AND q.status IN('approved','consumed'))",vec![(now - 86_400_000).into()]),
            Statement::new("INSERT INTO oauth_registered_clients(client_id,client_name,redirect_uris,grant_types,created_at) SELECT ?,?,?,?,? WHERE (SELECT count(*) FROM oauth_registered_clients)<1000 RETURNING client_id",vec![id.clone().into(),registration.client_name.clone().into(),redirects.into(),grants.into(),now.into()]),
        ]).await?;
        if rows[1].is_empty() {
            return Err(oauth_error("temporarily_unavailable"));
        }
        Ok(Response::json(
            201,
            json!({"client_id":id,"client_id_issued_at":now/1000,"client_name":registration.client_name,"redirect_uris":registration.redirect_uris,"grant_types":registration.grant_types,"response_types":["code"],"token_endpoint_auth_method":"none"}),
        ))
    }
    pub(super) fn oauth_resource(&self) -> String {
        format!("{}/mcp", self.config.public_origin)
    }
    pub(super) fn oauth_challenge(&self, response: &mut Response) {
        if self.oauth.is_some() {
            crate::gateway::mcp::challenge(
                response,
                &self.config.public_origin,
                self.oauth_profile().default_scope,
            );
        }
    }
    pub(super) async fn oauth_handle(&self, r: &Request) -> Response {
        let result = self.oauth_action(r).await;
        let mut response = match result {
            Ok(r) => r,
            Err(e) => {
                let (code, status) = match e.code {
                    "invalid_request"
                    | "invalid_grant"
                    | "invalid_scope"
                    | "invalid_target"
                    | "unsupported_grant_type"
                    | "unsupported_response_type"
                    | "authorization_pending"
                    | "slow_down"
                    | "expired_token"
                    | "access_denied" => (e.code, 400),
                    "invalid_client" => ("invalid_client", 400),
                    "UNAUTHENTICATED" => ("access_denied", 401),
                    "FORBIDDEN" => ("access_denied", 403),
                    "NOT_FOUND" => ("invalid_request", 404),
                    "RATE_LIMITED" => ("temporarily_unavailable", 429),
                    "temporarily_unavailable" => ("temporarily_unavailable", 503),
                    "INTERNAL_ERROR" | "STORAGE_UNAVAILABLE" => ("server_error", 503),
                    _ => ("invalid_request", 400),
                };
                Response::json(status, json!({"error":code}))
            }
        };
        response
            .headers
            .insert("cache-control".into(), "no-store".into());
        response.headers.insert("pragma".into(), "no-cache".into());
        response
            .headers
            .insert("referrer-policy".into(), "no-referrer".into());
        response
    }
    async fn oauth_action(&self, r: &Request) -> Result<Response> {
        let config = self.oauth.as_ref().ok_or_else(Error::not_found)?;
        if r.headers
            .get("origin")
            .is_some_and(|o| o != &self.config.public_origin)
        {
            return Err(Error::forbidden());
        }
        let profile = self.oauth_profile();
        if r.method == "GET"
            && matches!(
                r.path.as_str(),
                "/.well-known/oauth-protected-resource/mcp"
                    | "/.well-known/oauth-protected-resource"
            )
        {
            return Ok(Response::json(
                200,
                json!({"resource":self.oauth_resource(),"authorization_servers":[self.config.public_origin],"scopes_supported":profile.scopes,"bearer_methods_supported":["header"],"resource_name":profile.resource_name}),
            ));
        }
        if r.method == "GET" && r.path == "/.well-known/oauth-authorization-server" {
            let origin = &self.config.public_origin;
            let mut grants = vec!["authorization_code", "refresh_token"];
            let mut metadata = json!({"issuer":origin,"authorization_endpoint":format!("{origin}/oauth/authorize"),"token_endpoint":format!("{origin}/oauth/token"),"revocation_endpoint":format!("{origin}/oauth/revoke"),"response_types_supported":["code"],"token_endpoint_auth_methods_supported":["none"],"revocation_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":profile.scopes,"authorization_response_iss_parameter_supported":true,"client_id_metadata_document_supported":config.client_id_metadata_documents});
            if profile.device_grant {
                grants.push("urn:ietf:params:oauth:grant-type:device_code");
                metadata["device_authorization_endpoint"] =
                    json!(format!("{origin}/oauth/device_authorization"));
            }
            if config.dynamic_registration {
                metadata["registration_endpoint"] = json!(format!("{origin}/oauth/register"));
            }
            metadata["grant_types_supported"] = json!(grants);
            return Ok(Response::json(200, metadata));
        }
        if r.method == "GET"
            && let Some(document) = self.hosted_client_document_json(&r.path)
        {
            return Ok(Response::json(200, document));
        }
        if r.path == "/oauth/authorize" && r.method == "GET" {
            return self.oauth_authorize(r, parse_params(&r.query)?).await;
        }
        if r.path == "/oauth/consent" {
            let body = if r.method == "GET" {
                serde_json::to_value(parse_params(&r.query)?)
                    .map_err(|_| oauth_error("invalid_request"))?
            } else {
                crate::json::parse(&r.body, self.limits.max_json_bytes)?
            };
            return self.oauth_consent(r, body).await;
        }
        if r.path == "/oauth/device_consent" && r.method == "POST" && profile.device_grant {
            return self
                .oauth_device_consent(r, crate::json::parse(&r.body, self.limits.max_json_bytes)?)
                .await;
        }
        if r.path == "/oauth/register" && r.method == "POST" {
            return self.register_client(r).await;
        }
        if r.method != "POST" {
            return Err(Error::not_found());
        }
        // Public clients only. Reject Basic/other authorization instead of
        // silently treating failed client authentication as anonymous.
        if r.headers.contains_key("authorization") {
            return Err(oauth_error("invalid_client"));
        }
        if r.headers
            .get("content-type")
            .and_then(|s| s.split(';').next())
            != Some("application/x-www-form-urlencoded")
        {
            return Err(oauth_error("invalid_request"));
        }
        let raw = std::str::from_utf8(&r.body).map_err(|_| oauth_error("invalid_request"))?;
        let params = parse_params(raw)?;
        let result = match r.path.as_str() {
            "/oauth/token" => self.oauth_token(params).await?,
            "/oauth/revoke" => self.oauth_revoke(params).await?,
            "/oauth/device_authorization" if profile.device_grant => {
                self.oauth_device_authorization(params).await?
            }
            _ => return Err(Error::not_found()),
        };
        Ok(Response::json(200, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_callback_variation_is_explicit_and_host_path_bound() {
        let mut client = OAuthClient {
            client_id: "native".into(),
            name: "Native".into(),
            redirect_uris: vec![
                "http://127.0.0.1:8765/callback".into(),
                "http://localhost:8766/callback".into(),
                "http://[::1]:8767/callback".into(),
            ],
            allow_loopback_port_variation: false,
        };
        assert!(client.accepts_redirect("http://localhost:8766/callback"));
        assert!(!client.accepts_redirect("http://127.0.0.1:54321/callback"));
        client.allow_loopback_port_variation = true;
        assert!(client.accepts_redirect("http://127.0.0.1:54321/callback"));
        assert!(client.accepts_redirect("http://[::1]:54321/callback"));
        for uri in [
            "http://localhost:54321/callback",
            "http://127.0.0.2:54321/callback",
            "http://127.0.0.1.evil:54321/callback",
            "https://127.0.0.1:54321/callback",
            "http://127.0.0.1:54321/callback/suffix",
            "http://127.0.0.1:54321/callback?x=1",
            "http://127.0.0.1:54321/callback#x",
            "http://user@127.0.0.1:54321/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1/callback",
            "http://2130706433:54321/callback",
            "http://127.0.0.1:54321/a/../callback",
        ] {
            assert!(!client.accepts_redirect(uri), "{uri}");
        }
        let old: OAuthConfig = serde_json::from_str(
            r#"{"clients":[{"client_id":"x","name":"X","redirect_uris":[]}]}"#,
        )
        .unwrap();
        assert!(!old.clients[0].allow_loopback_port_variation);
    }
    #[test]
    fn edge_throttle_preserves_oauth_error_contract() {
        let response = rate_limited_response();
        assert_eq!(response.status, 429);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body, json!({"error":"temporarily_unavailable"}));
        assert_eq!(response.headers["retry-after"], "60");
        assert_eq!(response.headers["cache-control"], "no-store");
    }
    #[test]
    fn form_parameters_reject_ambiguity() {
        for raw in [
            "client_id=a&client_id=b",
            "x=%",
            "x=%ff",
            "x=%GG",
            "a=1&%61=2",
        ] {
            assert!(parse_params(raw).is_err(), "{raw}");
        }
        let parsed =
            parse_params("resource=https%3A%2F%2Fexample.test%2Fmcp&scope=waypost").unwrap();
        assert_eq!(parsed["resource"], "https://example.test/mcp");
        assert!(parse_params(&"a".repeat(16385)).is_err());
    }
}
