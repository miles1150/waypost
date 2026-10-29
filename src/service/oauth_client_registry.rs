//! Bounded public-client discovery. Registration never grants account/Space access.
use super::oauth::{OAuthClient, oauth_error};
use super::*;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use url::Url;

pub trait OAuthClientMetadataFetcher {
    /// Trusted adapter must enforce public DNS+IP pinning, HTTPS, no redirects,
    /// 200/JSON only, ten-second total deadline and 16 KiB response bound.
    fn fetch<'a>(
        &'a self,
        client_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClientMetadataDocument>> + 'a>>;
}
pub struct OAuthClientMetadataDocument {
    pub body: Vec<u8>,
    pub max_age_seconds: u32,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthClientDiscoveryConfig {
    pub dynamic_registration: bool,
    pub max_clients: u32,
    pub registrations_per_minute: u32,
    pub cimd_cache_seconds: u32,
}
impl Default for OAuthClientDiscoveryConfig {
    fn default() -> Self {
        Self {
            dynamic_registration: true,
            max_clients: 1000,
            registrations_per_minute: 30,
            cimd_cache_seconds: 3600,
        }
    }
}
pub fn validate_cimd_url(id: &str) -> Result<Url> {
    let u = Url::parse(id).map_err(|_| oauth_error("invalid_client"))?;
    if id.len() > 2048
        || u.as_str() != id
        || u.scheme() != "https"
        || u.host_str().is_none()
        || u.path() == "/"
        || u.path().is_empty()
        || u.port_or_known_default() != Some(443)
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(oauth_error("invalid_client"));
    }
    Ok(u)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    #[serde(default)]
    client_id: Option<String>,
    client_name: String,
    redirect_uris: Vec<String>,
    #[serde(default = "auth_none")]
    token_endpoint_auth_method: String,
    #[serde(default = "grants")]
    grant_types: Vec<String>,
    #[serde(default = "responses")]
    response_types: Vec<String>,
    #[serde(default = "scope")]
    scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logo_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tos_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    software_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    software_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contacts: Option<Vec<String>>,
}
fn auth_none() -> String {
    "none".into()
}
fn grants() -> Vec<String> {
    vec!["authorization_code".into(), "refresh_token".into()]
}
fn responses() -> Vec<String> {
    vec!["code".into()]
}
fn scope() -> String {
    "waypost".into()
}
fn metadata(bytes: &[u8], id: Option<&str>, keys: bool) -> Result<Metadata> {
    if bytes.len() > 16384 {
        return Err(oauth_error("invalid_client_metadata"));
    }
    let mut m: Metadata =
        serde_json::from_slice(bytes).map_err(|_| oauth_error("invalid_client_metadata"))?;
    if keys {
        let raw: Value =
            serde_json::from_slice(bytes).map_err(|_| oauth_error("invalid_client_metadata"))?;
        if raw.get("scope").is_none() {
            m.scope = "keys:read keys:write".into();
        }
    }
    if m.client_id.as_deref() != id
        || m.client_name.is_empty()
        || m.client_name.len() > 200
        || m.client_name.chars().any(char::is_control)
        || !(1..=8).contains(&m.redirect_uris.len())
        || m.token_endpoint_auth_method != "none"
        || m.response_types != responses()
        || !m.grant_types.iter().any(|v| v == "authorization_code")
        || m.grant_types.iter().any(|v| !grants().contains(v))
        || m.grant_types.len() != 2
        || !m.grant_types.iter().any(|v| v == "refresh_token")
        || if keys {
            m.scope != "keys:read" && m.scope != "keys:write" && m.scope != "keys:read keys:write"
        } else {
            m.scope != "waypost"
        }
        || m.application_type
            .as_ref()
            .is_some_and(|v| v != "native" && v != "web")
    {
        return Err(oauth_error("invalid_client_metadata"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in &m.redirect_uris {
        let u = Url::parse(r).map_err(|_| oauth_error("invalid_redirect_uri"))?;
        if r.len() > 2048
            || u.as_str() != r
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || !seen.insert(r)
            || !(u.scheme() == "https"
                || u.scheme() == "http"
                    && matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
        {
            return Err(oauth_error("invalid_redirect_uri"));
        }
    }
    for s in [
        &m.client_uri,
        &m.logo_uri,
        &m.tos_uri,
        &m.policy_uri,
        &m.software_id,
        &m.software_version,
    ]
    .into_iter()
    .flatten()
    {
        if s.len() > 2048 || s.chars().any(char::is_control) {
            return Err(oauth_error("invalid_client_metadata"));
        }
    }
    if m.contacts.as_ref().is_some_and(|v| {
        v.len() > 8
            || v.iter()
                .any(|s| s.len() > 200 || s.chars().any(char::is_control))
    }) {
        return Err(oauth_error("invalid_client_metadata"));
    }
    Ok(m)
}
pub(super) struct ResolvedClient {
    pub client: OAuthClient,
    pub revision: i64,
    pub source: String,
}
impl std::ops::Deref for ResolvedClient {
    type Target = OAuthClient;
    fn deref(&self) -> &OAuthClient {
        &self.client
    }
}
impl ResolvedClient {
    pub(super) fn accepts_redirect(&self, candidate: &str) -> bool {
        if self.client.accepts_redirect(candidate) {
            return true;
        }
        if self.source == "legacy" {
            return false;
        }
        let Ok(mut u) = Url::parse(candidate) else {
            return false;
        };
        // RFC8252 literal-IP loopback port variation; localhost stays exact.
        if u.as_str() != candidate
            || u.scheme() != "http"
            || !matches!(u.host_str(), Some("127.0.0.1" | "[::1]"))
            || u.port().is_none_or(|p| p == 0)
        {
            return false;
        }
        self.redirect_uris.iter().any(|r| {
            let Ok(e) = Url::parse(r) else {
                return false;
            };
            if e.scheme() != "http" || e.host_str() != u.host_str() {
                return false;
            }
            if u.set_port(e.port()).is_err() {
                return false;
            }
            u.as_str() == r
        })
    }
}
fn resolved(row: &Row) -> Result<ResolvedClient> {
    let id = text(row, "client_id")?;
    let m: Metadata = serde_json::from_str(&text(row, "metadata_json")?)
        .map_err(|_| oauth_error("invalid_client"))?;
    Ok(ResolvedClient {
        client: OAuthClient {
            client_id: id,
            name: m.client_name,
            redirect_uris: m.redirect_uris,
            allow_loopback_port_variation: text(row, "source")? == "legacy"
                && integer(row, "allow_loopback_port_variation")? != 0,
        },
        revision: integer(row, "revision")?,
        source: text(row, "source")?,
    })
}
impl<D: Database, O: ObjectStore> App<D, O> {
    pub fn with_oauth_client_discovery(
        mut self,
        config: OAuthClientDiscoveryConfig,
        fetcher: Option<Rc<dyn OAuthClientMetadataFetcher>>,
    ) -> Result<Self> {
        if self.oidc.is_none()
            || !(1..=10000).contains(&config.max_clients)
            || !(1..=1000).contains(&config.registrations_per_minute)
            || !(1..=3600).contains(&config.cimd_cache_seconds)
        {
            return Err(Error::invalid(
                "Invalid OAuth client discovery configuration.",
            ));
        }
        let u = Url::parse(&self.config.public_origin)
            .map_err(|_| Error::invalid("Invalid OAuth origin."))?;
        if u.origin().ascii_serialization() != self.config.public_origin
            || !(u.scheme() == "https" || u.scheme() == "http" && u.host_str() == Some("127.0.0.1"))
        {
            return Err(Error::invalid("OAuth requires HTTPS or literal loopback."));
        }
        self.oauth_discovery = Some(config);
        self.oauth_metadata_fetcher = fetcher;
        Ok(self)
    }
    pub(super) fn oauth_enabled(&self) -> bool {
        self.oauth_discovery.is_some()
    }
    pub(super) async fn resolve_dynamic_client(&self, id: &str) -> Result<ResolvedClient> {
        let config = self
            .oauth_discovery
            .as_ref()
            .ok_or_else(|| oauth_error("invalid_client"))?;
        let now = self.clock.now_ms();
        let rows=self.db.query(Statement::new("SELECT * FROM oauth_dynamic_clients WHERE client_id=? AND disabled=0 AND valid_until>?",vec![id.into(),now.into()])).await?;
        if let Some(row) = rows.first() {
            let client = resolved(row)?;
            if client.source == "dcr" && config.dynamic_registration
                || client.source == "cimd" && self.oauth_metadata_fetcher.is_some()
                || client.source == "legacy"
            {
                return Ok(client);
            }
        }
        validate_cimd_url(id)?;
        let fetcher = self
            .oauth_metadata_fetcher
            .as_ref()
            .ok_or_else(|| oauth_error("invalid_client"))?;
        // Persistent finite fetch budget also covers uncached misses. Failed documents
        // never enter the client cache. No unbounded per-ID negative-cache records.
        self.reserve_client_budget("cimd").await?;
        let started = self.clock.now_ms();
        let document = fetcher.fetch(id).await?;
        if document.max_age_seconds == 0 {
            return Err(oauth_error("invalid_client"));
        }
        let m = metadata(&document.body, Some(id), self.keys.is_some())?;
        let raw = serde_json::to_string(&m).map_err(|_| Error::storage())?;
        let fp = hex::encode(Sha256::digest(raw.as_bytes()));
        let now = self.clock.now_ms();
        let until =
            started + (document.max_age_seconds.min(config.cimd_cache_seconds) as i64) * 1000;
        if now < started || now >= until {
            return Err(oauth_error("invalid_client"));
        }
        let rows=self.db.batch(vec![Self::unreferenced_client_cleanup(now,id),Statement::new("INSERT INTO oauth_dynamic_clients(client_id,source,metadata_json,security_fingerprint,revision,valid_until,created_at,updated_at) SELECT ?,'cimd',?,?,1,?,?,? WHERE (SELECT count(*) FROM oauth_dynamic_clients)<? OR EXISTS(SELECT 1 FROM oauth_dynamic_clients old WHERE old.client_id=? AND old.source='cimd' AND old.disabled=0) ON CONFLICT(client_id) DO UPDATE SET metadata_json=excluded.metadata_json,security_fingerprint=excluded.security_fingerprint,revision=oauth_dynamic_clients.revision+CASE WHEN oauth_dynamic_clients.security_fingerprint<>excluded.security_fingerprint THEN 1 ELSE 0 END,valid_until=excluded.valid_until,updated_at=excluded.updated_at WHERE oauth_dynamic_clients.source='cimd' AND oauth_dynamic_clients.disabled=0 RETURNING *",vec![id.into(),raw.into(),fp.into(),until.into(),now.into(),now.into(),(config.max_clients as i64).into(),id.into()])]).await?;
        rows.last()
            .and_then(|rows| rows.first())
            .map(resolved)
            .transpose()?
            .ok_or_else(|| oauth_error("temporarily_unavailable"))
    }
    async fn reserve_client_budget(&self, bucket: &str) -> Result<()> {
        let config = self.oauth_discovery.as_ref().ok_or_else(Error::not_found)?;
        let now = self.clock.now_ms();
        let nonce = random_id("budget")?;
        let rows=self.db.batch(vec![Statement::new("INSERT INTO oauth_client_budget(bucket,window_start,used,nonce) VALUES(?,?,1,?) ON CONFLICT(bucket) DO UPDATE SET window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END,used=CASE WHEN window_start<=? THEN 1 ELSE used+1 END,nonce=excluded.nonce WHERE window_start<=? OR used<? RETURNING nonce",vec![bucket.into(),now.into(),nonce.into(),(now-60000).into(),(now-60000).into(),(now-60000).into(),(config.registrations_per_minute as i64).into()])]).await?;
        if rows[0].is_empty() {
            return Err(oauth_error("temporarily_unavailable"));
        }
        Ok(())
    }
    fn unreferenced_client_cleanup(now: i64, keep_id: &str) -> Statement {
        Statement::new(
            "DELETE FROM oauth_dynamic_clients WHERE disabled=0 AND ((source='dcr' AND created_at<?) OR (source='cimd' AND valid_until<=?)) AND NOT EXISTS(SELECT 1 FROM oauth_requests q WHERE q.client_id=oauth_dynamic_clients.client_id AND q.status IN('pending','approved') AND q.expires_at>?) AND NOT EXISTS(SELECT 1 FROM oauth_families f WHERE f.client_id=oauth_dynamic_clients.client_id) AND NOT EXISTS(SELECT 1 FROM key_oauth_families k WHERE k.client_id=oauth_dynamic_clients.client_id) AND client_id<>?",
            vec![
                (now - 86_400_000).into(),
                now.into(),
                now.into(),
                keep_id.into(),
            ],
        )
    }
    pub(super) async fn oauth_register(&self, r: &Request) -> Result<Response> {
        let config = self
            .oauth_discovery
            .as_ref()
            .filter(|c| c.dynamic_registration)
            .ok_or_else(Error::not_found)?;
        if r.method != "POST"
            || r.headers.contains_key("authorization")
            || r.headers
                .get("content-type")
                .and_then(|s| s.split(';').next())
                != Some("application/json")
        {
            return Err(oauth_error("invalid_request"));
        }
        let mut m = metadata(&r.body, None, self.keys.is_some())?;
        self.reserve_client_budget("dcr").await?;
        let id = random_id("dcr")?;
        m.client_id = Some(id.clone());
        let raw = serde_json::to_string(&m).map_err(|_| Error::storage())?;
        let fp = hex::encode(Sha256::digest(raw.as_bytes()));
        let now = self.clock.now_ms();
        let rows=self.db.batch(vec![Self::unreferenced_client_cleanup(now,""),Statement::new("INSERT INTO oauth_dynamic_clients(client_id,source,metadata_json,security_fingerprint,revision,valid_until,created_at,updated_at) SELECT ?,'dcr',?,?,1,?,?,? WHERE (SELECT count(*) FROM oauth_dynamic_clients)<? RETURNING client_id",vec![id.clone().into(),raw.into(),fp.into(),9_007_199_254_740_991i64.into(),now.into(),now.into(),(config.max_clients as i64).into()])]).await?;
        if rows.last().is_none_or(Vec::is_empty) {
            return Err(oauth_error("temporarily_unavailable"));
        }
        let mut out = serde_json::to_value(m).map_err(|_| Error::storage())?;
        out["client_id_issued_at"] = json!(now / 1000);
        Ok(Response::json(201, out))
    }
    /// Reused in every final grant/consent/token SQL guard. Alias refers to a
    /// request/family carrying its immutable approved client revision.
    pub(super) fn oauth_client_guard(&self, alias: &str, now: i64) -> (String, Vec<Sql>) {
        let dcr = self
            .oauth_discovery
            .as_ref()
            .is_some_and(|c| c.dynamic_registration);
        let cimd = self.oauth_discovery.is_some() && self.oauth_metadata_fetcher.is_some();
        let legacy = self.oauth_discovery.is_some();
        (
            format!(
                "EXISTS(SELECT 1 FROM oauth_dynamic_clients dc WHERE dc.client_id={alias}.client_id AND dc.revision={alias}.client_revision AND dc.disabled=0 AND dc.valid_until>? AND ((dc.source='dcr' AND ?) OR (dc.source='cimd' AND ?) OR (dc.source='legacy' AND ?)))"
            ),
            vec![now.into(), dcr.into(), cimd.into(), legacy.into()],
        )
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::native::{FileStore, SqliteDb};
    use std::cell::{Cell, RefCell};
    struct Time(Cell<i64>);
    impl Clock for Time {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
    }
    struct Fetch {
        doc: RefCell<Value>,
        clock: Rc<Time>,
        calls: Cell<u32>,
        delay: Cell<i64>,
        ttl: Cell<u32>,
    }
    impl OAuthClientMetadataFetcher for Fetch {
        fn fetch<'a>(
            &'a self,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<OAuthClientMetadataDocument>> + 'a>> {
            Box::pin(async move {
                self.calls.set(self.calls.get() + 1);
                self.clock.0.set(self.clock.now_ms() + self.delay.get());
                Ok(OAuthClientMetadataDocument {
                    body: serde_json::to_vec(&*self.doc.borrow()).unwrap(),
                    max_age_seconds: self.ttl.get(),
                })
            })
        }
    }
    type TestApp = App<SqliteDb, FileStore>;
    fn document() -> Value {
        json!({"client_name":"Untrusted <b>client</b>","redirect_uris":["http://127.0.0.1:8765/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]})
    }
    async fn fixture() -> (tempfile::TempDir, TestApp, Rc<Time>) {
        let dir = tempfile::tempdir().unwrap();
        let clock = Rc::new(Time(Cell::new(1_000_000)));
        let mut app = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: "test-only-admin-secret-long-enough".into(),
                public_origin: "http://127.0.0.1:8787".into(),
            },
        )
        .with_clock(clock.clone());
        app.oidc = Some(accounts_oidc::OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "fixture".into(),
            authorization_endpoint: "https://issuer.example/auth".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_secret: None,
            keys: vec![],
            google_jwks: false,
        });
        let app = app
            .with_oauth_client_discovery(OAuthClientDiscoveryConfig::default(), None)
            .unwrap();
        (dir, app, clock)
    }
    async fn register(app: &TestApp, body: Value) -> Result<Value> {
        let mut r = Request::json("POST", "/oauth/register", "", body);
        r.headers.remove("authorization");
        let response = app.oauth_register(&r).await?;
        assert_eq!(response.status, 201);
        Ok(serde_json::from_slice(&response.body).unwrap())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn dcr_public_metadata_redirects_and_atomic_budgets() {
        let (_dir, mut app, clock) = fixture().await;
        app.oauth_discovery.as_mut().unwrap().max_clients = 2;
        for field in ["client_secret", "jwks_uri"] {
            let mut body = document();
            body[field] = json!("https://private.example");
            assert!(register(&app, body).await.is_err());
        }
        for redirect in [
            "http://10.0.0.1/callback",
            "https://client.example/callback?x=1",
            "https://client.example/*#bad",
        ] {
            let mut body = document();
            body["redirect_uris"] = json!([redirect]);
            assert!(register(&app, body).await.is_err());
        }
        let mut body = document();
        body["grant_types"] = json!(["authorization_code"]);
        assert!(register(&app, body).await.is_err());
        let first = register(&app, document()).await.unwrap();
        let id = first["client_id"].as_str().unwrap();
        assert!(id.starts_with("dcr_"));
        assert!(first.get("client_secret").is_none());
        let client = app.oauth_client(id).await.unwrap();
        assert_eq!(client.revision, 1);
        assert!(client.accepts_redirect("http://127.0.0.1:43210/callback"));
        assert!(!client.accepts_redirect("http://localhost:43210/callback"));
        register(&app, document()).await.unwrap();
        assert_eq!(
            register(&app, document()).await.unwrap_err().code,
            "temporarily_unavailable"
        );
        app.oauth_discovery.as_mut().unwrap().max_clients = 10;
        app.oauth_discovery
            .as_mut()
            .unwrap()
            .registrations_per_minute = 1;
        assert!(register(&app, document()).await.is_err());
        clock.0.set(clock.now_ms() + 60_001);
        register(&app, document()).await.unwrap();
        assert!(register(&app, document()).await.is_err());
        let mut device = BTreeMap::from([
            ("client_id".into(), id.into()),
            ("resource".into(), app.oauth_resource()),
        ]);
        assert_eq!(
            app.oauth_device_authorization(device.clone())
                .await
                .unwrap_err()
                .code,
            "unauthorized_client"
        );
        device.insert(
            "grant_type".into(),
            "urn:ietf:params:oauth:grant-type:device_code".into(),
        );
        assert_eq!(
            app.oauth_token(device).await.unwrap_err().code,
            "unauthorized_client"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn cimd_cache_revision_capacity_and_expired_or_invalid_documents_fail_closed() {
        let (_dir, mut app, clock) = fixture().await;
        let id = "https://client.example/metadata.json";
        let mut body = document();
        body["client_id"] = json!(id);
        let fetch = Rc::new(Fetch {
            doc: RefCell::new(body),
            clock: clock.clone(),
            calls: 0.into(),
            delay: 0.into(),
            ttl: 60.into(),
        });
        app.oauth_metadata_fetcher = Some(fetch.clone());
        app.oauth_discovery.as_mut().unwrap().max_clients = 1;
        assert_eq!(app.oauth_client(id).await.unwrap().revision, 1);
        assert_eq!(app.oauth_client(id).await.unwrap().revision, 1);
        assert_eq!(fetch.calls.get(), 1);
        clock.0.set(clock.now_ms() + 61_000);
        fetch.doc.borrow_mut()["client_name"] = json!("Changed client");
        assert_eq!(app.oauth_client(id).await.unwrap().revision, 2); // existing refresh works at capacity
        clock.0.set(clock.now_ms() + 61_000);
        fetch.doc.borrow_mut()["client_id"] = json!("https://attacker.example/metadata");
        assert!(app.oauth_client(id).await.is_err());
        let rows = app
            .db
            .query(Statement::new(
                "SELECT revision FROM oauth_dynamic_clients",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(integer(&rows[0], "revision").unwrap(), 2);
        fetch.doc.borrow_mut()["client_id"] = json!(id);
        fetch.ttl.set(1);
        fetch.delay.set(2000);
        assert!(app.oauth_client(id).await.is_err());
        for bad in [
            "http://client.example/metadata",
            "https://client.example/",
            "https://user@client.example/meta",
            "https://client.example/meta#x",
        ] {
            assert!(validate_cimd_url(bad).is_err());
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn dynamic_revision_binds_authorization_code_refresh_and_final_access_guard() {
        let (_dir, app, clock) = fixture().await;
        let registered = register(&app, document()).await.unwrap();
        let id = registered["client_id"].as_str().unwrap();
        let body = json!({"request_id":"dynamic-test","display_name":"Test"});
        let space = app
            .admin(
                &Request::json(
                    "POST",
                    "/admin/v0/spaces",
                    &app.config.admin_secret,
                    body.clone(),
                ),
                body,
            )
            .await
            .unwrap();
        let sid = space["space_id"].as_str().unwrap();
        let aid = space["default_actor_id"].as_str().unwrap();
        let cid = space["default_consumer_id"].as_str().unwrap();
        let verifier = "v".repeat(43);
        let code = "c".repeat(43);
        let resource = app.oauth_resource();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        app.db.batch(vec![
            Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('acct','https://issuer.example','sub',0)",vec![]),
            Statement::new("INSERT INTO account_spaces VALUES(?,'acct',0)",vec![sid.into()]),
            Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,redirect_uri,code_challenge,code_digest,status,created_at,expires_at,next_poll_at,account_id,space_id,actor_id,consumer_id,client_revision) VALUES('request','code',? ,?,'waypost','http://127.0.0.1:8765/callback',?,?,'approved',0,?,0,'acct',?,?,?,1)",vec![id.into(),resource.clone().into(),challenge.into(),Sha256::digest(code.as_bytes()).to_vec().into(),(clock.now_ms()+120000).into(),sid.into(),aid.into(),cid.into()]),
        ]).await.unwrap();
        let params = BTreeMap::from([
            ("grant_type".into(), "authorization_code".into()),
            ("client_id".into(), id.into()),
            ("resource".into(), resource.clone()),
            (
                "redirect_uri".into(),
                "http://127.0.0.1:8765/callback".into(),
            ),
            ("code".into(), code),
            ("code_verifier".into(), verifier),
        ]);
        let issued = app.oauth_token(params).await.unwrap();
        let request = Request::json(
            "POST",
            "/mcp",
            issued["access_token"].as_str().unwrap(),
            json!({}),
        );
        let principal = app.authenticate(&request).await.unwrap();
        app.current(&principal).await.unwrap();
        app.db
            .batch(vec![Statement::new(
                "UPDATE oauth_dynamic_clients SET revision=revision+1 WHERE client_id=?",
                vec![id.into()],
            )])
            .await
            .unwrap();
        assert!(app.authenticate(&request).await.is_err());
        assert!(app.current(&principal).await.is_err());
        let refresh = BTreeMap::from([
            ("grant_type".into(), "refresh_token".into()),
            ("client_id".into(), id.into()),
            ("resource".into(), resource),
            (
                "refresh_token".into(),
                issued["refresh_token"].as_str().unwrap().into(),
            ),
        ]);
        assert!(app.oauth_token(refresh).await.is_err());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn stale_ungranted_dcr_is_reclaimed_without_deleting_request_or_family_history() {
        let (_dir, app, clock) = fixture().await;
        let mut ids = Vec::new();
        for _ in 0..4 {
            ids.push(
                register(&app, document()).await.unwrap()["client_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        let now = clock.now_ms() + 86_400_001;
        clock.0.set(now);
        app.db.batch(vec![
            Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,status,created_at,expires_at,next_poll_at,client_revision) VALUES('expired','code',?,'r','waypost','pending',0,?,0,1),('live','code',?,'r','waypost','approved',0,?,0,1),('denied','code',?,'r','waypost','denied',0,?,0,1)",vec![ids[0].clone().into(),now.into(),ids[1].clone().into(),(now+1).into(),ids[2].clone().into(),(now+1000).into()]),
        ]).await.unwrap();
        // Family history is protected even after expiry/revocation. Create a real
        // FK-valid owner identity rather than disabling constraints for this test.
        let body = json!({"request_id":"cleanup-space","display_name":"Test"});
        let space = app
            .admin(
                &Request::json(
                    "POST",
                    "/admin/v0/spaces",
                    &app.config.admin_secret,
                    body.clone(),
                ),
                body,
            )
            .await
            .unwrap();
        app.db.batch(vec![
            Statement::new("INSERT INTO accounts VALUES('history','https://issuer.example','history',0,0)",vec![]),
            Statement::new("INSERT INTO oauth_families(family_id,client_id,resource,scope,account_id,space_id,actor_id,consumer_id,created_at,expires_at,revoked_at,client_revision) VALUES('history',?,'r','waypost','history',?,?,?,0,1,1,1)",vec![ids[3].clone().into(),space["space_id"].as_str().unwrap().into(),space["default_actor_id"].as_str().unwrap().into(),space["default_consumer_id"].as_str().unwrap().into()]),
        ]).await.unwrap();
        register(&app, document()).await.unwrap();
        let rows = app
            .db
            .query(Statement::new(
                "SELECT client_id FROM oauth_dynamic_clients ORDER BY client_id",
                vec![],
            ))
            .await
            .unwrap();
        let left = rows
            .iter()
            .map(|r| text(r, "client_id").unwrap())
            .collect::<Vec<_>>();
        assert!(!left.contains(&ids[0]));
        assert!(left.contains(&ids[1]));
        assert!(!left.contains(&ids[2]));
        assert!(left.contains(&ids[3]));
        let rows=app.db.query(Statement::new("SELECT (SELECT count(*) FROM oauth_requests) requests,(SELECT count(*) FROM oauth_families) families",vec![])).await.unwrap();
        assert_eq!(integer(&rows[0], "requests").unwrap(), 3);
        assert_eq!(integer(&rows[0], "families").unwrap(), 1);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn expired_unreferenced_cimd_reclaims_capacity_but_disabled_tombstones_remain() {
        let (_dir, mut app, clock) = fixture().await;
        let first = "https://client.example/one.json";
        let second = "https://client.example/two.json";
        let mut doc = document();
        doc["client_id"] = json!(first);
        let fetch = Rc::new(Fetch {
            doc: RefCell::new(doc),
            clock: clock.clone(),
            calls: 0.into(),
            delay: 0.into(),
            ttl: 60.into(),
        });
        app.oauth_metadata_fetcher = Some(fetch.clone());
        app.oauth_discovery.as_mut().unwrap().max_clients = 1;
        app.oauth_client(first).await.unwrap();
        clock.0.set(clock.now_ms() + 61000);
        fetch.doc.borrow_mut()["client_id"] = json!(second);
        app.oauth_client(second).await.unwrap();
        let rows = app
            .db
            .query(Statement::new(
                "SELECT client_id FROM oauth_dynamic_clients",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(text(&rows[0], "client_id").unwrap(), second);
        app.db
            .batch(vec![Statement::new(
                "UPDATE oauth_dynamic_clients SET disabled=1",
                vec![],
            )])
            .await
            .unwrap();
        clock.0.set(clock.now_ms() + 61000);
        fetch.doc.borrow_mut()["client_id"] = json!(first);
        assert!(app.oauth_client(first).await.is_err());
        let rows = app
            .db
            .query(Statement::new(
                "SELECT disabled FROM oauth_dynamic_clients",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(integer(&rows[0], "disabled").unwrap(), 1);
        // The same administrative disable tombstone rule applies to DCR clients.
        app.db
            .batch(vec![Statement::new(
                "UPDATE oauth_dynamic_clients SET source='dcr',created_at=0",
                vec![],
            )])
            .await
            .unwrap();
        clock.0.set(100_000_000);
        assert!(register(&app, document()).await.is_err());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn dcr_errors_preserve_standard_protocol_codes() {
        let (_dir, app, _clock) = fixture().await;
        for (field, value, expected) in [
            (
                "client_secret",
                json!("not-supported"),
                "invalid_client_metadata",
            ),
            (
                "redirect_uris",
                json!(["http://10.0.0.1/cb"]),
                "invalid_redirect_uri",
            ),
        ] {
            let mut body = document();
            body[field] = value;
            let mut request = Request::json("POST", "/oauth/register", "", body);
            request.headers.remove("authorization");
            let result = app.handle(request).await;
            assert_eq!(result.status, 400);
            let value: Value = serde_json::from_slice(&result.body).unwrap();
            assert_eq!(value["error"], expected);
        }
    }
}
