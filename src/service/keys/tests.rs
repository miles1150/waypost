//! Keys product contract over the real request path: OAuth (metadata documents,
//! dynamic registration), consent, the five tools and product isolation.
use super::super::accounts::{BrowserCookie, browser_cookie_name};
use super::super::accounts_oidc::{OidcCodeExchange, OidcConfig, OidcRsaKey};
use super::super::oauth::{OAuthClient, OAuthConfig};
use super::*;
use crate::native::{FileStore, SqliteDb};
use crate::service::oauth_client_registry::{
    OAuthClientDiscoveryConfig, OAuthClientMetadataDocument, OAuthClientMetadataFetcher,
};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use std::{cell::Cell, future::Future, pin::Pin};
use url::Url;

type TestApp = App<SqliteDb, FileStore>;
const KEYS: &str = "https://keys.example";
const WAYPOST: &str = "https://waypost.example";
const SESSION: &str = "sssssssssssssssssssssssssssssssssssssssssss";
const VERIFIER: &str = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";
const CLAUDE: &str = "https://claude.ai/oauth/claude-code-client-metadata";
const CODEX: &str = "https://chatgpt.com/oauth/codex/client.json";
const SECRET: &str = "ghp_TOPSECRETvalue_0123456789";
const ROTATED: &str = "ghp_ROTATEDsecret_9876543210";
const KEYRING: &str = r#"{"active":"k1","keys":{"k1":"1111111111111111111111111111111111111111111111111111111111111111"}}"#;

struct NoExchange;
impl OidcCodeExchange for NoExchange {
    fn exchange<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
        Box::pin(async { panic!("fixture never contacts an identity provider") })
    }
}
/// Serves fixed documents and counts fetches.
struct FakeFetch {
    docs: BTreeMap<String, Value>,
    calls: Rc<Cell<usize>>,
}
impl OAuthClientMetadataFetcher for FakeFetch {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClientMetadataDocument>> + 'a>> {
        self.calls.set(self.calls.get() + 1);
        let doc = self.docs.get(url).cloned();
        Box::pin(async move {
            let doc = doc.ok_or_else(Error::not_found)?;
            Ok(OAuthClientMetadataDocument {
                body: serde_json::to_vec(&doc).unwrap(),
                max_age_seconds: 600,
            })
        })
    }
}
fn oidc() -> OidcConfig {
    let k = RsaPrivateKey::from_pkcs8_pem(include_str!(
        "../../../tests/fixtures/oidc-test-private.pem"
    ))
    .unwrap();
    OidcConfig {
        issuer: "https://issuer.example".into(),
        client_id: "test-client".into(),
        authorization_endpoint: "https://issuer.example/authorize".into(),
        token_endpoint: "https://issuer.example/token".into(),
        client_secret: None,
        google_jwks: false,
        keys: vec![OidcRsaKey {
            kid: "test".into(),
            n: URL_SAFE_NO_PAD.encode(k.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(k.e().to_bytes_be()),
        }],
    }
}
fn claude_doc() -> Value {
    json!({"client_id":CLAUDE,"client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"})
}
fn base(path: &std::path::Path, origin: &str) -> TestApp {
    App::new(
        SqliteDb::open(path.join("db")).unwrap(),
        FileStore::open(path.join("objects")).unwrap(),
        Config {
            admin_secret: "test-only-admin-secret-long-enough".into(),
            public_origin: origin.into(),
        },
    )
    .with_accounts(oidc(), Rc::new(NoExchange), 1)
    .unwrap()
}
struct Fixture {
    _dir: tempfile::TempDir,
    app: TestApp,
    calls: Rc<Cell<usize>>,
}
/// Documents are served at their own client_id unless a `_served_at` URL is given.
async fn fixture_with(docs: Vec<Value>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let calls = Rc::new(Cell::new(0));
    let fetch = FakeFetch {
        docs: docs
            .into_iter()
            .map(|mut d| {
                let url = d
                    .as_object_mut()
                    .unwrap()
                    .remove("_served_at")
                    .unwrap_or_else(|| d["client_id"].clone());
                (url.as_str().unwrap().to_owned(), d)
            })
            .collect(),
        calls: calls.clone(),
    };
    let app = base(dir.path(), KEYS)
        .with_oauth_client_discovery(OAuthClientDiscoveryConfig::default(), Some(Rc::new(fetch)))
        .unwrap()
        .with_csrf_secret("test-only-csrf-secret-32-bytes-long")
        .unwrap()
        .with_cursor_secret("test-only-cursor-secret-32-bytes-long")
        .unwrap()
        .with_operator_mode("disabled")
        .unwrap()
        .with_account_owner_subject("owner")
        .unwrap()
        .with_keys(KEYRING)
        .unwrap();
    let now = app.clock.now_ms();
    app.db.batch(vec![
        Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('acct_owner','https://issuer.example','owner',?)",vec![now.into()]),
        Statement::new("INSERT INTO account_sessions(session_digest,account_id,created_at,expires_at) VALUES(?,'acct_owner',?,?)",vec![Sha256::digest(SESSION.as_bytes()).to_vec().into(),now.into(),(now+3_600_000).into()]),
    ]).await.unwrap();
    Fixture {
        _dir: dir,
        app,
        calls,
    }
}
async fn fixture() -> Fixture {
    fixture_with(vec![claude_doc()]).await
}

#[tokio::test(flavor = "current_thread")]
async fn keys_product_fails_closed_without_owner_or_dynamic_registration() {
    let dir = tempfile::tempdir().unwrap();
    let app = base(dir.path(), KEYS)
        .with_oauth_client_discovery(OAuthClientDiscoveryConfig::default(), None)
        .unwrap()
        .with_csrf_secret("test-only-csrf-secret-32-bytes-long")
        .unwrap()
        .with_cursor_secret("test-only-cursor-secret-32-bytes-long")
        .unwrap()
        .with_operator_mode("disabled")
        .unwrap();
    assert!(app.with_keys(KEYRING).is_err());
    let dir = tempfile::tempdir().unwrap();
    let app = base(dir.path(), KEYS)
        .with_oauth_client_discovery(
            OAuthClientDiscoveryConfig {
                dynamic_registration: false,
                ..Default::default()
            },
            None,
        )
        .unwrap()
        .with_csrf_secret("test-only-csrf-secret-32-bytes-long")
        .unwrap()
        .with_cursor_secret("test-only-cursor-secret-32-bytes-long")
        .unwrap()
        .with_operator_mode("disabled")
        .unwrap()
        .with_account_owner_subject("owner")
        .unwrap();
    assert!(app.with_keys(KEYRING).is_err());
}
fn body(response: &Response) -> Value {
    serde_json::from_slice(&response.body).unwrap_or(Value::Null)
}
fn pkce() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}
fn get(path: &str, query: &str) -> Request {
    Request {
        method: "GET".into(),
        path: path.into(),
        query: query.into(),
        headers: BTreeMap::new(),
        body: vec![],
    }
}
fn form(path: &str, params: &[(&str, &str)]) -> Request {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        f.append_pair(k, v);
    }
    Request {
        method: "POST".into(),
        path: path.into(),
        query: String::new(),
        headers: BTreeMap::from([(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        )]),
        body: f.finish().into_bytes(),
    }
}
impl Fixture {
    fn browser(
        &self,
        method: &str,
        path: &str,
        query: &str,
        browser: &str,
        value: Option<Value>,
    ) -> Request {
        let origin = &self.app.config.public_origin;
        let account = browser_cookie_name(origin, BrowserCookie::Account);
        let mut r = get(path, query);
        r.method = method.into();
        r.headers
            .insert("cookie".into(), format!("{account}={SESSION}; {browser}"));
        if let Some(v) = value {
            r.headers.insert("origin".into(), origin.clone());
            r.headers
                .insert("content-type".into(), "application/json".into());
            r.headers.insert(
                "x-waypost-csrf".into(),
                self.app.csrf_token(SESSION).unwrap(),
            );
            r.body = serde_json::to_vec(&v).unwrap();
        }
        r
    }
    /// Start an authorization request; returns (request_id, browser cookie pair).
    async fn authorize(&self, client: &str, redirect: &str, scope: &str) -> Response {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("client_id", client)
            .append_pair("redirect_uri", redirect)
            .append_pair("response_type", "code")
            .append_pair(
                "resource",
                &format!("{}/mcp", self.app.config.public_origin),
            )
            .append_pair("scope", scope)
            .append_pair("state", "st")
            .append_pair("code_challenge", &pkce())
            .append_pair("code_challenge_method", "S256");
        self.app.handle(get("/oauth/authorize", &q.finish())).await
    }
    async fn started(&self, client: &str, redirect: &str, scope: &str) -> (String, String) {
        let response = self.authorize(client, redirect, scope).await;
        assert_eq!(response.status, 303, "{:?}", body(&response));
        let location = &response.headers["location"];
        let id = location.split("oauth_request=").nth(1).unwrap().to_owned();
        let browser = response.headers["set-cookie"]
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (id, browser)
    }
    async fn consent(&self, client: &str, redirect: &str, scope: &str, grant: Value) -> String {
        let (id, browser) = self.started(client, redirect, scope).await;
        let mut decision = json!({"request_id":id,"decision":"approve"});
        for (k, v) in grant.as_object().unwrap() {
            decision[k] = v.clone();
        }
        let response = self
            .app
            .handle(self.browser("POST", "/oauth/consent", "", &browser, Some(decision)))
            .await;
        assert_eq!(response.status, 200, "{:?}", body(&response));
        let callback = Url::parse(body(&response)["redirect_uri"].as_str().unwrap()).unwrap();
        assert_eq!(
            callback.query_pairs().find(|(k, _)| k == "iss").unwrap().1,
            KEYS
        );
        callback
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned()
    }
    async fn token(&self, client: &str, redirect: &str, scope: &str, grant: Value) -> Value {
        let code = self.consent(client, redirect, scope, grant).await;
        let resource = format!("{KEYS}/mcp");
        let response = self
            .app
            .handle(form(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", client),
                    ("code", &code),
                    ("redirect_uri", redirect),
                    ("code_verifier", VERIFIER),
                    ("resource", &resource),
                ],
            ))
            .await;
        assert_eq!(response.status, 200, "{:?}", body(&response));
        body(&response)
    }
    async fn rpc(&self, token: &str, method: &str, params: Value) -> Response {
        let mut r = Request::json(
            "POST",
            "/mcp",
            token,
            json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
        );
        r.headers
            .insert("mcp-protocol-version".into(), "2025-11-25".into());
        self.app.handle(r).await
    }
    /// Call a tool; returns (raw response body text, structured envelope).
    async fn tool(&self, token: &str, name: &str, args: Value) -> (String, Value) {
        let response = self
            .rpc(token, "tools/call", json!({"name":name,"arguments":args}))
            .await;
        assert_eq!(response.status, 200);
        let raw = String::from_utf8(response.body.clone()).unwrap();
        (raw, body(&response)["result"]["structuredContent"].clone())
    }
}
fn access(v: &Value) -> String {
    v["access_token"].as_str().unwrap().to_owned()
}

struct RevisionRaceDb {
    inner: SqliteDb,
    trigger: &'static str,
    fired: Cell<bool>,
}
impl Database for RevisionRaceDb {
    async fn query(&self, statement: Statement) -> Result<Vec<Row>> {
        self.inner.query(statement).await
    }
    async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<Vec<Row>>> {
        if !self.fired.get() && statements.iter().any(|s| s.sql.contains(self.trigger)) {
            self.fired.set(true);
            self.inner
                .batch(vec![Statement::new(
                    "UPDATE oauth_dynamic_clients SET revision=revision+1 WHERE client_id=?",
                    vec![CLAUDE.into()],
                )])
                .await?;
        }
        self.inner.batch(statements).await
    }
}
fn with_revision_race(original: TestApp, trigger: &'static str) -> App<RevisionRaceDb, FileStore> {
    let mut app = App::new(
        RevisionRaceDb {
            inner: original.db,
            trigger,
            fired: Cell::new(false),
        },
        original.objects,
        original.config,
    );
    app.clock = original.clock;
    app.limits = original.limits;
    app.cursor_key = original.cursor_key;
    app.csrf_key = original.csrf_key;
    app.explicit_cursor_secret = original.explicit_cursor_secret;
    app.explicit_csrf_secret = original.explicit_csrf_secret;
    app.operator_enabled = original.operator_enabled;
    app.encryption = original.encryption;
    app.oidc = original.oidc;
    app.account_signup_limit = original.account_signup_limit;
    app.account_owner_subject = original.account_owner_subject;
    app.keys = original.keys;
    app.oauth_discovery = original.oauth_discovery;
    app.oauth_metadata_fetcher = original.oauth_metadata_fetcher;
    app.invitations_enabled = original.invitations_enabled;
    app.oidc_exchange = original.oidc_exchange;
    app
}

#[tokio::test(flavor = "current_thread")]
async fn revision_change_at_database_boundary_blocks_consent_and_secret_read() {
    let f = fixture().await;
    let redirect = "http://127.0.0.1:40000/callback";
    let (id, browser) = f.started(CLAUDE, redirect, "keys:read").await;
    let request = f.browser(
        "POST",
        "/oauth/consent",
        "",
        &browser,
        Some(json!({"request_id":id,"decision":"approve","all_read":true})),
    );
    let app = with_revision_race(f.app, "UPDATE oauth_requests SET status='approved'");
    let response = app.handle(request).await;
    assert!(app.db.fired.get());
    assert_ne!(response.status, 200);

    let f = fixture().await;
    let token = f
        .token(
            CLAUDE,
            redirect,
            "keys:read keys:write",
            json!({"all_read":true,"can_create":true}),
        )
        .await;
    let token = access(&token);
    let (_, created) = f
        .tool(
            &token,
            "create_entry",
            json!({"name":"race/test","fields":{"VALUE":SECRET}}),
        )
        .await;
    assert_eq!(created["ok"], true);
    let mut request = Request::json(
        "POST",
        "/mcp",
        &token,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_entry","arguments":{"name":"race/test"}}}),
    );
    request
        .headers
        .insert("mcp-protocol-version".into(), "2025-11-25".into());
    let app = with_revision_race(f.app, "INSERT INTO key_audit");
    let response = app.handle(request).await;
    assert!(app.db.fired.get());
    assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
    assert_eq!(body(&response)["result"]["structuredContent"]["ok"], false);
}

#[tokio::test(flavor = "current_thread")]
async fn revision_change_at_database_boundary_blocks_code_refresh_and_write() {
    let redirect = "http://127.0.0.1:40000/callback";
    let resource = format!("{KEYS}/mcp");
    let f = fixture().await;
    let code = f
        .consent(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    let request = form(
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CLAUDE),
            ("code", &code),
            ("redirect_uri", redirect),
            ("code_verifier", VERIFIER),
            ("resource", &resource),
        ],
    );
    let app = with_revision_race(f.app, "UPDATE oauth_requests AS q SET status='consumed'");
    assert_eq!(
        body(&app.handle(request).await),
        json!({"error":"invalid_grant"})
    );
    assert!(app.db.fired.get());

    let f = fixture().await;
    let tokens = f
        .token(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    let request = form(
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLAUDE),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("resource", &resource),
        ],
    );
    let app = with_revision_race(f.app, "UPDATE key_oauth_refresh_tokens SET used_at");
    assert_eq!(
        body(&app.handle(request).await),
        json!({"error":"invalid_grant"})
    );
    assert!(app.db.fired.get());

    let f = fixture().await;
    let token = access(
        &f.token(
            CLAUDE,
            redirect,
            "keys:read keys:write",
            json!({"can_create":true}),
        )
        .await,
    );
    let mut request = Request::json(
        "POST",
        "/mcp",
        &token,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_entry","arguments":{"name":"race/new","fields":{"VALUE":SECRET}}}}),
    );
    request
        .headers
        .insert("mcp-protocol-version".into(), "2025-11-25".into());
    let app = with_revision_race(f.app, "INSERT INTO key_entries");
    let response = app.handle(request).await;
    assert!(app.db.fired.get());
    assert_eq!(body(&response)["result"]["structuredContent"]["ok"], false);
    let rows = app
        .db
        .query(Statement::new(
            "SELECT count(*) AS n FROM key_entries WHERE name='race/new'",
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(integer(&rows[0], "n").unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn client_revision_fences_consent_code_refresh_and_access() {
    let redirect = "http://127.0.0.1:40000/callback";
    let f = fixture().await;
    let (id, browser) = f.started(CLAUDE, redirect, "keys:read").await;
    f.app
        .db
        .batch(vec![Statement::new(
            "UPDATE oauth_dynamic_clients SET revision=revision+1 WHERE client_id=?",
            vec![CLAUDE.into()],
        )])
        .await
        .unwrap();
    let denied = f
        .app
        .handle(f.browser(
            "POST",
            "/oauth/consent",
            "",
            &browser,
            Some(json!({"request_id":id,"decision":"approve","all_read":true})),
        ))
        .await;
    assert_ne!(denied.status, 200);

    let f = fixture().await;
    let code = f
        .consent(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    f.app
        .db
        .batch(vec![Statement::new(
            "UPDATE oauth_dynamic_clients SET revision=revision+1 WHERE client_id=?",
            vec![CLAUDE.into()],
        )])
        .await
        .unwrap();
    let resource = format!("{KEYS}/mcp");
    let denied = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", CLAUDE),
                ("code", &code),
                ("redirect_uri", redirect),
                ("code_verifier", VERIFIER),
                ("resource", &resource),
            ],
        ))
        .await;
    assert_eq!(body(&denied), json!({"error":"invalid_grant"}));

    let f = fixture().await;
    let token = f
        .token(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    f.app
        .db
        .batch(vec![Statement::new(
            "UPDATE oauth_dynamic_clients SET revision=revision+1 WHERE client_id=?",
            vec![CLAUDE.into()],
        )])
        .await
        .unwrap();
    assert_eq!(
        f.rpc(&access(&token), "tools/list", json!({})).await.status,
        401
    );
    let denied = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLAUDE),
                ("refresh_token", token["refresh_token"].as_str().unwrap()),
                ("resource", &resource),
            ],
        ))
        .await;
    assert_eq!(body(&denied), json!({"error":"invalid_grant"}));
}

#[tokio::test(flavor = "current_thread")]
async fn changing_bound_owner_invalidates_existing_keys_grant() {
    let mut f = fixture().await;
    let redirect = "http://127.0.0.1:40000/callback";
    let token = f
        .token(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    f.app.account_owner_subject = Some("different-subject".into());
    assert_eq!(
        f.rpc(&access(&token), "tools/list", json!({})).await.status,
        401
    );
    let resource = format!("{KEYS}/mcp");
    let denied = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLAUDE),
                ("refresh_token", token["refresh_token"].as_str().unwrap()),
                ("resource", &resource),
            ],
        ))
        .await;
    assert_eq!(body(&denied), json!({"error":"invalid_grant"}));
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_scope_cannot_widen_or_silently_change_the_grant() {
    let f = fixture().await;
    let redirect = "http://127.0.0.1:40000/callback";
    let token = f
        .token(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    let resource = format!("{KEYS}/mcp");
    let denied = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLAUDE),
                ("refresh_token", token["refresh_token"].as_str().unwrap()),
                ("resource", &resource),
                ("scope", "keys:read keys:write"),
            ],
        ))
        .await;
    assert_eq!(body(&denied), json!({"error":"invalid_grant"}));
    let accepted = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLAUDE),
                ("refresh_token", token["refresh_token"].as_str().unwrap()),
                ("resource", &resource),
                ("scope", "keys:read"),
            ],
        ))
        .await;
    assert_eq!(body(&accepted)["scope"], "keys:read");
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_advertises_cimd_dcr_and_keys_scopes() {
    let f = fixture().await;
    let meta = body(
        &f.app
            .handle(get("/.well-known/oauth-authorization-server", ""))
            .await,
    );
    assert_eq!(meta["issuer"], KEYS);
    assert_eq!(meta["client_id_metadata_document_supported"], true);
    assert_eq!(
        meta["registration_endpoint"],
        format!("{KEYS}/oauth/register")
    );
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(meta["authorization_response_iss_parameter_supported"], true);
    assert_eq!(meta["scopes_supported"], json!(["keys:read", "keys:write"]));
    assert!(meta.get("device_authorization_endpoint").is_none());
    let resource = body(
        &f.app
            .handle(get("/.well-known/oauth-protected-resource/mcp", ""))
            .await,
    );
    assert_eq!(resource["resource"], format!("{KEYS}/mcp"));
    let challenge = f.rpc("", "tools/list", json!({})).await;
    assert_eq!(challenge.status, 401);
    assert!(challenge.headers["www-authenticate"].contains("scope=\"keys:read keys:write\""));
    // Waypost routes do not exist on a keys deployment.
    for path in [
        "/v0/describe",
        "/admin/v0/spaces",
        "/account/spaces/create",
        "/dashboard",
    ] {
        assert_eq!(f.app.handle(get(path, "")).await.status, 404, "{path}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tool_contract_never_echoes_written_values() {
    let f = fixture().await;
    let redirect = "http://127.0.0.1:53682/callback";
    let (id, browser) = f.started(CLAUDE, redirect, "keys:read keys:write").await;
    let preview = body(
        &f.app
            .handle(f.browser(
                "GET",
                "/oauth/consent",
                &format!("request_id={id}"),
                &browser,
                None,
            ))
            .await,
    );
    assert_eq!(preview["client_kind"], "metadata_document");
    assert_eq!(preview["client_host"], "claude.ai");
    assert_eq!(preview["redirect_host"], "127.0.0.1");
    assert_eq!(preview["client_warnings"].as_array().unwrap().len(), 1);
    assert_eq!(f.calls.get(), 1, "document is cached after the first fetch");
    let tokens = f
        .token(
            CLAUDE,
            redirect,
            "keys:read keys:write",
            json!({"can_create":true}),
        )
        .await;
    assert_eq!(tokens["scope"], "keys:read keys:write");
    assert!(tokens["access_token"].as_str().unwrap().starts_with("kso_"));
    let token = access(&tokens);
    let listed = body(&f.rpc(&token, "tools/list", json!({})).await);
    let names: Vec<_> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_entries",
            "fetch_entry",
            "create_entry",
            "update_entry",
            "disable_entry"
        ]
    );

    let (raw, created) = f.tool(&token, "create_entry", json!({"name":"github/token","purpose":"CI pushes","fields":{"GH_TOKEN":SECRET,"GH_USER":"octo-cat-user"}})).await;
    assert_eq!(created["ok"], true, "{created}");
    assert_eq!(
        created["data"],
        json!({"created":true,"name":"github/token","fields":["GH_TOKEN","GH_USER"]})
    );
    assert!(!raw.contains(SECRET) && !raw.contains("octo-cat-user"));

    let (raw, updated) = f.tool(&token, "update_entry", json!({"name":"github/token","set_fields":{"GH_TOKEN":ROTATED},"remove_fields":["GH_USER"],"expires":"2999-01-01"})).await;
    assert_eq!(
        updated["data"],
        json!({"updated":true,"name":"github/token","fields":["GH_TOKEN"]})
    );
    assert!(!raw.contains(ROTATED) && !raw.contains(SECRET));

    // Validation errors name fields, never values.
    let bad = format!("{SECRET}\u{0}");
    let (raw, rejected) = f
        .tool(
            &token,
            "update_entry",
            json!({"name":"github/token","set_fields":{"GH_TOKEN":bad}}),
        )
        .await;
    assert_eq!(rejected["ok"], false);
    assert!(raw.contains("GH_TOKEN") && !raw.contains(SECRET));
    let (raw, _) = f
        .tool(
            &token,
            "create_entry",
            json!({"name":"Bad Name","fields":{"X":SECRET}}),
        )
        .await;
    assert!(!raw.contains(SECRET));
    let (raw, _) = f
        .tool(
            &token,
            "create_entry",
            json!({"name":"github/token","fields":{"X":SECRET}}),
        )
        .await;
    assert!(raw.contains("ENTRY_EXISTS") && !raw.contains(SECRET));

    let (raw, list) = f.tool(&token, "list_entries", json!({})).await;
    assert!(!raw.contains(ROTATED));
    assert_eq!(
        list["data"]["entries"],
        json!([{"name":"github/token","purpose":"CI pushes","fields":["GH_TOKEN"],"disabled":false,"expires":"2999-01-01","readable":true,"writable":true}])
    );

    let (raw, fetched) = f
        .tool(&token, "fetch_entry", json!({"name":"github/token"}))
        .await;
    assert!(raw.contains(ROTATED));
    assert_eq!(
        fetched["data"],
        json!({"name":"github/token","fields":{"GH_TOKEN":ROTATED}})
    );

    // Stored rows are ciphertext; the audit log has names and actions only.
    let rows = f
        .app
        .db
        .query(Statement::new(
            "SELECT name,kid,nonce,ciphertext FROM key_fields",
            vec![],
        ))
        .await
        .unwrap();
    let dump = format!("{rows:?}");
    assert!(!dump.contains(ROTATED) && !dump.contains("TOPSECRET"));
    let audit = f
        .app
        .db
        .query(Statement::new(
            "SELECT action,entry_name FROM key_audit ORDER BY created_at,action",
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(audit.len(), 3);
    assert!(!format!("{audit:?}").contains("ghp_"));

    let (_, disabled) = f
        .tool(&token, "disable_entry", json!({"name":"github/token"}))
        .await;
    assert_eq!(
        disabled["data"],
        json!({"name":"github/token","disabled":true})
    );
    let (_, refused) = f
        .tool(&token, "fetch_entry", json!({"name":"github/token"}))
        .await;
    assert_eq!(refused["error"]["code"], "ENTRY_DISABLED");
    f.tool(
        &token,
        "disable_entry",
        json!({"name":"github/token","disabled":false}),
    )
    .await;
    let (_, expired) = f
        .tool(
            &token,
            "update_entry",
            json!({"name":"github/token","expires":"2000-01-01"}),
        )
        .await;
    assert_eq!(expired["ok"], true);
    let (_, refused) = f
        .tool(&token, "fetch_entry", json!({"name":"github/token"}))
        .await;
    assert_eq!(refused["error"]["code"], "ENTRY_EXPIRED");
}

#[tokio::test(flavor = "current_thread")]
async fn read_and_write_are_authorized_separately() {
    let f = fixture().await;
    let redirect = "http://127.0.0.1:40000/callback";
    let writer = access(
        &f.token(
            CLAUDE,
            redirect,
            "keys:read keys:write",
            json!({"can_create":true}),
        )
        .await,
    );
    for name in ["shared/readable", "shared/writable", "private/hidden"] {
        let (_, r) = f
            .tool(
                &writer,
                "create_entry",
                json!({"name":name,"fields":{"VALUE":SECRET}}),
            )
            .await;
        assert_eq!(r["ok"], true);
    }
    // Scope keys:read only, even with write boxes ticked, cannot write.
    let reader = access(
        &f.token(
            CLAUDE,
            redirect,
            "keys:read",
            json!({"all_read":true,"all_write":true,"can_create":true}),
        )
        .await,
    );
    let (_, fetched) = f
        .tool(&reader, "fetch_entry", json!({"name":"private/hidden"}))
        .await;
    assert_eq!(fetched["ok"], true);
    for (tool, args, code) in [
        (
            "create_entry",
            json!({"name":"new/one","fields":{"A":"b"}}),
            "CREATE_NOT_GRANTED",
        ),
        (
            "update_entry",
            json!({"name":"shared/writable","set_fields":{"A":"b"}}),
            "WRITE_NOT_GRANTED",
        ),
        (
            "disable_entry",
            json!({"name":"shared/writable"}),
            "WRITE_NOT_GRANTED",
        ),
    ] {
        let (_, r) = f.tool(&reader, tool, args).await;
        assert_eq!(r["error"]["code"], code, "{tool}");
    }
    // Per-entry consent: read one, write another, nothing else visible.
    let scoped = access(&f.token(CLAUDE, redirect, "keys:read keys:write", json!({"entries":[{"name":"shared/readable","read":true},{"name":"shared/writable","write":true}]})).await);
    let (raw, list) = f.tool(&scoped, "list_entries", json!({})).await;
    assert!(!raw.contains("private/hidden"));
    assert_eq!(list["data"]["can_create"], false);
    let entries = list["data"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (
            entries[0]["readable"].clone(),
            entries[0]["writable"].clone()
        ),
        (json!(true), json!(false))
    );
    assert_eq!(
        (
            entries[1]["readable"].clone(),
            entries[1]["writable"].clone()
        ),
        (json!(false), json!(true))
    );
    let (_, r) = f
        .tool(&scoped, "fetch_entry", json!({"name":"shared/readable"}))
        .await;
    assert_eq!(r["ok"], true);
    let (_, r) = f
        .tool(&scoped, "fetch_entry", json!({"name":"shared/writable"}))
        .await;
    assert_eq!(r["error"]["code"], "READ_NOT_GRANTED");
    let (_, r) = f
        .tool(
            &scoped,
            "update_entry",
            json!({"name":"shared/readable","set_fields":{"A":"b"}}),
        )
        .await;
    assert_eq!(r["error"]["code"], "WRITE_NOT_GRANTED");
    let (raw, r) = f
        .tool(
            &scoped,
            "update_entry",
            json!({"name":"shared/writable","set_fields":{"VALUE":ROTATED}}),
        )
        .await;
    assert_eq!(r["ok"], true);
    assert!(!raw.contains(ROTATED));
    let (_, r) = f
        .tool(&scoped, "fetch_entry", json!({"name":"private/hidden"}))
        .await;
    assert_eq!(r["error"]["code"], "ENTRY_NOT_FOUND");
    let (_, r) = f
        .tool(
            &scoped,
            "create_entry",
            json!({"name":"x/y","fields":{"A":"b"}}),
        )
        .await;
    assert_eq!(r["error"]["code"], "CREATE_NOT_GRANTED");
    // Consent with no permission at all is refused.
    let (id, browser) = f.started(CLAUDE, redirect, "keys:read").await;
    let refused = f
        .app
        .handle(f.browser(
            "POST",
            "/oauth/consent",
            "",
            &browser,
            Some(json!({"request_id":id,"decision":"approve"})),
        ))
        .await;
    assert_eq!(body(&refused), json!({"error":"invalid_request"}));
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_revocation_and_owner_revoke_end_access() {
    let f = fixture().await;
    let redirect = "http://127.0.0.1:40001/callback";
    let first = f
        .token(
            CLAUDE,
            redirect,
            "keys:read keys:write",
            json!({"can_create":true}),
        )
        .await;
    let resource = format!("{KEYS}/mcp");
    let refreshed = body(
        &f.app
            .handle(form(
                "/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", CLAUDE),
                    ("refresh_token", first["refresh_token"].as_str().unwrap()),
                    ("resource", &resource),
                ],
            ))
            .await,
    );
    assert!(
        refreshed["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("ksr_")
    );
    assert_eq!(refreshed["scope"], "keys:read keys:write");
    let token = access(&refreshed);
    assert_eq!(
        f.tool(&token, "list_entries", json!({})).await.1["ok"],
        true
    );
    // Replaying the old refresh token revokes the whole family.
    let replay = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLAUDE),
                ("refresh_token", first["refresh_token"].as_str().unwrap()),
                ("resource", &resource),
            ],
        ))
        .await;
    assert_eq!(body(&replay), json!({"error":"invalid_grant"}));
    assert_eq!(f.rpc(&token, "tools/list", json!({})).await.status, 401);
    // RFC 7009 revocation.
    let second = f
        .token(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    f.app
        .handle(form(
            "/oauth/revoke",
            &[
                ("client_id", CLAUDE),
                ("token", second["access_token"].as_str().unwrap()),
            ],
        ))
        .await;
    assert_eq!(
        f.rpc(&access(&second), "tools/list", json!({}))
            .await
            .status,
        401
    );
    // Owner revokes a connection from the account page.
    let third = f
        .token(CLAUDE, redirect, "keys:read", json!({"all_read":true}))
        .await;
    let grants = body(
        &f.app
            .handle(f.browser("GET", "/account/keys/grants", "", "", None))
            .await,
    );
    let live = grants["data"]["grants"].as_array().unwrap();
    assert_eq!(live.len(), 1);
    let revoked = f
        .app
        .handle(f.browser(
            "POST",
            "/account/keys/grants/revoke",
            "",
            "",
            Some(json!({"grant_id":live[0]["grant_id"]})),
        ))
        .await;
    assert_eq!(revoked.status, 200);
    assert_eq!(
        f.rpc(&access(&third), "tools/list", json!({})).await.status,
        401
    );
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_document_validation_and_redirect_rules() {
    let mut wrong_id = claude_doc();
    wrong_id["client_id"] = json!("https://evil.example/client.json");
    wrong_id["_served_at"] = json!("https://claude.example/doc.json");
    let mut jwt = claude_doc();
    jwt["client_id"] = json!("https://jwt.example/client.json");
    jwt["token_endpoint_auth_method"] = json!("private_key_jwt");
    let codex = json!({"client_id":CODEX,"client_name":"Codex","redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none"});
    let f = fixture_with(vec![claude_doc(), codex, jwt, wrong_id]).await;
    // Mismatched client_id, private_key_jwt and unknown/unsafe IDs are local errors.
    for client in [
        "https://claude.example/doc.json",
        "https://jwt.example/client.json",
        "https://missing.example/client.json",
        "https://127.0.0.1/client.json",
        "http://claude.ai/oauth/claude-code-client-metadata",
        "unknown-client",
        "dcr_unregistered",
    ] {
        let r = f
            .authorize(client, "http://127.0.0.1:5000/callback", "keys:read")
            .await;
        assert!(matches!(r.status, 400 | 404), "{client}: {}", r.status);
    }
    // Redirects outside the document never receive a redirect, even for errors.
    for redirect in [
        "http://127.0.0.2:5000/callback",
        "http://127.0.0.1:5000/other",
        "https://claude.ai/callback",
        "http://localhost:5000/callback?x=1",
    ] {
        let r = f.authorize(CLAUDE, redirect, "keys:read").await;
        assert_eq!(
            (r.status, body(&r)),
            (400, json!({"error":"invalid_request"})),
            "{redirect}"
        );
    }
    // Codex declares a portless 127.0.0.1 callback; any port is accepted, localhost is not.
    f.started(CODEX, "http://127.0.0.1:61234/callback", "keys:read")
        .await;
    let r = f
        .authorize(CODEX, "http://localhost:61234/callback", "keys:read")
        .await;
    assert_eq!(r.status, 400);
    // Unsupported scope is reported to the validated redirect.
    let r = f
        .authorize(CODEX, "http://127.0.0.1:61234/callback", "waypost")
        .await;
    assert_eq!(r.status, 303);
    assert!(r.headers["location"].contains("error=invalid_scope"));
    // A code is bound to the exact port used at authorization.
    let code = f
        .consent(
            CODEX,
            "http://127.0.0.1:61234/callback",
            "keys:read",
            json!({"all_read":true}),
        )
        .await;
    let resource = format!("{KEYS}/mcp");
    let r = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", CODEX),
                ("code", &code),
                ("redirect_uri", "http://127.0.0.1:61235/callback"),
                ("code_verifier", VERIFIER),
                ("resource", &resource),
            ],
        ))
        .await;
    assert_eq!(body(&r), json!({"error":"invalid_grant"}));
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_registration_issues_public_clients() {
    let f = fixture().await;
    let mut register = Request::json(
        "POST",
        "/oauth/register",
        "",
        json!({"client_name":"Cursor","redirect_uris":["https://www.cursor.com/agents/mcp/oauth/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]}),
    );
    register.headers.remove("authorization");
    let response = f.app.handle(register.clone()).await;
    assert_eq!(response.status, 201);
    let client = body(&response);
    let id = client["client_id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("dcr_"));
    assert_eq!(client["token_endpoint_auth_method"], "none");
    assert_eq!(client["scope"], "keys:read keys:write");
    let (rid, browser) = f
        .started(
            &id,
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "keys:read",
        )
        .await;
    let preview = body(
        &f.app
            .handle(f.browser(
                "GET",
                "/oauth/consent",
                &format!("request_id={rid}"),
                &browser,
                None,
            ))
            .await,
    );
    assert_eq!(preview["client_kind"], "dynamic_registration");
    assert!(
        preview["client_warnings"][0]
            .as_str()
            .unwrap()
            .contains("not verified")
    );
    let token = access(
        &f.token(
            &id,
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "keys:read",
            json!({"all_read":true}),
        )
        .await,
    );
    assert_eq!(f.rpc(&token, "tools/list", json!({})).await.status, 200);
    // Disabling the registration stops existing grants on the next request.
    f.app
        .db
        .batch(vec![Statement::new(
            "UPDATE oauth_dynamic_clients SET disabled=1 WHERE source='dcr'",
            vec![],
        )])
        .await
        .unwrap();
    assert_eq!(f.rpc(&token, "tools/list", json!({})).await.status, 401);
    // Confidential or malformed registrations are refused with RFC 7591 errors.
    for (payload, error) in [
        (
            json!({"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}),
            "invalid_client_metadata",
        ),
        (
            json!({"client_name":"bad","redirect_uris":["http://a.example/cb"]}),
            "invalid_redirect_uri",
        ),
    ] {
        let mut r = register.clone();
        r.body = serde_json::to_vec(&payload).unwrap();
        let response = f.app.handle(r).await;
        assert_eq!(
            (response.status, body(&response)),
            (400, json!({"error":error}))
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn registration_cleanup_preserves_clients_with_keys_grant_history() {
    let f = fixture().await;
    let mut register = Request::json(
        "POST",
        "/oauth/register",
        "",
        json!({"client_name":"test","redirect_uris":["http://127.0.0.1:4444/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]}),
    );
    register.headers.remove("authorization");
    let response = f.app.handle(register.clone()).await;
    assert_eq!(response.status, 201);
    let id = body(&response)["client_id"].as_str().unwrap().to_owned();
    let (request_id, browser) = f
        .started(&id, "http://127.0.0.1:4444/callback", "keys:read")
        .await;
    let preview = body(
        &f.app
            .handle(f.browser(
                "GET",
                "/oauth/consent",
                &format!("request_id={request_id}"),
                &browser,
                None,
            ))
            .await,
    );
    let warnings = preview["client_warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 2);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("impersonated"))
    );
    let token = f
        .token(
            &id,
            "http://127.0.0.1:4444/callback",
            "keys:read",
            json!({"all_read":true}),
        )
        .await;
    f.app
        .db
        .batch(vec![Statement::new(
            "UPDATE oauth_dynamic_clients SET created_at=0 WHERE client_id=?",
            vec![id.clone().into()],
        )])
        .await
        .unwrap();
    assert_eq!(f.app.handle(register).await.status, 201);
    let rows = f
        .app
        .db
        .query(Statement::new(
            "SELECT client_id FROM oauth_dynamic_clients WHERE client_id=?",
            vec![id.into()],
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        f.rpc(&access(&token), "tools/list", json!({})).await.status,
        200
    );
}

/// Keys and Waypost may even share one database: tokens still never cross.
#[tokio::test(flavor = "current_thread")]
async fn tokens_never_cross_products() {
    let f = fixture().await;
    let redirect = "http://127.0.0.1:40002/callback";
    let keys_tokens = f
        .token(
            CLAUDE,
            redirect,
            "keys:read keys:write",
            json!({"all_read":true,"all_write":true,"can_create":true}),
        )
        .await;
    let waypost = base(f._dir.path(), WAYPOST)
        .import_legacy_oauth_clients(OAuthConfig {
            clients: vec![OAuthClient {
                client_id: "client".into(),
                name: "Waypost client".into(),
                redirect_uris: vec!["https://client.example/callback".into()],
                allow_loopback_port_variation: false,
            }],
        })
        .await
        .unwrap();
    // Waypost OAuth token for a real Space/Actor/Consumer binding.
    let admin = &waypost.config.admin_secret.clone();
    let space = body(
        &waypost
            .handle(Request::json(
                "POST",
                "/admin/v0/spaces",
                admin,
                json!({"request_id":"cross","display_name":"Cross"}),
            ))
            .await,
    )["data"]
        .clone();
    let now = waypost.clock.now_ms();
    waypost.db.batch(vec![
        Statement::new("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,'acct_owner',?)",vec![space["space_id"].as_str().unwrap().into(),now.into()]),
        Statement::new("UPDATE account_sessions SET selected_space_id=?",vec![space["space_id"].as_str().unwrap().into()]),
    ]).await.unwrap();
    let w = Fixture {
        _dir: tempfile::tempdir().unwrap(),
        app: waypost,
        calls: Rc::new(Cell::new(0)),
    };
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    q.append_pair("client_id", "client")
        .append_pair("redirect_uri", "https://client.example/callback")
        .append_pair("response_type", "code")
        .append_pair("resource", &format!("{WAYPOST}/mcp"))
        .append_pair("code_challenge", &pkce())
        .append_pair("code_challenge_method", "S256");
    let started = w.app.handle(get("/oauth/authorize", &q.finish())).await;
    let id = started.headers["location"]
        .split("oauth_request=")
        .nth(1)
        .unwrap()
        .to_owned();
    let browser = started.headers["set-cookie"]
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let approved = body(&w.app.handle(w.browser("POST", "/oauth/consent", "", &browser, Some(json!({"request_id":id,"decision":"approve","actor_id":space["default_actor_id"],"consumer_id":space["default_consumer_id"]})))).await);
    let callback = Url::parse(approved["redirect_uri"].as_str().unwrap()).unwrap();
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let waypost_resource = format!("{WAYPOST}/mcp");
    let wtokens = body(
        &w.app
            .handle(form(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", "client"),
                    ("code", &code),
                    ("redirect_uri", "https://client.example/callback"),
                    ("code_verifier", VERIFIER),
                    ("resource", &waypost_resource),
                ],
            ))
            .await,
    );
    assert!(
        wtokens["access_token"]
            .as_str()
            .unwrap()
            .starts_with("wpo_")
    );
    // Each token works on its own product only.
    assert_eq!(
        w.rpc(access(&wtokens).as_str(), "tools/list", json!({}))
            .await
            .status,
        200
    );
    assert_eq!(
        f.rpc(access(&wtokens).as_str(), "tools/list", json!({}))
            .await
            .status,
        401
    );
    assert_eq!(
        w.rpc(access(&keys_tokens).as_str(), "tools/list", json!({}))
            .await
            .status,
        401
    );
    let mut describe = Request::json("GET", "/v0/describe", &access(&keys_tokens), json!({}));
    describe.body.clear();
    assert_eq!(w.app.handle(describe).await.status, 401);
    // Refresh tokens are not redeemable across products, whatever the resource says.
    let keys_resource = format!("{KEYS}/mcp");
    for (app, refresh, resource) in [
        (
            &w.app,
            keys_tokens["refresh_token"].as_str().unwrap(),
            waypost_resource.as_str(),
        ),
        (
            &f.app,
            wtokens["refresh_token"].as_str().unwrap(),
            keys_resource.as_str(),
        ),
    ] {
        let r = app
            .handle(form(
                "/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", "client"),
                    ("refresh_token", refresh),
                    ("resource", resource),
                ],
            ))
            .await;
        assert_ne!(r.status, 200);
    }
    let r = f
        .app
        .handle(form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLAUDE),
                (
                    "refresh_token",
                    keys_tokens["refresh_token"].as_str().unwrap(),
                ),
                ("resource", &waypost_resource),
            ],
        ))
        .await;
    assert_eq!(body(&r), json!({"error":"invalid_target"}));
    // Keys scopes are not Waypost scopes and vice versa.
    let r = f.authorize(CLAUDE, redirect, "waypost").await;
    assert!(r.headers["location"].contains("error=invalid_scope"));
}
