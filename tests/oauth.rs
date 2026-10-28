//! Real loopback HTTP OAuth integration; account login is a synthetic local fixture.
mod common;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{ADMIN, call};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin, rc::Rc};
use waypost::accounts_oidc::{OidcCodeExchange, OidcConfig, OidcRsaKey};
use waypost::native::{FileStore, SqliteDb};
use waypost::{App, Clock, Config, OAuthClient, OAuthConfig, SystemClock};

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VERIFIER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CALLBACK: &str = "https://client.example/callback";
struct UnusedExchange;
impl OidcCodeExchange for UnusedExchange {
    fn exchange<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = waypost::error::Result<String>> + 'a>> {
        Box::pin(async { panic!("OAuth fixture must not contact an upstream OIDC provider") })
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    client: reqwest::Client,
    origin: String,
    space: Value,
    foreign: Value,
    owner: String,
    csrf: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let key =
            RsaPrivateKey::from_pkcs8_pem(include_str!("fixtures/oidc-test-private.pem")).unwrap();
        let app = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: ADMIN.into(),
                public_origin: origin.clone(),
            },
        )
        .with_accounts(
            OidcConfig {
                issuer: "https://issuer.example".into(),
                client_id: "oidc-test".into(),
                authorization_endpoint: "https://issuer.example/authorize".into(),
                token_endpoint: "https://issuer.example/token".into(),
                client_secret: None,
                keys: vec![OidcRsaKey {
                    kid: "test".into(),
                    n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                    e: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
                }],
            },
            Rc::new(UnusedExchange),
            1,
        )
        .unwrap()
        .with_oauth(OAuthConfig {
            clients: vec![OAuthClient {
                client_id: "client".into(),
                name: "Integration client".into(),
                redirect_uris: vec![CALLBACK.into()],
            }],
        })
        .unwrap();
        let space = call(
            &app,
            "POST",
            "/admin/v0/spaces",
            ADMIN,
            json!({"request_id":"oauth-space","display_name":"OAuth fixture"}),
        )
        .await;
        let foreign = call(
            &app,
            "POST",
            "/admin/v0/spaces",
            ADMIN,
            json!({"request_id":"foreign-space","display_name":"Foreign fixture"}),
        )
        .await;
        let owner = call(
            &app,
            "POST",
            &format!(
                "/admin/v0/spaces/{}/owner-credential",
                space["space_id"].as_str().unwrap()
            ),
            ADMIN,
            json!({"expected_version":0}),
        )
        .await["credential"]
            .as_str()
            .unwrap()
            .to_owned();
        let db = rusqlite::Connection::open(dir.path().join("db")).unwrap();
        let now = SystemClock.now_ms();
        db.execute("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_oauth','https://issuer.example','synthetic',?)",[now]).unwrap();
        db.execute("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,'account_oauth',?)",rusqlite::params![space["space_id"].as_str().unwrap(),now]).unwrap();
        db.execute("INSERT INTO account_sessions(session_digest,account_id,selected_space_id,created_at,expires_at) VALUES(?,'account_oauth',?,?,?)",rusqlite::params![Sha256::digest(SESSION.as_bytes()).to_vec(),space["space_id"].as_str().unwrap(),now,now+3600000]).unwrap();
        drop(db);
        let server =
            tokio::task::spawn_local(waypost::native::server::serve(listener, Rc::new(app)));
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let mut f = Self {
            _dir: dir,
            server,
            client,
            origin,
            space,
            foreign,
            owner,
            csrf: String::new(),
        };
        let (_, session) = decode(
            f.client
                .get(format!("{}/account/session", f.origin))
                .header("cookie", format!("waypost_account={SESSION}"))
                .send()
                .await
                .unwrap(),
        )
        .await;
        f.csrf = session["data"]["csrf_token"].as_str().unwrap().into();
        f
    }
    fn resource(&self) -> String {
        format!("{}/mcp", self.origin)
    }
    fn browser(&self, path: &str, browser: &str, body: Value) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}{path}", self.origin))
            .header("origin", &self.origin)
            .header("cookie", format!("waypost_account={SESSION}; {browser}"))
            .header("x-waypost-csrf", &self.csrf)
            .header("content-type", "application/json")
            .body(body.to_string())
    }
    async fn start(&self) -> (String, String) {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", "client"),
                ("response_type", "code"),
                ("redirect_uri", CALLBACK),
                ("resource", &self.resource()),
                ("scope", "waypost"),
                ("state", "opaque&state"),
                ("code_challenge_method", "S256"),
                (
                    "code_challenge",
                    &URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
                ),
            ])
            .finish();
        let response = self
            .client
            .get(format!("{}/oauth/authorize?{query}", self.origin))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let cookie = response.headers()["set-cookie"].to_str().unwrap();
        assert!(cookie.contains("HttpOnly"));
        let id = response.headers()["location"]
            .to_str()
            .unwrap()
            .strip_prefix("/account?oauth_request=")
            .unwrap()
            .to_owned();
        (id, cookie.split(';').next().unwrap().into())
    }
    async fn approve(&self) -> String {
        let (id, browser) = self.start().await;
        let (status,body)=decode(self.browser("/oauth/consent",&browser,json!({"request_id":id,"decision":"approve","actor_id":self.space["default_actor_id"],"consumer_id":self.space["default_consumer_id"]})).send().await.unwrap()).await;
        assert_eq!(status, 200, "consent failed: {body}");
        let callback = url::Url::parse(body["redirect_uri"].as_str().unwrap()).unwrap();
        assert_eq!(
            callback.origin().ascii_serialization(),
            "https://client.example"
        );
        let query: std::collections::BTreeMap<_, _> = callback.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "opaque&state");
        assert_eq!(query["iss"], self.origin);
        query["code"].clone()
    }
    async fn form(&self, path: &str, fields: &[(&str, &str)]) -> (u16, Value) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        decode(
            self.client
                .post(format!("{}{path}", self.origin))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .unwrap(),
        )
        .await
    }
    async fn exchange(&self, code: &str, verifier: &str, resource: &str) -> (u16, Value) {
        self.form(
            "/oauth/token",
            &[
                ("client_id", "client"),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", CALLBACK),
                ("resource", resource),
            ],
        )
        .await
    }
    async fn token(&self) -> Value {
        let code = self.approve().await;
        let (status, token) = self.exchange(&code, VERIFIER, &self.resource()).await;
        assert_eq!(status, 200, "exchange failed: {token}");
        token
    }
    async fn refresh(&self, token: &str) -> (u16, Value) {
        self.form(
            "/oauth/token",
            &[
                ("client_id", "client"),
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("resource", &self.resource()),
            ],
        )
        .await
    }
    async fn mcp(&self, token: &str) -> (u16, Value) {
        decode(self.client.post(self.resource()).bearer_auth(token).header("content-type","application/json").header("mcp-protocol-version","2025-11-25").body(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"waypost_describe","arguments":{}}}).to_string()).send().await.unwrap()).await
    }
}
async fn decode(response: reqwest::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = response.bytes().await.unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}

#[tokio::test(flavor = "current_thread")]
async fn http_discovery_consent_pkce_mcp_refresh_and_revocation() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let f = Fixture::new().await;
            let (status, metadata) = decode(
                f.client
                    .get(format!(
                        "{}/.well-known/oauth-protected-resource/mcp",
                        f.origin
                    ))
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(metadata["resource"], f.resource());
            let (_, metadata) = decode(
                f.client
                    .get(format!(
                        "{}/.well-known/oauth-authorization-server",
                        f.origin
                    ))
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(metadata["issuer"], f.origin);
            assert_eq!(
                metadata["code_challenge_methods_supported"],
                json!(["S256"])
            );
            let unauth = f
                .client
                .post(f.resource())
                .header("content-type", "application/json")
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(unauth.status(), 401);
            assert!(
                unauth.headers()["www-authenticate"]
                    .to_str()
                    .unwrap()
                    .contains("oauth-protected-resource/mcp")
            );
            let code = f.approve().await;
            assert_eq!(
                f.exchange(&code, VERIFIER, "https://wrong.example/mcp")
                    .await
                    .1["error"],
                "invalid_target"
            );
            assert_eq!(
                f.exchange(&code, &"x".repeat(43), &f.resource()).await.1["error"],
                "invalid_grant"
            );
            let (status, token) = f.exchange(&code, VERIFIER, &f.resource()).await;
            assert_eq!(status, 200);
            assert_eq!(token["token_type"], "Bearer");
            let access = token["access_token"].as_str().unwrap();
            let (status, description) = f.mcp(access).await;
            assert_eq!(status, 200);
            assert_eq!(description["result"]["isError"], false, "{description}");
            let (status, next) = f.refresh(token["refresh_token"].as_str().unwrap()).await;
            assert_eq!(status, 200);
            assert_ne!(next["refresh_token"], token["refresh_token"]);
            assert_eq!(f.mcp(next["access_token"].as_str().unwrap()).await.0, 200);
            let revoke = f
                .form(
                    "/oauth/revoke",
                    &[
                        ("client_id", "client"),
                        ("token", next["refresh_token"].as_str().unwrap()),
                    ],
                )
                .await;
            assert_eq!(revoke.0, 200);
            assert_eq!(f.mcp(next["access_token"].as_str().unwrap()).await.0, 401);
            assert_eq!(f.mcp(access).await.0, 401);
            assert_eq!(
                f.refresh(next["refresh_token"].as_str().unwrap()).await.1["error"],
                "invalid_grant"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn http_consent_requires_browser_csrf_and_selected_space() {
    tokio::task::LocalSet::new().run_until(async {
    let f=Fixture::new().await;let (id,browser)=f.start().await;
    let approve=json!({"request_id":id,"decision":"approve","actor_id":f.space["default_actor_id"],"consumer_id":f.space["default_consumer_id"]});
    assert_eq!(decode(f.browser("/oauth/consent","",approve.clone()).send().await.unwrap()).await,(400,json!({"error":"access_denied"})));
    let missing_csrf=f.client.post(format!("{}/oauth/consent",f.origin)).header("origin",&f.origin).header("cookie",format!("waypost_account={SESSION}; {browser}")).header("content-type","application/json").body(approve.to_string()).send().await.unwrap();assert_eq!(decode(missing_csrf).await,(403,json!({"error":"access_denied"})));
    let foreign=json!({"request_id":id,"decision":"approve","actor_id":f.foreign["default_actor_id"],"consumer_id":f.foreign["default_consumer_id"]});
    assert_eq!(decode(f.browser("/oauth/consent",&browser,foreign).send().await.unwrap()).await,(400,json!({"error":"access_denied"})));
    let preview=f.client.get(format!("{}/oauth/consent?request_id={id}",f.origin)).header("cookie",format!("waypost_account={SESSION}; {browser}")).send().await.unwrap();let (status,preview)=decode(preview).await;assert_eq!(status,200);assert_eq!(preview["selected_space_id"],f.space["space_id"]);assert!(preview.get("redirect_uri").is_none());
    let denied=decode(f.browser("/oauth/consent",&browser,json!({"request_id":id,"decision":"deny"})).send().await.unwrap()).await;assert_eq!(denied.0,200);
    let redirect=url::Url::parse(denied.1["redirect_uri"].as_str().unwrap()).unwrap();assert!(redirect.query_pairs().any(|(k,v)|k=="error"&&v=="access_denied"));assert!(!redirect.query_pairs().any(|(k,_)|k=="code"));
    assert_eq!(decode(f.browser("/oauth/consent",&browser,approve).send().await.unwrap()).await,(400,json!({"error":"invalid_request"})));
 }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn http_refresh_replay_and_unlink_invalidate_existing_authority() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let f = Fixture::new().await;
            let token = f.token().await;
            let old = token["refresh_token"].as_str().unwrap();
            let (_, next) = f.refresh(old).await;
            assert_eq!(f.refresh(old).await.1["error"], "invalid_grant");
            assert_eq!(f.mcp(next["access_token"].as_str().unwrap()).await.0, 401);
            assert_eq!(
                f.refresh(next["refresh_token"].as_str().unwrap()).await.1["error"],
                "invalid_grant"
            );
            let code = f.approve().await;
            let (status, replay_token) = f.exchange(&code, VERIFIER, &f.resource()).await;
            assert_eq!(status, 200);
            assert_eq!(
                f.exchange(&code, VERIFIER, &f.resource()).await.1["error"],
                "invalid_grant"
            );
            assert_eq!(
                f.mcp(replay_token["access_token"].as_str().unwrap())
                    .await
                    .0,
                401
            );
            let token = f.token().await;
            let unredeemed_code = f.approve().await;
            let unlink = decode(
                f.browser(
                    "/account/spaces/unlink",
                    "",
                    json!({"space_id":f.space["space_id"],"owner_credential":f.owner}),
                )
                .send()
                .await
                .unwrap(),
            )
            .await;
            assert_eq!(unlink.0, 200);
            assert_eq!(
                f.exchange(&unredeemed_code, VERIFIER, &f.resource())
                    .await
                    .1["error"],
                "invalid_grant"
            );
            assert_eq!(f.mcp(token["access_token"].as_str().unwrap()).await.0, 401);
            assert_eq!(
                f.refresh(token["refresh_token"].as_str().unwrap()).await.1["error"],
                "invalid_grant"
            );
        })
        .await;
}
