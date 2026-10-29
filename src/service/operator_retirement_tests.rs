use super::*;
use crate::{
    domain::OwnerAuthority,
    native::{FileStore, SqliteDb},
};
use accounts_oidc::{OidcCodeExchange, OidcConfig, OidcRsaKey};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use std::{future::Future, pin::Pin};
const ADMIN: &str = "legacy-operator-secret-at-least-32-bytes";
const CSRF: &str = "independent-browser-csrf-secret-32-bytes";
const CURSOR: &str = "independent-feed-cursor-secret-32-bytes";
const OWNER: &str = "legacy-scoped-owner-credential-32-bytes";
struct NoExchange;
impl OidcCodeExchange for NoExchange {
    fn exchange<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
        Box::pin(async { Err(Error::unauthenticated()) })
    }
}
fn oidc() -> OidcConfig {
    let key =
        RsaPrivateKey::from_pkcs8_pem(include_str!("../../tests/fixtures/oidc-test-private.pem"))
            .unwrap();
    OidcConfig {
        issuer: "https://issuer.example".into(),
        client_id: "test".into(),
        authorization_endpoint: "https://issuer.example/authorize".into(),
        token_endpoint: "https://issuer.example/token".into(),
        client_secret: None,
        google_jwks: false,
        keys: vec![OidcRsaKey {
            kid: "test".into(),
            n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }],
    }
}
type TestApp = App<SqliteDb, FileStore>;
fn app(dir: &std::path::Path, secret: &str) -> TestApp {
    App::new(
        SqliteDb::open(dir.join("db")).unwrap(),
        FileStore::open(dir.join("objects")).unwrap(),
        Config {
            admin_secret: secret.into(),
            public_origin: "http://127.0.0.1:8787".into(),
        },
    )
}
fn ready_accounts(app: TestApp) -> TestApp {
    app.with_accounts(oidc(), Rc::new(NoExchange), 0)
        .unwrap()
        .with_csrf_secret(CSRF)
        .unwrap()
        .with_cursor_secret(CURSOR)
        .unwrap()
}
#[test]
fn disabled_requires_explicit_independent_signers_and_account_path() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        app(dir.path(), ADMIN)
            .with_operator_mode("disabled")
            .is_err()
    );
    assert!(
        app(dir.path(), ADMIN)
            .with_csrf_secret(CSRF)
            .unwrap()
            .with_cursor_secret(CURSOR)
            .unwrap()
            .with_operator_mode("disabled")
            .is_err()
    );
    assert!(
        app(dir.path(), ADMIN)
            .with_accounts(oidc(), Rc::new(NoExchange), 0)
            .unwrap()
            .with_operator_mode("disabled")
            .is_err()
    );
    assert!(
        ready_accounts(app(dir.path(), ADMIN))
            .with_csrf_secret(CURSOR)
            .unwrap()
            .with_operator_mode("disabled")
            .is_err()
    );
    assert!(
        ready_accounts(app(dir.path(), ADMIN))
            .with_csrf_secret(ADMIN)
            .unwrap()
            .with_operator_mode("disabled")
            .is_err()
    );
    assert!(
        ready_accounts(app(dir.path(), ""))
            .with_operator_mode("disabled")
            .is_ok()
    );
    assert!(app(dir.path(), "").with_operator_mode("enabled").is_err());
    assert!(app(dir.path(), ADMIN).with_operator_mode("typo").is_err());
    assert!(app(dir.path(), ADMIN).validate_runtime_auth().is_ok());
}
#[test]
fn independent_signers_survive_admin_rotation_and_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let first = ready_accounts(app(dir.path(), ADMIN));
    let cursor = first.sign_cursor("unchanged-feed-binding").unwrap();
    let csrf = first.csrf_token("stable-account-cookie").unwrap();
    let second = ready_accounts(app(dir.path(), "rotated-admin-secret-at-least-32-bytes"))
        .with_operator_mode("disabled")
        .unwrap();
    assert_eq!(
        second.verify_cursor(&cursor).unwrap(),
        "unchanged-feed-binding"
    );
    assert_eq!(second.csrf_token("stable-account-cookie").unwrap(), csrf);
    let third = second
        .with_csrf_secret("new-browser-signing-secret-at-least-32-bytes")
        .unwrap();
    assert_ne!(third.csrf_token("stable-account-cookie").unwrap(), csrf);
    assert_eq!(
        third.verify_cursor(&cursor).unwrap(),
        "unchanged-feed-binding"
    );
    let legacy = app(dir.path(), ADMIN);
    assert_ne!(legacy.csrf_token("stable-account-cookie").unwrap(), csrf);
    assert!(legacy.verify_cursor(&cursor).is_err());
}
#[tokio::test(flavor = "current_thread")]
async fn disabled_rejects_operator_bearer_login_cookie_and_captured_final_authority() {
    let dir = tempfile::tempdir().unwrap();
    let app = ready_accounts(app(dir.path(), ADMIN));
    let space = app
        .admin(
            &Request::json("POST", "/admin/v0/spaces", ADMIN, json!({})),
            json!({"request_id":"space","display_name":"Existing"}),
        )
        .await
        .unwrap();
    let sid = space["space_id"].as_str().unwrap();
    let bearer = Request::json("GET", "/admin/v0/spaces", ADMIN, json!({}));
    let operator = app.dashboard_owner(&bearer, sid, None).await.unwrap();
    let response = app
        .admin_session(&Request::json(
            "POST",
            "/admin/session",
            "",
            json!({"admin_secret":ADMIN}),
        ))
        .await;
    assert_eq!(response.status, 200);
    let cookie = response.headers["set-cookie"]
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut session = Request::json("GET", "/admin/v0/spaces", "", json!({}));
    session.headers.remove("authorization");
    session.headers.insert("cookie".into(), cookie);
    let session_principal = app.dashboard_owner(&session, sid, None).await.unwrap();
    app.db.batch(vec![Statement::new("INSERT INTO space_admin_credentials(space_id,credential_digest,version,created_at) VALUES(?,?,1,?)",vec![sid.into(),Sha256::digest(OWNER.as_bytes()).to_vec().into(),app.clock.now_ms().into()]),Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at) VALUES('token_existing',?,?,?,?,?)",vec![Sha256::digest(b"existing-agent-credential").to_vec().into(),sid.into(),space["default_actor_id"].as_str().unwrap().into(),space["default_consumer_id"].as_str().unwrap().into(),app.clock.now_ms().into()])]).await.unwrap();
    let owner_request = Request::json("GET", "/admin/v0/spaces", OWNER, json!({}));
    let owner = app
        .dashboard_owner(&owner_request, sid, None)
        .await
        .unwrap();
    let agent_request = Request::json(
        "GET",
        "/v0/describe",
        "existing-agent-credential",
        json!({}),
    );
    let agent = app.authenticate(&agent_request).await.unwrap();
    let app = app.with_operator_mode("disabled").unwrap();
    assert!(app.admin_identity(&bearer).await.is_err());
    assert!(app.admin_access(&session).await.is_err());
    assert_eq!(
        app.admin_session(&Request::json(
            "POST",
            "/admin/session",
            "",
            json!({"admin_secret":ADMIN})
        ))
        .await
        .status,
        401
    );
    assert!(app.current(&operator).await.is_err());
    assert!(app.current(&session_principal).await.is_err());
    assert_eq!(
        app.admin_identity(&owner_request).await.unwrap(),
        Some(sid.into())
    );
    app.current(&owner).await.unwrap();
    app.current(&agent).await.unwrap();
    app.authenticate(&agent_request).await.unwrap();
    // Even a malformed historical owner record must not reinterpret the retired
    // global credential as a scoped key, including pre-captured credential authority.
    app.db
        .batch(vec![Statement::new(
            "UPDATE space_admin_credentials SET credential_digest=? WHERE space_id=?",
            vec![Sha256::digest(ADMIN.as_bytes()).to_vec().into(), sid.into()],
        )])
        .await
        .unwrap();
    assert!(app.admin_identity(&bearer).await.is_err());
    let mut forged = operator.clone();
    forged.owner_authority = Some(OwnerAuthority::Credential(
        Sha256::digest(ADMIN.as_bytes()).to_vec(),
    ));
    assert!(app.current(&forged).await.is_err());
}
