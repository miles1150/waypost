//! OAuth token endpoint state transitions. Secrets are returned only once.
use super::oauth::oauth_error;
use super::*;

const ACCESS_MS: i64 = 300_000;
const FAMILY_MS: i64 = 30 * 24 * 60 * 60 * 1000;
fn digest(value: &str) -> Sql {
    Sha256::digest(value.as_bytes()).to_vec().into()
}
fn required<'a>(p: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    p.get(key)
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .ok_or_else(|| oauth_error("invalid_request"))
}
fn fields(p: &BTreeMap<String, String>, allowed: &[&str]) -> Result<()> {
    if p.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(oauth_error("invalid_request"));
    }
    Ok(())
}
fn opaque(value: &str) -> Result<()> {
    if !(20..=256).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(oauth_error("invalid_grant"));
    }
    Ok(())
}
fn verifier(value: &str) -> Result<String> {
    if !(43..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return Err(oauth_error("invalid_grant"));
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes())))
}
fn secret(prefix: &str) -> Result<String> {
    Ok(format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(random_bytes::<32>()?)
    ))
}

// Alias f is always an OAuth family. This is rechecked in the issuing batch.
const LIVE_FAMILY: &str = "f.revoked_at IS NULL AND f.expires_at>? AND EXISTS(SELECT 1 FROM accounts a JOIN account_spaces m ON m.account_id=a.account_id JOIN actors x ON x.space_id=m.space_id JOIN consumers c ON c.space_id=x.space_id AND c.actor_id=x.actor_id WHERE a.account_id=f.account_id AND m.space_id=f.space_id AND x.actor_id=f.actor_id AND c.consumer_id=f.consumer_id AND a.disabled=0 AND x.disabled=0 AND c.disabled=0 AND c.view='inbox')";
// Alias q is the original approved authorization request.
const LIVE_REQUEST: &str = "EXISTS(SELECT 1 FROM accounts a JOIN account_spaces m ON m.account_id=a.account_id JOIN actors x ON x.space_id=m.space_id JOIN consumers c ON c.space_id=x.space_id AND c.actor_id=x.actor_id WHERE a.account_id=q.account_id AND m.space_id=q.space_id AND x.actor_id=q.actor_id AND c.consumer_id=q.consumer_id AND a.disabled=0 AND x.disabled=0 AND c.disabled=0 AND c.view='inbox')";

fn revoke_queries(selector: &str, args: Vec<Sql>, now: i64) -> Vec<Statement> {
    let mut first = vec![now.into()];
    first.extend(args.clone());
    let mut second = vec![now.into()];
    second.extend(args);
    vec![
        Statement::new(
            format!(
                "UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,?) WHERE family_id IN ({selector})"
            ),
            first,
        ),
        Statement::new(
            format!(
                "UPDATE tokens SET revoked_at=COALESCE(revoked_at,?),authority_version=authority_version+CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END WHERE token_id IN(SELECT token_id FROM oauth_access_tokens WHERE family_id IN ({selector}))"
            ),
            second,
        ),
    ]
}

impl<D: Database, O: ObjectStore> App<D, O> {
    pub(super) async fn oauth_token(&self, p: BTreeMap<String, String>) -> Result<Value> {
        let client = required(&p, "client_id")?;
        self.oauth_client(client)?;
        let resource = required(&p, "resource")?;
        if resource != self.oauth_resource() {
            return Err(oauth_error("invalid_target"));
        }
        if p.get("scope").is_some_and(|s| s != "waypost") {
            return Err(oauth_error("invalid_scope"));
        }
        match required(&p, "grant_type")? {
            "authorization_code" => {
                fields(
                    &p,
                    &[
                        "grant_type",
                        "client_id",
                        "resource",
                        "scope",
                        "code",
                        "redirect_uri",
                        "code_verifier",
                    ],
                )?;
                let code = required(&p, "code")?;
                opaque(code)?;
                let challenge = verifier(required(&p, "code_verifier")?)?;
                let redirect = required(&p, "redirect_uri")?;
                if !self.oauth_client(client)?.accepts_redirect(redirect) {
                    return Err(oauth_error("invalid_grant"));
                }
                let now = self.clock.now_ms();
                let nonce = random_id("redeem")?;
                let selector = "SELECT family_id FROM oauth_requests WHERE kind='code' AND code_digest=? AND client_id=? AND resource=? AND redirect_uri=? AND code_challenge=? AND status='consumed'";
                let tuple = vec![
                    digest(code),
                    client.into(),
                    resource.into(),
                    redirect.into(),
                    challenge.clone().into(),
                ];
                let mut queries = revoke_queries(selector, tuple.clone(), now);
                let mut claim = vec![nonce.clone().into()];
                claim.extend(tuple);
                claim.push(now.into());
                queries.push(Statement::new(format!("UPDATE oauth_requests AS q SET status='consumed',claim_nonce=? WHERE kind='code' AND code_digest=? AND client_id=? AND resource=? AND redirect_uri=? AND code_challenge=? AND status='approved' AND expires_at>? AND {LIVE_REQUEST}"),claim));
                self.issue_request(queries, &nonce, now).await
            }
            "refresh_token" => {
                fields(
                    &p,
                    &[
                        "grant_type",
                        "client_id",
                        "resource",
                        "scope",
                        "refresh_token",
                    ],
                )?;
                self.rotate_refresh(client, resource, required(&p, "refresh_token")?)
                    .await
            }
            "urn:ietf:params:oauth:grant-type:device_code" => {
                fields(
                    &p,
                    &[
                        "grant_type",
                        "client_id",
                        "resource",
                        "scope",
                        "device_code",
                    ],
                )?;
                self.redeem_device(client, resource, required(&p, "device_code")?)
                    .await
            }
            _ => Err(oauth_error("unsupported_grant_type")),
        }
    }
    async fn issue_request(
        &self,
        mut queries: Vec<Statement>,
        nonce: &str,
        now: i64,
    ) -> Result<Value> {
        let family = random_id("grant")?;
        let token_id = random_id("token")?;
        let access = secret("wpo_")?;
        let refresh = secret("wpr_")?;
        queries.push(Statement::new("INSERT INTO oauth_families(family_id,client_id,resource,scope,account_id,space_id,actor_id,consumer_id,created_at,expires_at) SELECT ?,client_id,resource,scope,account_id,space_id,actor_id,consumer_id,?,? FROM oauth_requests WHERE claim_nonce=? AND status='consumed'",vec![family.clone().into(),now.into(),(now+FAMILY_MS).into(),nonce.into()]));
        queries.push(Statement::new("UPDATE oauth_requests SET family_id=? WHERE claim_nonce=? AND status='consumed' AND EXISTS(SELECT 1 FROM oauth_families WHERE family_id=?)",vec![family.clone().into(),nonce.into(),family.clone().into()]));
        queries.push(Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,expires_at,created_at,credential_kind) SELECT ?,?,space_id,actor_id,consumer_id,?,?,'oauth' FROM oauth_families WHERE family_id=? RETURNING token_id",vec![token_id.clone().into(),digest(&access),(now+ACCESS_MS).into(),now.into(),family.clone().into()]));
        let result_index = queries.len() - 1;
        queries.push(Statement::new("INSERT INTO oauth_access_tokens(token_id,family_id) SELECT token_id,? FROM tokens WHERE token_id=?",vec![family.clone().into(),token_id.into()]));
        queries.push(Statement::new("INSERT INTO oauth_refresh_tokens(token_digest,family_id,expires_at) SELECT ?,family_id,expires_at FROM oauth_families WHERE family_id=?",vec![digest(&refresh),family.into()]));
        let results = self.db.batch(queries).await?;
        if results[result_index].is_empty() {
            return Err(oauth_error("invalid_grant"));
        }
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":ACCESS_MS/1000,"refresh_token":refresh,"scope":"waypost"}),
        )
    }
    async fn rotate_refresh(&self, client: &str, resource: &str, raw: &str) -> Result<Value> {
        opaque(raw)?;
        let now = self.clock.now_ms();
        let nonce = random_id("refresh")?;
        let selector = "SELECT r.family_id FROM oauth_refresh_tokens r JOIN oauth_families f ON f.family_id=r.family_id WHERE r.token_digest=? AND f.client_id=? AND f.resource=? AND r.used_at IS NOT NULL";
        let mut q = revoke_queries(
            selector,
            vec![digest(raw), client.into(), resource.into()],
            now,
        );
        q.push(Statement::new(format!("UPDATE oauth_refresh_tokens SET used_at=?,redeem_nonce=? WHERE token_digest=? AND used_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM oauth_families f WHERE f.family_id=oauth_refresh_tokens.family_id AND f.client_id=? AND f.resource=? AND {LIVE_FAMILY})"),vec![now.into(),nonce.clone().into(),digest(raw),now.into(),client.into(),resource.into(),now.into()]));
        let token_id = random_id("token")?;
        let access = secret("wpo_")?;
        let refresh = secret("wpr_")?;
        // The old digest remains for replay detection. The family has an absolute expiry.
        q.push(Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,expires_at,created_at,credential_kind) SELECT ?,?,f.space_id,f.actor_id,f.consumer_id,MIN(?,f.expires_at),?,'oauth' FROM oauth_refresh_tokens r JOIN oauth_families f ON f.family_id=r.family_id WHERE r.redeem_nonce=? RETURNING expires_at",vec![token_id.clone().into(),digest(&access),(now+ACCESS_MS).into(),now.into(),nonce.clone().into()]));
        q.push(Statement::new("INSERT INTO oauth_access_tokens(token_id,family_id) SELECT ?,family_id FROM oauth_refresh_tokens WHERE redeem_nonce=?",vec![token_id.into(),nonce.clone().into()]));
        q.push(Statement::new("INSERT INTO oauth_refresh_tokens(token_digest,family_id,expires_at) SELECT ?,family_id,expires_at FROM oauth_refresh_tokens WHERE redeem_nonce=?",vec![digest(&refresh),nonce.into()]));
        let rows = self.db.batch(q).await?;
        let row = rows[3]
            .first()
            .ok_or_else(|| oauth_error("invalid_grant"))?;
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":(integer(row,"expires_at")?-now)/1000,"refresh_token":refresh,"scope":"waypost"}),
        )
    }
    async fn redeem_device(&self, client: &str, resource: &str, raw: &str) -> Result<Value> {
        opaque(raw)?;
        let now = self.clock.now_ms();
        let rows=self.db.query(Statement::new("SELECT status,expires_at FROM oauth_requests WHERE kind='device' AND device_digest=? AND client_id=? AND resource=?",vec![digest(raw),client.into(),resource.into()])).await?;
        let row = rows.first().ok_or_else(|| oauth_error("invalid_grant"))?;
        if integer(row, "expires_at")? <= now {
            return Err(oauth_error("expired_token"));
        }
        match text(row, "status")?.as_str() {
            "denied" => return Err(oauth_error("access_denied")),
            "consumed" => return Err(oauth_error("invalid_grant")),
            _ => {}
        }
        let now = self.clock.now_ms();
        let nonce = random_id("devicepoll")?;
        let results=self.db.batch(vec![
            Statement::new("UPDATE oauth_requests SET interval_sec=interval_sec+5,next_poll_at=?+(interval_sec+5)*1000 WHERE kind='device' AND device_digest=? AND client_id=? AND resource=? AND expires_at>? AND status IN('pending','approved') AND next_poll_at>? RETURNING request_id",vec![now.into(),digest(raw),client.into(),resource.into(),now.into(),now.into()]),
            Statement::new("UPDATE oauth_requests SET next_poll_at=?+interval_sec*1000,claim_nonce=? WHERE kind='device' AND device_digest=? AND client_id=? AND resource=? AND expires_at>? AND status IN('pending','approved') AND next_poll_at<=? RETURNING status",vec![now.into(),nonce.clone().into(),digest(raw),client.into(),resource.into(),now.into(),now.into()])
        ]).await?;
        if !results[0].is_empty() {
            return Err(oauth_error("slow_down"));
        }
        let Some(row) = results[1].first() else {
            return Err(self.device_terminal_error(client, resource, raw).await?);
        };
        if text(row, "status")? == "pending" {
            return Err(oauth_error("authorization_pending"));
        }
        // Refresh time after awaiting polling and recheck authority inside issuance batch.
        let now = self.clock.now_ms();
        let claim = Statement::new(
            format!(
                "UPDATE oauth_requests AS q SET status='consumed' WHERE claim_nonce=? AND status='approved' AND expires_at>? AND {LIVE_REQUEST}"
            ),
            vec![nonce.clone().into(), now.into()],
        );
        match self.issue_request(vec![claim], &nonce, now).await {
            Err(error) if error.code == "invalid_grant" => {
                Err(self.device_terminal_error(client, resource, raw).await?)
            }
            result => result,
        }
    }
    // An await may span denial or expiry. Classify only after failed conditional
    // writes, keeping the usual polling path to its existing query/batch budget.
    async fn device_terminal_error(
        &self,
        client: &str,
        resource: &str,
        raw: &str,
    ) -> Result<Error> {
        let rows=self.db.query(Statement::new(format!("SELECT status,expires_at,({LIVE_REQUEST}) AS live FROM oauth_requests q WHERE kind='device' AND device_digest=? AND client_id=? AND resource=?"),vec![digest(raw),client.into(),resource.into()])).await?;
        let Some(row) = rows.first() else {
            return Ok(oauth_error("invalid_grant"));
        };
        if integer(row, "expires_at")? <= self.clock.now_ms() {
            return Ok(oauth_error("expired_token"));
        }
        Ok(oauth_error(if text(row, "status")? == "denied" {
            "access_denied"
        } else if matches!(text(row, "status")?.as_str(), "pending" | "approved")
            && (text(row, "status")? == "pending" || integer(row, "live")? == 1)
        {
            // Another interval-eligible poll can replace our nonce while this
            // request awaits D1. Keep the client polling; do not terminate a
            // still-live grant. The stored next_poll_at remains authoritative.
            "authorization_pending"
        } else {
            "invalid_grant"
        }))
    }
    pub(super) async fn oauth_revoke(&self, p: BTreeMap<String, String>) -> Result<Value> {
        fields(&p, &["client_id", "token", "token_type_hint"])?;
        let client = required(&p, "client_id")?;
        self.oauth_client(client)?;
        let raw = required(&p, "token")?;
        // Unknown tokens return the same success; neither discovery nor oracle response.
        if raw.len() > 512 {
            return Ok(json!({}));
        }
        let selector = "SELECT f.family_id FROM oauth_families f WHERE f.client_id=? AND (EXISTS(SELECT 1 FROM oauth_refresh_tokens r WHERE r.family_id=f.family_id AND r.token_digest=?) OR EXISTS(SELECT 1 FROM oauth_access_tokens a JOIN tokens t ON t.token_id=a.token_id WHERE a.family_id=f.family_id AND t.token_digest=?))";
        self.db
            .batch(revoke_queries(
                selector,
                vec![client.into(), digest(raw), digest(raw)],
                self.clock.now_ms(),
            ))
            .await?;
        Ok(json!({}))
    }
}

#[cfg(all(test, feature = "native"))]
pub(super) mod tests {
    use super::*;
    use crate::native::{FileStore, SqliteDb};
    use std::cell::Cell;
    pub(super) struct TestClock(pub(super) Cell<i64>);
    impl Clock for TestClock {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
    }
    type TestApp = App<SqliteDb, FileStore>;
    const CODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DEVICE: &str = "ddddddddddddddddddddddddddddddddddddddddddd";
    const VERIFIER: &str = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";
    const RESOURCE: &str = "https://waypost.example/mcp";
    fn params(grant: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("grant_type".into(), grant.into()),
            ("client_id".into(), "test".into()),
            ("resource".into(), RESOURCE.into()),
        ])
    }
    pub(super) fn code_params() -> BTreeMap<String, String> {
        let mut p = params("authorization_code");
        p.extend([
            ("code".into(), CODE.into()),
            (
                "redirect_uri".into(),
                "https://client.example/callback".into(),
            ),
            ("code_verifier".into(), VERIFIER.into()),
        ]);
        p
    }
    pub(super) fn refresh_params(v: &Value) -> BTreeMap<String, String> {
        let mut p = params("refresh_token");
        p.insert(
            "refresh_token".into(),
            v["refresh_token"].as_str().unwrap().into(),
        );
        p
    }
    pub(super) fn device_params() -> BTreeMap<String, String> {
        let mut p = params("urn:ietf:params:oauth:grant-type:device_code");
        p.insert("device_code".into(), DEVICE.into());
        p
    }
    pub(super) async fn fixture() -> (tempfile::TempDir, TestApp, Rc<TestClock>) {
        let dir = tempfile::tempdir().unwrap();
        let clock = Rc::new(TestClock(Cell::new(1_000_000)));
        let mut app = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: "test-only-admin-secret-32-bytes-long".into(),
                public_origin: "https://waypost.example".into(),
            },
        )
        .with_clock(clock.clone());
        app.oauth = Some(super::super::oauth::OAuthConfig {
            clients: vec![
                super::super::oauth::OAuthClient {
                    client_id: "test".into(),
                    name: "Test".into(),
                    redirect_uris: vec!["https://client.example/callback".into()],
                    allow_loopback_port_variation: false,
                },
                super::super::oauth::OAuthClient {
                    client_id: "other".into(),
                    name: "Other".into(),
                    redirect_uris: vec![],
                    allow_loopback_port_variation: false,
                },
            ],
        });
        let response = app
            .handle(Request::json(
                "POST",
                "/admin/v0/spaces",
                &app.config.admin_secret,
                json!({"request_id":"oauth-test-space","display_name":"Test"}),
            ))
            .await;
        assert_eq!(response.status, 200);
        let space = serde_json::from_slice::<Value>(&response.body).unwrap()["data"].clone();
        let sid = space["space_id"].as_str().unwrap();
        let actor = space["default_actor_id"].as_str().unwrap();
        let consumer = space["default_consumer_id"].as_str().unwrap();
        app.db.batch(vec![
   Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('acct','https://issuer.example','sub',?)",vec![clock.now_ms().into()]),
   Statement::new("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,'acct',?)",vec![sid.into(),clock.now_ms().into()]),
   Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,redirect_uri,code_challenge,code_digest,status,created_at,expires_at,next_poll_at,account_id,space_id,actor_id,consumer_id) VALUES('code','code','test',?,'waypost','https://client.example/callback',?,?,'approved',?,?,?,'acct',?,?,?)",vec![RESOURCE.into(),verifier(VERIFIER).unwrap().into(),digest(CODE),clock.now_ms().into(),(clock.now_ms()+600_000).into(),clock.now_ms().into(),sid.into(),actor.into(),consumer.into()]),
   Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,device_digest,status,created_at,expires_at,next_poll_at,account_id,space_id,actor_id,consumer_id) VALUES('device','device','test',?,'waypost',?,'pending',?,?,?,'acct',?,?,?)",vec![RESOURCE.into(),digest(DEVICE),clock.now_ms().into(),(clock.now_ms()+600_000).into(),clock.now_ms().into(),sid.into(),actor.into(),consumer.into()])
  ]).await.unwrap();
        (dir, app, clock)
    }
    async fn count(app: &TestApp, sql: &str) -> i64 {
        integer(
            &app.db.query(Statement::new(sql, vec![])).await.unwrap()[0],
            "n",
        )
        .unwrap()
    }
    #[tokio::test(flavor = "current_thread")]
    async fn code_binding_and_replay_revoke_family() {
        let (_dir, app, _clock) = fixture().await;
        for (key, value, error) in [
            (
                "code_verifier",
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "invalid_grant",
            ),
            (
                "redirect_uri",
                "https://evil.example/callback",
                "invalid_grant",
            ),
            ("client_id", "other", "invalid_grant"),
            ("resource", "https://other.example/mcp", "invalid_target"),
            ("scope", "admin", "invalid_scope"),
        ] {
            let mut p = code_params();
            p.insert(key.into(), value.into());
            assert_eq!(app.oauth_token(p).await.unwrap_err().code, error);
        }
        let result = app.oauth_token(code_params()).await.unwrap();
        assert_eq!(result["expires_in"], 300);
        let mut wrong_replay = code_params();
        wrong_replay.insert(
            "code_verifier".into(),
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
        );
        assert_eq!(
            app.oauth_token(wrong_replay).await.unwrap_err().code,
            "invalid_grant"
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) n FROM oauth_families WHERE revoked_at IS NULL"
            )
            .await,
            1
        );
        assert!(result["access_token"].as_str().unwrap().starts_with("wpo_"));
        assert_eq!(
            count(
                &app,
                "SELECT count(*) n FROM tokens WHERE credential_kind='oauth' AND revoked_at IS NULL"
            )
            .await,
            1
        );
        assert_eq!(
            app.oauth_token(code_params()).await.unwrap_err().code,
            "invalid_grant"
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) n FROM oauth_families WHERE revoked_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) n FROM tokens WHERE credential_kind='oauth' AND revoked_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            app.oauth_token(refresh_params(&result))
                .await
                .unwrap_err()
                .code,
            "invalid_grant"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn refresh_rotation_wrong_client_and_replay() {
        let (_dir, app, clock) = fixture().await;
        let first = app.oauth_token(code_params()).await.unwrap();
        clock.0.set(clock.now_ms() + 1000);
        let mut wrong = refresh_params(&first);
        wrong.insert("client_id".into(), "other".into());
        assert_eq!(
            app.oauth_token(wrong).await.unwrap_err().code,
            "invalid_grant"
        );
        let second = app.oauth_token(refresh_params(&first)).await.unwrap();
        assert_ne!(first["refresh_token"], second["refresh_token"]);
        assert_eq!(
            count(
                &app,
                "SELECT count(*) n FROM oauth_refresh_tokens WHERE used_at IS NOT NULL"
            )
            .await,
            1
        );
        assert_eq!(
            app.oauth_token(refresh_params(&first))
                .await
                .unwrap_err()
                .code,
            "invalid_grant"
        );
        assert_eq!(
            app.oauth_token(refresh_params(&second))
                .await
                .unwrap_err()
                .code,
            "invalid_grant"
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) n FROM tokens WHERE credential_kind='oauth' AND revoked_at IS NULL"
            )
            .await,
            0
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn device_polling_backoff_and_one_use() {
        let (_dir, app, clock) = fixture().await;
        assert_eq!(
            app.oauth_token(device_params()).await.unwrap_err().code,
            "authorization_pending"
        );
        assert_eq!(
            app.oauth_token(device_params()).await.unwrap_err().code,
            "slow_down"
        );
        assert_eq!(
            app.oauth_token(device_params()).await.unwrap_err().code,
            "slow_down"
        );
        assert_eq!(
            count(
                &app,
                "SELECT interval_sec n FROM oauth_requests WHERE request_id='device'"
            )
            .await,
            15
        );
        app.db
            .batch(vec![Statement::new(
                "UPDATE oauth_requests SET status='approved' WHERE request_id='device'",
                vec![],
            )])
            .await
            .unwrap();
        clock.0.set(clock.now_ms() + 15_000);
        let tokens = app.oauth_token(device_params()).await.unwrap();
        assert_eq!(tokens["token_type"], "Bearer");
        assert_eq!(
            app.oauth_token(device_params()).await.unwrap_err().code,
            "invalid_grant"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn authority_revocation_expiry_and_device_denial() {
        let (_dir, app, clock) = fixture().await;
        app.db
            .batch(vec![Statement::new(
                "UPDATE oauth_requests SET status='denied' WHERE request_id='device'",
                vec![],
            )])
            .await
            .unwrap();
        assert_eq!(
            app.oauth_token(device_params()).await.unwrap_err().code,
            "access_denied"
        );
        let issued = app.oauth_token(code_params()).await.unwrap();
        app.db
            .batch(vec![Statement::new(
                "DELETE FROM account_spaces WHERE account_id='acct'",
                vec![],
            )])
            .await
            .unwrap();
        assert_eq!(
            app.oauth_token(refresh_params(&issued))
                .await
                .unwrap_err()
                .code,
            "invalid_grant"
        );
        clock.0.set(clock.now_ms() + 600_001);
        assert_eq!(
            app.oauth_token(device_params()).await.unwrap_err().code,
            "expired_token"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn revocation_ownership_unknown_and_access_or_refresh() {
        for key in ["access_token", "refresh_token"] {
            let (_dir, app, _clock) = fixture().await;
            let issued = app.oauth_token(code_params()).await.unwrap();
            let revoke = |client: &str, token: &str| {
                BTreeMap::from([
                    ("client_id".into(), client.into()),
                    ("token".into(), token.into()),
                ])
            };
            assert_eq!(
                app.oauth_revoke(revoke("test", "unknown")).await.unwrap(),
                json!({})
            );
            assert_eq!(
                app.oauth_revoke(revoke("other", issued[key].as_str().unwrap()))
                    .await
                    .unwrap(),
                json!({})
            );
            assert_eq!(
                count(
                    &app,
                    "SELECT count(*) n FROM oauth_families WHERE revoked_at IS NULL"
                )
                .await,
                1
            );
            app.oauth_revoke(revoke("test", issued[key].as_str().unwrap()))
                .await
                .unwrap();
            assert_eq!(
                app.oauth_token(refresh_params(&issued))
                    .await
                    .unwrap_err()
                    .code,
                "invalid_grant"
            );
            assert_eq!(count(&app,"SELECT count(*) n FROM tokens WHERE credential_kind='oauth' AND revoked_at IS NULL").await,0);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn code_and_refresh_expiry_never_create_extra_tokens() {
        let (_dir, app, clock) = fixture().await;
        clock.0.set(clock.now_ms() + 600_001);
        assert_eq!(
            app.oauth_token(code_params()).await.unwrap_err().code,
            "invalid_grant"
        );
        assert_eq!(
            count(&app, "SELECT count(*) n FROM oauth_families").await,
            0
        );
        let (_dir, app, clock) = fixture().await;
        let first = app.oauth_token(code_params()).await.unwrap();
        clock.0.set(clock.now_ms() + FAMILY_MS - 1000);
        let last = app.oauth_token(refresh_params(&first)).await.unwrap();
        assert_eq!(last["expires_in"], 1);
        clock.0.set(clock.now_ms() + 1000);
        assert_eq!(
            app.oauth_token(refresh_params(&last))
                .await
                .unwrap_err()
                .code,
            "invalid_grant"
        );
        assert_eq!(
            count(&app, "SELECT count(*) n FROM oauth_access_tokens").await,
            2
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn disabled_identity_cannot_redeem_approved_code_or_device() {
        for statement in [
            "UPDATE accounts SET disabled=1",
            "UPDATE actors SET disabled=1",
            "UPDATE consumers SET disabled=1",
            "DELETE FROM account_spaces",
        ] {
            let (_dir, app, _clock) = fixture().await;
            app.db
                .batch(vec![
                    Statement::new(statement, vec![]),
                    Statement::new(
                        "UPDATE oauth_requests SET status='approved' WHERE request_id='device'",
                        vec![],
                    ),
                ])
                .await
                .unwrap();
            assert_eq!(
                app.oauth_token(code_params()).await.unwrap_err().code,
                "invalid_grant"
            );
            assert_eq!(
                app.oauth_token(device_params()).await.unwrap_err().code,
                "invalid_grant"
            );
            assert_eq!(
                count(&app, "SELECT count(*) n FROM oauth_families").await,
                0
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn access_authentication_and_final_guard_fail_closed() {
        for statement in [
            "UPDATE oauth_families SET revoked_at=1",
            "UPDATE oauth_families SET resource='https://other.example/mcp'",
            "UPDATE oauth_families SET client_id='removed'",
            "UPDATE accounts SET disabled=1",
            "DELETE FROM account_spaces",
            "DELETE FROM oauth_access_tokens",
            "UPDATE oauth_families SET expires_at=1",
        ] {
            let (_dir, app, _clock) = fixture().await;
            let issued = app.oauth_token(code_params()).await.unwrap();
            let request = Request::json(
                "POST",
                "/mcp",
                issued["access_token"].as_str().unwrap(),
                json!({}),
            );
            let principal = app.authenticate(&request).await.unwrap();
            app.current(&principal).await.unwrap();
            app.db
                .batch(vec![Statement::new(statement, vec![])])
                .await
                .unwrap();
            assert!(app.authenticate(&request).await.is_err(), "{statement}");
            assert!(app.current(&principal).await.is_err(), "{statement}");
        }
        let (_dir, mut app, _clock) = fixture().await;
        let issued = app.oauth_token(code_params()).await.unwrap();
        let request = Request::json(
            "POST",
            "/mcp",
            issued["access_token"].as_str().unwrap(),
            json!({}),
        );
        let principal = app.authenticate(&request).await.unwrap();
        app.oauth = None;
        assert!(app.authenticate(&request).await.is_err());
        assert!(app.current(&principal).await.is_err());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn mcp_unauthorized_has_resource_challenge_when_enabled() {
        let (_dir, app, _clock) = fixture().await;
        let response = app
            .handle(Request::json("POST", "/mcp", "invalid", json!({})))
            .await;
        assert_eq!(response.status, 401);
        assert_eq!(
            response.headers.get("www-authenticate").unwrap(),
            "Bearer resource_metadata=\"https://waypost.example/.well-known/oauth-protected-resource/mcp\", scope=\"waypost\""
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn removed_redirect_cannot_exchange_already_approved_code() {
        let (_dir, mut app, _clock) = fixture().await;
        app.oauth.as_mut().unwrap().clients[0].redirect_uris.clear();
        assert_eq!(
            app.oauth_token(code_params()).await.unwrap_err().code,
            "invalid_grant"
        );
        assert_eq!(
            count(&app, "SELECT count(*) n FROM oauth_families").await,
            0
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn device_expiry_during_poll_or_claim_returns_expired_token() {
        struct AdvancingClock {
            now: Cell<i64>,
            step: i64,
        }
        impl Clock for AdvancingClock {
            fn now_ms(&self) -> i64 {
                let now = self.now.get();
                self.now.set(now + self.step);
                now
            }
        }
        for step in [600_001, 300_001] {
            let (_dir, mut app, _clock) = fixture().await;
            app.db
                .batch(vec![Statement::new(
                    "UPDATE oauth_requests SET status='approved' WHERE request_id='device'",
                    vec![],
                )])
                .await
                .unwrap();
            app.clock = Rc::new(AdvancingClock {
                now: Cell::new(1_000_000),
                step,
            });
            assert_eq!(
                app.oauth_token(device_params()).await.unwrap_err().code,
                "expired_token"
            );
            assert_eq!(
                count(&app, "SELECT count(*) n FROM oauth_families").await,
                0
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn device_denial_between_read_poll_and_claim_is_reported() {
        struct DenialClock {
            path: std::path::PathBuf,
            calls: Cell<usize>,
            deny_on: usize,
        }
        impl Clock for DenialClock {
            fn now_ms(&self) -> i64 {
                let calls = self.calls.get() + 1;
                self.calls.set(calls);
                if calls == self.deny_on {
                    rusqlite::Connection::open(&self.path)
                        .unwrap()
                        .execute(
                            "UPDATE oauth_requests SET status='denied' WHERE request_id='device'",
                            [],
                        )
                        .unwrap();
                }
                1_000_000
            }
        }
        for deny_on in [2, 3] {
            let (dir, mut app, _clock) = fixture().await;
            app.db
                .batch(vec![Statement::new(
                    "UPDATE oauth_requests SET status='approved' WHERE request_id='device'",
                    vec![],
                )])
                .await
                .unwrap();
            app.clock = Rc::new(DenialClock {
                path: dir.path().join("db"),
                calls: Cell::new(0),
                deny_on,
            });
            assert_eq!(
                app.oauth_token(device_params()).await.unwrap_err().code,
                "access_denied"
            );
            assert_eq!(
                count(&app, "SELECT count(*) n FROM oauth_families").await,
                0
            );
        }
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "oauth_token_adversarial_tests.rs"]
mod adversarial_tests;
