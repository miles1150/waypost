//! Optional, custom JSON device pairing. This is NOT RFC 8628 or MCP OAuth.
//! Device possession and PKCE never confer authority until a browser owner approves.
use super::*;
use crate::json::{fields, required};

const DEVICE_LIFETIME: i64 = 10 * 60 * 1000;
const POLL_INTERVAL: i64 = 5 * 1000;
const TOKEN_LIFETIME: i64 = 30 * 24 * 60 * 60 * 1000;

fn digest(value: &str) -> Sql {
    Sha256::digest(value.as_bytes()).to_vec().into()
}
fn user_digest(value: &str) -> Result<Sql> {
    let normalized = value.replace('-', "").to_ascii_uppercase();
    if normalized.len() != 16 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::invalid("Invalid pairing code."));
    }
    Ok(digest(&normalized))
}
fn optional_integer(row: &Row, name: &str) -> Result<Option<i64>> {
    match row.get(name) {
        Some(Sql::Null) => Ok(None),
        _ => integer(row, name).map(Some),
    }
}
fn pkce(value: &str, challenge: bool) -> Result<()> {
    let valid = if challenge {
        value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && URL_SAFE_NO_PAD.decode(value).is_ok_and(|b| b.len() == 32)
    } else {
        (43..=128).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    };
    if valid {
        Ok(())
    } else {
        Err(Error::invalid("Invalid S256 PKCE value."))
    }
}

impl<D: Database, O: ObjectStore> App<D, O> {
    pub(super) async fn account_device_action(
        &self,
        request: &Request,
        body: Value,
    ) -> Result<Value> {
        if request.method != "POST" {
            return Err(Error::not_found());
        }
        let now = self.clock.now_ms();
        match request.path.as_str() {
            "/account/devices/start" => {
                fields(
                    &body,
                    &["display_name", "code_challenge", "code_challenge_method"],
                )?;
                let name = required(&body, "display_name")?;
                if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
                    return Err(Error::invalid(
                        "Device name must be 1–80 bytes without controls.",
                    ));
                }
                if required(&body, "code_challenge_method")? != "S256" {
                    return Err(Error::invalid("Only S256 is supported."));
                }
                let challenge = required(&body, "code_challenge")?;
                pkce(&challenge, true)?;
                let device = URL_SAFE_NO_PAD.encode(random_bytes::<32>()?);
                // 64-bit human code, separate from the high-entropy redemption credential.
                let user = hex::encode_upper(random_bytes::<8>()?);
                let id = random_id("device")?;
                let rows = self.db.batch(vec![
                    Statement::new("DELETE FROM account_devices WHERE state='pending' AND expires_at<=?",vec![now.into()]),
                    Statement::new("INSERT INTO account_devices(device_id,device_digest,user_digest,code_challenge,display_name,state,created_at,expires_at,next_poll_at) SELECT ?,?,?,?,?,'pending',?,?,? WHERE (SELECT COUNT(*) FROM account_devices WHERE state IN('pending','approved') AND expires_at>?)<1000 RETURNING device_id", vec![id.clone().into(),digest(&device),digest(&user),challenge.into(),name.into(),now.into(),(now+DEVICE_LIFETIME).into(),now.into(),now.into()])
                ]).await?;
                if rows[1].is_empty() {
                    return Err(Error::new(
                        "RATE_LIMITED",
                        "Too many outstanding pairing requests.",
                    ));
                }
                Ok(
                    json!({"device_id":id,"device_code":device,"user_code":format!("{}-{}-{}-{}",&user[0..4],&user[4..8],&user[8..12],&user[12..16]),"expires_in":DEVICE_LIFETIME/1000,"interval":POLL_INTERVAL/1000,"protocol":"waypost-device-pairing-v1"}),
                )
            }
            "/account/devices/inspect" | "/account/devices/approve" => {
                let approval = request.path.ends_with("/approve");
                fields(
                    &body,
                    if approval {
                        &["user_code", "actor_id", "consumer_id"]
                    } else {
                        &["user_code"]
                    },
                )?;
                let session = self.account_session(request, true).await?;
                let now = self.clock.now_ms();
                if approval && integer(&session, "created_at")? < now - 15 * 60 * 1000 {
                    return Err(Error::forbidden());
                }
                let account = text(&session, "account_id")?;
                let sid = text(&session, "selected_space_id").map_err(|_| Error::forbidden())?;
                let user = user_digest(&required(&body, "user_code")?)?;
                let rows=self.db.query(Statement::new("SELECT device_id,display_name,expires_at FROM account_devices WHERE user_digest=? AND state='pending' AND expires_at>?",vec![user.clone(),now.into()])).await?;
                let row = rows.first().ok_or_else(Error::not_found)?;
                if !approval {
                    return Ok(
                        json!({"device_id":text(row,"device_id")?,"display_name":text(row,"display_name")?,"expires_at":integer(row,"expires_at")?,"space_id":sid,"access_model":"space_membership","warning":"This connection can send messages and read/write shared space materials. Device name is untrusted."}),
                    );
                }
                let aid = required(&body, "actor_id")?;
                let cid = required(&body, "consumer_id")?;
                crate::domain::check_id(&aid)?;
                crate::domain::check_id(&cid)?;
                let cookie = super::accounts::account_cookie(request, &self.config.public_origin)?;
                let now = self.clock.now_ms();
                let rows=self.db.batch(vec![Statement::new("UPDATE account_devices SET state='approved',account_id=?,space_id=?,actor_id=?,consumer_id=?,approved_at=? WHERE user_digest=? AND state='pending' AND expires_at>? AND EXISTS(SELECT 1 FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id JOIN account_spaces m ON m.account_id=a.account_id AND m.space_id=s.selected_space_id WHERE s.session_digest=? AND s.account_id=? AND s.selected_space_id=? AND s.expires_at>? AND s.created_at>=? AND a.disabled=0) AND EXISTS(SELECT 1 FROM actors a JOIN consumers c ON c.space_id=a.space_id AND c.actor_id=a.actor_id WHERE a.space_id=? AND a.actor_id=? AND c.consumer_id=? AND a.disabled=0 AND c.disabled=0 AND c.view='inbox') RETURNING device_id",vec![account.clone().into(),sid.clone().into(),aid.into(),cid.into(),now.into(),user,now.into(),digest(&cookie),account.into(),sid.clone().into(),now.into(),(now-15*60*1000).into(),sid.into(),required(&body,"actor_id")?.into(),required(&body,"consumer_id")?.into()])]).await?;
                if rows[0].is_empty() {
                    return Err(Error::forbidden());
                }
                Ok(json!({"approved":true,"device_id":text(&rows[0][0],"device_id")?}))
            }
            "/account/devices/token" => {
                fields(&body, &["device_code", "code_verifier"])?;
                let device = required(&body, "device_code")?;
                if device.len() != 43 {
                    return Err(Error::unauthenticated());
                }
                let verifier = required(&body, "code_verifier")?;
                pkce(&verifier, false)?;
                let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                let nonce = random_id("poll")?;
                let rows=self.db.batch(vec![Statement::new("UPDATE account_devices SET next_poll_at=?,poll_nonce=? WHERE device_digest=? AND code_challenge=? AND expires_at>? AND next_poll_at<=? AND state IN('pending','approved') RETURNING state,device_id",vec![(now+POLL_INTERVAL).into(),nonce.clone().into(),digest(&device),challenge.into(),now.into(),now.into()])]).await?;
                let Some(row) = rows[0].first() else {
                    return Err(Error::new(
                        "PAIRING_NOT_READY",
                        "Pairing unavailable or polled too soon; wait five seconds. Consumed codes cannot be recovered.",
                    ));
                };
                if text(row, "state")? == "pending" {
                    return Err(Error::new(
                        "AUTHORIZATION_PENDING",
                        "Owner approval is pending; wait five seconds.",
                    ));
                }
                let token_id = random_id("token")?;
                let token = format!("wp_{}", URL_SAFE_NO_PAD.encode(random_bytes::<32>()?));
                let now = self.clock.now_ms();
                // Both writes are one transaction. The winning nonce and all authority are
                // rechecked at commit, not inferred from the earlier poll response.
                let guard = "EXISTS(SELECT 1 FROM account_devices d JOIN accounts a ON a.account_id=d.account_id JOIN account_spaces m ON m.account_id=d.account_id AND m.space_id=d.space_id JOIN actors x ON x.space_id=d.space_id AND x.actor_id=d.actor_id JOIN consumers c ON c.space_id=d.space_id AND c.consumer_id=d.consumer_id AND c.actor_id=d.actor_id WHERE d.poll_nonce=? AND d.state='approved' AND d.expires_at>? AND a.disabled=0 AND x.disabled=0 AND c.disabled=0 AND c.view='inbox')";
                let rows=self.db.batch(vec![
                    Statement::new(format!("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,expires_at,created_at) SELECT ?,?,space_id,actor_id,consumer_id,?,? FROM account_devices WHERE poll_nonce=? AND {guard} RETURNING space_id,actor_id,consumer_id"),vec![token_id.clone().into(),digest(&token),(now+TOKEN_LIFETIME).into(),now.into(),nonce.clone().into(),nonce.clone().into(),now.into()]),
                    Statement::new("UPDATE account_devices SET state='consumed',token_id=? WHERE poll_nonce=? AND state='approved' AND EXISTS(SELECT 1 FROM tokens WHERE token_id=?)",vec![token_id.clone().into(),nonce.into(),token_id.clone().into()])
                ]).await?;
                let row = rows[0].first().ok_or_else(Error::forbidden)?;
                Ok(
                    json!({"token":token,"token_id":token_id,"token_type":"Bearer","expires_in":TOKEN_LIFETIME/1000,"space_id":text(row,"space_id")?,"actor_id":text(row,"actor_id")?,"consumer_id":text(row,"consumer_id")?}),
                )
            }
            "/account/devices/list" => {
                fields(&body, &["cursor"])?;
                let cursor = match body.get("cursor") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(id)) => {
                        crate::domain::check_id(id)?;
                        Some(id.clone())
                    }
                    _ => return Err(Error::invalid("Invalid device cursor.")),
                };
                let session = self.account_session(request, true).await?;
                let rows=self.db.query(Statement::new("SELECT d.device_id,d.display_name,d.state,d.space_id,d.actor_id,d.consumer_id,d.token_id,d.created_at,d.expires_at AS pairing_expires_at,d.approved_at,t.expires_at AS token_expires_at,t.revoked_at FROM account_devices d LEFT JOIN tokens t ON t.token_id=d.token_id WHERE d.account_id=? AND (? IS NULL OR d.device_id>?) ORDER BY d.device_id LIMIT 101",vec![text(&session,"account_id")?.into(),cursor.clone().into(),cursor.into()])).await?;
                let more = rows.len() > 100;
                let devices=rows.iter().take(100).map(|r| Ok(json!({"device_id":text(r,"device_id")?,"display_name":text(r,"display_name")?,"state":text(r,"state")?,"space_id":crate::storage::driver::optional_text(r,"space_id"),"actor_id":crate::storage::driver::optional_text(r,"actor_id"),"consumer_id":crate::storage::driver::optional_text(r,"consumer_id"),"token_id":crate::storage::driver::optional_text(r,"token_id"),"created_at":integer(r,"created_at")?,"pairing_expires_at":integer(r,"pairing_expires_at")?,"token_expires_at":optional_integer(r,"token_expires_at")?,"revoked_at":optional_integer(r,"revoked_at")?}))).collect::<Result<Vec<_>>>()?;
                let next = if more {
                    devices.last().and_then(|d| d["device_id"].as_str())
                } else {
                    None
                };
                Ok(json!({"devices":devices,"has_more":more,"next_cursor":next}))
            }
            "/account/devices/deny" => {
                fields(&body, &["user_code"])?;
                let session = self.account_session(request, true).await?;
                let account = text(&session, "account_id")?;
                let cookie = super::accounts::account_cookie(request, &self.config.public_origin)?;
                let rows=self.db.batch(vec![Statement::new("UPDATE account_devices SET state='denied',account_id=? WHERE user_digest=? AND state='pending' AND expires_at>? AND EXISTS(SELECT 1 FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id WHERE s.session_digest=? AND s.account_id=? AND s.expires_at>? AND a.disabled=0) RETURNING device_id",vec![account.clone().into(),user_digest(&required(&body,"user_code")?)?,now.into(),digest(&cookie),account.into(),now.into()])]).await?;
                if rows[0].is_empty() {
                    return Err(Error::not_found());
                }
                Ok(json!({"denied":true,"device_id":text(&rows[0][0],"device_id")?}))
            }
            "/account/devices/revoke" => {
                fields(&body, &["device_id"])?;
                let session = self.account_session(request, true).await?;
                let account = text(&session, "account_id")?;
                let id = required(&body, "device_id")?;
                crate::domain::check_id(&id)?;
                let cookie = super::accounts::account_cookie(request, &self.config.public_origin)?;
                let authority = "EXISTS(SELECT 1 FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id WHERE s.session_digest=? AND s.account_id=? AND s.expires_at>? AND a.disabled=0)";
                // Revocation remains possible after unlinking a Space: it only removes
                // this account's own device credential, never grants or moves authority.
                let rows=self.db.batch(vec![Statement::new(format!("UPDATE account_devices SET state='revoked' WHERE device_id=? AND account_id=? AND {authority} RETURNING token_id"),vec![id.clone().into(),account.clone().into(),digest(&cookie),account.clone().into(),now.into()]),Statement::new("UPDATE tokens SET revoked_at=COALESCE(revoked_at,?),authority_version=authority_version+CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END WHERE token_id IN(SELECT token_id FROM account_devices WHERE device_id=? AND account_id=? AND state='revoked')",vec![now.into(),id.into(),account.into()])]).await?;
                if rows[0].is_empty() {
                    return Err(Error::not_found());
                }
                Ok(json!({"revoked":true}))
            }
            _ => Err(Error::not_found()),
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::native::{FileStore, SqliteDb};
    use std::cell::Cell;
    struct TestClock(Cell<i64>);
    impl Clock for TestClock {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
    }
    type TestApp = App<SqliteDb, FileStore>;
    const COOKIE: &str = "ccccccccccccccccccccccccccccccccccccccccccc";
    const VERIFIER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    async fn fixture() -> (tempfile::TempDir, TestApp, Rc<TestClock>, Value) {
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
        app.oidc = Some(accounts_oidc::OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "test".into(),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_secret: None,
            google_jwks: false,
            keys: vec![],
        });
        let req = Request::json(
            "POST",
            "/admin/v0/spaces",
            &app.config.admin_secret,
            json!({"request_id":"device-test-space","display_name":"Test"}),
        );
        let response = app.handle(req).await;
        assert_eq!(response.status, 200);
        let space: Value = serde_json::from_slice::<Value>(&response.body).unwrap()["data"].clone();
        let sid = space["space_id"].as_str().unwrap();
        app.db.batch(vec![
            Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_test','https://issuer.example','subject',?)",vec![clock.now_ms().into()]),
            Statement::new("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,'account_test',?)",vec![sid.into(),clock.now_ms().into()]),
            Statement::new("INSERT INTO account_sessions(session_digest,account_id,selected_space_id,created_at,expires_at) VALUES(?,'account_test',?,?,?)",vec![digest(COOKIE),sid.into(),clock.now_ms().into(),(clock.now_ms()+3_600_000).into()])
        ]).await.unwrap();
        (dir, app, clock, space)
    }
    fn request(app: &TestApp, path: &str) -> Request {
        let mut r = Request::json("POST", path, "", json!({}));
        r.headers.remove("authorization");
        r.headers.insert(
            "cookie".into(),
            format!(
                "{}={COOKIE}",
                super::accounts::browser_cookie_name(
                    &app.config.public_origin,
                    super::accounts::BrowserCookie::Account
                )
            ),
        );
        r.headers
            .insert("origin".into(), app.config.public_origin.clone());
        r.headers
            .insert("x-waypost-csrf".into(), app.csrf_token(COOKIE).unwrap());
        r
    }
    async fn start(app: &TestApp) -> Value {
        app.account_device_action(&request(app,"/account/devices/start"),json!({"display_name":"Test laptop","code_challenge_method":"S256","code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))})).await.unwrap()
    }
    async fn approve(app: &TestApp, device: &Value, space: &Value) -> Result<Value> {
        app.account_device_action(&request(app,"/account/devices/approve"),json!({"user_code":device["user_code"],"actor_id":space["default_actor_id"],"consumer_id":space["default_consumer_id"]})).await
    }
    async fn redeem(app: &TestApp, device: &Value, verifier: &str) -> Result<Value> {
        app.account_device_action(
            &request(app, "/account/devices/token"),
            json!({"device_code":device["device_code"],"code_verifier":verifier}),
        )
        .await
    }
    #[tokio::test(flavor = "current_thread")]
    async fn device_pending_pkce_interval_one_time_and_revoke() {
        let (_dir, app, clock, space) = fixture().await;
        let device = start(&app).await;
        assert_eq!(
            redeem(&app, &device, VERIFIER).await.unwrap_err().code,
            "AUTHORIZATION_PENDING"
        );
        approve(&app, &device, &space).await.unwrap();
        assert_eq!(
            redeem(&app, &device, VERIFIER).await.unwrap_err().code,
            "PAIRING_NOT_READY"
        );
        clock.0.set(clock.now_ms() + POLL_INTERVAL);
        assert!(
            redeem(&app, &device, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .await
                .is_err()
        );
        let issued = redeem(&app, &device, VERIFIER).await.unwrap();
        // A lost successful response must never create a second usable credential.
        clock.0.set(clock.now_ms() + POLL_INTERVAL);
        assert!(redeem(&app, &device, VERIFIER).await.is_err());
        let token = issued["token"].as_str().unwrap();
        assert_eq!(
            app.handle(Request::json("GET", "/v0/describe", token, json!({})))
                .await
                .status,
            200
        );
        app.account_device_action(
            &request(&app, "/account/devices/revoke"),
            json!({"device_id":device["device_id"]}),
        )
        .await
        .unwrap();
        assert_eq!(
            app.handle(Request::json("GET", "/v0/describe", token, json!({})))
                .await
                .status,
            401
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn approval_requires_browser_csrf_and_matching_existing_identity() {
        let (_dir, app, _clock, space) = fixture().await;
        let device = start(&app).await;
        let mut r = request(&app, "/account/devices/approve");
        r.headers.remove("x-waypost-csrf");
        let body = json!({"user_code":device["user_code"],"actor_id":space["default_actor_id"],"consumer_id":space["default_consumer_id"]});
        assert!(app.account_device_action(&r, body.clone()).await.is_err());
        let mut bad = body;
        bad["consumer_id"] = json!("consumer_foreign");
        assert!(
            app.account_device_action(&request(&app, "/account/devices/approve"), bad)
                .await
                .is_err()
        );
        approve(&app, &device, &space).await.unwrap();
        assert!(approve(&app, &device, &space).await.is_err());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn revoked_membership_disabled_account_and_expiry_block_redemption() {
        let (_dir, app, clock, space) = fixture().await;
        let device = start(&app).await;
        approve(&app, &device, &space).await.unwrap();
        app.db
            .batch(vec![Statement::new(
                "DELETE FROM account_spaces WHERE account_id='account_test'",
                vec![],
            )])
            .await
            .unwrap();
        assert!(redeem(&app, &device, VERIFIER).await.is_err());
        app.db.batch(vec![Statement::new("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,'account_test',?)",vec![space["space_id"].as_str().unwrap().into(),clock.now_ms().into()])]).await.unwrap();
        clock.0.set(clock.now_ms() + POLL_INTERVAL);
        app.db
            .batch(vec![Statement::new(
                "UPDATE accounts SET disabled=1 WHERE account_id='account_test'",
                vec![],
            )])
            .await
            .unwrap();
        assert!(redeem(&app, &device, VERIFIER).await.is_err());
        app.db
            .batch(vec![Statement::new(
                "UPDATE accounts SET disabled=0 WHERE account_id='account_test'",
                vec![],
            )])
            .await
            .unwrap();
        clock.0.set(clock.now_ms() + DEVICE_LIFETIME);
        assert!(redeem(&app, &device, VERIFIER).await.is_err());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owner_denial_is_terminal_and_listing_never_returns_codes() {
        let (_dir, app, _clock, _space) = fixture().await;
        let device = start(&app).await;
        let out = app
            .account_device_action(
                &request(&app, "/account/devices/deny"),
                json!({"user_code":device["user_code"]}),
            )
            .await
            .unwrap();
        assert_eq!(out["denied"], true);
        assert!(redeem(&app, &device, VERIFIER).await.is_err());
        let listed = app
            .account_device_action(&request(&app, "/account/devices/list"), json!({}))
            .await
            .unwrap();
        assert_eq!(listed["devices"].as_array().unwrap().len(), 1);
        assert_eq!(listed["devices"][0]["state"], "denied");
        let serialized = listed.to_string();
        assert!(!serialized.contains(device["device_code"].as_str().unwrap()));
        assert!(!serialized.contains(device["user_code"].as_str().unwrap()));
        app.db
            .batch(vec![Statement::new(
                "UPDATE account_devices SET account_id=NULL WHERE device_id=?",
                vec![device["device_id"].as_str().unwrap().into()],
            )])
            .await
            .unwrap();
        let listed = app
            .account_device_action(&request(&app, "/account/devices/list"), json!({}))
            .await
            .unwrap();
        assert!(listed["devices"].as_array().unwrap().is_empty());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn pending_pairing_cap_is_atomic_and_only_expired_pending_are_cleaned() {
        let (_dir, app, clock, _space) = fixture().await;
        app.db.batch(vec![Statement::new("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO account_devices(device_id,device_digest,user_digest,code_challenge,display_name,state,created_at,expires_at,next_poll_at) SELECT 'device_test_'||x,randomblob(32),randomblob(32),'unused','Synthetic','pending',?,?,? FROM n",vec![clock.now_ms().into(),(clock.now_ms()+DEVICE_LIFETIME).into(),clock.now_ms().into()])]).await.unwrap();
        let args = json!({"display_name":"At cap","code_challenge_method":"S256","code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))});
        assert_eq!(
            app.account_device_action(&request(&app, "/account/devices/start"), args.clone())
                .await
                .unwrap_err()
                .code,
            "RATE_LIMITED"
        );
        app.db
            .batch(vec![Statement::new(
                "UPDATE account_devices SET state='approved' WHERE device_id='device_test_1'",
                vec![],
            )])
            .await
            .unwrap();
        clock.0.set(clock.now_ms() + DEVICE_LIFETIME);
        app.account_device_action(&request(&app, "/account/devices/start"), args)
            .await
            .unwrap();
        let rows = app
            .db
            .query(Statement::new(
                "SELECT COUNT(*) AS total FROM account_devices",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(integer(&rows[0], "total").unwrap(), 2);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn approval_requires_recent_browser_authentication() {
        let (_dir, app, clock, space) = fixture().await;
        let device = start(&app).await;
        app.db
            .batch(vec![Statement::new(
                "UPDATE account_sessions SET created_at=?",
                vec![(clock.now_ms() - 15 * 60 * 1000 - 1).into()],
            )])
            .await
            .unwrap();
        assert_eq!(
            approve(&app, &device, &space).await.unwrap_err().code,
            "FORBIDDEN"
        );
        app.db
            .batch(vec![Statement::new(
                "UPDATE account_sessions SET created_at=?",
                vec![clock.now_ms().into()],
            )])
            .await
            .unwrap();
        approve(&app, &device, &space).await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn issued_token_loses_authentication_and_final_authority_on_account_changes() {
        let (_dir, app, clock, space) = fixture().await;
        let device = start(&app).await;
        approve(&app, &device, &space).await.unwrap();
        let issued = redeem(&app, &device, VERIFIER).await.unwrap();
        let r = Request::json(
            "GET",
            "/v0/describe",
            issued["token"].as_str().unwrap(),
            json!({}),
        );
        let principal = app.authenticate(&r).await.unwrap();
        app.current(&principal).await.unwrap();
        app.db
            .batch(vec![Statement::new(
                "UPDATE accounts SET disabled=1",
                vec![],
            )])
            .await
            .unwrap();
        assert!(app.authenticate(&r).await.is_err());
        assert!(app.current(&principal).await.is_err());
        app.db
            .batch(vec![Statement::new(
                "UPDATE accounts SET disabled=0",
                vec![],
            )])
            .await
            .unwrap();
        app.current(&principal).await.unwrap();
        app.db
            .batch(vec![Statement::new("DELETE FROM account_spaces", vec![])])
            .await
            .unwrap();
        assert!(app.authenticate(&r).await.is_err());
        assert!(app.current(&principal).await.is_err());
        app.db.batch(vec![Statement::new("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,'account_test',?)",vec![space["space_id"].as_str().unwrap().into(),clock.now_ms().into()])]).await.unwrap();
        app.current(&principal).await.unwrap();
        app.db
            .batch(vec![Statement::new(
                "UPDATE account_devices SET state='revoked'",
                vec![],
            )])
            .await
            .unwrap();
        assert!(app.authenticate(&r).await.is_err());
        assert!(app.current(&principal).await.is_err());
    }
    struct ExpiringPollDb {
        inner: SqliteDb,
        clock: Rc<TestClock>,
    }
    impl Database for ExpiringPollDb {
        async fn query(&self, s: Statement) -> Result<Vec<Row>> {
            self.inner.query(s).await
        }
        async fn batch(&self, s: Vec<Statement>) -> Result<Vec<Vec<Row>>> {
            let poll = s.first().is_some_and(|s| {
                s.sql
                    .starts_with("UPDATE account_devices SET next_poll_at=")
            });
            let result = self.inner.batch(s).await?;
            if poll {
                self.clock.0.set(self.clock.now_ms() + DEVICE_LIFETIME);
            }
            Ok(result)
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn expiry_during_poll_database_await_cannot_issue_token() {
        let (_dir, app, clock, space) = fixture().await;
        let device = start(&app).await;
        approve(&app, &device, &space).await.unwrap();
        let r = request(&app, "/account/devices/token");
        let timed = App::new(
            ExpiringPollDb {
                inner: app.db,
                clock: clock.clone(),
            },
            app.objects,
            app.config,
        )
        .with_clock(clock);
        let result = timed
            .account_device_action(
                &r,
                json!({"device_code":device["device_code"],"code_verifier":VERIFIER}),
            )
            .await;
        assert_eq!(result.unwrap_err().code, "FORBIDDEN");
        let rows = timed
            .db
            .query(Statement::new(
                "SELECT COUNT(*) AS total FROM tokens",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(integer(&rows[0], "total").unwrap(), 0);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn expired_approved_records_preserve_evidence_without_consuming_capacity() {
        let (_dir, app, clock, _space) = fixture().await;
        app.db.batch(vec![Statement::new("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO account_devices(device_id,device_digest,user_digest,code_challenge,display_name,state,created_at,expires_at,next_poll_at) SELECT 'device_old_'||x,randomblob(32),randomblob(32),'unused','Synthetic','approved',?,?,? FROM n",vec![clock.now_ms().into(),clock.now_ms().into(),clock.now_ms().into()])]).await.unwrap();
        start(&app).await;
        let rows = app
            .db
            .query(Statement::new(
                "SELECT COUNT(*) AS total FROM account_devices",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(integer(&rows[0], "total").unwrap(), 1001);
    }
}
