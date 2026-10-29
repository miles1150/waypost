//! Account-only management. Every database read/write rechecks the selected owned
//! Space and recent browser session; no generic admin route is delegated here.
use super::*;
use crate::json::{fields, required};
use crate::storage::driver::optional_text;

const PAGE: usize = 50;
// Legacy keys retain their lifecycle; account devices and normal OAuth grants have
// their own revocation UI. Orphan OAuth access tokens remain individually revocable.
const DIRECT_CONNECTION: &str = "NOT EXISTS(SELECT 1 FROM account_devices d WHERE d.token_id=t.token_id) AND (t.credential_kind='legacy' OR (t.credential_kind='oauth' AND NOT EXISTS(SELECT 1 FROM oauth_access_tokens x JOIN oauth_families f ON f.family_id=x.family_id WHERE x.token_id=t.token_id)))";
struct Owner {
    account: String,
    space: String,
    digest: Vec<u8>,
}
impl Owner {
    fn guard(&self, now: i64) -> (String, Vec<Sql>) {
        ("EXISTS(SELECT 1 FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id JOIN account_spaces m ON m.account_id=a.account_id AND m.space_id=s.selected_space_id WHERE s.session_digest=? AND s.account_id=? AND s.selected_space_id=? AND s.expires_at>? AND s.created_at>=? AND a.disabled=0)".into(),vec![self.digest.clone().into(),self.account.clone().into(),self.space.clone().into(),now.into(),(now-900_000).into()])
    }
}
fn nullable_integer(row: &Row, key: &str) -> Result<Option<i64>> {
    if matches!(row.get(key), Some(Sql::Null)) {
        Ok(None)
    } else {
        integer(row, key).map(Some)
    }
}
fn cursor(body: &Value) -> Result<String> {
    let cursor = body
        .get("cursor")
        .filter(|v| !v.is_null())
        .map(|v| v.as_str().ok_or_else(|| Error::invalid("Invalid cursor.")))
        .transpose()?
        .unwrap_or("");
    if !cursor.is_empty() {
        crate::domain::check_id(cursor)?;
    }
    Ok(cursor.into())
}
fn page(items: Vec<Value>, sid: &str, key: &str) -> Value {
    let more = items.len() > PAGE;
    let mut items = items;
    items.truncate(PAGE);
    let next = if more {
        items.last().and_then(|v| v.get(key)).cloned()
    } else {
        None
    };
    json!({"space_id":sid,"items":items,"has_more":more,"next_cursor":next})
}
impl<D: Database, O: ObjectStore> App<D, O> {
    async fn management_rows(
        &self,
        owner: &Owner,
        sql: String,
        mut args: Vec<Sql>,
    ) -> Result<Vec<Row>> {
        let (guard, parameters) = owner.guard(self.clock.now_ms());
        args.extend(parameters.clone());
        let mut results = self
            .db
            .batch(vec![
                Statement::new(format!("SELECT 1 AS allowed WHERE {guard}"), parameters),
                Statement::new(sql.replace("$guard", &guard), args),
            ])
            .await?;
        if results[0].is_empty() {
            return Err(Error::forbidden());
        }
        Ok(results.remove(1))
    }
    pub(super) async fn account_management_action(
        &self,
        r: &Request,
        body: Value,
    ) -> Result<Value> {
        if r.method != "POST" {
            return Err(Error::not_found());
        }
        let session = self.account_session(r, true).await?;
        if integer(&session, "created_at")? < self.clock.now_ms() - 900_000 {
            return Err(Error::new(
                "REAUTHENTICATION_REQUIRED",
                "Sign in again before managing connections.",
            ));
        }
        let owner = Owner {
            account: text(&session, "account_id")?,
            space: optional_text(&session, "selected_space_id").ok_or_else(Error::forbidden)?,
            digest: blob(&session, "session_digest")?,
        };
        if !r.path.ends_with("/list") && required(&body, "space_id")? != owner.space {
            return Err(Error::forbidden());
        }
        match r.path.as_str() {
            "/account/connections/list" => {
                fields(&body, &["cursor"])?;
                let rows=self.management_rows(&owner,format!("SELECT t.token_id,t.actor_id,t.consumer_id,t.credential_kind,t.created_at,t.expires_at,t.revoked_at FROM tokens t WHERE t.space_id=? AND t.token_id>? AND {DIRECT_CONNECTION} AND $guard ORDER BY t.token_id LIMIT 51"),vec![owner.space.clone().into(),cursor(&body)?.into()]).await?;
                let items=rows.iter().map(|row|Ok(json!({"token_id":text(row,"token_id")?,"actor_id":text(row,"actor_id")?,"consumer_id":text(row,"consumer_id")?,"credential_kind":text(row,"credential_kind")?,"created_at":integer(row,"created_at")?,"expires_at":nullable_integer(row,"expires_at")?,"revoked_at":nullable_integer(row,"revoked_at")?}))).collect::<Result<Vec<_>>>()?;
                Ok(page(items, &owner.space, "token_id"))
            }
            "/account/connections/revoke" => {
                fields(&body, &["space_id", "token_id"])?;
                let id = required(&body, "token_id")?;
                crate::domain::check_id(&id)?;
                let now = self.clock.now_ms();
                let rows=self.management_rows(&owner,format!("UPDATE tokens AS t SET revoked_at=COALESCE(revoked_at,?),authority_version=authority_version+CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END WHERE space_id=? AND token_id=? AND {DIRECT_CONNECTION} AND $guard RETURNING token_id"),vec![now.into(),owner.space.clone().into(),id.clone().into()]).await?;
                if rows.is_empty() {
                    return Err(Error::not_found());
                }
                Ok(json!({"token_id":id,"revoked":true}))
            }
            "/account/oauth/list" => {
                fields(&body, &["cursor"])?;
                let rows=self.management_rows(&owner,"SELECT family_id,client_id,actor_id,consumer_id,created_at,expires_at,revoked_at FROM oauth_families WHERE account_id=? AND space_id=? AND family_id>? AND $guard ORDER BY family_id LIMIT 51".into(),vec![owner.account.clone().into(),owner.space.clone().into(),cursor(&body)?.into()]).await?;
                let items=rows.iter().map(|row|Ok(json!({"family_id":text(row,"family_id")?,"client_id":text(row,"client_id")?,"actor_id":text(row,"actor_id")?,"consumer_id":text(row,"consumer_id")?,"created_at":integer(row,"created_at")?,"expires_at":integer(row,"expires_at")?,"revoked_at":nullable_integer(row,"revoked_at")?}))).collect::<Result<Vec<_>>>()?;
                Ok(page(items, &owner.space, "family_id"))
            }
            "/account/oauth/revoke" => {
                fields(&body, &["space_id", "family_id"])?;
                let id = required(&body, "family_id")?;
                crate::domain::check_id(&id)?;
                let now = self.clock.now_ms();
                let (guard, g) = owner.guard(now);
                let mut family = vec![
                    now.into(),
                    id.clone().into(),
                    owner.account.clone().into(),
                    owner.space.clone().into(),
                ];
                family.extend(g.clone());
                let mut tokens = vec![
                    now.into(),
                    owner.space.clone().into(),
                    id.clone().into(),
                    owner.account.clone().into(),
                    owner.space.clone().into(),
                ];
                tokens.extend(g.clone());
                let results=self.db.batch(vec![
                    Statement::new(format!("SELECT 1 AS allowed WHERE {guard}"),g),
                    Statement::new(format!("UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,?) WHERE family_id=? AND account_id=? AND space_id=? AND {guard} RETURNING family_id"),family),
                    Statement::new(format!("UPDATE tokens SET revoked_at=COALESCE(revoked_at,?),authority_version=authority_version+CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END WHERE space_id=? AND token_id IN(SELECT x.token_id FROM oauth_access_tokens x JOIN oauth_families f ON f.family_id=x.family_id WHERE f.family_id=? AND f.account_id=? AND f.space_id=?) AND {guard}"),tokens),
                ]).await?;
                if results[0].is_empty() {
                    return Err(Error::forbidden());
                }
                if results[1].is_empty() {
                    return Err(Error::not_found());
                }
                Ok(json!({"family_id":id,"revoked":true}))
            }
            "/account/identities/list" => {
                fields(&body, &["kind", "cursor"])?;
                let kind = required(&body, "kind")?;
                let (table, id, projection) = match kind.as_str() {
                    "actors" => ("actors", "actor_id", "display_name,kind,authority_version"),
                    "consumers" => ("consumers", "consumer_id", "actor_id,view,view_revision"),
                    _ => return Err(Error::invalid("Unknown identity kind.")),
                };
                let (guard, g) = owner.guard(self.clock.now_ms());
                let mut args = vec![owner.space.clone().into(), cursor(&body)?.into()];
                args.extend(g.clone());
                let mut state = vec![owner.space.clone().into()];
                state.extend(g.clone());
                let rows=self.db.batch(vec![Statement::new(format!("SELECT primary_actor_id,primary_revision FROM spaces WHERE space_id=? AND {guard}"),state),Statement::new(format!("SELECT {id},disabled,{projection} FROM {table} WHERE space_id=? AND {id}>? AND {guard} ORDER BY {id} LIMIT 51"),args)]).await?;
                let state = rows[0].first().ok_or_else(Error::forbidden)?;
                let items = rows[1]
                    .iter()
                    .map(|row| {
                        let mut value =
                            json!({id:text(row,id)?,"disabled":integer(row,"disabled")?!=0});
                        for field in projection.split(',') {
                            value[field] = match row.get(field) {
                                Some(Sql::Text(v)) => json!(v),
                                Some(Sql::Integer(v)) => json!(v),
                                _ => return Err(Error::storage()),
                            };
                        }
                        Ok(value)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let mut result = page(items, &owner.space, id);
                result["primary_actor_id"] = json!(optional_text(state, "primary_actor_id"));
                result["primary_revision"] = json!(integer(state, "primary_revision")?);
                Ok(result)
            }
            "/account/identities/disable" => {
                fields(&body, &["space_id", "kind", "identity_id"])?;
                let kind = required(&body, "kind")?;
                let id = required(&body, "identity_id")?;
                crate::domain::check_id(&id)?;
                let (table, key, version, protected) = match kind.as_str() {
                    "actors" => (
                        "actors",
                        "actor_id",
                        "authority_version",
                        "NOT EXISTS(SELECT 1 FROM spaces s WHERE s.space_id=actors.space_id AND (s.default_actor_id=actors.actor_id OR s.primary_actor_id=actors.actor_id))",
                    ),
                    "consumers" => (
                        "consumers",
                        "consumer_id",
                        "view_revision",
                        "NOT EXISTS(SELECT 1 FROM spaces s WHERE s.space_id=consumers.space_id AND s.default_consumer_id=consumers.consumer_id)",
                    ),
                    _ => return Err(Error::invalid("Unknown identity kind.")),
                };
                let rows=self.management_rows(&owner,format!("UPDATE {table} SET disabled=1,{version}={version}+CASE WHEN disabled=0 THEN 1 ELSE 0 END WHERE space_id=? AND {key}=? AND {protected} AND $guard RETURNING {key}"),vec![owner.space.clone().into(),id.clone().into()]).await?;
                if rows.is_empty() {
                    return Err(Error::invalid(
                        "Identity is unavailable or protected. Change the primary assistant before disabling it; default owner identities cannot be disabled here.",
                    ));
                }
                Ok(json!({"identity_id":id,"disabled":true}))
            }
            "/account/primary/set" => {
                fields(&body, &["space_id", "expected_revision", "actor_id"])?;
                let expected = body
                    .get("expected_revision")
                    .and_then(Value::as_i64)
                    .filter(|v| *v >= 0 && *v < i64::MAX)
                    .ok_or_else(|| Error::invalid("Invalid primary revision."))?;
                let actor = match body.get("actor_id") {
                    Some(Value::Null) => None,
                    Some(Value::String(v)) => {
                        crate::domain::check_id(v)?;
                        Some(v.clone())
                    }
                    _ => return Err(Error::invalid("Choose a primary assistant or null.")),
                };
                let rows=self.management_rows(&owner,"UPDATE spaces SET primary_actor_id=?,primary_revision=primary_revision+1,primary_nonce=? WHERE space_id=? AND primary_revision=? AND (? IS NULL OR EXISTS(SELECT 1 FROM actors a WHERE a.space_id=spaces.space_id AND a.actor_id=? AND a.kind='agent' AND a.disabled=0)) AND $guard RETURNING primary_actor_id,primary_revision".into(),vec![actor.clone().into(),random_id("primary")?.into(),owner.space.clone().into(),expected.into(),actor.clone().into(),actor.clone().into()]).await?;
                let rows = if rows.is_empty() {
                    self.management_rows(&owner,"SELECT primary_actor_id,primary_revision FROM spaces WHERE space_id=? AND $guard".into(),vec![owner.space.clone().into()]).await?
                } else {
                    rows
                };
                let row = rows.first().ok_or_else(Error::forbidden)?;
                if optional_text(row, "primary_actor_id") != actor
                    || integer(row, "primary_revision")? != expected + 1
                {
                    return Err(Error::new(
                        "REVISION_CONFLICT",
                        "Primary assistant changed or is unavailable; refresh before choosing.",
                    ));
                }
                Ok(
                    json!({"space_id":owner.space,"primary_actor_id":actor,"primary_revision":integer(row,"primary_revision")?}),
                )
            }
            _ => Err(Error::not_found()),
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::native::{FileStore, SqliteDb};
    use std::cell::RefCell;
    struct RaceDb {
        inner: SqliteDb,
        after_auth: RefCell<Option<Statement>>,
    }
    impl Database for RaceDb {
        async fn query(&self, s: Statement) -> Result<Vec<Row>> {
            let auth = s.sql.starts_with("SELECT s.* FROM account_sessions");
            let rows = self.inner.query(s).await?;
            if auth {
                let mutation = self.after_auth.borrow_mut().take();
                if let Some(s) = mutation {
                    self.inner.batch(vec![s]).await?;
                }
            }
            Ok(rows)
        }
        async fn batch(&self, s: Vec<Statement>) -> Result<Vec<Vec<Row>>> {
            self.inner.batch(s).await
        }
    }
    type TestApp = App<RaceDb, FileStore>;
    const COOKIE: &str = "ccccccccccccccccccccccccccccccccccccccccccc";
    fn request(app: &TestApp, path: &str, body: Value) -> Request {
        let mut r = Request::json("POST", path, "", body);
        r.headers.remove("authorization");
        r.headers
            .insert("cookie".into(), format!("waypost_account={COOKIE}"));
        r.headers
            .insert("origin".into(), app.config.public_origin.clone());
        r.headers
            .insert("x-waypost-csrf".into(), app.csrf_token(COOKIE).unwrap());
        r
    }
    async fn action(app: &TestApp, path: &str, body: Value) -> Result<Value> {
        app.account_management_action(&request(app, path, body.clone()), body)
            .await
    }
    async fn fixture() -> (tempfile::TempDir, TestApp, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = RaceDb {
            inner: SqliteDb::open(dir.path().join("db")).unwrap(),
            after_auth: RefCell::new(None),
        };
        let mut app = App::new(
            db,
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: "test-only-admin-secret-long-enough".into(),
                public_origin: "http://127.0.0.1:8787".into(),
            },
        );
        app.oidc = Some(accounts_oidc::OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "test".into(),
            authorization_endpoint: "https://issuer.example/auth".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_secret: None,
            keys: vec![],
            google_jwks: false,
        });
        let body = json!({"request_id":"management-space","display_name":"Test"});
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
        let sid = space["space_id"].as_str().unwrap().to_owned();
        let now = app.clock.now_ms();
        app.db.batch(vec![
            Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_test','https://issuer.example','subject',?)",vec![now.into()]),
            Statement::new("INSERT INTO account_spaces VALUES(?,'account_test',?)",vec![sid.clone().into(),now.into()]),
            Statement::new("INSERT INTO account_sessions VALUES(?,'account_test',?,?,?)",vec![Sha256::digest(COOKIE.as_bytes()).to_vec().into(),sid.clone().into(),now.into(),(now+3_600_000).into()]),
            Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at,credential_kind) SELECT value,randomblob(32),space_id,default_actor_id,default_consumer_id,?,CASE WHEN value='legacy' THEN 'legacy' ELSE 'oauth' END FROM spaces,json_each('[\"legacy\",\"orphan\",\"mapped\"]') WHERE space_id=?",vec![now.into(),sid.clone().into()]),
            Statement::new("INSERT INTO oauth_families(family_id,client_id,resource,scope,account_id,space_id,actor_id,consumer_id,created_at,expires_at) SELECT 'family','client','http://127.0.0.1:8787/mcp','space','account_test',space_id,default_actor_id,default_consumer_id,?,? FROM spaces WHERE space_id=?",vec![now.into(),(now+3_600_000).into(),sid.clone().into()]),
            Statement::new("INSERT INTO oauth_access_tokens VALUES('mapped','family')",vec![]),
        ]).await.unwrap();
        (dir, app, sid)
    }
    #[tokio::test(flavor = "current_thread")]
    async fn lists_redact_secrets_revoke_legacy_orphan_and_oauth_idempotently() {
        let (_dir, app, sid) = fixture().await;
        let listed = action(&app, "/account/connections/list", json!({}))
            .await
            .unwrap();
        let ids: Vec<_> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["token_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["legacy", "orphan"]);
        assert!(!listed.to_string().contains("token_digest"));
        for id in ["legacy", "orphan"] {
            for _ in 0..2 {
                action(
                    &app,
                    "/account/connections/revoke",
                    json!({"space_id":sid,"token_id":id}),
                )
                .await
                .unwrap();
            }
        }
        assert!(
            action(
                &app,
                "/account/connections/revoke",
                json!({"space_id":sid,"token_id":"mapped"})
            )
            .await
            .is_err()
        );
        let listed = action(&app, "/account/oauth/list", json!({}))
            .await
            .unwrap();
        assert_eq!(listed["items"][0]["family_id"], "family");
        for _ in 0..2 {
            action(
                &app,
                "/account/oauth/revoke",
                json!({"space_id":sid,"family_id":"family"}),
            )
            .await
            .unwrap();
        }
        let rows = app
            .db
            .query(Statement::new(
                "SELECT count(*) n FROM tokens WHERE revoked_at IS NULL",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(integer(&rows[0], "n").unwrap(), 0);
        let rows = app
            .db
            .query(Statement::new(
                "SELECT authority_version FROM tokens WHERE token_id='legacy'",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(integer(&rows[0], "authority_version").unwrap(), 1);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn connection_pagination_is_bounded_and_never_includes_paired_devices() {
        let (_dir, app, sid) = fixture().await;
        let ids: Vec<_> = (0..52).map(|i| format!("connection_{i:03}")).collect();
        app.db.batch(vec![
            Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at) SELECT value,randomblob(32),space_id,default_actor_id,default_consumer_id,0 FROM spaces,json_each(?) WHERE space_id=?",vec![serde_json::to_string(&ids).unwrap().into(),sid.clone().into()]),
            Statement::new("INSERT INTO account_devices(device_id,device_digest,user_digest,code_challenge,display_name,state,created_at,expires_at,next_poll_at,account_id,space_id,actor_id,consumer_id,token_id) SELECT 'paired',randomblob(32),randomblob(32),'testchallenge','Test','consumed',0,9999999999999,0,'account_test',space_id,default_actor_id,default_consumer_id,'connection_000' FROM spaces WHERE space_id=?",vec![sid.clone().into()]),
        ]).await.unwrap();
        let first = action(&app, "/account/connections/list", json!({}))
            .await
            .unwrap();
        assert_eq!(first["items"].as_array().unwrap().len(), 50);
        assert_eq!(first["has_more"], true);
        assert!(!first.to_string().contains("connection_000"));
        let second = action(
            &app,
            "/account/connections/list",
            json!({"cursor":first["next_cursor"]}),
        )
        .await
        .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 3);
        assert_eq!(second["has_more"], false);
        assert!(
            action(
                &app,
                "/account/connections/revoke",
                json!({"space_id":sid,"token_id":"connection_000"})
            )
            .await
            .is_err()
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn security_controls_and_cross_space_intent_fail_closed() {
        let (_dir, app, sid) = fixture().await;
        for header in ["origin", "x-waypost-csrf", "cookie"] {
            let mut r = request(&app, "/account/connections/list", json!({}));
            r.headers.remove(header);
            assert!(app.account_management_action(&r, json!({})).await.is_err());
        }
        assert!(
            action(
                &app,
                "/account/connections/revoke",
                json!({"space_id":"other","token_id":"legacy"})
            )
            .await
            .is_err()
        );
        assert!(
            action(
                &app,
                "/account/oauth/revoke",
                json!({"space_id":sid,"family_id":"unknown"})
            )
            .await
            .is_err()
        );
        app.db
            .batch(vec![Statement::new(
                "UPDATE account_sessions SET created_at=0",
                vec![],
            )])
            .await
            .unwrap();
        assert_eq!(
            action(&app, "/account/connections/list", json!({}))
                .await
                .unwrap_err()
                .code,
            "REAUTHENTICATION_REQUIRED"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_authority_loss_blocks_empty_lists_and_both_revoke_paths() {
        for mutation in [
            "UPDATE accounts SET disabled=1",
            "DELETE FROM account_spaces",
            "UPDATE account_sessions SET selected_space_id=NULL",
            "UPDATE account_sessions SET expires_at=0",
            "UPDATE account_sessions SET created_at=0",
        ] {
            for (path, body) in [
                ("/account/connections/list", json!({"cursor":"zzzz"})),
                ("/account/oauth/list", json!({"cursor":"zzzz"})),
                ("/account/identities/list", json!({"kind":"actors"})),
                (
                    "/account/primary/set",
                    json!({"expected_revision":0,"actor_id":null}),
                ),
                ("/account/connections/revoke", json!({"token_id":"legacy"})),
                ("/account/oauth/revoke", json!({"family_id":"family"})),
            ] {
                let (_dir, app, sid) = fixture().await;
                let mut body = body;
                if !path.ends_with("list") {
                    body["space_id"] = json!(sid);
                }
                app.db
                    .after_auth
                    .replace(Some(Statement::new(mutation, vec![])));
                assert!(
                    action(&app, path, body).await.is_err(),
                    "{path}: {mutation}"
                );
                let rows = app
                    .db
                    .query(Statement::new(
                        "SELECT count(*) n FROM tokens WHERE revoked_at IS NOT NULL",
                        vec![],
                    ))
                    .await
                    .unwrap();
                assert_eq!(integer(&rows[0], "n").unwrap(), 0);
                let rows = app
                    .db
                    .query(Statement::new(
                        "SELECT count(*) n FROM oauth_families WHERE revoked_at IS NOT NULL",
                        vec![],
                    ))
                    .await
                    .unwrap();
                assert_eq!(integer(&rows[0], "n").unwrap(), 0);
            }
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn primary_setting_uses_cas_without_changing_owner_and_protects_default_identity() {
        let (_dir, app, sid) = fixture().await;
        let inventory = action(&app, "/account/identities/list", json!({"kind":"actors"}))
            .await
            .unwrap();
        let default = inventory["items"][0]["actor_id"].as_str().unwrap();
        assert!(
            action(
                &app,
                "/account/identities/disable",
                json!({"space_id":sid,"kind":"actors","identity_id":default})
            )
            .await
            .is_err()
        );
        app.db.batch(vec![Statement::new("INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES(?,'agent','Agent','agent',0)",vec![sid.clone().into()])]).await.unwrap();
        for _ in 0..2 {
            let result = action(
                &app,
                "/account/primary/set",
                json!({"space_id":sid,"expected_revision":0,"actor_id":"agent"}),
            )
            .await
            .unwrap();
            assert_eq!(result["primary_revision"], 1);
        }
        assert!(
            action(
                &app,
                "/account/identities/disable",
                json!({"space_id":sid,"kind":"actors","identity_id":"agent"})
            )
            .await
            .is_err()
        );
        assert!(
            action(
                &app,
                "/account/primary/set",
                json!({"space_id":sid,"expected_revision":0,"actor_id":null})
            )
            .await
            .is_err()
        );
        action(
            &app,
            "/account/primary/set",
            json!({"space_id":sid,"expected_revision":1,"actor_id":null}),
        )
        .await
        .unwrap();
        action(
            &app,
            "/account/identities/disable",
            json!({"space_id":sid,"kind":"actors","identity_id":"agent"}),
        )
        .await
        .unwrap();
        let rows = app
            .db
            .query(Statement::new(
                "SELECT default_actor_id FROM spaces WHERE space_id=?",
                vec![sid.into()],
            ))
            .await
            .unwrap();
        assert_eq!(text(&rows[0], "default_actor_id").unwrap(), default);
    }
}
