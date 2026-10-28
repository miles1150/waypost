use super::*;
use crate::{domain::check_id, json::fields, storage::driver::optional_text};

impl<D: Database, O: ObjectStore> App<D, O> {
    pub(crate) async fn token_permission_detail(&self, sid: &str, tid: &str) -> Result<Value> {
        check_id(tid)?;
        let rows = self.db.query(Statement::new("SELECT t.token_id,t.actor_id,t.consumer_id,t.authority_version,t.default_recipient_id,t.expires_at,t.revoked_at,a.disabled AS actor_disabled,c.disabled AS consumer_disabled FROM tokens t JOIN actors a ON a.space_id=t.space_id AND a.actor_id=t.actor_id JOIN consumers c ON c.space_id=t.space_id AND c.consumer_id=t.consumer_id WHERE t.space_id=? AND t.token_id=?", vec![sid.into(),tid.into()])).await?;
        let row = rows.first().ok_or_else(Error::not_found)?;
        let scopes = self
            .db
            .query(Statement::new(
                "SELECT scope FROM token_scopes WHERE token_id=? ORDER BY scope",
                vec![tid.into()],
            ))
            .await?
            .iter()
            .map(|r| text(r, "scope"))
            .collect::<Result<Vec<_>>>()?;
        let recipients = self
            .db
            .query(Statement::new(
                "SELECT actor_id FROM token_recipients WHERE token_id=? ORDER BY actor_id",
                vec![tid.into()],
            ))
            .await?
            .iter()
            .map(|r| text(r, "actor_id"))
            .collect::<Result<Vec<_>>>()?;
        let collections = self.db.query(Statement::new("SELECT collection_id,action FROM token_collections WHERE token_id=? ORDER BY collection_id",vec![tid.into()])).await?;
        let mut read = Vec::new();
        let mut write = Vec::new();
        for r in collections {
            if text(&r, "action")? == "read" {
                read.push(text(&r, "collection_id")?);
            } else {
                write.push(text(&r, "collection_id")?);
            }
        }
        let blobs = self
            .db
            .query(Statement::new(
                "SELECT blob_id FROM token_blob_grants WHERE token_id=? ORDER BY blob_id",
                vec![tid.into()],
            ))
            .await?
            .iter()
            .map(|r| text(r, "blob_id"))
            .collect::<Result<Vec<_>>>()?;
        // Separate reads must not expose grants from a newer version beside an old
        // CAS version. A caller can refresh if a concurrent editor won mid-read.
        let latest = self
            .db
            .query(Statement::new(
                "SELECT authority_version FROM tokens WHERE space_id=? AND token_id=?",
                vec![sid.into(), tid.into()],
            ))
            .await?;
        if latest
            .first()
            .map(|r| integer(r, "authority_version"))
            .transpose()?
            != Some(integer(row, "authority_version")?)
        {
            return Err(Error::new(
                "REVISION_CONFLICT",
                "Connection permissions changed; refresh before editing.",
            ));
        }
        let expires = match row.get("expires_at") {
            Some(Sql::Integer(n)) => Some(*n),
            _ => None,
        };
        let revoked = match row.get("revoked_at") {
            Some(Sql::Integer(n)) => Some(*n),
            _ => None,
        };
        Ok(
            json!({"token_id":tid,"actor_id":text(row,"actor_id")?,"consumer_id":text(row,"consumer_id")?,"authority_version":integer(row,"authority_version")?,"default_recipient_id":optional_text(row,"default_recipient_id"),"expires_at":expires.map(stamp).transpose()?,"revoked_at":revoked.map(stamp).transpose()?,"editable":revoked.is_none() && expires.is_none_or(|n|n>self.clock.now_ms()) && integer(row,"actor_disabled")? == 0 && integer(row,"consumer_disabled")? == 0,"scopes":scopes,"resource_grants":{"recipient_ids":recipients,"memory_read_collection_ids":read,"memory_write_collection_ids":write,"blob_reference_ids":blobs}}),
        )
    }

    pub(crate) async fn token_permissions(
        &self,
        request: &Request,
        sid: &str,
        tid: &str,
        body: Value,
    ) -> Result<Value> {
        if request.method == "GET" {
            return self.token_permission_detail(sid, tid).await;
        }
        if request.method != "PUT" {
            return Err(Error::not_found());
        }
        fields(
            &body,
            &[
                "request_id",
                "expected_authority_version",
                "scopes",
                "resource_grants",
                "default_recipient_id",
            ],
        )?;
        // Require a caller-held key so a lost response can be recovered without another edit.
        crate::json::required(&body, "request_id")?;
        let (key, fp) = admin::admin_key(&body)?;
        let expected = body
            .get("expected_authority_version")
            .and_then(Value::as_i64)
            .filter(|v| *v >= 0 && *v < i64::MAX)
            .ok_or_else(|| Error::invalid("Invalid expected authority version."))?;
        let before = self.token_permission_detail(sid, tid).await?;
        let previous=self.db.query(Statement::new("SELECT fingerprint,authority_version FROM token_permission_changes WHERE space_id=? AND token_id=? AND request_id=?",vec![sid.into(),tid.into(),key.clone().into()])).await?;
        if let Some(row) = previous.first() {
            if text(row, "fingerprint")? != fp {
                return Err(Error::new(
                    "IDEMPOTENCY_CONFLICT",
                    "Request ID was used with different permissions.",
                ));
            }
            let mut result = before;
            result["applied_authority_version"] = json!(integer(row, "authority_version")?);
            result["replayed"] = json!(true);
            return Ok(result);
        }
        if before["editable"] != true {
            return Err(Error::forbidden());
        }
        if before["authority_version"] != expected {
            return Err(Error::new(
                "REVISION_CONFLICT",
                "Connection permissions changed; refresh before editing.",
            ));
        }
        if self
            .admin_actor(sid, before["actor_id"].as_str().ok_or_else(Error::storage)?)
            .await?["disabled"]
            == true
            || self
                .admin_consumer(
                    sid,
                    before["consumer_id"].as_str().ok_or_else(Error::storage)?,
                )
                .await?["disabled"]
                == true
        {
            return Err(Error::forbidden());
        }
        let mut scopes: Vec<String> = crate::json::decode(
            body.get("scopes")
                .cloned()
                .ok_or_else(|| Error::invalid("Missing scopes."))?,
        )?;
        if scopes.iter().any(|s| {
            ![
                "message.send",
                "message.read",
                "space.observe",
                "receipt.write",
                "memory.write",
                "memory.read",
                "blob.write",
                "blob.reference",
                "event.subscribe",
            ]
            .contains(&s.as_str())
        }) {
            return Err(Error::invalid("Unknown scope."));
        }
        scopes.sort();
        scopes.dedup();
        let mut grants: ResourceGrants = crate::json::decode(
            body.get("resource_grants")
                .cloned()
                .ok_or_else(|| Error::invalid("Missing resource grants."))?,
        )?;
        for list in [
            &mut grants.recipient_ids,
            &mut grants.memory_read_collection_ids,
            &mut grants.memory_write_collection_ids,
            &mut grants.blob_reference_ids,
        ] {
            for id in list.iter() {
                check_id(id)?;
            }
            list.sort();
            list.dedup();
            if list.len() > 64 {
                return Err(Error::new("RESOURCE_LIMIT", "Too many grants."));
            }
        }
        for id in &grants.recipient_ids {
            self.admin_actor(sid, id).await?;
        }
        for id in grants
            .memory_read_collection_ids
            .iter()
            .chain(&grants.memory_write_collection_ids)
        {
            self.admin_collection(sid, id).await?;
        }
        for id in &grants.blob_reference_ids {
            if self
                .db
                .query(Statement::new(
                    "SELECT 1 AS valid FROM blobs WHERE space_id=? AND blob_id=?",
                    vec![sid.into(), id.clone().into()],
                ))
                .await?
                .is_empty()
            {
                return Err(Error::not_found());
            }
        }
        let default = match body.get("default_recipient_id") {
            Some(Value::Null) => None,
            Some(Value::String(id)) => {
                check_id(id)?;
                self.admin_actor(sid, id).await?;
                let allowed = if grants.recipient_ids.is_empty() {
                    vec![
                        self.admin_space(sid).await?["default_actor_id"]
                            .as_str()
                            .ok_or_else(Error::storage)?
                            .to_owned(),
                    ]
                } else {
                    grants.recipient_ids.clone()
                };
                if !allowed.contains(id) {
                    return Err(Error::invalid(
                        "Default recipient must be explicitly authorized.",
                    ));
                }
                Some(id.clone())
            }
            _ => return Err(Error::invalid("Missing or invalid default recipient.")),
        };
        let now = self.clock.now_ms();
        let nonce = random_id("permission")?;
        // The audit row is the transaction's unique winner marker. Every mutation below
        // requires this invocation's nonce, so losing CAS/replays cannot alter child grants.
        let manager = match self.admin_access(request).await? {
            Some(space) => format!("owner:{space}"),
            None => "operator".to_owned(),
        };
        let managing_principal = self.dashboard_owner(request, sid, None).await?;
        let (managing_guard, managing_args) = self.owner_authority_guard(&managing_principal);
        let after = json!({"scopes":scopes,"resource_grants":grants,"default_recipient_id":default,"authority_version":expected+1});
        let mut q = vec![Statement::new(
            "INSERT INTO token_permission_changes(change_id,space_id,token_id,request_id,fingerprint,authority_version,manager,before_json,after_json,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM tokens t JOIN actors a ON a.space_id=t.space_id AND a.actor_id=t.actor_id JOIN consumers c ON c.space_id=t.space_id AND c.consumer_id=t.consumer_id WHERE t.space_id=? AND t.token_id=? AND t.authority_version=? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>?) AND a.disabled=0 AND c.disabled=0) ON CONFLICT DO NOTHING",
            vec![
                nonce.clone().into(),
                sid.into(),
                tid.into(),
                key.clone().into(),
                fp.clone().into(),
                (expected + 1).into(),
                manager.into(),
                serde_json::to_string(&before)
                    .map_err(|_| Error::storage())?
                    .into(),
                serde_json::to_string(&after)
                    .map_err(|_| Error::storage())?
                    .into(),
                now.into(),
                sid.into(),
                tid.into(),
                expected.into(),
                now.into(),
            ],
        )];
        q[0].sql = q[0].sql.replace(
            " ON CONFLICT DO NOTHING",
            &format!(" AND {managing_guard} ON CONFLICT DO NOTHING"),
        );
        q[0].parameters.extend(managing_args);
        let guard = (
            "EXISTS(SELECT 1 FROM token_permission_changes WHERE change_id=?)".to_owned(),
            vec![nonce.clone().into()],
        );
        q.push(Statement::new(format!("UPDATE tokens SET authority_version=authority_version+1,default_recipient_id=? WHERE space_id=? AND token_id=? AND {}",guard.0),vec![default.into(),sid.into(),tid.into(),nonce.clone().into()]));
        for table in [
            "token_scopes",
            "token_recipients",
            "token_collections",
            "token_blob_grants",
        ] {
            q.push(Statement::new(
                format!("DELETE FROM {table} WHERE token_id=? AND {}", guard.0),
                vec![tid.into(), nonce.clone().into()],
            ));
        }
        q.extend(push_rows(
            "token_scopes",
            "token_id,scope",
            scopes
                .into_iter()
                .map(|s| vec![tid.into(), s.into()])
                .collect(),
            Some(guard.clone()),
        ));
        q.extend(push_rows(
            "token_recipients",
            "token_id,space_id,actor_id",
            grants
                .recipient_ids
                .into_iter()
                .map(|s| vec![tid.into(), sid.into(), s.into()])
                .collect(),
            Some(guard.clone()),
        ));
        q.extend(push_rows(
            "token_collections",
            "token_id,space_id,collection_id,action",
            grants
                .memory_read_collection_ids
                .into_iter()
                .map(|s| vec![tid.into(), sid.into(), s.into(), "read".into()])
                .chain(
                    grants
                        .memory_write_collection_ids
                        .into_iter()
                        .map(|s| vec![tid.into(), sid.into(), s.into(), "write".into()]),
                )
                .collect(),
            Some(guard.clone()),
        ));
        q.extend(push_rows(
            "token_blob_grants",
            "token_id,space_id,blob_id",
            grants
                .blob_reference_ids
                .into_iter()
                .map(|s| vec![tid.into(), sid.into(), s.into()])
                .collect(),
            Some(guard),
        ));
        self.db.batch(q).await?;
        self.current(&managing_principal).await?;
        let rows=self.db.query(Statement::new("SELECT fingerprint,authority_version,change_id FROM token_permission_changes WHERE space_id=? AND token_id=? AND request_id=?",vec![sid.into(),tid.into(),key.into()])).await?;
        let row = rows.first().ok_or_else(|| {
            Error::new(
                "REVISION_CONFLICT",
                "Connection permissions changed; refresh before editing.",
            )
        })?;
        if text(row, "fingerprint")? != fp {
            return Err(Error::new(
                "IDEMPOTENCY_CONFLICT",
                "Request ID was used with different permissions.",
            ));
        }
        let mut result = self.token_permission_detail(sid, tid).await?;
        result["applied_authority_version"] = json!(integer(row, "authority_version")?);
        result["replayed"] = json!(text(row, "change_id")? != nonce);
        Ok(result)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::native::{FileStore, SqliteDb};
    #[tokio::test(flavor = "current_thread")]
    async fn old_principal_is_fenced_and_legacy_cursor_remains_readable() {
        let dir = tempfile::tempdir().unwrap();
        let app = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: "test-permissions-admin-32-bytes-long".into(),
                public_origin: "http://localhost".into(),
            },
        );
        let request = Request::json(
            "POST",
            "/admin/v0/spaces",
            "test-permissions-admin-32-bytes-long",
            json!({"request_id":"setup","display_name":"Test"}),
        );
        let space = app
            .admin(
                &request,
                json!({"request_id":"setup","display_name":"Test"}),
            )
            .await
            .unwrap();
        let sid = space["space_id"].as_str().unwrap();
        let body = json!({"request_id":"token","actor_id":space["default_actor_id"],"consumer_id":space["default_consumer_id"],"scopes":["message.read"],"resource_grants":{}});
        let issued = app
            .admin(
                &Request::json(
                    "POST",
                    &format!("/admin/v0/spaces/{sid}/tokens"),
                    "",
                    body.clone(),
                ),
                body,
            )
            .await
            .unwrap();
        let principal = app
            .authenticate(&Request::json(
                "GET",
                "/v0/describe",
                issued["token"].as_str().unwrap(),
                json!({}),
            ))
            .await
            .unwrap();
        let old = app
            .sign_cursor(&format!(
                "f2|{}|{}|{}|{}|{}|{}|0",
                principal.space_id,
                principal.actor_id,
                principal.consumer_id,
                principal.view_revision,
                principal.filter_fingerprint,
                principal.grant_fingerprint
            ))
            .unwrap();
        assert_eq!(app.feed_position(&principal, &old).unwrap(), 0);
        let new = app.feed_cursor(&principal, 0).unwrap();
        let body = json!({"request_id":"change","expected_authority_version":0,"scopes":["message.read","message.send"],"resource_grants":{},"default_recipient_id":null});
        let req = Request::json(
            "PUT",
            &format!(
                "/admin/v0/spaces/{sid}/tokens/{}/permissions",
                issued["token_id"].as_str().unwrap()
            ),
            "test-permissions-admin-32-bytes-long",
            body.clone(),
        );
        app.token_permissions(&req, sid, issued["token_id"].as_str().unwrap(), body)
            .await
            .unwrap();
        assert_eq!(
            app.current(&principal).await.unwrap_err().code,
            "UNAUTHENTICATED"
        );
        let fresh = app
            .authenticate(&Request::json(
                "GET",
                "/v0/describe",
                issued["token"].as_str().unwrap(),
                json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(app.feed_position(&fresh, &new).unwrap(), 0);
        assert_eq!(
            app.feed_position(&fresh, &old).unwrap_err().code,
            "CURSOR_SCOPE_CHANGED"
        );
    }

    // Force both independently authenticated edits past their prechecks before
    // either transaction runs. A simple join over synchronous SQLite futures
    // would otherwise only test sequential rejection, not the SQL CAS guards.
    struct GateDb {
        inner: SqliteDb,
        gate: std::cell::Cell<bool>,
        arrivals: std::cell::Cell<usize>,
        waiting: std::cell::RefCell<Option<std::task::Waker>>,
        before_batch: std::cell::RefCell<Vec<Statement>>,
    }
    impl Database for GateDb {
        async fn query(&self, s: Statement) -> Result<Vec<Row>> {
            self.inner.query(s).await
        }
        async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<Vec<Row>>> {
            if statements
                .first()
                .is_some_and(|s| s.sql.starts_with("INSERT INTO token_permission_changes"))
            {
                if self.gate.get() {
                    self.arrivals.set(self.arrivals.get() + 1);
                    futures_util::future::poll_fn(|cx| {
                        if self.arrivals.get() >= 2 {
                            if let Some(w) = self.waiting.borrow_mut().take() {
                                w.wake();
                            }
                            std::task::Poll::Ready(())
                        } else {
                            *self.waiting.borrow_mut() = Some(cx.waker().clone());
                            std::task::Poll::Pending
                        }
                    })
                    .await;
                }
                let inject = self.before_batch.borrow_mut().drain(..).collect::<Vec<_>>();
                if !inject.is_empty() {
                    self.inner.batch(inject).await?;
                }
            }
            self.inner.batch(statements).await
        }
    }
    const ADMIN: &str = "test-permissions-admin-32-bytes-long";
    async fn gate_fixture() -> (tempfile::TempDir, App<GateDb, FileStore>, Value, Value) {
        let dir = tempfile::tempdir().unwrap();
        let app = App::new(
            GateDb {
                inner: SqliteDb::open(dir.path().join("db")).unwrap(),
                gate: std::cell::Cell::new(false),
                arrivals: std::cell::Cell::new(0),
                waiting: std::cell::RefCell::new(None),
                before_batch: std::cell::RefCell::new(vec![]),
            },
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: ADMIN.into(),
                public_origin: "http://localhost".into(),
            },
        );
        let body = json!({"request_id":"setup","display_name":"Test"});
        let space = app
            .admin(
                &Request::json("POST", "/admin/v0/spaces", ADMIN, body.clone()),
                body,
            )
            .await
            .unwrap();
        let sid = space["space_id"].as_str().unwrap();
        let body = json!({"request_id":"token","actor_id":space["default_actor_id"],"consumer_id":space["default_consumer_id"],"scopes":["message.read"],"resource_grants":{}});
        let issued = app
            .admin(
                &Request::json(
                    "POST",
                    &format!("/admin/v0/spaces/{sid}/tokens"),
                    ADMIN,
                    body.clone(),
                ),
                body,
            )
            .await
            .unwrap();
        (dir, app, space, issued)
    }
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_edit_cas_preserves_exact_winner_grants_and_one_audit() {
        let (_dir, app, space, issued) = gate_fixture().await;
        let sid = space["space_id"].as_str().unwrap();
        let tid = issued["token_id"].as_str().unwrap();
        let route = format!("/admin/v0/spaces/{sid}/tokens/{tid}/permissions");
        let one = json!({"request_id":"concurrent-one","expected_authority_version":0,"scopes":["message.read"],"resource_grants":{},"default_recipient_id":null});
        let two = json!({"request_id":"concurrent-two","expected_authority_version":0,"scopes":["message.send","receipt.write"],"resource_grants":{"recipient_ids":[space["default_actor_id"]]},"default_recipient_id":space["default_actor_id"]});
        let r1 = Request::json("PUT", &route, ADMIN, one.clone());
        let r2 = Request::json("PUT", &route, ADMIN, two.clone());
        app.db.gate.set(true);
        let (a, b) = futures_util::join!(
            app.token_permissions(&r1, sid, tid, one.clone()),
            app.token_permissions(&r2, sid, tid, two.clone())
        );
        assert_eq!(
            app.db.arrivals.get(),
            2,
            "both edits reached the transaction boundary"
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let winner = if a.is_ok() { one } else { two };
        let loser = if let Err(e) = a { e } else { b.unwrap_err() };
        assert_eq!(loser.code, "REVISION_CONFLICT");
        let current = app.token_permission_detail(sid, tid).await.unwrap();
        assert_eq!(current["authority_version"], 1);
        assert_eq!(current["scopes"], winner["scopes"]);
        assert_eq!(
            current["default_recipient_id"],
            winner["default_recipient_id"]
        );
        assert_eq!(
            current["resource_grants"]["recipient_ids"],
            winner["resource_grants"]
                .get("recipient_ids")
                .cloned()
                .unwrap_or(json!([]))
        );
        assert_eq!(
            current["resource_grants"]["memory_read_collection_ids"],
            json!([])
        );
        assert_eq!(
            current["resource_grants"]["memory_write_collection_ids"],
            json!([])
        );
        assert_eq!(current["resource_grants"]["blob_reference_ids"], json!([]));
        let rows = app
            .db
            .query(Statement::new(
                "SELECT request_id,after_json FROM token_permission_changes",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            text(&rows[0], "request_id").unwrap(),
            winner["request_id"].as_str().unwrap()
        );
        let audited: Value = serde_json::from_str(&text(&rows[0], "after_json").unwrap()).unwrap();
        assert_eq!(audited["scopes"], current["scopes"]);
        assert_eq!(audited["resource_grants"], current["resource_grants"]);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owner_revocation_at_transaction_boundary_prevents_grants_and_audit() {
        let (_dir, app, space, issued) = gate_fixture().await;
        let sid = space["space_id"].as_str().unwrap();
        let tid = issued["token_id"].as_str().unwrap();
        let body = json!({"expected_version":0});
        let route = format!("/admin/v0/spaces/{sid}/owner-credential");
        let owner = app
            .admin(&Request::json("POST", &route, ADMIN, body.clone()), body)
            .await
            .unwrap();
        let body = json!({"request_id":"revoked-owner","expected_authority_version":0,"scopes":["message.send"],"resource_grants":{"recipient_ids":[space["default_actor_id"]]},"default_recipient_id":space["default_actor_id"]});
        let req = Request::json(
            "PUT",
            &format!("/admin/v0/spaces/{sid}/tokens/{tid}/permissions"),
            owner["credential"].as_str().unwrap(),
            body.clone(),
        );
        app.db.before_batch.borrow_mut().push(Statement::new(
            "UPDATE space_admin_credentials SET revoked_at=1 WHERE space_id=?",
            vec![sid.into()],
        ));
        assert_eq!(
            app.token_permissions(&req, sid, tid, body)
                .await
                .unwrap_err()
                .code,
            "UNAUTHENTICATED"
        );
        let current = app.token_permission_detail(sid, tid).await.unwrap();
        assert_eq!(current["authority_version"], 0);
        assert_eq!(current["scopes"], json!(["message.read"]));
        assert_eq!(current["resource_grants"]["recipient_ids"], json!([]));
        assert!(current["default_recipient_id"].is_null());
        assert!(
            app.db
                .query(Statement::new(
                    "SELECT change_id FROM token_permission_changes",
                    vec![]
                ))
                .await
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owner_key_rotation_and_session_logout_fence_inflight_edits() {
        for use_session in [false, true] {
            let (_dir, app, space, issued) = gate_fixture().await;
            let sid = space["space_id"].as_str().unwrap();
            let tid = issued["token_id"].as_str().unwrap();
            let body = json!({"expected_version":0});
            let route = format!("/admin/v0/spaces/{sid}/owner-credential");
            let owner = app
                .admin(&Request::json("POST", &route, ADMIN, body.clone()), body)
                .await
                .unwrap();
            let body = json!({"request_id":"rotated-owner","expected_authority_version":0,"scopes":["message.send"],"resource_grants":{"recipient_ids":[space["default_actor_id"]]},"default_recipient_id":space["default_actor_id"]});
            let mut req = Request::json(
                "PUT",
                &format!("/admin/v0/spaces/{sid}/tokens/{tid}/permissions"),
                owner["credential"].as_str().unwrap(),
                body.clone(),
            );
            if use_session {
                let response = app
                    .handle(Request::json(
                        "POST",
                        "/admin/session",
                        "",
                        json!({"admin_secret":owner["credential"]}),
                    ))
                    .await;
                assert_eq!(response.status, 200);
                let value: Value = serde_json::from_slice(&response.body).unwrap();
                req.headers.remove("authorization");
                req.headers.insert(
                    "cookie".into(),
                    response.headers["set-cookie"]
                        .split(';')
                        .next()
                        .unwrap()
                        .into(),
                );
                req.headers.insert(
                    "x-waypost-csrf".into(),
                    value["data"]["csrf_token"].as_str().unwrap().into(),
                );
                app.db.before_batch.borrow_mut().push(Statement::new(
                    "DELETE FROM admin_sessions WHERE space_id=?",
                    vec![sid.into()],
                ));
            } else {
                // The replacement key is active, so checking only space identity
                // or 'some active owner key' would incorrectly allow the old request.
                app.db.before_batch.borrow_mut().push(Statement::new("UPDATE space_admin_credentials SET credential_digest=?,version=version+1 WHERE space_id=?",vec![Sha256::digest(b"replacement-owner-credential").to_vec().into(),sid.into()]));
            }
            assert_eq!(
                app.token_permissions(&req, sid, tid, body)
                    .await
                    .unwrap_err()
                    .code,
                "UNAUTHENTICATED"
            );
            let current = app.token_permission_detail(sid, tid).await.unwrap();
            assert_eq!(current["authority_version"], 0);
            assert_eq!(current["scopes"], json!(["message.read"]));
            assert_eq!(current["resource_grants"]["recipient_ids"], json!([]));
            assert!(current["default_recipient_id"].is_null());
            assert!(
                app.db
                    .query(Statement::new(
                        "SELECT change_id FROM token_permission_changes",
                        vec![]
                    ))
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
