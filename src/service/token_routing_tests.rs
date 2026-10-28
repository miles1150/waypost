use super::*;
use crate::native::{FileStore, SqliteDb};

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
            .is_some_and(|s| s.sql.starts_with("INSERT INTO token_routing_changes"))
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
const ADMIN: &str = "test-routing-admin-32-bytes-long";
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
    let body = json!({"request_id":"token","actor_id":space["default_actor_id"],"consumer_id":space["default_consumer_id"]});
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
async fn concurrent_routing_cas_preserves_exact_winner_and_one_audit() {
    let (_dir, app, space, issued) = gate_fixture().await;
    let sid = space["space_id"].as_str().unwrap();
    let tid = issued["token_id"].as_str().unwrap();
    let route = format!("/admin/v0/spaces/{sid}/tokens/{tid}/routing");
    let one = json!({"request_id":"concurrent-one","expected_authority_version":0,"default_recipient_id":null});
    let two = json!({"request_id":"concurrent-two","expected_authority_version":0,"default_recipient_id":space["default_actor_id"]});
    let r1 = Request::json("PUT", &route, ADMIN, one.clone());
    let r2 = Request::json("PUT", &route, ADMIN, two.clone());
    app.db.gate.set(true);
    let (a, b) = futures_util::join!(
        app.token_routing(&r1, sid, tid, one.clone()),
        app.token_routing(&r2, sid, tid, two.clone())
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
    let current = app.token_routing_detail(sid, tid).await.unwrap();
    assert_eq!(current["authority_version"], 1);
    assert_eq!(
        current["default_recipient_id"],
        winner["default_recipient_id"]
    );
    let rows = app
        .db
        .query(Statement::new(
            "SELECT request_id,after_json FROM token_routing_changes",
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
    assert_eq!(
        audited["default_recipient_id"],
        current["default_recipient_id"]
    );
    assert_eq!(audited["authority_version"], current["authority_version"]);
}
#[tokio::test(flavor = "current_thread")]
async fn owner_revocation_at_transaction_boundary_prevents_routing_and_audit() {
    let (_dir, app, space, issued) = gate_fixture().await;
    let sid = space["space_id"].as_str().unwrap();
    let tid = issued["token_id"].as_str().unwrap();
    let body = json!({"expected_version":0});
    let route = format!("/admin/v0/spaces/{sid}/owner-credential");
    let owner = app
        .admin(&Request::json("POST", &route, ADMIN, body.clone()), body)
        .await
        .unwrap();
    let body = json!({"request_id":"revoked-owner","expected_authority_version":0,"default_recipient_id":space["default_actor_id"]});
    let req = Request::json(
        "PUT",
        &format!("/admin/v0/spaces/{sid}/tokens/{tid}/routing"),
        owner["credential"].as_str().unwrap(),
        body.clone(),
    );
    app.db.before_batch.borrow_mut().push(Statement::new(
        "UPDATE space_admin_credentials SET revoked_at=1 WHERE space_id=?",
        vec![sid.into()],
    ));
    assert_eq!(
        app.token_routing(&req, sid, tid, body)
            .await
            .unwrap_err()
            .code,
        "UNAUTHENTICATED"
    );
    let current = app.token_routing_detail(sid, tid).await.unwrap();
    assert_eq!(current["authority_version"], 0);

    assert!(current["default_recipient_id"].is_null());
    assert!(
        app.db
            .query(Statement::new(
                "SELECT change_id FROM token_routing_changes",
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
        let body = json!({"request_id":"rotated-owner","expected_authority_version":0,"default_recipient_id":space["default_actor_id"]});
        let mut req = Request::json(
            "PUT",
            &format!("/admin/v0/spaces/{sid}/tokens/{tid}/routing"),
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
            app.token_routing(&req, sid, tid, body)
                .await
                .unwrap_err()
                .code,
            "UNAUTHENTICATED"
        );
        let current = app.token_routing_detail(sid, tid).await.unwrap();
        assert_eq!(current["authority_version"], 0);

        assert!(current["default_recipient_id"].is_null());
        assert!(
            app.db
                .query(Statement::new(
                    "SELECT change_id FROM token_routing_changes",
                    vec![]
                ))
                .await
                .unwrap()
                .is_empty()
        );
    }
}
