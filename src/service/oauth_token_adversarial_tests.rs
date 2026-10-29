//! Faults and scheduling at the database await boundary, using the real token SQL.
use super::tests::{TestClock, code_params, device_params, fixture, refresh_params};
use super::*;
use crate::native::{FileStore, SqliteDb};
use std::cell::Cell;

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Rollback,
    UnknownCommit,
    ReplaceDevicePoll,
}
struct FaultDb {
    inner: SqliteDb,
    fault: Cell<Fault>,
    clock: Rc<TestClock>,
}
impl Database for FaultDb {
    async fn query(&self, statement: Statement) -> Result<Vec<Row>> {
        tokio::task::yield_now().await;
        self.inner.query(statement).await
    }
    async fn batch(&self, mut statements: Vec<Statement>) -> Result<Vec<Vec<Row>>> {
        tokio::task::yield_now().await;
        let issuing = statements
            .iter()
            .any(|s| s.sql.starts_with("INSERT INTO tokens("));
        let poll = statements
            .iter()
            .any(|s| s.sql.contains("SET interval_sec=interval_sec+5"));
        let fault = self.fault.get();
        if issuing && matches!(fault, Fault::Rollback | Fault::UnknownCommit) {
            self.fault.set(Fault::None);
            if fault == Fault::Rollback {
                // Fail after every issuance write. Native must roll back the
                // consumed request/refresh digest as well as all new tokens.
                statements.push(Statement::new("INSERT INTO oauth_access_tokens(token_id,family_id) VALUES('missing-token','missing-family')", vec![]));
            }
            let rows = self.inner.batch(statements).await?;
            return if fault == Fault::UnknownCommit {
                Err(Error::storage())
            } else {
                Ok(rows)
            };
        }
        let rows = self.inner.batch(statements).await?;
        if poll && fault == Fault::ReplaceDevicePoll {
            self.fault.set(Fault::None);
            // Suspend A after its polling batch. A second valid poll B, five
            // seconds later, writes a different nonce before A issues tokens.
            tokio::task::yield_now().await;
            self.clock.0.set(self.clock.now_ms() + 5_000);
            let now = self.clock.now_ms();
            self.inner.batch(vec![Statement::new("UPDATE oauth_requests SET next_poll_at=?+interval_sec*1000,claim_nonce='competing-poll' WHERE request_id='device' AND status='approved' AND next_poll_at<=?",vec![now.into(),now.into()])]).await?;
        }
        Ok(rows)
    }
}
fn wrapped(
    app: App<SqliteDb, FileStore>,
    clock: Rc<TestClock>,
    fault: Fault,
) -> App<FaultDb, FileStore> {
    let oauth_discovery = app.oauth_discovery.clone();
    let mut wrapped = App::new(
        FaultDb {
            inner: app.db,
            fault: Cell::new(fault),
            clock: clock.clone(),
        },
        app.objects,
        app.config,
    )
    .with_clock(clock);
    wrapped.oauth_discovery = oauth_discovery;
    wrapped
}
async fn count<D: Database>(app: &App<D, FileStore>, sql: &str) -> i64 {
    integer(
        &app.db.query(Statement::new(sql, vec![])).await.unwrap()[0],
        "n",
    )
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn delayed_device_poll_remains_retryable_and_obeys_replaced_schedule() {
    let (_dir, app, clock) = fixture().await;
    app.db
        .batch(vec![Statement::new(
            "UPDATE oauth_requests SET status='approved' WHERE request_id='device'",
            vec![],
        )])
        .await
        .unwrap();
    let app = wrapped(app, clock.clone(), Fault::ReplaceDevicePoll);
    assert_eq!(
        app.oauth_token(device_params()).await.unwrap_err().code,
        "authorization_pending"
    );
    assert_eq!(
        count(&app, "SELECT count(*) n FROM oauth_families").await,
        0
    );
    assert_eq!(
        app.oauth_token(device_params()).await.unwrap_err().code,
        "slow_down"
    );
    clock.0.set(clock.now_ms() + 10_000);
    assert!(app.oauth_token(device_params()).await.is_ok());
    assert_eq!(
        count(&app, "SELECT count(*) n FROM oauth_families").await,
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn failed_final_write_rolls_back_code_and_refresh_consumption() {
    let (_dir, app, clock) = fixture().await;
    let app = wrapped(app, clock, Fault::Rollback);
    assert!(app.oauth_token(code_params()).await.is_err());
    assert_eq!(
        count(
            &app,
            "SELECT count(*) n FROM oauth_requests WHERE request_id='code' AND status='approved'"
        )
        .await,
        1
    );
    assert_eq!(
        count(&app, "SELECT count(*) n FROM oauth_families").await,
        0
    );
    assert_eq!(
        count(
            &app,
            "SELECT count(*) n FROM tokens WHERE credential_kind='oauth'"
        )
        .await,
        0
    );
    let first = app.oauth_token(code_params()).await.unwrap();
    app.db.fault.set(Fault::Rollback);
    assert!(app.oauth_token(refresh_params(&first)).await.is_err());
    assert_eq!(
        count(
            &app,
            "SELECT count(*) n FROM oauth_refresh_tokens WHERE used_at IS NOT NULL"
        )
        .await,
        0
    );
    assert_eq!(
        count(&app, "SELECT count(*) n FROM oauth_access_tokens").await,
        1
    );
    assert!(app.oauth_token(refresh_params(&first)).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_commit_retries_revoke_instead_of_issuing_twice() {
    for refresh in [false, true] {
        let (_dir, app, clock) = fixture().await;
        let app = wrapped(app, clock, Fault::None);
        let request = if refresh {
            refresh_params(&app.oauth_token(code_params()).await.unwrap())
        } else {
            code_params()
        };
        app.db.fault.set(Fault::UnknownCommit);
        assert!(app.oauth_token(request.clone()).await.is_err());
        assert_eq!(
            app.oauth_token(request).await.unwrap_err().code,
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
    }
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_code_and_refresh_on_independent_connections_revoke_replay() {
    for refresh in [false, true] {
        let (dir, app, clock) = fixture().await;
        let mut second = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            app.objects.clone(),
            app.config.clone(),
        )
        .with_clock(clock.clone());
        second.oauth_discovery = app.oauth_discovery.clone();
        let first = wrapped(app, clock.clone(), Fault::None);
        let second = wrapped(second, clock, Fault::None);
        let request = if refresh {
            refresh_params(&first.oauth_token(code_params()).await.unwrap())
        } else {
            code_params()
        };
        let (a, b) = tokio::join!(
            first.oauth_token(request.clone()),
            second.oauth_token(request)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let error = if let Err(error) = a {
            error
        } else {
            b.unwrap_err()
        };
        assert_eq!(error.code, "invalid_grant");
        assert_eq!(
            count(
                &first,
                "SELECT count(*) n FROM oauth_families WHERE revoked_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &first,
                "SELECT count(*) n FROM tokens WHERE credential_kind='oauth' AND revoked_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            count(&first, "SELECT count(*) n FROM oauth_access_tokens").await,
            if refresh { 2 } else { 1 }
        );
    }
}
