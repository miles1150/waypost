mod common;
use common::*;
use serde_json::{Value, json};

async fn token(f: &Fixture, key: &str) -> Value {
    call(&f.app,"POST",&format!("/admin/v0/spaces/{}/tokens",f.sid()),ADMIN,json!({"request_id":key,"actor_id":f.space["default_actor_id"],"consumer_id":f.space["default_consumer_id"]})).await
}
fn path(f: &Fixture, t: &Value) -> String {
    format!(
        "/admin/v0/spaces/{}/tokens/{}/routing",
        f.sid(),
        t["token_id"].as_str().unwrap()
    )
}
fn edit(key: &str, version: i64, destination: Value) -> Value {
    json!({"request_id":key,"expected_authority_version":version,"default_recipient_id":destination})
}

#[tokio::test(flavor = "current_thread")]
async fn routing_updates_same_connection_with_cas_and_idempotent_replay() {
    let f = Fixture::new().await;
    let t = token(&f, "routing").await;
    let bearer = t["token"].as_str().unwrap();
    let route = path(&f, &t);
    let before = call(&f.app, "GET", &route, ADMIN, json!({})).await;
    let input = edit("route-to-agent", 0, f.writer["actor_id"].clone());
    let updated = call(&f.app, "PUT", &route, ADMIN, input.clone()).await;
    assert_eq!(updated["authority_version"], 1);
    for key in ["actor_id", "consumer_id", "expires_at", "revoked_at"] {
        assert_eq!(updated[key], before[key], "{key}");
    }
    let describe = call(&f.app, "GET", "/v0/describe", bearer, json!({})).await;
    assert_eq!(describe["default_recipient_id"], f.writer["actor_id"]);
    let replay = call(&f.app, "PUT", &route, ADMIN, input.clone()).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["authority_version"], 1);
    let mut conflict = input;
    conflict["default_recipient_id"] = Value::Null;
    assert_eq!(
        raw(&f.app, "PUT", &route, ADMIN, conflict).await.1["error"]["code"],
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        raw(&f.app, "PUT", &route, ADMIN, edit("stale", 0, Value::Null))
            .await
            .1["error"]["code"],
        "REVISION_CONFLICT"
    );
    call(&f.app,"POST","/v0/messages",bearer,json!({"request_id":"default-route","kind":"info","subject":"Default","body":{"text":"To agent"}})).await;
    assert_eq!(f.writer_inbox().await["items"].as_array().unwrap().len(), 1);
    // Explicit same-space destinations remain usable regardless of default routing.
    call(&f.app,"POST","/v0/messages",bearer,json!({"request_id":"explicit-route","recipient_ids":[f.space["default_actor_id"]],"kind":"info","subject":"Explicit","body":{"text":"To owner"}})).await;
}

#[tokio::test(flavor = "current_thread")]
async fn routing_change_preserves_read_cursor_and_receipts() {
    let f = Fixture::new().await;
    let t = token(&f, "cursor").await;
    let bearer = t["token"].as_str().unwrap();
    f.send("cursor-message", "body").await;
    let page = call(
        &f.app,
        "POST",
        "/v0/inbox/read",
        bearer,
        json!({"consumer_id":f.space["default_consumer_id"]}),
    )
    .await;
    call(&f.app,"POST","/v0/receipts",bearer,json!({"request_id":"saved","consumer_id":f.space["default_consumer_id"],"items":[{"item_id":page["items"][0]["item_id"],"stage":"received"}],"checkpoint_cursor":page["next_cursor"]})).await;
    call(
        &f.app,
        "PUT",
        &path(&f, &t),
        ADMIN,
        edit("route", 0, f.writer["actor_id"].clone()),
    )
    .await;
    call(
        &f.app,
        "POST",
        "/v0/inbox/read",
        bearer,
        json!({"consumer_id":f.space["default_consumer_id"],"cursor":page["next_cursor"]}),
    )
    .await;
    let conn = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn routing_keeps_management_space_and_credential_boundaries() {
    let f = Fixture::new().await;
    let t = token(&f, "restricted-management").await;
    let route = path(&f, &t);
    let input = edit("edit", 0, f.writer["actor_id"].clone());
    for method in ["GET", "PUT"] {
        assert_eq!(
            raw(&f.app, method, &route, &f.writer_token, input.clone())
                .await
                .0,
            401
        );
    }
    let other = call(
        &f.app,
        "POST",
        "/admin/v0/spaces",
        ADMIN,
        json!({"request_id":"other-space","display_name":"Other"}),
    )
    .await;
    let wrong = route.replace(f.sid(), other["space_id"].as_str().unwrap());
    assert_eq!(
        raw(&f.app, "PUT", &wrong, ADMIN, input.clone()).await.0,
        404
    );
    assert_eq!(
        raw(
            &f.app,
            "PUT",
            &route,
            ADMIN,
            edit("foreign-target", 0, other["default_actor_id"].clone())
        )
        .await
        .0,
        404
    );
    // Removed permissions API cannot silently accept an old grant update.
    assert_eq!(
        raw(
            &f.app,
            "PUT",
            &route.replace("/routing", "/permissions"),
            ADMIN,
            json!({})
        )
        .await
        .0,
        404
    );
    call(
        &f.app,
        "DELETE",
        route.trim_end_matches("/routing"),
        ADMIN,
        json!({}),
    )
    .await;
    assert_eq!(
        raw(&f.app, "PUT", &route, ADMIN, input.clone()).await.0,
        403
    );
    assert_eq!(
        raw(
            &f.app,
            "GET",
            "/v0/describe",
            t["token"].as_str().unwrap(),
            json!({})
        )
        .await
        .0,
        401
    );
    let expired = token(&f, "expired").await;
    let conn = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    conn.execute(
        "UPDATE tokens SET expires_at=1 WHERE token_id=?",
        [expired["token_id"].as_str().unwrap()],
    )
    .unwrap();
    assert_eq!(
        raw(&f.app, "PUT", &path(&f, &expired), ADMIN, input)
            .await
            .0,
        403
    );
}

#[tokio::test(flavor = "current_thread")]
async fn owner_can_route_only_own_space_without_secret_disclosure() {
    let f = Fixture::new().await;
    let issued = call(
        &f.app,
        "POST",
        &format!("/admin/v0/spaces/{}/owner-credential", f.sid()),
        ADMIN,
        json!({"expected_version":0}),
    )
    .await;
    let owner = issued["credential"].as_str().unwrap();
    let t = token(&f, "owner-routing").await;
    let route = path(&f, &t);
    let updated = call(
        &f.app,
        "PUT",
        &route,
        owner,
        edit("owner-route", 0, f.writer["actor_id"].clone()),
    )
    .await;
    assert!(!updated.to_string().contains(owner));
    assert!(!updated.to_string().contains(t["token"].as_str().unwrap()));
    assert!(updated.get("token_digest").is_none());
    let other = call(
        &f.app,
        "POST",
        "/admin/v0/spaces",
        ADMIN,
        json!({"request_id":"other-owner","display_name":"Other"}),
    )
    .await;
    let wrong = route.replace(f.sid(), other["space_id"].as_str().unwrap());
    assert_eq!(raw(&f.app, "GET", &wrong, owner, json!({})).await.0, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_routing_edits_have_one_winner_and_disabled_destinations_fail() {
    let f = Fixture::new().await;
    let t = token(&f, "concurrent-routing").await;
    let route = path(&f, &t);
    let (a, b) = tokio::join!(
        raw(
            &f.app,
            "PUT",
            &route,
            ADMIN,
            edit("route-a", 0, f.writer["actor_id"].clone())
        ),
        raw(
            &f.app,
            "PUT",
            &route,
            ADMIN,
            edit("route-b", 0, Value::Null)
        )
    );
    assert_eq!(
        [a.0, b.0].iter().filter(|status| **status == 200).count(),
        1
    );
    let loser = if a.0 == 200 { b } else { a };
    assert_eq!(loser.1["error"]["code"], "REVISION_CONFLICT");
    let detail = call(&f.app, "GET", &route, ADMIN, json!({})).await;
    assert_eq!(detail["authority_version"], 1);
    let conn = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    let (count, before, after): (i64, String, String) = conn
        .query_row(
            "SELECT count(*),before_json,after_json FROM token_routing_changes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert!(!before.contains(t["token"].as_str().unwrap()));
    assert!(!after.contains(t["token"].as_str().unwrap()));
    call(
        &f.app,
        "POST",
        &format!(
            "/admin/v0/spaces/{}/actors/{}/disable",
            f.sid(),
            f.writer["actor_id"].as_str().unwrap()
        ),
        ADMIN,
        json!({}),
    )
    .await;
    assert_eq!(
        raw(
            &f.app,
            "PUT",
            &route,
            ADMIN,
            edit("disabled-route", 1, f.writer["actor_id"].clone())
        )
        .await
        .0,
        403
    );
}
