mod common;
use common::*;
use serde_json::{Value, json};

async fn token(f: &Fixture, key: &str, scopes: Value) -> Value {
    call(&f.app,"POST",&format!("/admin/v0/spaces/{}/tokens",f.sid()),ADMIN,json!({"request_id":key,"actor_id":f.space["default_actor_id"],"consumer_id":f.space["default_consumer_id"],"scopes":scopes,"resource_grants":{}})).await
}
fn path(f: &Fixture, t: &Value) -> String {
    format!(
        "/admin/v0/spaces/{}/tokens/{}/permissions",
        f.sid(),
        t["token_id"].as_str().unwrap()
    )
}
fn edit(key: &str, version: i64, scopes: Value) -> Value {
    json!({"request_id":key,"expected_authority_version":version,"scopes":scopes,"resource_grants":{},"default_recipient_id":null})
}

#[tokio::test(flavor = "current_thread")]
async fn same_bearer_gains_read_without_replacing_identity_and_replays_safely() {
    let f = Fixture::new().await;
    let t = token(&f, "editable", json!(["message.send"])).await;
    let bearer = t["token"].as_str().unwrap();
    let route = path(&f, &t);
    f.send("before-grant", "old history").await;
    assert_eq!(
        raw(
            &f.app,
            "POST",
            "/v0/inbox/read",
            bearer,
            json!({"consumer_id":f.space["default_consumer_id"]})
        )
        .await
        .0,
        403
    );
    let input = edit("grant-read", 0, json!(["message.read", "receipt.write"]));
    let result = call(&f.app, "PUT", &route, ADMIN, input.clone()).await;
    assert_eq!(result["authority_version"], 1);
    assert_eq!(result["actor_id"], f.space["default_actor_id"]);
    assert_eq!(result["consumer_id"], f.space["default_consumer_id"]);
    let inbox = call(
        &f.app,
        "POST",
        "/v0/inbox/read",
        bearer,
        json!({"consumer_id":result["consumer_id"]}),
    )
    .await;
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    let replay = call(&f.app, "PUT", &route, ADMIN, input.clone()).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["authority_version"], 1);
    let mut changed = input;
    changed["scopes"] = json!(["message.send"]);
    assert_eq!(
        raw(&f.app, "PUT", &route, ADMIN, changed).await.1["error"]["code"],
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        raw(
            &f.app,
            "PUT",
            &route,
            ADMIN,
            edit("stale", 0, json!(["message.send"]))
        )
        .await
        .1["error"]["code"],
        "REVISION_CONFLICT"
    );
    let conn = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM token_permission_changes", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn write_permissions_preserve_cursor_read_permissions_invalidate_it() {
    let f = Fixture::new().await;
    let t = token(&f, "cursor", json!(["message.read", "receipt.write"])).await;
    let bearer = t["token"].as_str().unwrap();
    let route = path(&f, &t);
    f.send("cursor-msg", "body").await;
    let page = call(
        &f.app,
        "POST",
        "/v0/inbox/read",
        bearer,
        json!({"consumer_id":f.space["default_consumer_id"]}),
    )
    .await;
    let request =
        json!({"consumer_id":f.space["default_consumer_id"],"cursor":page["next_cursor"]});
    call(&f.app,"POST","/v0/receipts",bearer,json!({"request_id":"saved","consumer_id":f.space["default_consumer_id"],"items":[{"item_id":page["items"][0]["item_id"],"stage":"received"}],"checkpoint_cursor":page["next_cursor"]})).await;
    call(
        &f.app,
        "PUT",
        &route,
        ADMIN,
        edit(
            "add-write",
            0,
            json!(["message.read", "receipt.write", "message.send"]),
        ),
    )
    .await;
    call(&f.app, "POST", "/v0/inbox/read", bearer, request.clone()).await;
    call(
        &f.app,
        "PUT",
        &route,
        ADMIN,
        edit("remove-read", 1, json!(["memory.read", "receipt.write"])),
    )
    .await;
    assert_eq!(
        raw(&f.app, "POST", "/v0/inbox/read", bearer, request)
            .await
            .1["error"]["code"],
        "CURSOR_SCOPE_CHANGED"
    );
    let conn = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn non_admin_cross_space_revoked_expired_and_bad_grants_are_rejected() {
    let f = Fixture::new().await;
    let t = token(&f, "invalid", json!(["message.send"])).await;
    let route = path(&f, &t);
    let input = edit("edit-invalid", 0, json!(["message.read"]));
    assert_eq!(
        raw(&f.app, "GET", &route, &f.writer_token, json!({}))
            .await
            .0,
        401
    );
    assert_eq!(
        raw(&f.app, "PUT", &route, &f.writer_token, input.clone())
            .await
            .0,
        401
    );
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
    let mut bad = input.clone();
    bad["resource_grants"] = json!({"recipient_ids":[other["default_actor_id"]]});
    assert_eq!(raw(&f.app, "PUT", &route, ADMIN, bad).await.0, 404);
    let mut bad = input.clone();
    bad["default_recipient_id"] = f.writer["actor_id"].clone();
    assert_eq!(raw(&f.app, "PUT", &route, ADMIN, bad).await.0, 400);
    call(
        &f.app,
        "DELETE",
        route.trim_end_matches("/permissions"),
        ADMIN,
        json!({}),
    )
    .await;
    assert_eq!(
        raw(&f.app, "PUT", &route, ADMIN, input.clone()).await.0,
        403
    );
    let expired = token(&f, "expired", json!(["message.send"])).await;
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
async fn space_owner_can_edit_only_own_connection_and_audit_has_no_secret() {
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
    let t = token(&f, "owner-edit", json!(["message.send"])).await;
    let route = path(&f, &t);
    call(&f.app, "GET", &route, owner, json!({})).await;
    call(
        &f.app,
        "PUT",
        &route,
        owner,
        edit("owner-edit", 0, json!(["message.send", "message.read"])),
    )
    .await;
    let other = call(
        &f.app,
        "POST",
        "/admin/v0/spaces",
        ADMIN,
        json!({"request_id":"owner-other","display_name":"Other"}),
    )
    .await;
    let wrong = route.replace(f.sid(), other["space_id"].as_str().unwrap());
    assert_eq!(raw(&f.app, "GET", &wrong, owner, json!({})).await.0, 404);
    let conn = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    let (manager, before, after): (String, String, String) = conn
        .query_row(
            "SELECT manager,before_json,after_json FROM token_permission_changes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(manager, format!("owner:{}", f.sid()));
    for text in [before, after] {
        assert!(!text.contains(owner));
        assert!(!text.contains(t["token"].as_str().unwrap()));
    }
}
