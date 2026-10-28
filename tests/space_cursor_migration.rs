mod common;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::*;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use waypost::Request;

// Reproduce an authenticated legacy cursor, rather than testing an invalid signature.
// Its old grants fingerprint is deliberately different from the new shared-space view.
fn legacy_cursor(current: &str, version: &str) -> String {
    let body = current.split_once('.').unwrap().0;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap();
    let mut fields: Vec<_> = payload.split('|').map(str::to_owned).collect();
    fields[0] = version.into();
    fields[6] = "previous-connection-grants-fingerprint".into();
    let payload = fields.join("|");
    let mut key = Hmac::<Sha256>::new_from_slice(ADMIN.as_bytes()).unwrap();
    key.update(b"waypost-cursor-v2");
    let mut signature = Hmac::<Sha256>::new_from_slice(&key.finalize().into_bytes()).unwrap();
    signature.update(payload.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(signature.finalize().into_bytes())
    )
}

#[tokio::test(flavor = "current_thread")]
async fn old_inbox_cursors_require_rescan_without_losing_stable_item_ids() {
    let f = Fixture::new().await;
    f.send("before-upgrade", "Already seen").await;
    f.send("after-upgrade", "Not yet seen").await;
    let page = call(
        &f.app,
        "POST",
        "/v0/inbox/read",
        &f.reader_token,
        json!({"consumer_id":f.space["default_consumer_id"],"limit":1}),
    )
    .await;
    assert_eq!(page["has_more"], true);
    for version in ["f2", "f3"] {
        let cursor = legacy_cursor(page["next_cursor"].as_str().unwrap(), version);
        let (status, error) = raw(
            &f.app,
            "POST",
            "/v0/inbox/read",
            &f.reader_token,
            json!({"consumer_id":f.space["default_consumer_id"],"cursor":cursor}),
        )
        .await;
        assert_eq!(status, 409, "{version}: {error}");
        assert_eq!(error["error"]["code"], "CURSOR_SCOPE_CHANGED");
        let reset = f.inbox().await;
        assert_eq!(reset["items"].as_array().unwrap().len(), 2);
        assert_eq!(reset["items"][0]["item_id"], page["items"][0]["item_id"]);
        assert_ne!(reset["items"][1]["item_id"], page["items"][0]["item_id"]);
        // Continuing with the replacement cursor is valid and does not repeat history.
        let next = call(
            &f.app,
            "POST",
            "/v0/inbox/read",
            &f.reader_token,
            json!({"consumer_id":f.space["default_consumer_id"],"cursor":reset["next_cursor"]}),
        )
        .await;
        assert!(next["items"].as_array().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn old_memory_cursor_resets_to_a_complete_shared_collection() {
    let f = Fixture::new().await;
    let content = b"shared note";
    let upload = call(&f.app, "POST", "/v0/uploads", &f.writer_token,
        json!({"request_id":"cursor-blob","content_type":"text/plain","size_bytes":content.len(),"sha256":hex::encode(Sha256::digest(content))})).await;
    let uid = upload["upload_id"].as_str().unwrap();
    let mut put = Request::json(
        "PUT",
        &format!("/v0/uploads/{uid}/content"),
        &f.writer_token,
        json!({}),
    );
    put.body = content.to_vec();
    put.headers
        .insert("content-type".into(), "text/plain".into());
    assert_eq!(f.app.handle(put).await.status, 200);
    let sealed = call(
        &f.app,
        "POST",
        &format!("/v0/uploads/{uid}/commit"),
        &f.writer_token,
        json!({"request_id":"cursor-seal"}),
    )
    .await;
    let collection = call(&f.app, "POST", &format!("/admin/v0/spaces/{}/collections", f.sid()), ADMIN,
        json!({"request_id":"cursor-collection","source_actor_id":f.writer["actor_id"],"scope":"shared","display_name":"Shared"})).await;
    let cid = collection["collection_id"].as_str().unwrap();
    call(
        &f.app,
        "POST",
        &format!("/v0/memory/collections/{cid}/revisions"),
        &f.writer_token,
        json!({"request_id":"cursor-publish","expected_revision":0,"mode":"snapshot","items":[
            {"item_id":"first","blob_id":sealed["blob_id"],"path":"first.txt"},
            {"item_id":"second","blob_id":sealed["blob_id"],"path":"second.txt"}]}),
    )
    .await;
    let path = format!("/v0/memory/collections/{cid}/read");
    let page = call(&f.app, "POST", &path, &f.reader_token, json!({"limit":1})).await;
    assert_eq!(page["has_more"], true);
    let cursor = legacy_cursor(page["next_cursor"].as_str().unwrap(), "m1");
    let (status, error) = raw(
        &f.app,
        "POST",
        &path,
        &f.reader_token,
        json!({"cursor":cursor}),
    )
    .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["error"]["code"], "CURSOR_SCOPE_CHANGED");
    let reset = call(
        &f.app,
        "POST",
        &path,
        &f.reader_token,
        json!({"cursor":null}),
    )
    .await;
    assert_eq!(reset["revision"], page["revision"]);
    assert_eq!(reset["items"].as_array().unwrap().len(), 2);
    assert_eq!(reset["items"][0]["item_id"], page["items"][0]["item_id"]);
    let next = call(
        &f.app,
        "POST",
        &path,
        &f.reader_token,
        json!({"cursor":reset["next_cursor"]}),
    )
    .await;
    assert!(next["items"].as_array().unwrap().is_empty());
}
