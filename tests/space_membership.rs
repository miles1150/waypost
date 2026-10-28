mod common;
use common::*;
use serde_json::json;

#[tokio::test(flavor = "current_thread")]
async fn same_space_delivery_needs_no_grant_but_foreign_and_disabled_targets_fail() {
    let f = Fixture::new().await;
    let root = format!("/admin/v0/spaces/{}", f.sid());
    let actor = call(
        &f.app,
        "POST",
        &format!("{root}/actors"),
        ADMIN,
        json!({"request_id":"recipient","display_name":"Recipient","kind":"agent"}),
    )
    .await;
    let consumer = call(
        &f.app,
        "POST",
        &format!("{root}/consumers"),
        ADMIN,
        json!({"request_id":"consumer","actor_id":actor["actor_id"],"view":"inbox","filter":{}}),
    )
    .await;
    let token=call(&f.app,"POST",&format!("{root}/tokens"),ADMIN,json!({"request_id":"token","actor_id":actor["actor_id"],"consumer_id":consumer["consumer_id"]})).await;
    let message = json!({"request_id":"unlisted-recipient","recipient_ids":[actor["actor_id"]],"kind":"info","subject":"Direct","body":{"text":"No recipient grant needed"}});
    let sent = call(
        &f.app,
        "POST",
        "/v0/messages",
        &f.writer_token,
        message.clone(),
    )
    .await;
    call(
        &f.app,
        "GET",
        &format!("/v0/messages/{}", sent["message_id"].as_str().unwrap()),
        token["token"].as_str().unwrap(),
        json!({}),
    )
    .await;
    // Space sharing does not change message addressing or allow claiming another Consumer's ACKs.
    assert_eq!(
        raw(
            &f.app,
            "GET",
            &format!("/v0/messages/{}", sent["message_id"].as_str().unwrap()),
            &f.reader_token,
            json!({})
        )
        .await
        .0,
        404
    );
    assert_eq!(
        raw(
            &f.app,
            "POST",
            "/v0/inbox/read",
            &f.reader_token,
            json!({"consumer_id":consumer["consumer_id"]})
        )
        .await
        .0,
        404
    );
    let other = call(
        &f.app,
        "POST",
        "/admin/v0/spaces",
        ADMIN,
        json!({"request_id":"foreign","display_name":"Foreign"}),
    )
    .await;
    let mut foreign = message.clone();
    foreign["request_id"] = json!("foreign-target");
    foreign["recipient_ids"] = json!([other["default_actor_id"]]);
    assert_eq!(
        raw(&f.app, "POST", "/v0/messages", &f.writer_token, foreign)
            .await
            .0,
        404
    );
    call(
        &f.app,
        "POST",
        &format!(
            "{root}/actors/{}/disable",
            actor["actor_id"].as_str().unwrap()
        ),
        ADMIN,
        json!({}),
    )
    .await;
    let mut disabled = message;
    disabled["request_id"] = json!("disabled-target");
    assert_eq!(
        raw(&f.app, "POST", "/v0/messages", &f.writer_token, disabled)
            .await
            .0,
        404
    );
    assert_eq!(
        raw(
            &f.app,
            "GET",
            "/v0/describe",
            token["token"].as_str().unwrap(),
            json!({})
        )
        .await
        .0,
        401
    );
}

#[tokio::test(flavor = "current_thread")]
async fn obsolete_grant_fields_are_rejected_instead_of_silently_ignored() {
    let f = Fixture::new().await;
    let route = format!("/admin/v0/spaces/{}/tokens", f.sid());
    let base = json!({"request_id":"legacy","actor_id":f.writer["actor_id"],"consumer_id":f.writer_consumer["consumer_id"]});
    for (key, value) in [
        ("scopes", json!(["message.send"])),
        ("resource_grants", json!({"recipient_ids":[]})),
    ] {
        let mut body = base.clone();
        body[key] = value;
        assert_eq!(
            raw(&f.app, "POST", &route, ADMIN, body).await.0,
            400,
            "{key}"
        );
    }
}
