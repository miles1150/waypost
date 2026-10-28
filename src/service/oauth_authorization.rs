//! Browser consent and RFC 8628 authorization requests. No request selects its own authority.
//! The shared 1000-live-request cap bounds storage, not caller abuse: public clients
//! can exhaust it until requests expire. Internet exposure still needs deployment
//! rate limits. Pending tombstones retain RFC8628 expiry errors for 24 hours.
use super::oauth::oauth_error;
use super::*;
use crate::json::{fields, required};
use crate::storage::driver::optional_text;

fn digest(value: &str) -> Sql {
    Sha256::digest(value.as_bytes()).to_vec().into()
}
fn secret() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}
fn parameter(params: &BTreeMap<String, String>, key: &str) -> Result<String> {
    params
        .get(key)
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| oauth_error("invalid_request"))
}
fn browser_cookie(request: &Request, origin: &str) -> Result<String> {
    let name = super::accounts::browser_cookie_name(origin, super::accounts::BrowserCookie::OAuth);
    let values: Vec<_> = request
        .headers
        .get("cookie")
        .into_iter()
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .collect();
    if values.len() != 1
        || values[0].len() != 43
        || !URL_SAFE_NO_PAD
            .decode(values[0])
            .is_ok_and(|v| v.len() == 32)
    {
        return Err(oauth_error("access_denied"));
    }
    Ok(values[0].to_owned())
}
fn human_digest(value: &str) -> Result<Sql> {
    let code = value.replace('-', "").to_ascii_uppercase();
    if code.len() != 16 || !code.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(oauth_error("invalid_request"));
    }
    Ok(digest(&code))
}
fn pkce_challenge(value: &str) -> Result<()> {
    if value.len() != 43 || !URL_SAFE_NO_PAD.decode(value).is_ok_and(|v| v.len() == 32) {
        return Err(oauth_error("invalid_request"));
    }
    Ok(())
}
fn completion_uri(
    redirect: &str,
    state: Option<String>,
    issuer: &str,
    code: Option<&str>,
) -> Result<String> {
    let mut url = url::Url::parse(redirect).map_err(|_| oauth_error("invalid_request"))?;
    let mut query = url.query_pairs_mut();
    match code {
        Some(code) => {
            query.append_pair("code", code);
        }
        None => {
            query.append_pair("error", "access_denied");
        }
    }
    if let Some(state) = state {
        query.append_pair("state", &state);
    }
    query.append_pair("iss", issuer);
    drop(query);
    Ok(url.to_string())
}

impl<D: Database, O: ObjectStore> App<D, O> {
    fn authorization_scope_resource(
        &self,
        params: &BTreeMap<String, String>,
    ) -> Result<(String, String)> {
        let resource = parameter(params, "resource")?;
        if resource != self.oauth_resource() {
            return Err(oauth_error("invalid_target"));
        }
        let scope = params
            .get("scope")
            .cloned()
            .unwrap_or_else(|| "waypost".into());
        if scope != "waypost" {
            return Err(oauth_error("invalid_scope"));
        }
        Ok((resource, scope))
    }
    pub(super) async fn oauth_authorize(
        &self,
        request: &Request,
        params: BTreeMap<String, String>,
    ) -> Result<Response> {
        if request.method != "GET" {
            return Err(oauth_error("invalid_request"));
        }
        let client_id = parameter(&params, "client_id")?;
        let client = self.oauth_client(&client_id)?;
        let redirect = parameter(&params, "redirect_uri")?;
        if !client.accepts_redirect(&redirect) {
            return Err(oauth_error("invalid_request"));
        }
        let state = params.get("state").cloned();
        if state
            .as_ref()
            .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
        {
            return Err(oauth_error("invalid_request"));
        }
        match self.oauth_authorize_validated(request, params).await {
            Ok(response) => Ok(response),
            Err(error) => {
                let code = match error.code {
                    "invalid_request"
                    | "unsupported_response_type"
                    | "invalid_scope"
                    | "invalid_target"
                    | "temporarily_unavailable" => error.code,
                    _ => "server_error",
                };
                let mut target =
                    url::Url::parse(&redirect).map_err(|_| oauth_error("invalid_request"))?;
                {
                    let mut query = target.query_pairs_mut();
                    query.append_pair("error", code);
                    if let Some(state) = state {
                        query.append_pair("state", &state);
                    }
                    query.append_pair("iss", &self.config.public_origin);
                }
                let mut response = Response::json(303, json!({}));
                response
                    .headers
                    .insert("location".into(), target.to_string());
                Ok(response)
            }
        }
    }
    async fn oauth_authorize_validated(
        &self,
        request: &Request,
        params: BTreeMap<String, String>,
    ) -> Result<Response> {
        if request.method != "GET" {
            return Err(oauth_error("invalid_request"));
        }
        let client_id = parameter(&params, "client_id")?;
        let client = self.oauth_client(&client_id)?;
        let redirect = parameter(&params, "redirect_uri")?;
        // Never redirect errors to an unvalidated or subsequently changed client URI.
        if !client.accepts_redirect(&redirect) {
            return Err(oauth_error("invalid_request"));
        }
        if parameter(&params, "response_type")? != "code" {
            return Err(oauth_error("unsupported_response_type"));
        }
        let (resource, scope) = self.authorization_scope_resource(&params)?;
        if parameter(&params, "code_challenge_method")? != "S256" {
            return Err(oauth_error("invalid_request"));
        }
        let challenge = parameter(&params, "code_challenge")?;
        pkce_challenge(&challenge)?;
        let state = params.get("state").cloned();
        if state
            .as_ref()
            .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
        {
            return Err(oauth_error("invalid_request"));
        }
        let now = self.clock.now_ms();
        let id = random_id("oauth")?;
        let browser = secret()?;
        let rows=self.db.batch(vec![
            Statement::new("DELETE FROM oauth_requests WHERE status='pending' AND expires_at<=?",vec![(now - 86_400_000).into()]),
            Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,redirect_uri,client_state,code_challenge,browser_digest,status,created_at,expires_at,next_poll_at) SELECT ?,'code',?,?,?,?,?,?,?,'pending',?,?,? WHERE (SELECT count(*) FROM oauth_requests WHERE status IN('pending','approved') AND expires_at>?)<1000 RETURNING request_id",vec![id.clone().into(),client_id.into(),resource.into(),scope.into(),redirect.into(),state.into(),challenge.into(),digest(&browser),now.into(),(now+600_000).into(),now.into(),now.into()])
        ]).await?;
        if rows[1].is_empty() {
            return Err(oauth_error("temporarily_unavailable"));
        }
        let mut response = Response::json(303, json!({}));
        response
            .headers
            .insert("location".into(), format!("/account?oauth_request={id}"));
        let secure = if self.config.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        let cookie_path = if secure.is_empty() { "/oauth" } else { "/" };
        response.headers.insert(
            "set-cookie".into(),
            format!(
                "{}={browser}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=600{secure}",
                super::accounts::browser_cookie_name(
                    &self.config.public_origin,
                    super::accounts::BrowserCookie::OAuth
                )
            ),
        );
        Ok(response)
    }
    pub(super) async fn oauth_device_authorization(
        &self,
        params: BTreeMap<String, String>,
    ) -> Result<Value> {
        let client_id = parameter(&params, "client_id")?;
        self.oauth_client(&client_id)?;
        let (resource, scope) = self.authorization_scope_resource(&params)?;
        let now = self.clock.now_ms();
        let id = random_id("oauth")?;
        let device = secret()?;
        let human = hex::encode_upper(random_bytes::<8>()?);
        let rows=self.db.batch(vec![
            Statement::new("DELETE FROM oauth_requests WHERE status='pending' AND expires_at<=?",vec![(now - 86_400_000).into()]),
            Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,device_digest,user_digest,status,created_at,expires_at,next_poll_at) SELECT ?,'device',?,?,?,?,?,'pending',?,?,? WHERE (SELECT count(*) FROM oauth_requests WHERE status IN('pending','approved') AND expires_at>?)<1000 RETURNING request_id",vec![id.into(),client_id.into(),resource.into(),scope.into(),digest(&device),digest(&human),now.into(),(now+600_000).into(),now.into(),now.into()])
        ]).await?;
        if rows[1].is_empty() {
            return Err(oauth_error("temporarily_unavailable"));
        }
        Ok(
            json!({"device_code":device,"user_code":format!("{}-{}-{}-{}",&human[..4],&human[4..8],&human[8..12],&human[12..]),"verification_uri":format!("{}/account",self.config.public_origin),"expires_in":600,"interval":5}),
        )
    }
    fn current_authorization_client(&self, row: &Row) -> Result<String> {
        let client = self.oauth_client(&text(row, "client_id")?)?;
        if text(row, "resource")? != self.oauth_resource() || text(row, "scope")? != "waypost" {
            return Err(oauth_error("invalid_target"));
        }
        if text(row, "kind")? == "code" && !client.accepts_redirect(&text(row, "redirect_uri")?) {
            return Err(oauth_error("invalid_request"));
        }
        Ok(client.name.clone())
    }
    pub(super) async fn oauth_consent(&self, request: &Request, body: Value) -> Result<Response> {
        let writing = request.method == "POST";
        if !writing && request.method != "GET" {
            return Err(oauth_error("invalid_request"));
        }
        fields(
            &body,
            if writing {
                &["request_id", "decision", "actor_id", "consumer_id"]
            } else {
                &["request_id"]
            },
        )
        .map_err(|_| oauth_error("invalid_request"))?;
        let id = required(&body, "request_id").map_err(|_| oauth_error("invalid_request"))?;
        let browser = browser_cookie(request, &self.config.public_origin)?;
        let session = self.account_session(request, writing).await?;
        let now = self.clock.now_ms();
        let rows=self.db.query(Statement::new("SELECT * FROM oauth_requests WHERE request_id=? AND kind='code' AND browser_digest=? AND status='pending' AND expires_at>?",vec![id.clone().into(),digest(&browser),now.into()])).await?;
        let row = rows.first().ok_or_else(|| oauth_error("invalid_request"))?;
        let client_name = self.current_authorization_client(row)?;
        if !writing {
            return Ok(Response::json(
                200,
                json!({"request_id":id,"client_id":text(row,"client_id")?,"client_name":client_name,"resource":text(row,"resource")?,"scope":text(row,"scope")?,"selected_space_id":optional_text(&session,"selected_space_id"),"warning":"This connection may send messages and read/write shared materials in the selected Space. It cannot manage the account."}),
            ));
        }
        let decision = required(&body, "decision").map_err(|_| oauth_error("invalid_request"))?;
        if !["approve", "deny"].contains(&decision.as_str()) {
            return Err(oauth_error("invalid_request"));
        }
        let code = if decision == "approve" {
            Some(secret()?)
        } else {
            None
        };
        self.commit_oauth_consent(
            request,
            &session,
            &id,
            &body,
            code.as_deref(),
            Some(digest(&browser)),
        )
        .await?;
        let redirect = completion_uri(
            &text(row, "redirect_uri")?,
            optional_text(row, "client_state"),
            &self.config.public_origin,
            code.as_deref(),
        )?;
        Ok(Response::json(200, json!({"redirect_uri":redirect})))
    }
    pub(super) async fn oauth_device_consent(
        &self,
        request: &Request,
        body: Value,
    ) -> Result<Response> {
        if request.method != "POST" {
            return Err(oauth_error("invalid_request"));
        }
        fields(&body, &["action", "user_code", "actor_id", "consumer_id"])
            .map_err(|_| oauth_error("invalid_request"))?;
        let action = required(&body, "action").map_err(|_| oauth_error("invalid_request"))?;
        if !["inspect", "approve", "deny"].contains(&action.as_str()) {
            return Err(oauth_error("invalid_request"));
        }
        let user = human_digest(
            &required(&body, "user_code").map_err(|_| oauth_error("invalid_request"))?,
        )?;
        let session = self.account_session(request, true).await?;
        let now = self.clock.now_ms();
        let rows=self.db.query(Statement::new("SELECT * FROM oauth_requests WHERE user_digest=? AND kind='device' AND status='pending' AND expires_at>?",vec![user,now.into()])).await?;
        let row = rows.first().ok_or_else(|| oauth_error("invalid_request"))?;
        let name = self.current_authorization_client(row)?;
        let id = text(row, "request_id")?;
        if action == "inspect" {
            return Ok(Response::json(
                200,
                json!({"request_id":id,"client_id":text(row,"client_id")?,"client_name":name,"resource":text(row,"resource")?,"scope":text(row,"scope")?,"selected_space_id":optional_text(&session,"selected_space_id"),"warning":"Verify this code came from your own device. Approval grants space-member access."}),
            ));
        }
        // This internal marker selects approve/deny; it is never an authorization code.
        self.commit_oauth_consent(
            request,
            &session,
            &id,
            &body,
            if action == "approve" {
                Some("device")
            } else {
                None
            },
            None,
        )
        .await?;
        Ok(Response::json(
            200,
            json!({"approved":action=="approve","request_id":id}),
        ))
    }
    async fn commit_oauth_consent(
        &self,
        request: &Request,
        session: &Row,
        id: &str,
        body: &Value,
        code: Option<&str>,
        browser: Option<Sql>,
    ) -> Result<()> {
        let now = self.clock.now_ms();
        if integer(session, "created_at")? < now - 900_000 {
            return Err(oauth_error("access_denied"));
        }
        let account = text(session, "account_id")?;
        let cookie = super::accounts::account_cookie(request, &self.config.public_origin)?;
        let (browser_guard, browser_args) = match browser {
            Some(d) => ("kind='code' AND browser_digest=?", vec![d]),
            None => ("kind='device'", vec![]),
        };
        let active = "EXISTS(SELECT 1 FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id WHERE s.session_digest=? AND s.account_id=? AND s.expires_at>? AND s.created_at>=? AND a.disabled=0)";
        if let Some(code) = code {
            let sid = optional_text(session, "selected_space_id")
                .ok_or_else(|| oauth_error("access_denied"))?;
            let actor = required(body, "actor_id").map_err(|_| oauth_error("invalid_request"))?;
            let consumer =
                required(body, "consumer_id").map_err(|_| oauth_error("invalid_request"))?;
            crate::domain::check_id(&actor).map_err(|_| oauth_error("invalid_request"))?;
            crate::domain::check_id(&consumer).map_err(|_| oauth_error("invalid_request"))?;
            let is_code = browser_guard.starts_with("kind='code'");
            let mut args = vec![
                account.clone().into(),
                sid.clone().into(),
                actor.clone().into(),
                consumer.clone().into(),
                now.into(),
                if is_code { digest(code) } else { Sql::Null },
                if is_code {
                    (now + 120_000).into()
                } else {
                    (now + 600_000).into()
                },
                id.into(),
                now.into(),
            ];
            args.extend(browser_args);
            args.extend([
                digest(&cookie),
                account.clone().into(),
                now.into(),
                (now - 900_000).into(),
                digest(&cookie),
                sid.clone().into(),
                account.into(),
                sid.clone().into(),
                sid.into(),
                actor.into(),
                consumer.into(),
            ]);
            let rows=self.db.batch(vec![Statement::new(format!("UPDATE oauth_requests SET status='approved',account_id=?,space_id=?,actor_id=?,consumer_id=?,approved_at=?,code_digest=?,expires_at=MIN(expires_at,?) WHERE request_id=? AND status='pending' AND expires_at>? AND {browser_guard} AND {active} AND EXISTS(SELECT 1 FROM account_sessions s JOIN account_spaces m ON m.account_id=s.account_id AND m.space_id=s.selected_space_id WHERE s.session_digest=? AND s.selected_space_id=? AND m.account_id=? AND m.space_id=?) AND EXISTS(SELECT 1 FROM actors a JOIN consumers c ON c.space_id=a.space_id AND c.actor_id=a.actor_id WHERE a.space_id=? AND a.actor_id=? AND c.consumer_id=? AND a.disabled=0 AND c.disabled=0 AND c.view='inbox') RETURNING request_id"),args)]).await?;
            if rows[0].is_empty() {
                return Err(oauth_error("access_denied"));
            }
        } else {
            let mut args = vec![account.clone().into(), now.into(), id.into(), now.into()];
            args.extend(browser_args);
            args.extend([
                digest(&cookie),
                account.into(),
                now.into(),
                (now - 900_000).into(),
            ]);
            let rows=self.db.batch(vec![Statement::new(format!("UPDATE oauth_requests SET status='denied',account_id=?,approved_at=? WHERE request_id=? AND status='pending' AND expires_at>? AND {browser_guard} AND {active} RETURNING request_id"),args)]).await?;
            if rows[0].is_empty() {
                return Err(oauth_error("access_denied"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "native")]
    #[tokio::test(flavor = "current_thread")]
    async fn requests_store_only_secrets_digests_and_reject_wrong_redirect_or_resource() {
        use crate::native::{FileStore, SqliteDb};
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: "test-only-admin-secret-long-enough".into(),
                public_origin: "https://waypost.example".into(),
            },
        );
        app.oauth = Some(super::super::oauth::OAuthConfig {
            clients: vec![super::super::oauth::OAuthClient {
                client_id: "client".into(),
                name: "Test client".into(),
                redirect_uris: vec!["https://client.example/callback".into()],
                allow_loopback_port_variation: false,
            }],
        });
        let mut params: BTreeMap<String, String> = [
            ("client_id", "client"),
            ("resource", "https://waypost.example/mcp"),
            ("scope", "waypost"),
            ("redirect_uri", "https://client.example/callback"),
            ("response_type", "code"),
            ("code_challenge_method", "S256"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        params.insert("code_challenge".into(), URL_SAFE_NO_PAD.encode([3; 32]));
        let request = Request::json("GET", "/oauth/authorize", "", json!({}));
        let response = app.oauth_authorize(&request, params.clone()).await.unwrap();
        assert_eq!(response.status, 303);
        assert!(response.headers["location"].starts_with("/account?oauth_request="));
        assert!(response.headers["set-cookie"].contains("HttpOnly; SameSite=Lax"));
        assert!(response.headers["set-cookie"].ends_with("; Secure"));
        assert!(response.headers["set-cookie"].starts_with("__Host-waypost_oauth="));
        assert!(response.headers["set-cookie"].contains("; Path=/;"));
        assert!(!response.headers["set-cookie"].contains("Domain="));
        let mut invalid = params.clone();
        invalid.insert("code_challenge_method".into(), "plain".into());
        invalid.insert(
            "state".into(),
            "state&redirect_uri=https://evil.example".into(),
        );
        let failure = app.oauth_authorize(&request, invalid).await.unwrap();
        assert_eq!(failure.status, 303);
        let callback = url::Url::parse(&failure.headers["location"]).unwrap();
        assert_eq!(callback.host_str(), Some("client.example"));
        let query: BTreeMap<_, _> = callback.query_pairs().into_owned().collect();
        assert_eq!(query["error"], "invalid_request");
        assert_eq!(query["state"], "state&redirect_uri=https://evil.example");
        params.insert(
            "redirect_uri".into(),
            "https://evil.example/callback".into(),
        );
        assert!(app.oauth_authorize(&request, params.clone()).await.is_err());
        params.insert("resource".into(), "https://evil.example/mcp".into());
        assert!(
            app.oauth_device_authorization(params.clone())
                .await
                .is_err()
        );
        params.insert("resource".into(), "https://waypost.example/mcp".into());
        params.remove("code_challenge");
        params.remove("code_challenge_method");
        let device = app.oauth_device_authorization(params).await.unwrap();
        assert_eq!(device["interval"], 5);
        assert_eq!(device["expires_in"], 600);
        let rows = app
            .db
            .query(Statement::new(
                "SELECT * FROM oauth_requests ORDER BY kind",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(text(&rows[0], "status").unwrap(), "pending");
        assert_eq!(blob(&rows[0], "browser_digest").unwrap().len(), 32);
        let raw = device["device_code"].as_str().unwrap();
        assert_eq!(
            blob(&rows[1], "device_digest").unwrap(),
            Sha256::digest(raw.as_bytes()).to_vec()
        );
        let raw_user = device["user_code"].as_str().unwrap().replace('-', "");
        assert_eq!(
            blob(&rows[1], "user_digest").unwrap(),
            Sha256::digest(raw_user.as_bytes()).to_vec()
        );
        // Retain recently expired requests so the RFC8628 endpoint can report
        // expired_token, while pruning old pending rows after the tombstone window.
        let now = app.clock.now_ms();
        app.db
            .batch(vec![
                Statement::new(
                    "UPDATE oauth_requests SET expires_at=? WHERE kind='device'",
                    vec![(now - 1).into()],
                ),
                Statement::new(
                    "UPDATE oauth_requests SET expires_at=? WHERE kind='code'",
                    vec![(now - 86_400_001).into()],
                ),
            ])
            .await
            .unwrap();
        let mut fresh = BTreeMap::new();
        fresh.insert("client_id".into(), "client".into());
        fresh.insert("resource".into(), "https://waypost.example/mcp".into());
        app.oauth_device_authorization(fresh).await.unwrap();
        let retained = app
            .db
            .query(Statement::new(
                "SELECT kind FROM oauth_requests WHERE expires_at<=?",
                vec![now.into()],
            ))
            .await
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(text(&retained[0], "kind").unwrap(), "device");
        let poll = BTreeMap::from([
            (
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
            ),
            ("client_id".into(), "client".into()),
            ("resource".into(), "https://waypost.example/mcp".into()),
            ("device_code".into(), raw.into()),
        ]);
        assert_eq!(
            app.oauth_token(poll).await.unwrap_err().code,
            "expired_token"
        );
    }
    #[test]
    fn callback_values_are_encoded_and_cannot_replace_registered_destination() {
        let result = completion_uri(
            "https://client.example/callback",
            Some("state&redirect_uri=https://evil.example".into()),
            "https://waypost.example",
            Some("opaque-code"),
        )
        .unwrap();
        let parsed = url::Url::parse(&result).unwrap();
        assert_eq!(parsed.host_str(), Some("client.example"));
        let query: BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "state&redirect_uri=https://evil.example");
        assert_eq!(query["code"], "opaque-code");
        assert_eq!(query["iss"], "https://waypost.example");
    }
    #[test]
    fn browser_cookie_is_unique_high_entropy_and_pkce_is_s256_size() {
        let mut request = Request::json("GET", "/oauth/consent", "", json!({}));
        request.headers.insert(
            "cookie".into(),
            format!("__Host-waypost_oauth={}", URL_SAFE_NO_PAD.encode([1; 32])),
        );
        assert!(browser_cookie(&request, "https://waypost.example").is_ok());
        request.headers.insert(
            "cookie".into(),
            format!("waypost_oauth={}", URL_SAFE_NO_PAD.encode([1; 32])),
        );
        assert!(browser_cookie(&request, "https://waypost.example").is_err());
        assert!(browser_cookie(&request, "http://127.0.0.1:8787").is_ok());
        request.headers.insert(
            "cookie".into(),
            format!(
                "__Host-waypost_oauth={}; __Host-waypost_oauth={}",
                URL_SAFE_NO_PAD.encode([1; 32]),
                URL_SAFE_NO_PAD.encode([2; 32])
            ),
        );
        assert!(browser_cookie(&request, "https://waypost.example").is_err());
        assert!(pkce_challenge("plain").is_err());
        assert!(pkce_challenge(&URL_SAFE_NO_PAD.encode([1; 32])).is_ok());
    }
}
