//! Optional account domain. Upstream identity never authenticates an Agent directly.
use super::*;
use crate::json::{fields, required};
use crate::storage::driver::optional_text;
use accounts_oidc::{OidcCodeExchange, OidcConfig};

pub(super) fn account_cookie(r: &Request) -> Result<String> {
    cookie(r, "waypost_account")
}
fn cookie(r: &Request, name: &str) -> Result<String> {
    let values: Vec<_> = r
        .headers
        .get("cookie")
        .into_iter()
        .flat_map(|s| s.split(';'))
        .filter_map(|s| s.trim().split_once('='))
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .collect();
    if values.len() != 1 || values[0].len() != 43 {
        return Err(Error::unauthenticated());
    }
    Ok(values[0].into())
}
fn digest(s: &str) -> Sql {
    Sha256::digest(s.as_bytes()).to_vec().into()
}
fn secret() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

// Every statement is guarded by the same transaction's successful owner-proof event.
// Keep consumed request/refresh history: it remains replay evidence. Terminating the
// approval and family prevents an unlink/reclaim cycle from reviving old authority.
fn oauth_detach_statements(event: &str, now: i64) -> Vec<Statement> {
    vec![
        Statement::new(
            "UPDATE oauth_requests SET status='denied' WHERE status IN('pending','approved') AND EXISTS(SELECT 1 FROM account_audit e WHERE e.event_id=? AND e.account_id=oauth_requests.account_id AND e.space_id=oauth_requests.space_id)",
            vec![event.into()],
        ),
        Statement::new(
            "UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,?) WHERE EXISTS(SELECT 1 FROM account_audit e WHERE e.event_id=? AND e.account_id=oauth_families.account_id AND e.space_id=oauth_families.space_id)",
            vec![now.into(), event.into()],
        ),
        // OAuth-kind also catches an orphaned mapping. Legacy credentials are unaffected.
        Statement::new(
            "UPDATE tokens SET revoked_at=?,authority_version=authority_version+1 WHERE revoked_at IS NULL AND ((credential_kind='oauth' AND EXISTS(SELECT 1 FROM account_audit e WHERE e.event_id=? AND e.space_id=tokens.space_id)) OR token_id IN(SELECT at.token_id FROM oauth_access_tokens at JOIN oauth_families f ON f.family_id=at.family_id JOIN account_audit e ON e.account_id=f.account_id AND e.space_id=f.space_id WHERE e.event_id=?))",
            vec![now.into(), event.into(), event.into()],
        ),
    ]
}

impl<D: Database, O: ObjectStore> App<D, O> {
    /// Explicit opt-in; never reads caller-supplied identity headers. Zero disables signup.
    pub fn with_accounts(
        mut self,
        config: OidcConfig,
        exchange: Rc<dyn OidcCodeExchange>,
        signup_limit: usize,
    ) -> Result<Self> {
        config.validate()?;
        if signup_limit > 100 {
            return Err(Error::invalid(
                "Account signup limit exceeds experimental maximum.",
            ));
        }
        let origin = url::Url::parse(&self.config.public_origin)
            .map_err(|_| Error::invalid("Invalid account origin."))?;
        if origin.origin().ascii_serialization() != self.config.public_origin
            || (origin.scheme() != "https"
                && !(origin.scheme() == "http" && origin.host_str() == Some("127.0.0.1")))
        {
            return Err(Error::invalid(
                "Accounts require HTTPS or literal loopback development origin.",
            ));
        }
        self.oidc = Some(config);
        self.oidc_exchange = Some(exchange);
        self.account_signup_limit = signup_limit;
        Ok(self)
    }
    pub(super) async fn account_session(&self, r: &Request, require_csrf: bool) -> Result<Row> {
        if self.oidc.is_none() {
            return Err(Error::not_found());
        }
        let raw = account_cookie(r)?;
        if require_csrf {
            if r.headers.get("origin") != Some(&self.config.public_origin) {
                return Err(Error::forbidden());
            }
            let supplied = r
                .headers
                .get("x-waypost-csrf")
                .ok_or_else(Error::forbidden)?;
            if Sha256::digest(supplied.as_bytes())
                != Sha256::digest(self.csrf_token(&raw)?.as_bytes())
            {
                return Err(Error::forbidden());
            }
        }
        let rows = self.db.query(Statement::new("SELECT s.* FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id WHERE s.session_digest=? AND s.expires_at>? AND a.disabled=0",vec![digest(&raw),self.clock.now_ms().into()])).await?;
        rows.first().cloned().ok_or_else(Error::unauthenticated)
    }
    pub(super) async fn account_handle(&self, r: &Request) -> Response {
        let result = self.account_action(r).await;
        let mut response = match result {
            Ok(r) => r,
            Err(e) => Response::json(e.status(), json!({"ok":false,"error":e.value()})),
        };
        response
            .headers
            .insert("cache-control".into(), "no-store".into());
        response
            .headers
            .insert("referrer-policy".into(), "no-referrer".into());
        response
    }
    async fn account_action(&self, r: &Request) -> Result<Response> {
        let config = self.oidc.as_ref().ok_or_else(Error::not_found)?;
        let secure = if self.config.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        let now = self.clock.now_ms();
        if r.method == "GET" && r.path == "/account" {
            let mut out = Response::json(200, json!(null));
            out.body = include_bytes!("../../dashboard/account.html").to_vec();
            out.headers
                .insert("content-type".into(), "text/html; charset=utf-8".into());
            out.headers.insert("content-security-policy".into(),"default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".into());
            return Ok(out);
        }
        if r.method == "GET" && r.path == "/account/app.js" {
            let mut out = Response::json(200, json!(null));
            out.body = include_bytes!("../../dashboard/account.js").to_vec();
            out.headers.insert(
                "content-type".into(),
                "text/javascript; charset=utf-8".into(),
            );
            return Ok(out);
        }
        if r.path == "/account/callback" && r.method == "GET" {
            let mut params = BTreeMap::new();
            for (k, v) in url::form_urlencoded::parse(r.query.as_bytes()) {
                if params.insert(k.into_owned(), v.into_owned()).is_some() {
                    return Err(Error::invalid("Repeated callback parameter."));
                }
            }
            let state = params.get("state").ok_or_else(Error::unauthenticated)?;
            let code = params.get("code").ok_or_else(Error::unauthenticated)?;
            if state.len() != 43 || code.len() > 4096 {
                return Err(Error::unauthenticated());
            }
            let browser = cookie(r, "waypost_login")?;
            // Claim before network exchange. A lost/failed exchange requires a fresh login,
            // never a replay of a possibly consumed authorization code.
            let rows = self.db.batch(vec![Statement::new("UPDATE account_login_attempts SET consumed=1 WHERE state_digest=? AND browser_digest=? AND expires_at>? AND consumed=0 RETURNING nonce,verifier",vec![digest(state),digest(&browser),now.into()])]).await?;
            let row = rows
                .first()
                .and_then(|r| r.first())
                .ok_or_else(Error::unauthenticated)?;
            let token = self
                .oidc_exchange
                .as_ref()
                .ok_or_else(Error::not_found)?
                .exchange(
                    code,
                    &text(row, "verifier")?,
                    &format!("{}/account/callback", self.config.public_origin),
                )
                .await?;
            let now = self.clock.now_ms();
            let identity = config.verify(&token, &text(row, "nonce")?, now)?;
            let aid = random_id("account")?;
            let session = secret()?;
            let expiry = now + 8 * 60 * 60 * 1000;
            self.db.batch(vec![
                Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) SELECT ?,?,?,? WHERE (SELECT count(*) FROM accounts)<? ON CONFLICT(issuer,subject) DO NOTHING",vec![aid.into(),identity.issuer.clone().into(),identity.subject.clone().into(),now.into(),(self.account_signup_limit as i64).into()]),
                Statement::new("INSERT INTO account_sessions(session_digest,account_id,created_at,expires_at) SELECT ?,account_id,?,? FROM accounts WHERE issuer=? AND subject=? AND disabled=0",vec![digest(&session),now.into(),expiry.into(),identity.issuer.into(),identity.subject.into()]),
                Statement::new("DELETE FROM account_login_attempts WHERE expires_at<=? OR state_digest=?",vec![now.into(),digest(state)]),
                Statement::new("DELETE FROM account_sessions WHERE expires_at<=?",vec![now.into()]),
            ]).await?;
            let exists = self
                .db
                .query(Statement::new(
                    "SELECT 1 AS ok FROM account_sessions WHERE session_digest=?",
                    vec![digest(&session)],
                ))
                .await?;
            if exists.is_empty() {
                return Err(Error::forbidden());
            }
            let mut out = Response::json(303, json!({"ok":true}));
            out.headers.insert("location".into(), "/account".into());
            out.headers.insert("set-cookie".into(),format!("waypost_account={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800{secure}"));
            return Ok(out);
        }
        if r.method != "GET"
            && r.headers
                .get("origin")
                .is_some_and(|o| o != &self.config.public_origin)
        {
            return Err(Error::forbidden());
        }
        if r.path == "/account/login" && r.method == "POST" {
            if r.headers.get("origin") != Some(&self.config.public_origin) {
                return Err(Error::forbidden());
            }
            let state = secret()?;
            let browser = secret()?;
            let nonce = secret()?;
            let verifier = secret()?;
            let url = config.authorization_url(
                &state,
                &nonce,
                &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                &format!("{}/account/callback", self.config.public_origin),
            )?;
            let rows = self.db.batch(vec![
                Statement::new("DELETE FROM account_login_attempts WHERE expires_at<=?",vec![now.into()]),
                Statement::new("INSERT INTO account_login_attempts(state_digest,browser_digest,nonce,verifier,expires_at) SELECT ?,?,?,?,? WHERE (SELECT count(*) FROM account_login_attempts)<1000 RETURNING state_digest",vec![digest(&state),digest(&browser),nonce.into(),verifier.into(),(now+600_000).into()])
            ]).await?;
            if rows[1].is_empty() {
                return Err(Error::new(
                    "RATE_LIMITED",
                    "Too many outstanding login attempts.",
                ));
            }
            let mut out = Response::json(200, json!({"ok":true,"data":{"authorization_url":url}}));
            out.headers.insert("set-cookie".into(),format!("waypost_login={browser}; Path=/account; HttpOnly; SameSite=Lax; Max-Age=600{secure}"));
            return Ok(out);
        }
        let body = if r.body.is_empty() {
            json!({})
        } else {
            crate::json::parse(&r.body, self.limits.max_json_bytes)?
        };
        if r.path.starts_with("/account/devices/") {
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":self.account_device_action(r,body).await?}),
            ));
        }
        if r.path == "/account/spaces/recover" && r.method == "POST" {
            // Recovery is proof of the existing legacy owner key, not an account cookie.
            // No platform operator token or ordinary Agent credential is accepted here.
            if r.headers.get("origin") != Some(&self.config.public_origin) {
                return Err(Error::forbidden());
            }
            fields(&body, &["space_id", "owner_credential"])?;
            let sid = required(&body, "space_id")?;
            let owner = required(&body, "owner_credential")?;
            let event = random_id("ownership")?;
            let mut statements = vec![
                Statement::new(
                    "INSERT INTO account_audit(event_id,account_id,space_id,action,created_at) SELECT ?,m.account_id,m.space_id,'recovery_detach',? FROM account_spaces m JOIN space_admin_credentials c ON c.space_id=m.space_id WHERE m.space_id=? AND c.credential_digest=? AND c.revoked_at IS NULL",
                    vec![
                        event.clone().into(),
                        now.into(),
                        sid.clone().into(),
                        digest(&owner),
                    ],
                ),
                Statement::new(
                    "UPDATE tokens SET revoked_at=?,authority_version=authority_version+1 WHERE revoked_at IS NULL AND token_id IN(SELECT d.token_id FROM account_devices d JOIN account_audit e ON e.account_id=d.account_id AND e.space_id=d.space_id WHERE e.event_id=?)",
                    vec![now.into(), event.clone().into()],
                ),
                Statement::new(
                    "UPDATE account_devices SET state='revoked' WHERE state IN('approved','consumed') AND EXISTS(SELECT 1 FROM account_audit e WHERE e.event_id=? AND e.account_id=account_devices.account_id AND e.space_id=account_devices.space_id)",
                    vec![event.clone().into()],
                ),
                Statement::new(
                    "UPDATE account_sessions SET selected_space_id=NULL WHERE EXISTS(SELECT 1 FROM account_audit e WHERE e.event_id=? AND e.account_id=account_sessions.account_id AND e.space_id=account_sessions.selected_space_id)",
                    vec![event.clone().into()],
                ),
                Statement::new(
                    "DELETE FROM account_spaces WHERE EXISTS(SELECT 1 FROM account_audit e WHERE e.event_id=? AND e.account_id=account_spaces.account_id AND e.space_id=account_spaces.space_id)",
                    vec![event.clone().into()],
                ),
            ];
            statements.extend(oauth_detach_statements(&event, now));
            self.db.batch(statements).await?;
            let done = self
                .db
                .query(Statement::new(
                    "SELECT 1 AS ok FROM account_audit WHERE event_id=?",
                    vec![event.into()],
                ))
                .await?;
            if done.is_empty() {
                return Err(Error::forbidden());
            }
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":{"detached":true}}),
            ));
        }
        let session = self.account_session(r, r.method != "GET").await?;
        let now = self.clock.now_ms();
        let aid = text(&session, "account_id")?;
        let session_digest = blob(&session, "session_digest")?;
        if r.path == "/account/session" && r.method == "GET" {
            let spaces=self.db.query(Statement::new("SELECT s.space_id,s.display_name FROM spaces s JOIN account_spaces m ON m.space_id=s.space_id WHERE m.account_id=? ORDER BY s.space_id",vec![aid.clone().into()])).await?;
            let spaces:Vec<_>=spaces.iter().map(|s| Ok(json!({"space_id":text(s,"space_id")?,"display_name":text(s,"display_name")?}))).collect::<Result<_>>()?;
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":{"account_id":aid,"selected_space_id":optional_text(&session,"selected_space_id"),"spaces":spaces,"csrf_token":self.csrf_token(&account_cookie(r)?)?}}),
            ));
        }
        if r.path == "/account/session" && r.method == "DELETE" {
            self.db
                .batch(vec![Statement::new(
                    "DELETE FROM account_sessions WHERE session_digest=?",
                    vec![session_digest.into()],
                )])
                .await?;
            let mut out = Response::json(200, json!({"ok":true}));
            out.headers.insert(
                "set-cookie".into(),
                format!("waypost_account=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"),
            );
            return Ok(out);
        }
        if r.method != "POST" {
            return Err(Error::not_found());
        }
        // Security changes require recent login, rather than a long-lived unattended cookie.
        if integer(&session, "created_at")? < now - 15 * 60 * 1000 {
            return Err(Error::new(
                "REAUTHENTICATION_REQUIRED",
                "Sign in again before changing ownership or selection.",
            ));
        }
        let active = "EXISTS(SELECT 1 FROM account_sessions x JOIN accounts a ON a.account_id=x.account_id WHERE x.session_digest=? AND x.account_id=? AND x.expires_at>? AND a.disabled=0)";
        if r.path == "/account/agents/create" {
            fields(&body, &["request_id", "display_name"])?;
            let key = required(&body, "request_id")?;
            crate::domain::check_request_id(&key)?;
            let name = required(&body, "display_name")?;
            if name.trim().is_empty() || name.len() > 200 {
                return Err(Error::invalid("Invalid Agent name."));
            }
            let sid = optional_text(&session, "selected_space_id").ok_or_else(Error::forbidden)?;
            let actor = random_id("actor")?;
            let consumer = random_id("consumer")?;
            let mut q = vec![Statement::new(
                format!(
                    "INSERT INTO account_agent_requests(account_id,request_id,space_id,display_name,actor_id,consumer_id,created_at) SELECT ?,?,?,?,?,?,? WHERE {active} AND EXISTS(SELECT 1 FROM account_spaces WHERE space_id=? AND account_id=?) ON CONFLICT(account_id,request_id) DO NOTHING"
                ),
                vec![
                    aid.clone().into(),
                    key.clone().into(),
                    sid.clone().into(),
                    name.clone().into(),
                    actor.clone().into(),
                    consumer.clone().into(),
                    now.into(),
                    session_digest.into(),
                    aid.clone().into(),
                    now.into(),
                    sid.clone().into(),
                    aid.clone().into(),
                ],
            )];
            let guard=Some(("EXISTS(SELECT 1 FROM account_agent_requests WHERE account_id=? AND request_id=? AND actor_id=?)".into(),vec![aid.clone().into(),key.clone().into(),actor.clone().into()]));
            q.extend(push_rows(
                "actors",
                "space_id,actor_id,display_name,kind,created_at",
                vec![vec![
                    sid.clone().into(),
                    actor.clone().into(),
                    name.clone().into(),
                    "agent".into(),
                    now.into(),
                ]],
                guard.clone(),
            ));
            q.extend(push_rows(
                "consumers",
                "space_id,consumer_id,actor_id,view,created_at",
                vec![vec![
                    sid.clone().into(),
                    consumer.into(),
                    actor.into(),
                    "inbox".into(),
                    now.into(),
                ]],
                guard,
            ));
            self.db.batch(q).await?;
            let rows = self
                .db
                .query(Statement::new(
                    "SELECT * FROM account_agent_requests WHERE account_id=? AND request_id=?",
                    vec![aid.into(), key.into()],
                ))
                .await?;
            let row = rows.first().ok_or_else(Error::forbidden)?;
            if text(row, "space_id")? != sid || text(row, "display_name")? != name {
                return Err(Error::new("IDEMPOTENCY_CONFLICT", "Agent request changed."));
            }
            self.account_session(r, true).await?;
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":{"actor_id":text(row,"actor_id")?,"consumer_id":text(row,"consumer_id")?}}),
            ));
        }
        if r.path == "/account/spaces/select" {
            fields(&body, &["space_id"])?;
            let sid = required(&body, "space_id")?;
            self.db.batch(vec![Statement::new(format!("UPDATE account_sessions SET selected_space_id=? WHERE session_digest=? AND EXISTS(SELECT 1 FROM account_spaces WHERE space_id=? AND account_id=?) AND {active}"),vec![sid.clone().into(),session_digest.clone().into(),sid.into(),aid.clone().into(),session_digest.into(),aid.into(),now.into()])]).await?;
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":{"selected_space_id":optional_text(&self.account_session(r,false).await?,"selected_space_id")}}),
            ));
        }
        if matches!(
            r.path.as_str(),
            "/account/spaces/claim" | "/account/spaces/unlink"
        ) {
            fields(&body, &["space_id", "owner_credential"])?;
            let sid = required(&body, "space_id")?;
            let owner = required(&body, "owner_credential")?;
            let event = random_id("ownership")?;
            let owner_guard = "EXISTS(SELECT 1 FROM space_admin_credentials WHERE space_id=? AND credential_digest=? AND revoked_at IS NULL)";
            let claim = r.path.ends_with("/claim");
            let binding = if claim {
                "NOT EXISTS(SELECT 1 FROM account_spaces WHERE space_id=?)"
            } else {
                "EXISTS(SELECT 1 FROM account_spaces WHERE space_id=? AND account_id=?)"
            };
            let mut args = vec![
                event.clone().into(),
                aid.clone().into(),
                sid.clone().into(),
                if claim {
                    "claim".into()
                } else {
                    "unlink".into()
                },
                now.into(),
                sid.clone().into(),
                digest(&owner),
                session_digest.clone().into(),
                aid.clone().into(),
                now.into(),
                sid.clone().into(),
            ];
            if !claim {
                args.push(aid.clone().into());
            }
            let mut q = vec![Statement::new(
                format!(
                    "INSERT INTO account_audit(event_id,account_id,space_id,action,created_at) SELECT ?,?,?,?,? WHERE {owner_guard} AND {active} AND {binding}"
                ),
                args,
            )];
            if claim {
                q.push(Statement::new("INSERT INTO account_spaces(space_id,account_id,created_at) SELECT space_id,account_id,created_at FROM account_audit WHERE event_id=?",vec![event.clone().into()]));
            } else {
                q.push(Statement::new("UPDATE tokens SET revoked_at=?,authority_version=authority_version+1 WHERE revoked_at IS NULL AND token_id IN(SELECT token_id FROM account_devices WHERE account_id=? AND space_id=?) AND EXISTS(SELECT 1 FROM account_audit WHERE event_id=?)",vec![now.into(),aid.clone().into(),sid.clone().into(),event.clone().into()]));
                q.push(Statement::new("UPDATE account_devices SET state='revoked' WHERE account_id=? AND space_id=? AND state IN('approved','consumed') AND EXISTS(SELECT 1 FROM account_audit WHERE event_id=?)",vec![aid.clone().into(),sid.clone().into(),event.clone().into()]));
                q.push(Statement::new("DELETE FROM account_spaces WHERE space_id=? AND account_id=? AND EXISTS(SELECT 1 FROM account_audit WHERE event_id=?)",vec![sid.clone().into(),aid.clone().into(),event.clone().into()]));
                q.push(Statement::new("UPDATE account_sessions SET selected_space_id=NULL WHERE selected_space_id=? AND account_id=? AND EXISTS(SELECT 1 FROM account_audit WHERE event_id=?)",vec![sid.into(),aid.into(),event.clone().into()]));
                q.extend(oauth_detach_statements(&event, now));
            }
            self.db.batch(q).await?;
            let done = self
                .db
                .query(Statement::new(
                    "SELECT 1 AS ok FROM account_audit WHERE event_id=?",
                    vec![event.into()],
                ))
                .await?;
            if done.is_empty() {
                return Err(Error::forbidden());
            }
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":{"linked":claim}}),
            ));
        }
        if r.path == "/account/spaces/create" {
            fields(&body, &["display_name"])?;
            let name = required(&body, "display_name")?;
            if name.trim().is_empty() || name.len() > 200 {
                return Err(Error::invalid("Invalid Space name."));
            }
            let sid = random_id("space")?;
            let actor = random_id("actor")?;
            let consumer = random_id("consumer")?;
            let event = random_id("ownership")?;
            let mut q = vec![Statement::new(
                format!(
                    "INSERT INTO account_audit(event_id,account_id,space_id,action,created_at) SELECT ?,?,?,'create',? WHERE {active} AND NOT EXISTS(SELECT 1 FROM account_spaces WHERE account_id=?)"
                ),
                vec![
                    event.clone().into(),
                    aid.clone().into(),
                    sid.clone().into(),
                    now.into(),
                    session_digest.into(),
                    aid.clone().into(),
                    now.into(),
                    aid.clone().into(),
                ],
            )];
            let guard = Some((
                "EXISTS(SELECT 1 FROM account_audit WHERE event_id=?)".into(),
                vec![event.clone().into()],
            ));
            q.extend(push_rows(
                "spaces",
                "space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at",
                vec![vec![
                    sid.clone().into(),
                    name.into(),
                    uuid_uri()?.into(),
                    actor.clone().into(),
                    consumer.clone().into(),
                    now.into(),
                ]],
                guard.clone(),
            ));
            q.extend(push_rows(
                "actors",
                "space_id,actor_id,display_name,kind,created_at",
                vec![vec![
                    sid.clone().into(),
                    actor.clone().into(),
                    "Owner".into(),
                    "user".into(),
                    now.into(),
                ]],
                guard.clone(),
            ));
            q.extend(push_rows(
                "consumers",
                "space_id,consumer_id,actor_id,view,created_at",
                vec![vec![
                    sid.clone().into(),
                    consumer.into(),
                    actor.into(),
                    "inbox".into(),
                    now.into(),
                ]],
                guard.clone(),
            ));
            q.extend(push_rows(
                "account_spaces",
                "space_id,account_id,created_at",
                vec![vec![sid.clone().into(), aid.clone().into(), now.into()]],
                guard,
            ));
            self.db.batch(q).await?;
            let rows=self.db.query(Statement::new("SELECT space_id FROM account_spaces WHERE account_id=? ORDER BY created_at LIMIT 1",vec![aid.into()])).await?;
            return Ok(Response::json(
                200,
                json!({"ok":true,"data":{"space_id":text(rows.first().ok_or_else(Error::forbidden)?,"space_id")?}}),
            ));
        }
        Err(Error::not_found())
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::native::{FileStore, SqliteDb};
    use accounts_oidc::{OidcCodeExchange, OidcRsaKey};
    use rsa::{
        RsaPrivateKey,
        pkcs8::DecodePrivateKey,
        signature::{SignatureEncoding, Signer},
        traits::PublicKeyParts,
    };
    use std::{cell::RefCell, future::Future, pin::Pin};
    const COOKIE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OWNER: &str = "legacy-owner-test-only-long-credential";
    struct Exchange(RefCell<String>);
    impl OidcCodeExchange for Exchange {
        fn exchange<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
            Box::pin(async { Ok(self.0.borrow().clone()) })
        }
    }
    type TestApp = App<SqliteDb, FileStore>;
    fn key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(include_str!("../../tests/fixtures/oidc-test-private.pem"))
            .unwrap()
    }
    fn config() -> OidcConfig {
        let k = key();
        OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "test-client".into(),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_secret: None,
            keys: vec![OidcRsaKey {
                kid: "test".into(),
                n: URL_SAFE_NO_PAD.encode(k.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(k.e().to_bytes_be()),
            }],
        }
    }
    fn request(app: &TestApp, path: &str, body: Value) -> Request {
        let mut r = Request::json("POST", path, "", body);
        r.headers.remove("authorization");
        r.headers
            .insert("origin".into(), app.config.public_origin.clone());
        r.headers
            .insert("cookie".into(), format!("waypost_account={COOKIE}"));
        r.headers
            .insert("x-waypost-csrf".into(), app.csrf_token(COOKIE).unwrap());
        r
    }
    async fn fixture() -> (tempfile::TempDir, TestApp, Rc<Exchange>, String) {
        let dir = tempfile::tempdir().unwrap();
        let exchange = Rc::new(Exchange(RefCell::new(String::new())));
        let app = App::new(
            SqliteDb::open(dir.path().join("db")).unwrap(),
            FileStore::open(dir.path().join("objects")).unwrap(),
            Config {
                admin_secret: "test-only-admin-secret-long-enough".into(),
                public_origin: "http://127.0.0.1:8787".into(),
            },
        )
        .with_accounts(config(), exchange.clone(), 2)
        .unwrap();
        let now = app.clock.now_ms();
        let space = app
            .admin(
                &Request::json(
                    "POST",
                    "/admin/v0/spaces",
                    &app.config.admin_secret,
                    json!({}),
                ),
                json!({"request_id":"old-space","display_name":"Old Space"}),
            )
            .await
            .unwrap();
        let sid = space["space_id"].as_str().unwrap().to_owned();
        app.db.batch(vec![
            Statement::new("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_test','https://issuer.example','existing',?)",vec![now.into()]),
            Statement::new("INSERT INTO account_sessions(session_digest,account_id,created_at,expires_at) VALUES(?,'account_test',?,?)",vec![digest(COOKIE),now.into(),(now+3600000).into()]),
            Statement::new("INSERT INTO space_admin_credentials(space_id,credential_digest,version,created_at) VALUES(?,?,1,?)",vec![sid.clone().into(),digest(OWNER),now.into()]),
        ]).await.unwrap();
        (dir, app, exchange, sid)
    }
    async fn action(app: &TestApp, path: &str, body: Value) -> Response {
        app.handle(request(app, path, body)).await
    }
    #[tokio::test(flavor = "current_thread")]
    async fn origin_validation_rejects_url_components_and_prefix_tricks() {
        for origin in [
            "https://example.test/path",
            "https://user@example.test",
            "https://example.test?x",
            "https://example.test/",
            "http://127.0.0.1:80@evil.test",
            "http://localhost:8787",
        ] {
            let (_d, mut app, exchange, _) = fixture().await;
            app.config.public_origin = origin.into();
            assert!(
                app.with_accounts(config(), exchange, 2).is_err(),
                "{origin}"
            );
        }
        for origin in ["https://example.test", "http://127.0.0.1:8787"] {
            let (_d, mut app, exchange, _) = fixture().await;
            app.config.public_origin = origin.into();
            assert!(app.with_accounts(config(), exchange, 2).is_ok(), "{origin}");
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn login_capacity_rejects_without_issuing_unpersisted_state() {
        let (_d, app, _, _) = fixture().await;
        app.db.batch(vec![Statement::new("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO account_login_attempts(state_digest,browser_digest,nonce,verifier,expires_at) SELECT randomblob(32),randomblob(32),'nonce','verifier',? FROM n", vec![(app.clock.now_ms()+600000).into()])]).await.unwrap();
        let response = action(&app, "/account/login", json!({})).await;
        assert_eq!(
            response.status,
            429,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        assert!(!response.headers.contains_key("set-cookie"));
        app.db
            .batch(vec![Statement::new(
                "DELETE FROM account_login_attempts",
                vec![],
            )])
            .await
            .unwrap();
        assert_eq!(action(&app, "/account/login", json!({})).await.status, 200);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn detach_revokes_oauth_permanently_and_preserves_legacy() {
        for path in ["/account/spaces/unlink", "/account/spaces/recover"] {
            let (_d, app, _, sid) = fixture().await;
            let proof = json!({"space_id":sid,"owner_credential":OWNER});
            assert_eq!(
                action(&app, "/account/spaces/claim", proof.clone())
                    .await
                    .status,
                200
            );
            app.db.batch(vec![
                Statement::new("INSERT INTO oauth_families SELECT 'family','client','http://127.0.0.1:8787/mcp','space','account_test',space_id,default_actor_id,default_consumer_id,0,9223372036854775807,NULL FROM spaces WHERE space_id=?",vec![sid.clone().into()]),
                Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at,credential_kind) SELECT 'oauth',randomblob(32),space_id,default_actor_id,default_consumer_id,0,'oauth' FROM spaces WHERE space_id=?",vec![sid.clone().into()]),
                Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at,credential_kind) SELECT 'orphan',randomblob(32),space_id,default_actor_id,default_consumer_id,0,'oauth' FROM spaces WHERE space_id=?",vec![sid.clone().into()]),
                Statement::new("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at) SELECT 'legacy',randomblob(32),space_id,default_actor_id,default_consumer_id,0 FROM spaces WHERE space_id=?",vec![sid.clone().into()]),
                Statement::new("INSERT INTO oauth_access_tokens VALUES('oauth','family')",vec![]),
                Statement::new("INSERT INTO oauth_refresh_tokens VALUES(randomblob(32),'family',9223372036854775807,1,'consumed')",vec![]),
                Statement::new("INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,status,created_at,expires_at,next_poll_at,account_id,space_id) SELECT value,'code','client','http://127.0.0.1:8787/mcp','space',value,0,9223372036854775807,0,'account_test',? FROM json_each('[\"pending\",\"approved\",\"consumed\"]')",vec![sid.clone().into()]),
            ]).await.unwrap();
            assert_eq!(
                action(
                    &app,
                    path,
                    json!({"space_id":sid,"owner_credential":"wrong"})
                )
                .await
                .status,
                403
            );
            let rows = app
                .db
                .query(Statement::new(
                    "SELECT count(*) AS n FROM oauth_families WHERE revoked_at IS NULL",
                    vec![],
                ))
                .await
                .unwrap();
            assert_eq!(integer(&rows[0], "n").unwrap(), 1);
            assert_eq!(action(&app, path, proof.clone()).await.status, 200);
            assert_eq!(
                action(&app, "/account/spaces/claim", proof).await.status,
                200
            );
            let rows=app.db.query(Statement::new("SELECT (SELECT count(*) FROM oauth_families WHERE revoked_at IS NULL) AS families,(SELECT count(*) FROM tokens WHERE token_id IN('oauth','orphan') AND revoked_at IS NULL) AS oauth,(SELECT count(*) FROM tokens WHERE token_id='legacy' AND revoked_at IS NULL) AS legacy,(SELECT count(*) FROM oauth_requests WHERE status='denied') AS denied,(SELECT count(*) FROM oauth_requests WHERE status='consumed') AS consumed,(SELECT count(*) FROM oauth_refresh_tokens WHERE used_at=1) AS history",vec![])).await.unwrap();
            for (column, expected) in [
                ("families", 0),
                ("oauth", 0),
                ("legacy", 1),
                ("denied", 2),
                ("consumed", 1),
                ("history", 1),
            ] {
                assert_eq!(
                    integer(&rows[0], column).unwrap(),
                    expected,
                    "{path}: {column}"
                );
            }
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn claim_requires_both_proofs_and_unlink_preserves_legacy_owner() {
        let (_d, app, _, sid) = fixture().await;
        assert_eq!(
            action(
                &app,
                "/account/spaces/claim",
                json!({"space_id":sid,"owner_credential":"wrong"})
            )
            .await
            .status,
            403
        );
        let mut missing = request(
            &app,
            "/account/spaces/claim",
            json!({"space_id":sid,"owner_credential":OWNER}),
        );
        missing.headers.remove("x-waypost-csrf");
        assert_eq!(app.handle(missing).await.status, 403);
        assert_eq!(
            action(
                &app,
                "/account/spaces/claim",
                json!({"space_id":sid,"owner_credential":OWNER})
            )
            .await
            .status,
            200
        );
        assert_eq!(
            action(
                &app,
                "/account/spaces/claim",
                json!({"space_id":sid,"owner_credential":OWNER})
            )
            .await
            .status,
            403
        );
        assert_eq!(
            action(&app, "/account/spaces/select", json!({"space_id":sid}))
                .await
                .status,
            200
        );
        let mut admin = request(&app, "/admin/v0/spaces", json!({}));
        admin.method = "GET".into();
        assert_eq!(app.handle(admin).await.status, 200);
        assert_eq!(
            action(
                &app,
                "/admin/v0/spaces",
                json!({"request_id":"forbidden","display_name":"x"})
            )
            .await
            .status,
            403
        );
        assert_eq!(
            action(
                &app,
                "/account/spaces/unlink",
                json!({"space_id":sid,"owner_credential":OWNER})
            )
            .await
            .status,
            200
        );
        let old = app
            .admin_identity(&Request::json("GET", "/admin/v0/spaces", OWNER, json!({})))
            .await
            .unwrap();
        assert_eq!(old, Some(sid));
        assert!(
            app.db
                .query(Statement::new("SELECT * FROM account_spaces", vec![]))
                .await
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn personal_creation_retries_and_agent_ids_are_stable() {
        let (_d, app, _, _) = fixture().await;
        let a = action(
            &app,
            "/account/spaces/create",
            json!({"display_name":"Personal"}),
        )
        .await;
        let b = action(
            &app,
            "/account/spaces/create",
            json!({"display_name":"Personal"}),
        )
        .await;
        assert_eq!(a.status, 200);
        assert_eq!(a.body, b.body);
        let v: Value = serde_json::from_slice(&a.body).unwrap();
        let sid = &v["data"]["space_id"];
        action(&app, "/account/spaces/select", json!({"space_id":sid})).await;
        let input = json!({"request_id":"stable-agent","display_name":"Laptop"});
        let a = action(&app, "/account/agents/create", input.clone()).await;
        let b = action(&app, "/account/agents/create", input).await;
        assert_eq!(a.status, 200);
        assert_eq!(a.body, b.body);
        assert_eq!(
            action(
                &app,
                "/account/agents/create",
                json!({"request_id":"stable-agent","display_name":"Changed"})
            )
            .await
            .status,
            409
        );
        app.db
            .batch(vec![Statement::new(
                "UPDATE accounts SET disabled=1",
                vec![],
            )])
            .await
            .unwrap();
        assert_eq!(
            action(
                &app,
                "/account/agents/create",
                json!({"request_id":"another","display_name":"Laptop"})
            )
            .await
            .status,
            401
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn browser_code_flow_binds_state_nonce_and_consumes_callback_once() {
        let (_d, app, exchange, _) = fixture().await;
        let start = action(&app, "/account/login", json!({})).await;
        assert_eq!(start.status, 200);
        let value: Value = serde_json::from_slice(&start.body).unwrap();
        let url = url::Url::parse(value["data"]["authorization_url"].as_str().unwrap()).unwrap();
        let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let now = app.clock.now_ms() / 1000;
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"RS256","kid":"test"})).unwrap());
        let claims=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://issuer.example","aud":"test-client","sub":"new-subject","nonce":params["nonce"],"iat":now,"exp":now+300})).unwrap());
        let message = format!("{header}.{claims}");
        let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key()).sign(message.as_bytes());
        *exchange.0.borrow_mut() =
            format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let mut callback = Request::json("GET", "/account/callback", "", json!({}));
        callback.headers.remove("authorization");
        callback.query = format!("state={}&code=synthetic-code", params["state"]);
        assert_eq!(app.handle(callback.clone()).await.status, 401);
        callback.headers.insert(
            "cookie".into(),
            start.headers["set-cookie"]
                .split(';')
                .next()
                .unwrap()
                .into(),
        );
        let response = app.handle(callback.clone()).await;
        assert_eq!(
            response.status,
            303,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        assert!(response.headers["set-cookie"].contains("HttpOnly"));
        assert_eq!(app.handle(callback).await.status, 401);
        let count = app
            .db
            .query(Statement::new("SELECT count(*) AS n FROM accounts", vec![]))
            .await
            .unwrap();
        assert_eq!(integer(&count[0], "n").unwrap(), 2);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn emergency_detach_does_not_need_lost_account_session_and_preserves_old_credentials() {
        let (_d, mut app, _, sid) = fixture().await;
        assert_eq!(
            action(
                &app,
                "/account/spaces/claim",
                json!({"space_id":sid,"owner_credential":OWNER})
            )
            .await
            .status,
            200
        );
        app.db.batch(vec![Statement::new("INSERT INTO account_devices(device_id,device_digest,user_digest,code_challenge,display_name,state,created_at,expires_at,next_poll_at,account_id,space_id) VALUES('d',zeroblob(32),zeroblob(32),'challenge','Lost device','approved',0,9223372036854775807,0,'account_test',?)",vec![sid.clone().into()])]).await.unwrap();
        let mut recovery = request(
            &app,
            "/account/spaces/recover",
            json!({"space_id":sid,"owner_credential":OWNER}),
        );
        recovery.headers.remove("cookie");
        recovery.headers.remove("x-waypost-csrf");
        assert_eq!(app.handle(recovery).await.status, 200);
        let row = app
            .db
            .query(Statement::new(
                "SELECT state FROM account_devices WHERE device_id='d'",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(text(&row[0], "state").unwrap(), "revoked");
        assert_eq!(
            action(
                &app,
                "/account/spaces/claim",
                json!({"space_id":sid,"owner_credential":OWNER})
            )
            .await
            .status,
            200
        );
        let old = app
            .admin_identity(&Request::json("GET", "/admin/v0/spaces", OWNER, json!({})))
            .await
            .unwrap();
        assert_eq!(old, Some(sid));
        app.oidc = None;
        assert_eq!(action(&app, "/account/login", json!({})).await.status, 404);
        assert_eq!(
            action(&app, "/account/devices/start", json!({}))
                .await
                .status,
            404
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn native_http_login_callback_and_private_session_roundtrip() {
        tokio::task::LocalSet::new().run_until(async {
            let (_d,mut app,exchange,_)=fixture().await;
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin=format!("http://{}",listener.local_addr().unwrap());
            app.config.public_origin=origin.clone();
            let handle=tokio::task::spawn_local(crate::native::server::serve(listener,Rc::new(app)));
            let client=reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
            let start=client.post(format!("{origin}/account/login")).header("origin",&origin).header("content-type","application/json").body("{}").send().await.unwrap();
            assert_eq!(start.status(),200);
            let cookie=start.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
            let body:Value=serde_json::from_slice(&start.bytes().await.unwrap()).unwrap();
            let url=url::Url::parse(body["data"]["authorization_url"].as_str().unwrap()).unwrap();
            let params:BTreeMap<_,_>=url.query_pairs().into_owned().collect();
            let now=SystemClock.now_ms()/1000;
            let header=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":"RS256","kid":"test"})).unwrap());
            let claims=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://issuer.example","aud":"test-client","sub":"http-user","nonce":params["nonce"],"iat":now,"exp":now+300})).unwrap());
            let message=format!("{header}.{claims}");let sig=rsa::pkcs1v15::SigningKey::<Sha256>::new(key()).sign(message.as_bytes());
            *exchange.0.borrow_mut()=format!("{message}.{}",URL_SAFE_NO_PAD.encode(sig.to_bytes()));
            let callback=client.get(format!("{origin}/account/callback?state={}&code=synthetic",params["state"])).header("cookie",cookie).send().await.unwrap();
            assert_eq!(callback.status(),303);
            let cookie=callback.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
            let session=client.get(format!("{origin}/account/session")).header("cookie",&cookie).send().await.unwrap();
            assert_eq!(session.status(),200);assert_eq!(session.headers()["cache-control"],"no-store");
            let session:Value=serde_json::from_slice(&session.bytes().await.unwrap()).unwrap();assert!(session["data"]["account_id"].as_str().unwrap().starts_with("account_"));
            let response=client.post(format!("{origin}/account/spaces/create")).header("origin",&origin).header("cookie",cookie).header("x-waypost-csrf",session["data"]["csrf_token"].as_str().unwrap()).header("content-type","application/json").body(json!({"display_name":"HTTP personal space"}).to_string()).send().await.unwrap();
            assert_eq!(response.status(),200);handle.abort();
        }).await;
    }
}
