//! The keys product (keyenv-remote): a personal secret store served through the
//! shared MCP gateway and OAuth server. Space, Actor, invitation and memory
//! models stay in Waypost; this module only reuses accounts and OAuth.
use super::*;
use crate::gateway::oauth_client::ClientDocument;
use crate::json::fields;
use crate::storage::driver::optional_text;
mod crypto;
#[cfg(all(test, feature = "native"))]
mod tests;
mod tools;
pub(crate) use tools::KeysTools;

/// Request body ceiling for the keys product: one entry may carry 64 fields of
/// up to 64 KiB each in keyenv, but a single write is capped at 256 KiB.
pub(crate) const MAX_JSON_BYTES: usize = 262_144;
/// Path of the metadata document for this deployment's own CLI client.
pub(crate) const CLI_DOCUMENT_PATH: &str = "/oauth/clients/keyenv-remote.json";
const CLI_REDIRECT: &str = "http://127.0.0.1/callback";
pub(crate) const MAX_ENTRIES: i64 = 500;

pub struct KeysConfig {
    pub(crate) keyring: crypto::Keyring,
}

impl<D: Database, O: ObjectStore> App<D, O> {
    /// Serve the keys product. Requires accounts; the keyring JSON has the shape
    /// `{"active":"k1","keys":{"k1":"<64 hex>"}}`.
    pub fn with_keys(mut self, keyring: &str) -> Result<Self> {
        if self.oidc.is_none() {
            return Err(Error::invalid("The keys product requires account sign-in."));
        }
        self.keys = Some(KeysConfig {
            keyring: crypto::Keyring::parse(keyring)?,
        });
        self.limits.max_json_bytes = MAX_JSON_BYTES;
        Ok(self)
    }
    pub(crate) fn keys_config(&self) -> Result<&KeysConfig> {
        self.keys.as_ref().ok_or_else(Error::not_found)
    }
    fn cli_document_url(&self) -> String {
        format!("{}{CLI_DOCUMENT_PATH}", self.config.public_origin)
    }
    pub(super) fn hosted_client_id(&self) -> Option<String> {
        self.keys.is_some().then(|| self.cli_document_url())
    }
    pub(super) fn hosted_client_document(&self, id: &str) -> Option<ClientDocument> {
        (self.keys.is_some() && id == self.cli_document_url()).then(|| ClientDocument {
            client_name: "keyenv-remote".into(),
            redirect_uris: vec![CLI_REDIRECT.into()],
        })
    }
    pub(super) fn hosted_client_document_json(&self, path: &str) -> Option<Value> {
        (self.keys.is_some() && path == CLI_DOCUMENT_PATH).then(|| {
            json!({"client_id":self.cli_document_url(),"client_name":"keyenv-remote","client_uri":self.config.public_origin,"redirect_uris":[CLI_REDIRECT],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"})
        })
    }

    /// Routing for a keys deployment. Waypost routes are not reachable here.
    pub(super) async fn keys_handle(&self, request: Request) -> Response {
        let path = request.path.as_str();
        if path == "/health" && request.method == "GET" {
            return Response::json(
                200,
                json!({"ok":true,"data":{"status":"ok","product":"keys"}}),
            );
        }
        if path.starts_with("/oauth/") || path.starts_with("/.well-known/oauth-") {
            return self.oauth_handle(&request).await;
        }
        if path == "/mcp" {
            let mut response = crate::gateway::mcp::serve(
                &KeysTools(self),
                &self.config.public_origin,
                self.limits.max_json_bytes,
                &request,
            )
            .await;
            self.oauth_challenge(&mut response);
            return response;
        }
        if request.method == "GET"
            && matches!(
                path,
                "/" | "/account" | "/account/app.js" | "/account/app.css"
            )
        {
            return keys_page(path);
        }
        if path.starts_with("/account/keys/") {
            let mut response = match self.keys_account_action(&request).await {
                Ok(data) => Response::json(200, json!({"ok":true,"data":data})),
                Err(e) => Response::json(e.status(), json!({"ok":false,"error":e.value()})),
            };
            response
                .headers
                .insert("referrer-policy".into(), "no-referrer".into());
            return response;
        }
        if matches!(
            path,
            "/account/login" | "/account/callback" | "/account/session"
        ) {
            return self.account_handle(&request).await;
        }
        Response::json(404, json!({"ok":false,"error":Error::not_found().value()}))
    }

    /// Owner-side grant management: list and revoke connections.
    async fn keys_account_action(&self, r: &Request) -> Result<Value> {
        let session = self.account_session(r, r.method != "GET").await?;
        let account = text(&session, "account_id")?;
        let now = self.clock.now_ms();
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/account/keys/grants") => {
                let rows = self.db.query(Statement::new("SELECT f.family_id,f.client_id,f.scope,f.created_at,k.can_create,k.all_read,k.all_write,(SELECT json_group_array(json_object('name',e.name,'read',c.can_read,'write',c.can_write)) FROM key_consent_entries c JOIN key_entries e ON e.entry_id=c.entry_id WHERE c.request_id=f.request_id) AS entries FROM key_oauth_families f JOIN key_consents k ON k.request_id=f.request_id WHERE f.account_id=? AND f.revoked_at IS NULL AND f.expires_at>? ORDER BY f.created_at DESC LIMIT 100",vec![account.into(),now.into()])).await?;
                let grants = rows
                    .iter()
                    .map(|row| {
                        Ok(json!({
                            "grant_id": text(row, "family_id")?,
                            "client_id": text(row, "client_id")?,
                            "scope": text(row, "scope")?,
                            "created_at": stamp(integer(row, "created_at")?)?,
                            "can_create": integer(row, "can_create")? == 1,
                            "all_read": integer(row, "all_read")? == 1,
                            "all_write": integer(row, "all_write")? == 1,
                            "entries": serde_json::from_str::<Value>(&text(row, "entries")?).map_err(|_| Error::internal("decode grant entries"))?,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(json!({"grants":grants}))
            }
            ("POST", "/account/keys/grants/revoke") => {
                let body = crate::json::parse(&r.body, 4096)?;
                fields(&body, &["grant_id"])?;
                let id = crate::json::required(&body, "grant_id")?;
                let rows = self.db.batch(vec![Statement::new("UPDATE key_oauth_families SET revoked_at=COALESCE(revoked_at,?) WHERE family_id=? AND account_id=? RETURNING family_id",vec![now.into(),id.into(),account.into()])]).await?;
                if rows[0].is_empty() {
                    return Err(Error::not_found());
                }
                Ok(json!({"revoked":true}))
            }
            _ => Err(Error::not_found()),
        }
    }

    /// Consent page data: the account's own entry metadata, never values.
    pub(super) async fn keys_consent_view(&self, session: &Row) -> Result<Value> {
        let account = text(session, "account_id")?;
        let rows = self.db.query(Statement::new("SELECT e.name,e.purpose,e.disabled,e.expires,(SELECT json_group_array(name) FROM (SELECT name FROM key_fields WHERE entry_id=e.entry_id ORDER BY name)) AS fields FROM key_entries e WHERE e.account_id=? ORDER BY e.name LIMIT ?",vec![account.into(),MAX_ENTRIES.into()])).await?;
        let entries = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "name": text(row, "name")?,
                    "purpose": text(row, "purpose")?,
                    "disabled": integer(row, "disabled")? == 1,
                    "expires": optional_text(row, "expires"),
                    "fields": serde_json::from_str::<Value>(&text(row, "fields")?).map_err(|_| Error::internal("decode field names"))?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({"entries":entries}))
    }

    /// Approve a keys authorization request: bind it to the signed-in account and
    /// the exact entry permissions chosen on the consent page, in one batch.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn keys_commit_consent(
        &self,
        id: &str,
        account: &str,
        cookie: &str,
        code: &str,
        browser: Sql,
        body: &Value,
        now: i64,
    ) -> Result<()> {
        let invalid = || super::oauth::oauth_error("invalid_request");
        let flag = |key: &str| -> Result<i64> {
            match body.get(key) {
                None => Ok(0),
                Some(Value::Bool(b)) => Ok(i64::from(*b)),
                Some(_) => Err(invalid()),
            }
        };
        let (can_create, all_read, all_write) =
            (flag("can_create")?, flag("all_read")?, flag("all_write")?);
        let mut selected = vec![];
        if let Some(list) = body.get("entries") {
            let list = list.as_array().ok_or_else(invalid)?;
            if list.len() > MAX_ENTRIES as usize {
                return Err(invalid());
            }
            for item in list {
                fields(item, &["name", "read", "write"]).map_err(|_| invalid())?;
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?;
                tools::check_name(name).map_err(|_| invalid())?;
                let bit = |k: &str| match item.get(k) {
                    None => Ok(0),
                    Some(Value::Bool(b)) => Ok(i64::from(*b)),
                    Some(_) => Err(invalid()),
                };
                let (read, write) = (bit("read")?, bit("write")?);
                if read + write > 0 {
                    selected.push(json!({"name":name,"read":read,"write":write}));
                }
            }
        }
        if can_create + all_read + all_write == 0 && selected.is_empty() {
            return Err(invalid());
        }
        let active = "EXISTS(SELECT 1 FROM account_sessions s JOIN accounts a ON a.account_id=s.account_id WHERE s.session_digest=? AND s.account_id=? AND s.expires_at>? AND s.created_at>=? AND a.disabled=0)";
        let cookie_digest: Sql = Sha256::digest(cookie.as_bytes()).to_vec().into();
        let code_digest: Sql = Sha256::digest(code.as_bytes()).to_vec().into();
        let rows = self.db.batch(vec![
            Statement::new(format!("UPDATE oauth_requests SET status='approved',account_id=?,approved_at=?,code_digest=?,expires_at=MIN(expires_at,?) WHERE request_id=? AND status='pending' AND expires_at>? AND kind='code' AND browser_digest=? AND {active} RETURNING request_id"),vec![account.into(),now.into(),code_digest.clone(),(now+120_000).into(),id.into(),now.into(),browser,cookie_digest,account.into(),now.into(),(now-900_000).into()]),
            Statement::new("INSERT INTO key_consents(request_id,account_id,can_create,all_read,all_write,created_at) SELECT request_id,account_id,?,?,?,? FROM oauth_requests WHERE request_id=? AND status='approved' AND account_id=? AND code_digest=?",vec![can_create.into(),all_read.into(),all_write.into(),now.into(),id.into(),account.into(),code_digest]),
            Statement::new("INSERT INTO key_consent_entries(request_id,entry_id,can_read,can_write) SELECT k.request_id,e.entry_id,json_extract(j.value,'$.read'),json_extract(j.value,'$.write') FROM json_each(?) j JOIN key_consents k ON k.request_id=? JOIN key_entries e ON e.account_id=k.account_id AND e.name=json_extract(j.value,'$.name')",vec![Value::Array(selected).to_string().into(),id.into()]),
        ]).await?;
        if rows[0].is_empty() {
            return Err(super::oauth::oauth_error("access_denied"));
        }
        Ok(())
    }
}

fn keys_page(path: &str) -> Response {
    let mut out = Response::json(200, json!(null));
    if path == "/account/app.css" {
        out.body = include_bytes!("../../../dashboard/keys.css").to_vec();
        out.headers
            .insert("content-type".into(), "text/css; charset=utf-8".into());
    } else if path == "/account/app.js" {
        out.body = include_bytes!("../../../dashboard/keys.js").to_vec();
        out.headers.insert(
            "content-type".into(),
            "text/javascript; charset=utf-8".into(),
        );
    } else {
        out.body = include_bytes!("../../../dashboard/keys.html").to_vec();
        out.headers
            .insert("content-type".into(), "text/html; charset=utf-8".into());
        out.headers.insert("content-security-policy".into(),"default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".into());
    }
    out.headers
        .insert("referrer-policy".into(), "no-referrer".into());
    out
}
