//! MCP tools of the keys product. Contract: only `fetch_entry` returns values;
//! write tools return success, the entry name and field names, never values.
//! Error messages name entries and fields at most, never values.
use super::crypto::Sealed;
use super::*;
use crate::gateway::mcp::{ServerInfo, ToolCatalog, ToolSpec, schema};
use zeroize::Zeroizing;

const MAX_FIELDS: usize = 64;
const MAX_VALUE_BYTES: usize = 65_536;
const MAX_PURPOSE_BYTES: usize = 2048;

pub(crate) struct KeysPrincipal {
    family_id: String,
    account_id: String,
    client_id: String,
    request_id: String,
    read: bool,
    write: bool,
    can_create: bool,
    all_read: bool,
    all_write: bool,
}

struct EntryAccess {
    entry_id: String,
    name: String,
    disabled: bool,
    expires: Option<String>,
    readable: bool,
    writable: bool,
}

/// Same rules as local keyenv entries, so `keyenv-remote import` round-trips.
pub(crate) fn check_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    if b.is_empty()
        || b.len() > 80
        || !b[0].is_ascii_lowercase()
        || !b
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"/_-".contains(c))
    {
        return Err(Error::invalid(
            "Entry names use lowercase letters, digits, '/', '_' or '-' and start with a letter (max 80).",
        ));
    }
    Ok(())
}
fn check_field_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    if b.is_empty()
        || b.len() > 128
        || !(b[0].is_ascii_alphabetic() || b[0] == b'_')
        || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
    {
        return Err(Error::invalid(
            "Field names must be environment variable names (max 128).",
        ));
    }
    Ok(())
}
fn check_expires(value: &str) -> Result<()> {
    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .filter(|d| d.format("%Y-%m-%d").to_string() == value)
        .map(|_| ())
        .ok_or_else(|| Error::invalid("expires must be a YYYY-MM-DD date."))
}
fn check_purpose(value: &str) -> Result<()> {
    if value.len() > MAX_PURPOSE_BYTES || value.contains('\0') {
        return Err(Error::invalid("purpose is too long."));
    }
    Ok(())
}
/// Parse `{FIELD: value}` without ever placing a value in an error.
fn field_values(value: Option<&Value>) -> Result<Vec<(String, Zeroizing<String>)>> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let object = value
        .as_object()
        .ok_or_else(|| Error::invalid("fields must be an object of field name to string value."))?;
    if object.len() > MAX_FIELDS {
        return Err(Error::invalid("An entry has at most 64 fields."));
    }
    let mut out = vec![];
    for (name, v) in object {
        check_field_name(name)?;
        let Some(v) = v.as_str() else {
            return Err(Error::invalid(format!("Field {name} must be a string.")));
        };
        if v.len() > MAX_VALUE_BYTES || v.contains('\0') {
            return Err(Error::invalid(format!(
                "Field {name} is longer than 65536 bytes or contains NUL."
            )));
        }
        out.push((name.clone(), Zeroizing::new(v.to_owned())));
    }
    Ok(out)
}
fn string_list(value: Option<&Value>, what: &str) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let list = value
        .as_array()
        .filter(|l| l.len() <= MAX_FIELDS)
        .ok_or_else(|| Error::invalid(format!("{what} must be a list of field names.")))?;
    let mut out: Vec<String> = vec![];
    for item in list {
        let name = item
            .as_str()
            .ok_or_else(|| Error::invalid(format!("{what} must be a list of field names.")))?;
        check_field_name(name)?;
        if !out.iter().any(|n| n == name) {
            out.push(name.to_owned());
        }
    }
    Ok(out)
}
fn optional_string<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(Error::invalid(format!("{key} must be a string."))),
    }
}
fn entry_not_found() -> Error {
    Error::new(
        "ENTRY_NOT_FOUND",
        "No entry with this name is available to this connection.",
    )
}

pub(crate) struct KeysTools<'a, D, O>(pub(crate) &'a App<D, O>);

impl<D: Database, O: ObjectStore> ToolCatalog for KeysTools<'_, D, O> {
    type Principal = KeysPrincipal;
    fn server(&self) -> ServerInfo {
        ServerInfo {
            name: "keyenv-remote",
            instructions: "Personal secret store. Call list_entries first and ask the user when a name is ambiguous. fetch_entry returns secret values: write them straight to a private 0600 file outside version control and refer to the path and field names only; never repeat values in replies, commits, logs or command arguments. create_entry and update_entry never return values; do not repeat values the user gave you.",
        }
    }
    fn tools(&self) -> Vec<ToolSpec> {
        let s = json!({"type":"string"});
        let names = json!({"type":"array","items":{"type":"string"},"maxItems":MAX_FIELDS});
        let values = json!({"type":"object","additionalProperties":{"type":"string"},"maxProperties":MAX_FIELDS});
        let expires =
            json!({"type":["string","null"],"description":"YYYY-MM-DD, or null to clear"});
        vec![
            ToolSpec {
                name: "list_entries",
                description: "List entries this connection may use: names, purposes and field names only, plus whether each is readable or writable here. Never returns values.",
                input_schema: schema(json!({}), &[]),
                read_only: true,
            },
            ToolSpec {
                name: "fetch_entry",
                description: "Return the secret values of one entry (optionally only some fields). The result contains secrets: save it to a private 0600 file and do not repeat it.",
                input_schema: schema(json!({"name":s,"fields":names}), &["name"]),
                read_only: true,
            },
            ToolSpec {
                name: "create_entry",
                description: "Create an entry with string fields. The result lists field names only and never echoes values.",
                input_schema: schema(
                    json!({"name":s,"purpose":s,"expires":expires,"fields":values}),
                    &["name", "fields"],
                ),
                read_only: false,
            },
            ToolSpec {
                name: "update_entry",
                description: "Set or remove fields, or change purpose/expiry, of an entry this connection may write. The result lists field names only and never echoes values.",
                input_schema: schema(
                    json!({"name":s,"set_fields":values,"remove_fields":names,"purpose":s,"expires":expires}),
                    &["name"],
                ),
                read_only: false,
            },
            ToolSpec {
                name: "disable_entry",
                description: "Disable (or re-enable with disabled=false) an entry this connection may write. Disabled entries cannot be fetched.",
                input_schema: schema(json!({"name":s,"disabled":{"type":"boolean"}}), &["name"]),
                read_only: false,
            },
        ]
    }
    async fn authenticate(&self, request: &Request) -> Result<KeysPrincipal> {
        self.0.keys_authenticate(request).await
    }
    async fn call(&self, p: &KeysPrincipal, name: &str, args: Value) -> Result<Value> {
        let app = self.0;
        match name {
            "list_entries" => {
                fields(&args, &[])?;
                app.keys_list(p).await
            }
            "fetch_entry" => {
                fields(&args, &["name", "fields"])?;
                app.keys_fetch(p, &args).await
            }
            "create_entry" => {
                fields(&args, &["name", "purpose", "expires", "fields"])?;
                app.keys_create(p, &args).await
            }
            "update_entry" => {
                fields(
                    &args,
                    &["name", "set_fields", "remove_fields", "purpose", "expires"],
                )?;
                app.keys_update(p, &args).await
            }
            "disable_entry" => {
                fields(&args, &["name", "disabled"])?;
                app.keys_disable(p, &args).await
            }
            _ => Err(Error::not_found()),
        }
    }
}

impl<D: Database, O: ObjectStore> App<D, O> {
    pub(crate) async fn keys_authenticate(&self, request: &Request) -> Result<KeysPrincipal> {
        let token = bearer(request)?;
        let now = self.clock.now_ms();
        let (clients, client_parameters) = self.client_guard("f.client_id");
        let mut parameters: Vec<Sql> = vec![
            Sha256::digest(token.as_bytes()).to_vec().into(),
            now.into(),
            now.into(),
            self.oauth_resource().into(),
        ];
        parameters.extend(client_parameters);
        let rows = self.db.query(Statement::new(format!("SELECT f.family_id,f.account_id,f.client_id,f.request_id,f.scope,k.can_create,k.all_read,k.all_write FROM key_access_tokens t JOIN key_oauth_families f ON f.family_id=t.family_id JOIN key_consents k ON k.request_id=f.request_id AND k.account_id=f.account_id JOIN accounts a ON a.account_id=f.account_id WHERE t.token_digest=? AND t.expires_at>? AND f.revoked_at IS NULL AND f.expires_at>? AND f.resource=? AND a.disabled=0 AND {clients}"),parameters)).await?;
        let row = rows.first().ok_or_else(Error::unauthenticated)?;
        let scope = text(row, "scope")?;
        let scopes: Vec<_> = scope.split(' ').collect();
        Ok(KeysPrincipal {
            family_id: text(row, "family_id")?,
            account_id: text(row, "account_id")?,
            client_id: text(row, "client_id")?,
            request_id: text(row, "request_id")?,
            read: scopes.contains(&"keys:read"),
            write: scopes.contains(&"keys:write"),
            can_create: integer(row, "can_create")? == 1,
            all_read: integer(row, "all_read")? == 1,
            all_write: integer(row, "all_write")? == 1,
        })
    }
    /// SQL guard re-checked inside every write batch: the grant is still live.
    fn keys_live(&self, p: &KeysPrincipal) -> (&'static str, Vec<Sql>) {
        (
            "EXISTS(SELECT 1 FROM key_oauth_families f JOIN accounts a ON a.account_id=f.account_id WHERE f.family_id=? AND f.revoked_at IS NULL AND f.expires_at>? AND a.disabled=0)",
            vec![p.family_id.clone().into(), self.clock.now_ms().into()],
        )
    }
    fn keys_audit(
        &self,
        p: &KeysPrincipal,
        action: &str,
        name: &str,
        guard: &str,
    ) -> Result<Statement> {
        Ok(Statement::new(
            format!(
                "INSERT INTO key_audit(event_id,account_id,family_id,client_id,action,entry_name,created_at) SELECT ?,?,?,?,?,?,? WHERE {guard}"
            ),
            vec![
                random_id("keyevent")?.into(),
                p.account_id.clone().into(),
                p.family_id.clone().into(),
                p.client_id.clone().into(),
                action.into(),
                name.into(),
                self.clock.now_ms().into(),
            ],
        ))
    }
    async fn keys_entry(&self, p: &KeysPrincipal, name: &str) -> Result<EntryAccess> {
        check_name(name)?;
        let rows = self.db.query(Statement::new("SELECT e.entry_id,e.name,e.disabled,e.expires,COALESCE(c.can_read,0) AS can_read,COALESCE(c.can_write,0) AS can_write FROM key_entries e LEFT JOIN key_consent_entries c ON c.request_id=? AND c.entry_id=e.entry_id WHERE e.account_id=? AND e.name=?",vec![p.request_id.clone().into(),p.account_id.clone().into(),name.into()])).await?;
        let row = rows.first().ok_or_else(entry_not_found)?;
        let access = EntryAccess {
            entry_id: text(row, "entry_id")?,
            name: text(row, "name")?,
            disabled: integer(row, "disabled")? == 1,
            expires: optional_text(row, "expires"),
            readable: p.read && (p.all_read || integer(row, "can_read")? == 1),
            writable: p.write && (p.all_write || integer(row, "can_write")? == 1),
        };
        // Entries outside this grant are indistinguishable from missing ones.
        if !access.readable && !access.writable {
            return Err(entry_not_found());
        }
        Ok(access)
    }
    async fn keys_list(&self, p: &KeysPrincipal) -> Result<Value> {
        let rows = self.db.query(Statement::new("SELECT e.name,e.purpose,e.disabled,e.expires,COALESCE(c.can_read,0) AS can_read,COALESCE(c.can_write,0) AS can_write,(SELECT json_group_array(name) FROM (SELECT name FROM key_fields WHERE entry_id=e.entry_id ORDER BY name)) AS fields FROM key_entries e LEFT JOIN key_consent_entries c ON c.request_id=? AND c.entry_id=e.entry_id WHERE e.account_id=? ORDER BY e.name LIMIT ?",vec![p.request_id.clone().into(),p.account_id.clone().into(),MAX_ENTRIES.into()])).await?;
        let mut entries = vec![];
        for row in &rows {
            let readable = p.read && (p.all_read || integer(row, "can_read")? == 1);
            let writable = p.write && (p.all_write || integer(row, "can_write")? == 1);
            if !readable && !writable {
                continue;
            }
            entries.push(json!({
                "name": text(row, "name")?,
                "purpose": text(row, "purpose")?,
                "fields": serde_json::from_str::<Value>(&text(row, "fields")?).map_err(|_| Error::internal("decode field names"))?,
                "disabled": integer(row, "disabled")? == 1,
                "expires": optional_text(row, "expires"),
                "readable": readable,
                "writable": writable,
            }));
        }
        Ok(json!({"entries":entries,"can_create":p.write && p.can_create}))
    }
    async fn keys_fetch(&self, p: &KeysPrincipal, args: &Value) -> Result<Value> {
        let name = crate::json::required(args, "name")?;
        let entry = self.keys_entry(p, &name).await?;
        if !entry.readable {
            return Err(Error::new(
                "READ_NOT_GRANTED",
                "This connection may not read this entry.",
            ));
        }
        if entry.disabled {
            return Err(Error::new("ENTRY_DISABLED", "This entry is disabled."));
        }
        if let Some(expires) = &entry.expires {
            let today = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(self.clock.now_ms())
                .ok_or_else(Error::storage)?
                .format("%Y-%m-%d")
                .to_string();
            if expires.as_str() < today.as_str() {
                return Err(Error::new("ENTRY_EXPIRED", "This entry has expired."));
            }
        }
        let wanted = string_list(args.get("fields"), "fields")?;
        let rows = self
            .db
            .query(Statement::new(
                "SELECT name,kid,nonce,ciphertext FROM key_fields WHERE entry_id=? ORDER BY name",
                vec![entry.entry_id.clone().into()],
            ))
            .await?;
        let keyring = &self.keys_config()?.keyring;
        let mut values = serde_json::Map::new();
        for row in &rows {
            let field = text(row, "name")?;
            if !wanted.is_empty() && !wanted.contains(&field) {
                continue;
            }
            let sealed = Sealed {
                kid: text(row, "kid")?,
                nonce: text(row, "nonce")?,
                ciphertext: text(row, "ciphertext")?,
            };
            let plain = keyring.open(&p.account_id, &entry.entry_id, &field, &sealed)?;
            values.insert(field, Value::String(plain.to_string()));
        }
        if let Some(missing) = wanted.iter().find(|f| !values.contains_key(*f)) {
            return Err(Error::new(
                "FIELD_NOT_FOUND",
                format!("Entry {name} has no field {missing}."),
            ));
        }
        let (guard, guard_args) = self.keys_live(p);
        let mut audit = self.keys_audit(p, "fetch", &entry.name, guard)?;
        audit.parameters.extend(guard_args);
        let written = self.db.batch(vec![audit]).await;
        // Never hand out values whose access could not be recorded.
        written?;
        self.current_keys_grant(p).await?;
        Ok(json!({"name":entry.name,"fields":values}))
    }
    async fn current_keys_grant(&self, p: &KeysPrincipal) -> Result<()> {
        let (guard, args) = self.keys_live(p);
        let rows = self
            .db
            .query(Statement::new(
                format!("SELECT 1 AS ok WHERE {guard}"),
                args,
            ))
            .await?;
        if rows.is_empty() {
            return Err(Error::unauthenticated());
        }
        Ok(())
    }
    fn sealed_json(
        &self,
        p: &KeysPrincipal,
        entry_id: &str,
        values: &[(String, Zeroizing<String>)],
    ) -> Result<String> {
        let keyring = &self.keys_config()?.keyring;
        let mut out = vec![];
        for (field, value) in values {
            let sealed = keyring.seal(&p.account_id, entry_id, field, value)?;
            out.push(
                json!({"name":field,"kid":sealed.kid,"nonce":sealed.nonce,"ct":sealed.ciphertext}),
            );
        }
        Ok(Value::Array(out).to_string())
    }
    async fn keys_create(&self, p: &KeysPrincipal, args: &Value) -> Result<Value> {
        if !(p.write && p.can_create) {
            return Err(Error::new(
                "CREATE_NOT_GRANTED",
                "This connection may not create entries.",
            ));
        }
        let name = crate::json::required(args, "name")?;
        check_name(&name)?;
        let purpose = optional_string(args, "purpose")?
            .unwrap_or_default()
            .to_owned();
        check_purpose(&purpose)?;
        let expires = match args.get("expires") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                check_expires(s)?;
                Some(s.clone())
            }
            Some(_) => return Err(Error::invalid("expires must be a YYYY-MM-DD date or null.")),
        };
        let values = field_values(args.get("fields"))?;
        if values.is_empty() {
            return Err(Error::invalid("An entry needs at least one field."));
        }
        let now = self.clock.now_ms();
        let entry_id = random_id("entry")?;
        let nonce = random_id("write")?;
        let sealed = self.sealed_json(p, &entry_id, &values)?;
        let (live, live_args) = self.keys_live(p);
        let written = "EXISTS(SELECT 1 FROM key_entries WHERE entry_id=? AND write_nonce=?)";
        let mut first = vec![
            entry_id.clone().into(),
            p.account_id.clone().into(),
            name.clone().into(),
            purpose.into(),
            expires.into(),
            now.into(),
            now.into(),
            nonce.clone().into(),
        ];
        first.extend(live_args);
        first.extend([
            p.account_id.clone().into(),
            MAX_ENTRIES.into(),
            p.account_id.clone().into(),
            name.clone().into(),
        ]);
        let mut audit = self.keys_audit(p, "create", &name, written)?;
        audit
            .parameters
            .extend([entry_id.clone().into(), nonce.clone().into()]);
        let rows = self.db.batch(vec![
            Statement::new(format!("INSERT INTO key_entries(entry_id,account_id,name,purpose,disabled,expires,created_at,updated_at,write_nonce) SELECT ?,?,?,?,0,?,?,?,? WHERE {live} AND (SELECT count(*) FROM key_entries WHERE account_id=?)<? AND NOT EXISTS(SELECT 1 FROM key_entries WHERE account_id=? AND name=?) RETURNING entry_id"),first),
            Statement::new(format!("INSERT INTO key_fields(entry_id,name,kid,nonce,ciphertext,updated_at) SELECT ?,json_extract(j.value,'$.name'),json_extract(j.value,'$.kid'),json_extract(j.value,'$.nonce'),json_extract(j.value,'$.ct'),? FROM json_each(?) j WHERE {written}"),vec![entry_id.clone().into(),now.into(),sealed.into(),entry_id.clone().into(),nonce.clone().into()]),
            // The creating connection can always read and change what it created.
            Statement::new(format!("INSERT INTO key_consent_entries(request_id,entry_id,can_read,can_write) SELECT ?,?,1,1 WHERE {written}"),vec![p.request_id.clone().into(),entry_id.clone().into(),entry_id.clone().into(),nonce.clone().into()]),
            audit,
        ]).await?;
        if rows[0].is_empty() {
            self.current_keys_grant(p).await?;
            return Err(Error::new(
                "ENTRY_EXISTS",
                "An entry with this name already exists, or the entry limit was reached.",
            ));
        }
        let mut names: Vec<_> = values.iter().map(|(n, _)| n.clone()).collect();
        names.sort();
        Ok(json!({"created":true,"name":name,"fields":names}))
    }
    async fn keys_update(&self, p: &KeysPrincipal, args: &Value) -> Result<Value> {
        let name = crate::json::required(args, "name")?;
        let entry = self.keys_entry(p, &name).await?;
        if !entry.writable {
            return Err(Error::new(
                "WRITE_NOT_GRANTED",
                "This connection may not change this entry.",
            ));
        }
        let set = field_values(args.get("set_fields"))?;
        let remove = string_list(args.get("remove_fields"), "remove_fields")?;
        let purpose = optional_string(args, "purpose")?;
        if let Some(purpose) = purpose {
            check_purpose(purpose)?;
        }
        let expires = match args.get("expires") {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::String(s)) => {
                check_expires(s)?;
                Some(Some(s.clone()))
            }
            Some(_) => return Err(Error::invalid("expires must be a YYYY-MM-DD date or null.")),
        };
        if set.is_empty() && remove.is_empty() && purpose.is_none() && expires.is_none() {
            return Err(Error::invalid("Nothing to update."));
        }
        if let Some(both) = set.iter().find(|(n, _)| remove.contains(n)) {
            return Err(Error::invalid(format!(
                "Field {} is both set and removed.",
                both.0
            )));
        }
        let rows = self.db.query(Statement::new("SELECT e.write_nonce,(SELECT json_group_array(name) FROM key_fields WHERE entry_id=e.entry_id) AS fields FROM key_entries e WHERE e.entry_id=?",vec![entry.entry_id.clone().into()])).await?;
        let row = rows.first().ok_or_else(entry_not_found)?;
        let previous_nonce = optional_text(row, "write_nonce");
        let mut current: Vec<String> = serde_json::from_str(&text(row, "fields")?)
            .map_err(|_| Error::internal("decode field names"))?;
        if let Some(missing) = remove.iter().find(|f| !current.contains(f)) {
            return Err(Error::new(
                "FIELD_NOT_FOUND",
                format!("Entry {name} has no field {missing}."),
            ));
        }
        current.retain(|f| !remove.contains(f));
        for (field, _) in &set {
            if !current.contains(field) {
                current.push(field.clone());
            }
        }
        if current.is_empty() || current.len() > MAX_FIELDS {
            return Err(Error::invalid("An entry keeps between 1 and 64 fields."));
        }
        current.sort();
        let now = self.clock.now_ms();
        let nonce = random_id("write")?;
        let sealed = self.sealed_json(p, &entry.entry_id, &set)?;
        let (live, live_args) = self.keys_live(p);
        let written = "EXISTS(SELECT 1 FROM key_entries WHERE entry_id=? AND write_nonce=?)";
        let mut first = vec![
            nonce.clone().into(),
            now.into(),
            i64::from(purpose.is_some()).into(),
            purpose.unwrap_or_default().into(),
            i64::from(expires.is_some()).into(),
            expires.flatten().into(),
            entry.entry_id.clone().into(),
            previous_nonce.into(),
        ];
        first.extend(live_args);
        let mut audit = self.keys_audit(p, "update", &entry.name, written)?;
        audit
            .parameters
            .extend([entry.entry_id.clone().into(), nonce.clone().into()]);
        let rows = self.db.batch(vec![
            // Optimistic concurrency: the previous write nonce must still be current.
            Statement::new(format!("UPDATE key_entries SET write_nonce=?,updated_at=?,purpose=CASE WHEN ?=1 THEN ? ELSE purpose END,expires=CASE WHEN ?=1 THEN ? ELSE expires END WHERE entry_id=? AND write_nonce IS ? AND {live} RETURNING entry_id"),first),
            Statement::new(format!("DELETE FROM key_fields WHERE entry_id=? AND name IN(SELECT value FROM json_each(?)) AND {written}"),vec![entry.entry_id.clone().into(),json!(remove).to_string().into(),entry.entry_id.clone().into(),nonce.clone().into()]),
            Statement::new(format!("INSERT INTO key_fields(entry_id,name,kid,nonce,ciphertext,updated_at) SELECT ?,json_extract(j.value,'$.name'),json_extract(j.value,'$.kid'),json_extract(j.value,'$.nonce'),json_extract(j.value,'$.ct'),? FROM json_each(?) j WHERE {written} ON CONFLICT(entry_id,name) DO UPDATE SET kid=excluded.kid,nonce=excluded.nonce,ciphertext=excluded.ciphertext,updated_at=excluded.updated_at"),vec![entry.entry_id.clone().into(),now.into(),sealed.into(),entry.entry_id.clone().into(),nonce.clone().into()]),
            audit,
        ]).await?;
        if rows[0].is_empty() {
            self.current_keys_grant(p).await?;
            return Err(Error::new(
                "ENTRY_CHANGED",
                "The entry changed concurrently; read it again and retry.",
            ));
        }
        Ok(json!({"updated":true,"name":entry.name,"fields":current}))
    }
    async fn keys_disable(&self, p: &KeysPrincipal, args: &Value) -> Result<Value> {
        let name = crate::json::required(args, "name")?;
        let disabled = match args.get("disabled") {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(Error::invalid("disabled must be a boolean.")),
        };
        let entry = self.keys_entry(p, &name).await?;
        if !entry.writable {
            return Err(Error::new(
                "WRITE_NOT_GRANTED",
                "This connection may not change this entry.",
            ));
        }
        let now = self.clock.now_ms();
        let nonce = random_id("write")?;
        let (live, live_args) = self.keys_live(p);
        let mut first = vec![
            i64::from(disabled).into(),
            nonce.clone().into(),
            now.into(),
            entry.entry_id.clone().into(),
        ];
        first.extend(live_args);
        let written = "EXISTS(SELECT 1 FROM key_entries WHERE entry_id=? AND write_nonce=?)";
        let mut audit = self.keys_audit(
            p,
            if disabled { "disable" } else { "enable" },
            &entry.name,
            written,
        )?;
        audit
            .parameters
            .extend([entry.entry_id.clone().into(), nonce.into()]);
        let rows = self.db.batch(vec![
            Statement::new(format!("UPDATE key_entries SET disabled=?,write_nonce=?,updated_at=? WHERE entry_id=? AND {live} RETURNING entry_id"),first),
            audit,
        ]).await?;
        if rows[0].is_empty() {
            return Err(Error::unauthenticated());
        }
        Ok(json!({"name":entry.name,"disabled":disabled}))
    }
}
