use super::*;
use crate::{domain::check_id, json::fields, storage::driver::optional_text};

impl<D: Database, O: ObjectStore> App<D, O> {
    pub(crate) async fn token_routing_detail(&self, sid: &str, tid: &str) -> Result<Value> {
        check_id(tid)?;
        let rows = self.db.query(Statement::new("SELECT t.token_id,t.actor_id,t.consumer_id,t.authority_version,t.default_recipient_id,t.expires_at,t.revoked_at,a.disabled AS actor_disabled,c.disabled AS consumer_disabled FROM tokens t JOIN actors a ON a.space_id=t.space_id AND a.actor_id=t.actor_id JOIN consumers c ON c.space_id=t.space_id AND c.consumer_id=t.consumer_id AND c.actor_id=t.actor_id WHERE t.space_id=? AND t.token_id=?", vec![sid.into(),tid.into()])).await?;
        let row = rows.first().ok_or_else(Error::not_found)?;
        let expires = match row.get("expires_at") {
            Some(Sql::Integer(n)) => Some(*n),
            _ => None,
        };
        let revoked = match row.get("revoked_at") {
            Some(Sql::Integer(n)) => Some(*n),
            _ => None,
        };
        Ok(
            json!({"token_id":tid,"actor_id":text(row,"actor_id")?,"consumer_id":text(row,"consumer_id")?,"authority_version":integer(row,"authority_version")?,"default_recipient_id":optional_text(row,"default_recipient_id"),"expires_at":expires.map(stamp).transpose()?,"revoked_at":revoked.map(stamp).transpose()?,"editable":revoked.is_none() && expires.is_none_or(|n|n>self.clock.now_ms()) && integer(row,"actor_disabled")? == 0 && integer(row,"consumer_disabled")? == 0}),
        )
    }

    pub(crate) async fn token_routing(
        &self,
        request: &Request,
        sid: &str,
        tid: &str,
        body: Value,
    ) -> Result<Value> {
        if request.method == "GET" {
            return self.token_routing_detail(sid, tid).await;
        }
        if request.method != "PUT" {
            return Err(Error::not_found());
        }
        fields(
            &body,
            &[
                "request_id",
                "expected_authority_version",
                "default_recipient_id",
            ],
        )?;
        // Require a caller-held key so a lost response can be recovered without another edit.
        crate::json::required(&body, "request_id")?;
        let (key, fp) = admin::admin_key(&body)?;
        let expected = body
            .get("expected_authority_version")
            .and_then(Value::as_i64)
            .filter(|v| *v >= 0 && *v < i64::MAX)
            .ok_or_else(|| Error::invalid("Invalid expected authority version."))?;
        let before = self.token_routing_detail(sid, tid).await?;
        let previous=self.db.query(Statement::new("SELECT fingerprint,authority_version FROM token_routing_changes WHERE space_id=? AND token_id=? AND request_id=?",vec![sid.into(),tid.into(),key.clone().into()])).await?;
        if let Some(row) = previous.first() {
            if text(row, "fingerprint")? != fp {
                return Err(Error::new(
                    "IDEMPOTENCY_CONFLICT",
                    "Request ID was used with different routing.",
                ));
            }
            let mut result = before;
            result["applied_authority_version"] = json!(integer(row, "authority_version")?);
            result["replayed"] = json!(true);
            return Ok(result);
        }
        if before["editable"] != true {
            return Err(Error::forbidden());
        }
        if before["authority_version"] != expected {
            return Err(Error::new(
                "REVISION_CONFLICT",
                "Connection routing changed; refresh before editing.",
            ));
        }
        let default = match body.get("default_recipient_id") {
            Some(Value::Null) => None,
            Some(Value::String(id)) => {
                check_id(id)?;
                if self.admin_actor(sid, id).await?["disabled"] == true {
                    return Err(Error::forbidden());
                }
                Some(id.clone())
            }
            _ => return Err(Error::invalid("Missing or invalid default recipient.")),
        };
        let now = self.clock.now_ms();
        let nonce = random_id("routing")?;
        // The audit row is the transaction's unique winner marker. Every mutation below
        // requires this invocation's nonce, so a losing CAS or replay cannot change routing.
        let manager = match self.admin_access(request).await? {
            Some(space) => format!("owner:{space}"),
            None => "operator".to_owned(),
        };
        let managing_principal = self.dashboard_owner(request, sid, None).await?;
        let (managing_guard, managing_args) = self.owner_authority_guard(&managing_principal);
        let after = json!({"default_recipient_id":default,"authority_version":expected+1});
        let mut q = vec![Statement::new(
            "INSERT INTO token_routing_changes(change_id,space_id,token_id,request_id,fingerprint,authority_version,manager,before_json,after_json,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM tokens t JOIN actors a ON a.space_id=t.space_id AND a.actor_id=t.actor_id JOIN consumers c ON c.space_id=t.space_id AND c.consumer_id=t.consumer_id AND c.actor_id=t.actor_id WHERE t.space_id=? AND t.token_id=? AND t.authority_version=? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>?) AND a.disabled=0 AND c.disabled=0) AND EXISTS(SELECT 1 FROM spaces s JOIN actors target ON target.space_id=s.space_id AND target.actor_id=COALESCE(?,s.default_actor_id) WHERE s.space_id=? AND target.disabled=0) ON CONFLICT DO NOTHING",
            vec![
                nonce.clone().into(),
                sid.into(),
                tid.into(),
                key.clone().into(),
                fp.clone().into(),
                (expected + 1).into(),
                manager.into(),
                serde_json::to_string(&before)
                    .map_err(|_| Error::storage())?
                    .into(),
                serde_json::to_string(&after)
                    .map_err(|_| Error::storage())?
                    .into(),
                now.into(),
                sid.into(),
                tid.into(),
                expected.into(),
                now.into(),
                default.clone().into(),
                sid.into(),
            ],
        )];
        q[0].sql = q[0].sql.replace(
            " ON CONFLICT DO NOTHING",
            &format!(" AND {managing_guard} ON CONFLICT DO NOTHING"),
        );
        q[0].parameters.extend(managing_args);
        let guard = "EXISTS(SELECT 1 FROM token_routing_changes WHERE change_id=?)";
        q.push(Statement::new(format!("UPDATE tokens SET authority_version=authority_version+1,default_recipient_id=? WHERE space_id=? AND token_id=? AND {}",guard),vec![default.into(),sid.into(),tid.into(),nonce.clone().into()]));
        self.db.batch(q).await?;
        self.current(&managing_principal).await?;
        let rows=self.db.query(Statement::new("SELECT fingerprint,authority_version,change_id FROM token_routing_changes WHERE space_id=? AND token_id=? AND request_id=?",vec![sid.into(),tid.into(),key.into()])).await?;
        let row = rows.first().ok_or_else(|| {
            Error::new(
                "REVISION_CONFLICT",
                "Connection routing changed; refresh before editing.",
            )
        })?;
        if text(row, "fingerprint")? != fp {
            return Err(Error::new(
                "IDEMPOTENCY_CONFLICT",
                "Request ID was used with different routing.",
            ));
        }
        let mut result = self.token_routing_detail(sid, tid).await?;
        result["applied_authority_version"] = json!(integer(row, "authority_version")?);
        result["replayed"] = json!(text(row, "change_id")? != nonce);
        Ok(result)
    }
}
