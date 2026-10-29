//! Worker entry. `WAYPOST_PRODUCT` selects the product (default `waypost`);
//! the keys product shares the gateway, accounts and OAuth but no Waypost routes.
use crate::gateway::cloudflare::{
    D1Store, convert, error_response, harden, log_and_error, log_json_error, log_structured,
    read_body,
};
use crate::{
    App, Config, Limits, Request, Response,
    error::{Error, Result},
    storage::{
        NoObjects, ObjectInfo, ObjectStore,
        driver::{Database, Statement, Value as Sql, blob, integer, text},
    },
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use worker::{Bucket, Conditional, Context, Env, FixedLengthStream, HttpMetadata, event};

struct R2Store {
    bucket: Bucket,
}
fn object_info(object: &worker::Object) -> Result<ObjectInfo> {
    Ok(ObjectInfo {
        size: object.size(),
        sha256: object.checksum().sha256.ok_or_else(Error::storage)?,
        content_type: object
            .http_metadata()
            .content_type
            .ok_or_else(Error::storage)?,
    })
}
impl R2Store {
    async fn put(
        &self,
        key: &str,
        data: worker::Data,
        content_type: &str,
        sha: &[u8],
        size: u64,
    ) -> Result<ObjectInfo> {
        let object = self
            .bucket
            .put(key, data)
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.into()),
                ..Default::default()
            })
            .only_if(Conditional {
                etag_does_not_match: Some("*".into()),
                ..Default::default()
            })
            .sha256(sha.to_vec())
            .execute()
            .await
            .map_err(|error| {
                if error.to_string().to_ascii_lowercase().contains("checksum") {
                    Error::new("CHECKSUM_MISMATCH", "R2 rejected the byte checksum.")
                } else {
                    Error::storage()
                }
            })?;
        let info = if let Some(object) = object {
            object_info(&object)?
        } else {
            self.inspect(key).await?.ok_or_else(Error::storage)?
        };
        if info.size != size || info.sha256 != sha || info.content_type != content_type {
            return Err(Error::new(
                "UPLOAD_CONTENT_CONFLICT",
                "Existing immutable object differs from the upload.",
            ));
        }
        Ok(info)
    }
}
impl ObjectStore for R2Store {
    async fn create_only(
        &self,
        key: &str,
        bytes: &[u8],
        content_type: &str,
        sha: &[u8],
    ) -> Result<ObjectInfo> {
        self.put(
            key,
            bytes.to_vec().into(),
            content_type,
            sha,
            bytes.len() as u64,
        )
        .await
    }
    async fn inspect(&self, key: &str) -> Result<Option<ObjectInfo>> {
        self.bucket
            .head(key)
            .await
            .map_err(|_| Error::storage())?
            .as_ref()
            .map(object_info)
            .transpose()
    }
    async fn read(&self, key: &str) -> Result<Vec<u8>> {
        let object = self
            .bucket
            .get(key)
            .execute()
            .await
            .map_err(|_| Error::storage())?
            .ok_or_else(Error::not_found)?;
        object
            .body()
            .ok_or_else(Error::storage)?
            .bytes()
            .await
            .map_err(|_| Error::storage())
    }
    async fn remove(&self, key: &str) -> Result<()> {
        self.bucket.delete(key).await.map_err(|_| Error::storage())
    }
}
impl App<D1Store, R2Store> {
    async fn streaming_upload(
        &self,
        request: &Request,
        raw: &mut worker::Request,
        id: &str,
    ) -> Result<Value> {
        if request
            .headers
            .get("origin")
            .is_some_and(|s| s != &self.config.public_origin)
        {
            return Err(Error::forbidden());
        }
        let p = self.authenticate(request).await?;
        let row = self.upload(&p, id).await?;
        crate::storage::rows::Upload::decode(&row)?.writable(self.clock.now_ms())?;
        let size = integer(&row, "size_bytes")? as u64;
        let content_type = text(&row, "content_type")?;
        if size > self.limits.max_blob_bytes {
            return Err(Error::new(
                "RESOURCE_LIMIT",
                "Blob exceeds Worker deployment limit.",
            ));
        }
        if request.headers.get("content-type") != Some(&content_type)
            || request
                .headers
                .get("content-length")
                .is_some_and(|v| v.parse::<u64>().ok() != Some(size))
        {
            return Err(Error::new(
                "INVALID_BLOB",
                "Size or content type does not match.",
            ));
        }
        let key = text(&row, "object_key")?;
        let existing = self.objects.inspect(&key).await?;
        let data = if raw.inner().body().is_none() {
            if size != 0 {
                return Err(Error::new("INVALID_BLOB", "Upload body is missing."));
            }
            worker::Data::Bytes(vec![])
        } else {
            FixedLengthStream::wrap(
                raw.stream()
                    .map_err(|_| Error::new("INVALID_BLOB", "Invalid upload stream."))?,
                size,
            )
            .into()
        };
        self.objects
            .put(&key, data, &content_type, &blob(&row, "sha256")?, size)
            .await?;
        self.current(&p).await?;
        let after = self.upload(&p, id).await?;
        crate::storage::rows::Upload::decode(&after)?.writable(self.clock.now_ms())?;
        Ok(json!({"upload_id":id,"already_uploaded":existing.is_some()}))
    }
    async fn streaming_download(&self, request: &Request, id: &str) -> Result<worker::Response> {
        if request
            .headers
            .get("origin")
            .is_some_and(|s| s != &self.config.public_origin)
        {
            return Err(Error::forbidden());
        }
        let p = self.authenticate(request).await?;
        let row = self.readable_blob(&p, id).await?;
        let object = self
            .objects
            .bucket
            .get(text(&row, "object_key")?)
            .execute()
            .await
            .map_err(|_| Error::storage())?
            .ok_or_else(Error::storage)?;
        let info = object_info(&object)?;
        crate::storage::rows::verify_object(&row, &info)?;
        self.current(&p).await?;
        let mut response = worker::Response::from_body(
            object
                .body()
                .ok_or_else(Error::storage)?
                .response_body()
                .map_err(|_| Error::storage())?,
        )
        .map_err(|_| Error::storage())?;
        for (k, v) in [
            ("content-type", info.content_type.as_str()),
            ("content-disposition", "attachment"),
            ("cache-control", "private, no-store"),
            ("x-content-type-options", "nosniff"),
        ] {
            response
                .headers_mut()
                .set(k, v)
                .map_err(|_| Error::storage())?;
        }
        Ok(response)
    }
}
#[event(fetch)]
pub async fn fetch(
    raw: worker::Request,
    env: Env,
    _ctx: Context,
) -> worker::Result<worker::Response> {
    let https = match raw.url() {
        Ok(url) => url.scheme() == "https",
        Err(_) => {
            log_structured("UNKNOWN /unknown", "INTERNAL_ERROR", None);
            return error_response(Error::internal("worker request boundary"));
        }
    };
    let route_name = crate::http::route_label(raw.method().as_ref(), &raw.path());
    let product = env
        .var("WAYPOST_PRODUCT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "waypost".into());
    let result = match product.as_str() {
        "waypost" => handle_fetch(raw, env).await,
        "keys" => handle_keys_fetch(raw, env).await,
        _ => log_and_error(&route_name, Error::internal("product configuration")),
    };
    let mut response = match result {
        Ok(response) => response,
        Err(_) => log_and_error(&route_name, Error::internal("worker request boundary"))?,
    };
    harden(&mut response, https)?;
    Ok(response)
}

/// Origin, rate limits and shared account/OAuth/signing configuration. Returns
/// the configured App, or the response to send instead.
async fn prepare<D: Database, O: ObjectStore>(
    raw: &worker::Request,
    env: &Env,
    app: App<D, O>,
    operator_mode: &str,
    production: bool,
) -> std::result::Result<App<D, O>, worker::Result<worker::Response>> {
    let route_name = crate::http::route_label(raw.method().as_ref(), &raw.path());
    let fail = |label: &'static str| Err(log_and_error(&route_name, Error::internal(label)));
    match raw.headers().get("origin") {
        Ok(Some(value)) if value != app.config.public_origin => {
            return Err(log_and_error(&route_name, Error::forbidden()));
        }
        Err(e) => return Err(Err(e)),
        _ => {}
    }
    // Production must not silently omit abuse controls when a binding is missing.
    let admin_limiter = env.rate_limiter("ADMIN_RATE_LIMITER");
    let api_limiter = env.rate_limiter("API_RATE_LIMITER");
    if production && (admin_limiter.is_err() || api_limiter.is_err()) {
        return fail("worker configuration");
    }
    let path = raw.path();
    let route = crate::http::classify(raw.method().as_ref(), &path);
    let limiter = if matches!(route, crate::http::Route::AdminSession)
        && raw.method() == worker::Method::Post
        && path != "/account/devices/token"
        && path != "/oauth/token"
    {
        admin_limiter.ok()
    } else if matches!(
        route,
        crate::http::Route::PublicAsset | crate::http::Route::Health
    ) {
        None
    } else {
        api_limiter.ok()
    };
    if let Some(limiter) = limiter {
        let ip = match raw.headers().get("cf-connecting-ip") {
            Ok(ip) => ip.unwrap_or_else(|| "local".into()),
            Err(e) => return Err(Err(e)),
        };
        let outcome = match limiter
            .limit(format!("ip:{}", hex::encode(Sha256::digest(ip.as_bytes()))))
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => return Err(Err(e)),
        };
        if !outcome.success {
            if path.starts_with("/oauth/") {
                log_structured(&route_name, "RATE_LIMITED", None);
                return Err(convert(crate::service::oauth::rate_limited_response()));
            }
            return Err(log_and_error(
                &route_name,
                Error::new("RATE_LIMITED", "Request rate limit exceeded; retry later."),
            )
            .and_then(|mut response| {
                response.headers_mut().set("retry-after", "60")?;
                Ok(response)
            }));
        }
    }
    let app = if let Ok(raw_config) = env.secret("WAYPOST_OIDC_CONFIG") {
        let configured: Result<_> = (|| {
            let config: crate::service::accounts_oidc::OidcConfig =
                serde_json::from_str(&raw_config.to_string())
                    .map_err(|_| Error::internal("OIDC configuration"))?;
            let exchange = crate::service::accounts_oidc::OidcHttpExchange::new(&config)?;
            let limit = env
                .var("WAYPOST_ACCOUNT_SIGNUP_LIMIT")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "0".into())
                .parse::<usize>()
                .map_err(|_| Error::internal("account signup limit"))?;
            app.with_accounts(config, std::rc::Rc::new(exchange), limit)
        })();
        match configured {
            Ok(app) => app,
            Err(_) => return fail("OIDC configuration"),
        }
    } else {
        app
    };
    let app = if let Ok(raw) = env.var("WAYPOST_OAUTH_CLIENTS") {
        let configured = serde_json::from_str::<crate::OAuthConfig>(&raw.to_string())
            .map_err(|_| Error::internal("OAuth configuration"))
            .and_then(|config| app.with_oauth(config));
        match configured {
            Ok(app) => app,
            Err(_) => return fail("OAuth configuration"),
        }
    } else {
        app
    };
    let app = if let Ok(secret) = env.secret("WAYPOST_CURSOR_SECRET") {
        match app.with_cursor_secret(&secret.to_string()) {
            Ok(app) => app,
            Err(_) => return fail("worker cursor key configuration"),
        }
    } else {
        app
    };
    let app = if let Ok(secret) = env.secret("WAYPOST_CSRF_SECRET") {
        match app.with_csrf_secret(&secret.to_string()) {
            Ok(app) => app,
            Err(_) => return fail("worker CSRF key configuration"),
        }
    } else {
        app
    };
    match app.with_operator_mode(operator_mode) {
        Ok(app) => Ok(app),
        Err(_) => fail("operator configuration"),
    }
}

fn worker_config(env: &Env, operator_mode: &str, production: bool) -> worker::Result<Config> {
    let config = Config {
        admin_secret: if operator_mode == "disabled" {
            env.secret("WAYPOST_ADMIN_SECRET")
                .map(|v| v.to_string())
                .unwrap_or_default()
        } else {
            env.secret("WAYPOST_ADMIN_SECRET")?.to_string()
        },
        public_origin: env.var("PUBLIC_ORIGIN")?.to_string(),
    };
    let origin = worker::Url::parse(&config.public_origin)
        .map_err(|_| worker::Error::from("Invalid public origin"))?;
    if (operator_mode != "disabled" && config.admin_secret.len() < 32)
        || !matches!(origin.scheme(), "http" | "https")
        || origin.origin().ascii_serialization() != config.public_origin
        || (production && origin.scheme() != "https")
    {
        return Err(worker::Error::from("worker configuration"));
    }
    Ok(config)
}

fn operator_mode(env: &Env) -> String {
    env.var("WAYPOST_OPERATOR_MODE")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "enabled".into())
}

/// The keys product: D1 only (no R2), its own body limit and data keyring.
async fn handle_keys_fetch(mut raw: worker::Request, env: Env) -> worker::Result<worker::Response> {
    let route_name = crate::http::route_label(raw.method().as_ref(), &raw.path());
    let production = env
        .var("DEPLOYMENT_ENV")
        .is_ok_and(|value| value.to_string() == "production");
    let operator_mode = operator_mode(&env);
    if operator_mode != "disabled" {
        // The keys product has no operator routes; never accept an operator credential.
        return log_and_error(&route_name, Error::internal("operator configuration"));
    }
    let Ok(config) = worker_config(&env, &operator_mode, production) else {
        return log_and_error(&route_name, Error::internal("worker configuration"));
    };
    let database = env.d1("DB")?;
    let session = database.with_session(Some("first-primary"))?;
    let app = App::new(D1Store::new(session), NoObjects, config);
    let app = match prepare(&raw, &env, app, &operator_mode, production).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let app = match env.secret("KEYS_DATA_KEYS") {
        Ok(keys) => match app.with_keys(&keys.to_string()) {
            Ok(app) => app,
            Err(_) => return log_and_error(&route_name, Error::internal("keys configuration")),
        },
        Err(_) => return log_and_error(&route_name, Error::internal("keys keyring missing")),
    };
    if app.validate_runtime_auth().is_err() {
        return log_and_error(&route_name, Error::internal("operator configuration"));
    }
    let body = match read_body(&mut raw, app.limits.max_json_bytes).await {
        Ok(body) => body,
        Err(e) => return log_and_error(&route_name, e),
    };
    let request = Request {
        method: raw.method().to_string(),
        path: raw.path(),
        query: raw.url()?.query().unwrap_or("").to_owned(),
        headers: raw.headers().entries().collect(),
        body,
    };
    let response = app.handle(request).await;
    if response.status >= 400 {
        log_json_error(&route_name, &response.body);
    }
    convert(response)
}

async fn handle_fetch(mut raw: worker::Request, env: Env) -> worker::Result<worker::Response> {
    let route_name = crate::http::route_label(raw.method().as_ref(), &raw.path());
    let production = env
        .var("DEPLOYMENT_ENV")
        .is_ok_and(|value| value.to_string() == "production");
    let operator_mode = operator_mode(&env);
    if !["enabled", "disabled"].contains(&operator_mode.as_str()) {
        return log_and_error(&route_name, Error::internal("operator configuration"));
    }
    let Ok(config) = worker_config(&env, &operator_mode, production) else {
        return log_and_error(&route_name, Error::internal("worker configuration"));
    };
    let path = raw.path();
    let route = crate::http::classify(raw.method().as_ref(), &path);
    let database = env.d1("DB")?;
    let session = database.with_session(Some("first-primary"))?;
    // Conservative Free-tier profile. Public describe reports these exact limits.
    let limits = Limits {
        max_json_bytes: 16384,
        max_blob_bytes: 256 * 1024,
        max_message_attachments: 4,
        max_inline_memory_changes: 8,
        max_manifest_memory_changes: 8,
        max_collection_items: 32,
        max_page_size: 20,
    };
    let app = App::new(
        D1Store::new(session),
        R2Store {
            bucket: env.bucket("OBJECTS")?,
        },
        config,
    )
    .with_limits(limits);
    let app = match prepare(&raw, &env, app, &operator_mode, production).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let onboarding = env
        .var("WAYPOST_ONBOARDING_MODE")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "legacy".into());
    let app = match app.with_onboarding_mode(&onboarding) {
        Ok(app) => app,
        Err(_) => return log_and_error(&route_name, Error::internal("onboarding configuration")),
    };
    let app = if let Ok(keys) = env.secret("WAYPOST_ENCRYPTION_KEYS") {
        let legacy = env
            .var("ALLOW_LEGACY_PLAINTEXT")
            .is_ok_and(|v| v.to_string() == "1");
        match app.with_encryption_keys(&keys.to_string(), legacy) {
            Ok(app) => app,
            Err(_) => {
                return log_and_error(
                    &route_name,
                    Error::internal("worker encryption configuration"),
                );
            }
        }
    } else if production {
        return log_and_error(
            &route_name,
            Error::internal("production encryption keyring missing"),
        );
    } else {
        app
    };
    if app.validate_runtime_auth().is_err() {
        return log_and_error(&route_name, Error::internal("operator configuration"));
    }
    let mut request = Request {
        method: raw.method().to_string(),
        path: raw.path(),
        query: raw.url()?.query().unwrap_or("").to_owned(),
        headers: raw.headers().entries().collect(),
        body: vec![],
    };
    if request.path == "/ready" && request.method == "GET" {
        let readiness: Result<Value> = async {
            if app.operator_enabled { app.admin_auth(&request)?; }
            else { app.admin_access(&request).await?; }
            let migrations=crate::storage::migrations::MIGRATIONS;
            let placeholders=vec!["?";migrations.len()].join(",");
            let rows=app.db.query(Statement::new(format!("SELECT count(*) AS applied FROM d1_migrations WHERE name IN ({placeholders})"),migrations.iter().map(|(name,_)|Sql::from(*name)).collect())).await?;
            if rows.first().map(|row|integer(row,"applied")).transpose()? != Some(migrations.len() as i64) {
                return Err(Error::internal("worker schema revision"));
            }
            app.objects.inspect("_waypost_readiness_probe").await?;
            Ok(json!({"status":"ready","schema_revision":crate::storage::migrations::MIGRATIONS.len(),"environment":if production {"production"} else {"development"}}))
        }.await;
        return match readiness {
            Ok(data) => convert(Response::json(200, json!({"ok":true,"data":data}))),
            Err(error) => log_and_error(&route_name, error),
        };
    }
    if let crate::http::Route::UploadContent(id) = route
        && app.encryption.is_none()
    {
        return match app.streaming_upload(&request, &mut raw, id).await {
            Ok(data) => convert(Response::json(200, json!({"ok":true,"data":data}))),
            Err(e) => log_and_error(&route_name, e),
        };
    }
    if let crate::http::Route::BlobContent(id) = route
        && app.encryption.is_none()
    {
        return match app.streaming_download(&request, id).await {
            Ok(response) => Ok(response),
            Err(e) => log_and_error(&route_name, e),
        };
    }
    let max_body = if matches!(route, crate::http::Route::UploadContent(_)) {
        app.limits.max_blob_bytes as usize
    } else {
        app.limits.max_json_bytes
    };
    if raw.inner().body().is_some() {
        let mut stream = raw.stream()?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if request.body.len() + chunk.len() > max_body {
                return log_and_error(
                    &route_name,
                    Error::new("RESOURCE_LIMIT", "Request exceeds Worker deployment limit."),
                );
            }
            request.body.extend(chunk);
        }
    }
    let response = app.handle(request).await;
    if response.status >= 400 {
        log_json_error(&route_name, &response.body);
    }
    convert(response)
}
