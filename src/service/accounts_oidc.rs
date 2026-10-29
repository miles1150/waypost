//! Optional OIDC code-flow verification. No discovery or token-controlled network access.
//!
//! The caller owns persisted single-use state/nonce, PKCE, browser binding and session
//! creation. Only a configured code-exchange transport can supply the signed ID token.
//! Reference: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::lock::Mutex;
use rsa::{BigUint, RsaPublicKey, pkcs1v15, signature::Verifier, traits::PublicKeyParts};
use serde::Deserialize;
use sha2::Sha256;
use std::{future::Future, pin::Pin, rc::Rc};
use url::Url;

/// Trusted runtime adapter, never constructed from browser-supplied endpoints.
/// Implementations must POST to a fixed HTTPS endpoint, reject redirects, bound the
/// response and timeout, and never log code, verifier, client secret or ID token.
/// The output is the signed `id_token`, not the access token or a caller-supplied subject.
/// A failed/ambiguous exchange must not be retried with a new login transaction.
pub trait OidcCodeExchange {
    /// Fixed Google public-key transport; custom pinned exchanges need not implement it.
    fn google_jwks(&self) -> Pin<Box<dyn Future<Output = Result<GoogleJwksResponse>> + '_>> {
        Box::pin(async { Err(rejected()) })
    }

    fn exchange<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>>;
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcRsaKey {
    pub kid: String,
    /// Base64url without padding, as in an RSA JWK.
    pub n: String,
    pub e: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Explicitly pinned verification keys. Rotation requires trusted configuration,
    /// not discovery using any field in an unverified token.
    #[serde(default)]
    pub keys: Vec<OidcRsaKey>,
    /// Opt in to the fixed Google provider and rotating public-key source.
    #[serde(default)]
    pub google_jwks: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default)]
    crit: Option<serde_json::Value>,
    #[serde(default)]
    jku: Option<serde_json::Value>,
    #[serde(default)]
    jwk: Option<serde_json::Value>,
    #[serde(default)]
    x5u: Option<serde_json::Value>,
    #[serde(default)]
    b64: Option<serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: i64,
    iat: i64,
    nbf: Option<i64>,
    nonce: String,
}

fn rejected() -> Error {
    Error::unauthenticated()
}
fn https_endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| Error::invalid("Invalid OIDC endpoint."))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(Error::invalid("OIDC endpoints must be fixed HTTPS URLs."));
    }
    Ok(url)
}
fn key(value: &OidcRsaKey) -> Result<RsaPublicKey> {
    if value.kid.is_empty() || value.kid.len() > 128 || value.n.len() > 700 || value.e.len() > 12 {
        return Err(Error::invalid("Invalid OIDC verification key."));
    }
    let n = URL_SAFE_NO_PAD.decode(&value.n).map_err(|_| rejected())?;
    let e = URL_SAFE_NO_PAD.decode(&value.e).map_err(|_| rejected())?;
    let k = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|_| rejected())?;
    if !(2048..=4096).contains(&k.n().bits()) || k.e() != &BigUint::from(65537u32) {
        return Err(Error::invalid(
            "OIDC RSA keys require 2048–4096 bits and exponent 65537.",
        ));
    }
    Ok(k)
}

const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const JWKS_LIMIT: usize = 65_536;
const REFRESH_COOLDOWN_MS: i64 = 30_000;
#[cfg(all(not(feature = "native"), feature = "cloudflare"))]
struct AbortOnDrop(Option<worker::AbortController>);
#[cfg(all(not(feature = "native"), feature = "cloudflare"))]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(controller) = self.0.take() {
            controller.abort();
        }
    }
}

/// Transport output contains public data only. URLs are not supplied by the token.
pub struct GoogleJwksResponse {
    pub body: Vec<u8>,
    pub cache_control: Option<String>,
    pub age: Option<String>,
}
#[derive(Default)]
struct GoogleKeyCache {
    keys: Vec<OidcRsaKey>,
    expires_at: i64,
    next_attempt: i64,
}
// Apps/transports are recreated on every Worker request. This stores ONLY owned
// public key data at isolate lifetime (thread lifetime on native). No fetch or
// response is shared between Worker request contexts. New isolates start cold;
// neither this cache nor its cooldown is a deployment-wide rate limiter.
thread_local! {
    static GOOGLE_CACHE: Rc<Mutex<GoogleKeyCache>> = Rc::new(Mutex::new(GoogleKeyCache::default()));
}
fn token_header(token: &str) -> Result<Header> {
    if token.len() > 16384 {
        return Err(rejected());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|s| s.is_empty()) {
        return Err(rejected());
    }
    let header: Header =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| rejected())?)
            .map_err(|_| rejected())?;
    if header.alg != "RS256"
        || header.kid.is_empty()
        || header.kid.len() > 128
        || header.crit.is_some()
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.b64.is_some()
    {
        return Err(rejected());
    }
    Ok(header)
}
fn cache_lifetime(response: &GoogleJwksResponse) -> Result<i64> {
    let mut max_age = None;
    if let Some(header) = &response.cache_control {
        if header.len() > 4096 {
            return Err(rejected());
        }
        for directive in header.split(',').map(str::trim) {
            let (name, value) = directive
                .split_once('=')
                .map_or((directive, None), |(k, v)| (k.trim(), Some(v.trim())));
            if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache") {
                return Err(rejected());
            }
            if name.eq_ignore_ascii_case("max-age") {
                if max_age.is_some() {
                    return Err(rejected());
                }
                let value = value.ok_or_else(rejected)?.trim_matches('"');
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(rejected());
                }
                max_age = Some(value.parse::<u64>().map_err(|_| rejected())?);
            }
        }
    }
    let age = match &response.age {
        Some(value)
            if value.len() <= 20
                && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit()) =>
        {
            value.parse::<u64>().map_err(|_| rejected())?
        }
        Some(_) => return Err(rejected()),
        None => 0,
    };
    // Missing freshness metadata gets a conservative minute, never indefinite use.
    let seconds = max_age.unwrap_or(60).saturating_sub(age).min(3600);
    if seconds == 0 {
        return Err(rejected());
    }
    Ok((seconds * 1000) as i64)
}
fn parse_google_keys(body: &[u8]) -> Result<Vec<OidcRsaKey>> {
    #[derive(Deserialize)]
    struct Set {
        keys: Vec<Jwk>,
    }
    #[derive(Deserialize)]
    struct Jwk {
        kid: String,
        kty: String,
        alg: String,
        #[serde(rename = "use")]
        usage: String,
        n: String,
        e: String,
        key_ops: Option<Vec<String>>,
    }
    if body.len() > JWKS_LIMIT {
        return Err(rejected());
    }
    let set: Set = serde_json::from_slice(body).map_err(|_| rejected())?;
    if !(1..=8).contains(&set.keys.len()) {
        return Err(rejected());
    }
    let mut keys = Vec::new();
    let mut kids = std::collections::BTreeSet::new();
    for jwk in set.keys {
        if jwk.kty != "RSA"
            || jwk.alg != "RS256"
            || jwk.usage != "sig"
            || jwk
                .key_ops
                .as_ref()
                .is_some_and(|v| v.len() != 1 || v[0] != "verify")
            || !kids.insert(jwk.kid.clone())
        {
            return Err(rejected());
        }
        let parsed = OidcRsaKey {
            kid: jwk.kid,
            n: jwk.n,
            e: jwk.e,
        };
        key(&parsed).map_err(|_| rejected())?;
        keys.push(parsed);
    }
    Ok(keys)
}
async fn google_keys(
    cache: &Mutex<GoogleKeyCache>,
    kid: &str,
    clock: &dyn super::Clock,
    exchange: &dyn OidcCodeExchange,
) -> Result<Vec<OidcRsaKey>> {
    // One fetch at a time. Contenders fail closed rather than sharing live I/O
    // across Worker requests. Dropping/canceling the future releases this guard.
    let mut cache = cache.try_lock().ok_or_else(rejected)?;
    let now = clock.now_ms();
    if now < 0 {
        return Err(rejected());
    }
    if now < cache.expires_at && cache.keys.iter().any(|k| k.kid == kid) {
        return Ok(cache.keys.clone());
    }
    if now < cache.next_attempt {
        return Err(rejected());
    }
    // Cooldown applies to success, malformed keys, transport failure and cancellation.
    cache.next_attempt = now.saturating_add(REFRESH_COOLDOWN_MS);
    let response = exchange.google_jwks().await?;
    let lifetime = cache_lifetime(&response)?;
    let keys = parse_google_keys(&response.body)?;
    let completed = clock.now_ms();
    if completed < now {
        return Err(rejected());
    }
    let expires_at = now.saturating_add(lifetime);
    if completed >= expires_at {
        return Err(rejected());
    }
    cache.expires_at = expires_at;
    cache.keys = keys;
    if !cache.keys.iter().any(|k| k.kid == kid) {
        return Err(rejected());
    }
    Ok(cache.keys.clone())
}

impl OidcConfig {
    pub fn validate(&self) -> Result<()> {
        https_endpoint(&self.issuer)?;
        https_endpoint(&self.authorization_endpoint)?;
        https_endpoint(&self.token_endpoint)?;
        if self
            .client_secret
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 4096)
        {
            return Err(Error::invalid("Invalid OIDC client secret configuration."));
        }
        if self.client_id.is_empty()
            || self.client_id.len() > 256
            || (!self.google_jwks && !(1..=8).contains(&self.keys.len()))
        {
            return Err(Error::invalid("Invalid OIDC client or key configuration."));
        }
        if self.google_jwks
            && (self.issuer != GOOGLE_ISSUER
                || self.authorization_endpoint != "https://accounts.google.com/o/oauth2/v2/auth"
                || self.token_endpoint != "https://oauth2.googleapis.com/token"
                || !self.keys.is_empty())
        {
            return Err(Error::invalid(
                "Google JWKS requires the fixed Google provider and no pinned keys.",
            ));
        }
        let mut kids = std::collections::BTreeSet::new();
        for k in &self.keys {
            if !kids.insert(&k.kid) {
                return Err(Error::invalid("Duplicate OIDC key ID."));
            }
            key(k)?;
        }
        Ok(())
    }

    pub fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        challenge: &str,
        redirect_uri: &str,
    ) -> Result<String> {
        self.validate()?;
        // Production callbacks are HTTPS. A trusted application may use literal
        // loopback HTTP for isolated native development, never arbitrary HTTP hosts.
        let callback =
            Url::parse(redirect_uri).map_err(|_| Error::invalid("Invalid OIDC callback."))?;
        if !(callback.scheme() == "https"
            || callback.scheme() == "http"
                && matches!(callback.host_str(), Some("127.0.0.1" | "[::1]")))
            || !callback.username().is_empty()
            || callback.password().is_some()
            || callback.query().is_some()
            || callback.fragment().is_some()
        {
            return Err(Error::invalid("Invalid OIDC callback."));
        }
        if state.len() < 32 || nonce.len() < 32 || challenge.len() != 43 {
            return Err(Error::invalid("Invalid OIDC login transaction."));
        }
        let mut url = https_endpoint(&self.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("scope", "openid")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Called only after a server-side authorization-code exchange. Account lookup
    /// uses (issuer, subject), never email, username or other mutable claims.
    pub fn verify(
        &self,
        token: &str,
        expected_nonce: &str,
        now_ms: i64,
    ) -> Result<VerifiedIdentity> {
        self.validate()?;
        if self.google_jwks {
            return Err(rejected());
        }
        self.verify_keys(token, expected_nonce, now_ms, &self.keys)
    }
    pub async fn verify_current(
        &self,
        token: &str,
        expected_nonce: &str,
        clock: &dyn super::Clock,
        exchange: &dyn OidcCodeExchange,
    ) -> Result<VerifiedIdentity> {
        self.validate()?;
        if !self.google_jwks {
            return self.verify(token, expected_nonce, clock.now_ms());
        }
        let kid = token_header(token)?.kid;
        let cache = GOOGLE_CACHE.with(Clone::clone);
        let keys = google_keys(&cache, &kid, clock, exchange).await?;
        // Never validate expiry against a timestamp taken before a network await.
        self.verify_keys(token, expected_nonce, clock.now_ms(), &keys)
    }
    fn verify_keys(
        &self,
        token: &str,
        expected_nonce: &str,
        now_ms: i64,
        keys: &[OidcRsaKey],
    ) -> Result<VerifiedIdentity> {
        if token.len() > 16384 || expected_nonce.len() < 32 || now_ms < 0 {
            return Err(rejected());
        }
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(rejected());
        }
        let header = token_header(token)?;
        let pinned = keys
            .iter()
            .find(|k| k.kid == header.kid)
            .ok_or_else(rejected)?;
        let signature = pkcs1v15::Signature::try_from(
            URL_SAFE_NO_PAD
                .decode(parts[2])
                .map_err(|_| rejected())?
                .as_slice(),
        )
        .map_err(|_| rejected())?;
        let signed = format!("{}.{}", parts[0], parts[1]);
        pkcs1v15::VerifyingKey::<Sha256>::new(key(pinned)?)
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| rejected())?;
        let claims: Claims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| rejected())?)
                .map_err(|_| rejected())?;
        let audiences = match claims.aud {
            Audience::One(a) => vec![a],
            Audience::Many(a) => a,
        };
        let now = now_ms / 1000;
        let issuer_matches = claims.iss == self.issuer
            || (self.issuer == GOOGLE_ISSUER && claims.iss == "accounts.google.com");
        if !issuer_matches
            || claims.sub.is_empty()
            || claims.sub.len() > 255
            || !audiences.contains(&self.client_id)
            || audiences.len() > 1 && claims.azp.as_deref() != Some(self.client_id.as_str())
            || claims.azp.as_ref().is_some_and(|a| a != &self.client_id)
            || claims.nonce != expected_nonce
            || claims.exp <= now
            || claims.iat > now.saturating_add(30)
            || claims.iat < now.saturating_sub(600)
            || claims.exp <= claims.iat
            || claims.nbf.is_some_and(|n| n > now.saturating_add(30))
        {
            return Err(rejected());
        }
        Ok(VerifiedIdentity {
            issuer: self.issuer.clone(),
            subject: claims.sub,
        })
    }
}

/// Fixed endpoint, no discovery, no redirect following. Does not retry exchanges:
/// an authorization code may have been consumed even when its response was lost.
pub struct OidcHttpExchange {
    endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    #[cfg(feature = "native")]
    client: reqwest::Client,
}
impl OidcHttpExchange {
    async fn fetch_google_keys(&self, endpoint: &str) -> Result<GoogleJwksResponse> {
        #[cfg(feature = "native")]
        {
            let mut response = self
                .client
                .get(endpoint)
                .header("accept", "application/json")
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
                .map_err(|_| rejected())?;
            if response.status().as_u16() != 200 {
                return Err(rejected());
            }
            let cache_control = response
                .headers()
                .get("cache-control")
                .map(|v| v.to_str().map(str::to_owned))
                .transpose()
                .map_err(|_| rejected())?;
            let age = response
                .headers()
                .get("age")
                .map(|v| v.to_str().map(str::to_owned))
                .transpose()
                .map_err(|_| rejected())?;
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| rejected())? {
                if body.len() + chunk.len() > JWKS_LIMIT {
                    return Err(rejected());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(GoogleJwksResponse {
                body,
                cache_control,
                age,
            })
        }
        #[cfg(all(not(feature = "native"), feature = "cloudflare"))]
        {
            use futures_util::{
                StreamExt,
                future::{Either, select},
            };
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Get)
                .with_redirect(worker::RequestRedirect::Manual);
            init.headers
                .set("accept", "application/json")
                .map_err(|_| rejected())?;
            let request =
                worker::Request::new_with_init(endpoint, &init).map_err(|_| rejected())?;
            let controller = worker::AbortController::default();
            let signal = controller.signal();
            let abort_guard = AbortOnDrop(Some(controller));
            let fetch = async {
                let mut response = worker::Fetch::Request(request)
                    .send_with_signal(&signal)
                    .await
                    .map_err(|_| rejected())?;
                if response.status_code() != 200 {
                    return Err(rejected());
                }
                let cache_control = response
                    .headers()
                    .get("cache-control")
                    .map_err(|_| rejected())?;
                let age = response.headers().get("age").map_err(|_| rejected())?;
                let mut stream = response.stream().map_err(|_| rejected())?;
                let mut body = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|_| rejected())?;
                    if body.len() + chunk.len() > JWKS_LIMIT {
                        return Err(rejected());
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(GoogleJwksResponse {
                    body,
                    cache_control,
                    age,
                })
            };
            let result = match select(
                Box::pin(fetch),
                Box::pin(worker::Delay::from(std::time::Duration::from_secs(10))),
            )
            .await
            {
                Either::Left((result, _)) => result,
                Either::Right(_) => Err(rejected()),
            };
            drop(abort_guard);
            result
        }
        #[cfg(not(any(feature = "native", feature = "cloudflare")))]
        {
            let _ = endpoint;
            Err(rejected())
        }
    }

    pub fn new(config: &OidcConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: config.token_endpoint.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            #[cfg(feature = "native")]
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|_| Error::invalid("Cannot initialize OIDC transport."))?,
        })
    }
    fn body(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<String> {
        if code.is_empty() || code.len() > 4096 || !(43..=128).contains(&verifier.len()) {
            return Err(rejected());
        }
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("client_id", &self.client_id)
            .append_pair("code", code)
            .append_pair("code_verifier", verifier)
            .append_pair("redirect_uri", redirect_uri);
        if let Some(secret) = &self.client_secret {
            form.append_pair("client_secret", secret);
        }
        Ok(form.finish())
    }
}
fn id_token(bytes: &[u8]) -> Result<String> {
    // Do not include provider error messages or response bodies in public errors.
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| rejected())?;
    if value.get("error").is_some() {
        return Err(rejected());
    }
    let token = value
        .get("id_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(rejected)?;
    if token.is_empty() || token.len() > 16384 {
        return Err(rejected());
    }
    Ok(token.to_owned())
}
impl OidcCodeExchange for OidcHttpExchange {
    fn google_jwks(&self) -> Pin<Box<dyn Future<Output = Result<GoogleJwksResponse>> + '_>> {
        Box::pin(self.fetch_google_keys(GOOGLE_JWKS_URL))
    }

    fn exchange<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
        Box::pin(async move {
            let body = self.body(code, verifier, redirect_uri)?;
            #[cfg(feature = "native")]
            {
                let mut response = self
                    .client
                    .post(&self.endpoint)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("accept", "application/json")
                    .body(body)
                    .send()
                    .await
                    .map_err(|_| rejected())?;
                if response.status().as_u16() != 200 {
                    return Err(rejected());
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| rejected())? {
                    if bytes.len() + chunk.len() > 65536 {
                        return Err(rejected());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                id_token(&bytes)
            }
            #[cfg(all(not(feature = "native"), feature = "cloudflare"))]
            {
                use futures_util::{
                    StreamExt,
                    future::{Either, select},
                };
                let mut init = worker::RequestInit::new();
                init.with_method(worker::Method::Post)
                    .with_redirect(worker::RequestRedirect::Manual)
                    .with_body(Some(body.into()));
                init.headers
                    .set("content-type", "application/x-www-form-urlencoded")
                    .map_err(|_| rejected())?;
                init.headers
                    .set("accept", "application/json")
                    .map_err(|_| rejected())?;
                let request = worker::Request::new_with_init(&self.endpoint, &init)
                    .map_err(|_| rejected())?;
                let controller = worker::AbortController::default();
                let signal = controller.signal();
                let abort_guard = AbortOnDrop(Some(controller));
                let fetch = async {
                    let mut response = worker::Fetch::Request(request)
                        .send_with_signal(&signal)
                        .await
                        .map_err(|_| rejected())?;
                    if response.status_code() != 200 {
                        return Err(rejected());
                    }
                    let mut stream = response.stream().map_err(|_| rejected())?;
                    let mut bytes = Vec::new();
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.map_err(|_| rejected())?;
                        if bytes.len() + chunk.len() > 65536 {
                            return Err(rejected());
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    id_token(&bytes)
                };
                let result = match select(
                    Box::pin(fetch),
                    Box::pin(worker::Delay::from(std::time::Duration::from_secs(15))),
                )
                .await
                {
                    Either::Left((result, _)) => result,
                    Either::Right(_) => Err(rejected()),
                };
                drop(abort_guard);
                result
            }
            #[cfg(not(any(feature = "native", feature = "cloudflare")))]
            {
                let _ = body;
                Err(Error::invalid("No OIDC runtime transport enabled."))
            }
        })
    }
}

#[cfg(all(test, feature = "native"))]
mod transport_tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test(flavor = "current_thread")]
    async fn google_key_transport_is_bounded_and_never_forwards_credentials_or_redirects() {
        for (status, body, okay) in [
            ("200 OK", "{\"keys\":[]}".to_owned(), true),
            ("302 Found", "private-provider-detail".into(), false),
            ("500 Error", "private-provider-detail".into(), false),
            ("200 OK", "x".repeat(JWKS_LIMIT + 1), false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/certs", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = vec![];
                let mut part = [0; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = socket.read(&mut part).unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&part[..n]);
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nCache-Control: public,max-age=60\r\nAge: 2\r\nLocation: http://127.0.0.1:1/never\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes());
                String::from_utf8(request).unwrap()
            });
            let transport = OidcHttpExchange {
                endpoint: "https://oauth2.googleapis.com/token".into(),
                client_id: "private-client".into(),
                client_secret: Some("private-secret".into()),
                client: reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
            };
            // Local URL injection is private to this unit test; production calls constant URL.
            let result = transport.fetch_google_keys(&endpoint).await;
            assert_eq!(result.is_ok(), okay);
            if let Ok(result) = result {
                assert_eq!(result.cache_control.as_deref(), Some("public,max-age=60"));
                assert_eq!(result.age.as_deref(), Some("2"));
            }
            let request = server.join().unwrap();
            assert!(request.starts_with("GET /certs "));
            assert!(!request.contains("private-"));
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn google_key_transport_times_out_stalled_body() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/certs", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                .unwrap();
            let mut bytes = [0; 4096];
            let _ = socket.read(&mut bytes);
            // Headers arrive immediately; the bounded timeout must also cover body reads.
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n{").unwrap();
            let _ = socket.read(&mut bytes);
        });
        let transport = OidcHttpExchange {
            endpoint: "https://oauth2.googleapis.com/token".into(),
            client_id: "test".into(),
            client_secret: None,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        };
        let start = std::time::Instant::now();
        assert!(transport.fetch_google_keys(&endpoint).await.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(14));
        server.join().unwrap();
    }
    async fn server_response(status: &str, body: &str) -> (Result<String>, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nLocation: http://127.0.0.1:1/never\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut part = [0; 1024];
            loop {
                let n = socket.read(&mut part).unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&part[..n]);
                if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..offset]).to_lowercase();
                    let len: usize = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= offset + 4 + len {
                        break;
                    }
                }
            }
            let _ = socket.write_all(response.as_bytes());
            String::from_utf8(bytes).unwrap()
        });
        // HTTP is only injected inside this module; public constructor rejects it.
        let transport = OidcHttpExchange {
            endpoint,
            client_id: "client&name".into(),
            client_secret: Some("secret+value".into()),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
        };
        let result = transport
            .exchange(
                "code+value",
                &"V".repeat(43),
                "https://waypost.example/account/callback",
            )
            .await;
        (result, server.join().unwrap())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn posts_encoded_code_pkce_and_secret_without_redirects() {
        let (result, request) =
            server_response("200 OK", r#"{"id_token":"signed.token.value"}"#).await;
        assert_eq!(result.unwrap(), "signed.token.value");
        assert!(request.contains("client_id=client%26name"));
        assert!(request.contains("client_secret=secret%2Bvalue"));
        assert!(request.contains("code=code%2Bvalue"));
        assert!(request.contains("code_verifier="));
        assert!(
            server_response("302 Found", r#"{"id_token":"not.accepted.token"}"#)
                .await
                .0
                .is_err()
        );
        assert!(
            server_response("200 OK", &"x".repeat(65537))
                .await
                .0
                .is_err()
        );
        assert!(
            server_response("400 Bad Request", r#"{"error":"provider private detail"}"#)
                .await
                .0
                .unwrap_err()
                .message
                .contains("valid credential")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        RsaPrivateKey,
        pkcs8::DecodePrivateKey,
        signature::{SignatureEncoding, Signer},
    };
    use serde_json::{Value, json};

    const NONCE: &str = "test-login-nonce-at-least-32-bytes-long";
    fn fixture() -> (OidcConfig, RsaPrivateKey) {
        // Publicly committed synthetic key, never used for a real identity provider.
        let private = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/oidc-test-private.pem"
        ))
        .unwrap();
        let config = OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "waypost-test".into(),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_secret: None,
            google_jwks: false,
            keys: vec![OidcRsaKey {
                kid: "test-only".into(),
                n: URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
            }],
        };
        (config, private)
    }
    fn claims() -> Value {
        json!({"iss":"https://issuer.example","sub":"immutable-subject","aud":"waypost-test","nonce":NONCE,"iat":1000,"exp":1300})
    }
    fn signed(private: &RsaPrivateKey, header: Value, claims: Value) -> String {
        let body = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = pkcs1v15::SigningKey::<Sha256>::new(private.clone()).sign(body.as_bytes());
        format!("{body}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
    fn token(private: &RsaPrivateKey, claims: Value) -> String {
        signed(private, json!({"alg":"RS256","kid":"test-only"}), claims)
    }
    struct MovingClock(std::cell::Cell<i64>);
    impl super::super::Clock for MovingClock {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
    }
    struct FakeKeys<'a> {
        clock: &'a MovingClock,
        calls: std::cell::Cell<usize>,
        body: std::cell::RefCell<Vec<u8>>,
        max_age: std::cell::RefCell<String>,
        elapsed: std::cell::Cell<i64>,
        fail: std::cell::Cell<bool>,
        pending: std::cell::Cell<bool>,
    }
    impl OidcCodeExchange for FakeKeys<'_> {
        fn exchange<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
            Box::pin(async { Err(rejected()) })
        }
        fn google_jwks(&self) -> Pin<Box<dyn Future<Output = Result<GoogleJwksResponse>> + '_>> {
            Box::pin(async move {
                self.calls.set(self.calls.get() + 1);
                if self.pending.get() {
                    futures_util::future::pending::<()>().await;
                }
                self.clock.0.set(self.clock.0.get() + self.elapsed.get());
                if self.fail.get() {
                    return Err(rejected());
                }
                Ok(GoogleJwksResponse {
                    body: self.body.borrow().clone(),
                    cache_control: Some(self.max_age.borrow().clone()),
                    age: None,
                })
            })
        }
    }
    fn jwks(config: &OidcConfig, kid: &str) -> Vec<u8> {
        let k = &config.keys[0];
        serde_json::to_vec(
            &json!({"keys":[{"kid":kid,"kty":"RSA","alg":"RS256","use":"sig","n":k.n,"e":k.e}]}),
        )
        .unwrap()
    }
    fn fake<'a>(clock: &'a MovingClock, config: &OidcConfig) -> FakeKeys<'a> {
        FakeKeys {
            clock,
            calls: 0.into(),
            body: std::cell::RefCell::new(jwks(config, "test-only")),
            max_age: std::cell::RefCell::new("public,max-age=120".into()),
            elapsed: 0.into(),
            fail: false.into(),
            pending: false.into(),
        }
    }
    #[cfg(feature = "native")]
    #[tokio::test(flavor = "current_thread")]
    async fn google_rotation_cooldown_failure_and_expiry() {
        let (config, _) = fixture();
        let clock = MovingClock(1_100_000.into());
        let source = fake(&clock, &config);
        let cache = Mutex::new(GoogleKeyCache::default());
        assert_eq!(
            google_keys(&cache, "test-only", &clock, &source)
                .await
                .unwrap()
                .len(),
            1
        );
        google_keys(&cache, "test-only", &clock, &source)
            .await
            .unwrap();
        assert_eq!(source.calls.get(), 1);
        assert!(
            google_keys(&cache, "unknown", &clock, &source)
                .await
                .is_err()
        );
        assert_eq!(source.calls.get(), 1);
        clock.0.set(1_131_000);
        source.body.replace(jwks(&config, "rotated"));
        google_keys(&cache, "rotated", &clock, &source)
            .await
            .unwrap();
        assert_eq!(source.calls.get(), 2);
        clock.0.set(1_162_000);
        source.fail.set(true);
        assert!(
            google_keys(&cache, "unknown", &clock, &source)
                .await
                .is_err()
        );
        assert_eq!(source.calls.get(), 3);
        // Failed refresh does not poison still-fresh trusted data, nor permit stale data.
        google_keys(&cache, "rotated", &clock, &source)
            .await
            .unwrap();
        assert!(google_keys(&cache, "other", &clock, &source).await.is_err());
        assert_eq!(source.calls.get(), 3);
        clock.0.set(1_252_000);
        assert!(
            google_keys(&cache, "rotated", &clock, &source)
                .await
                .is_err()
        );
        assert_eq!(source.calls.get(), 4);
    }
    #[cfg(feature = "native")]
    #[tokio::test(flavor = "current_thread")]
    async fn google_refresh_single_flight_cancellation_and_slow_response() {
        let (config, _) = fixture();
        let clock = MovingClock(1_100_000.into());
        let source = fake(&clock, &config);
        let cache = Mutex::new(GoogleKeyCache::default());
        source.pending.set(true);
        let mut inflight = Box::pin(google_keys(&cache, "test-only", &clock, &source));
        assert!(futures_util::poll!(inflight.as_mut()).is_pending());
        assert!(
            google_keys(&cache, "test-only", &clock, &source)
                .await
                .is_err()
        );
        assert_eq!(source.calls.get(), 1);
        drop(inflight);
        source.pending.set(false);
        assert!(
            google_keys(&cache, "test-only", &clock, &source)
                .await
                .is_err()
        );
        assert_eq!(source.calls.get(), 1);
        clock.0.set(1_131_000);
        source.elapsed.set(2000);
        source.max_age.replace("max-age=1".into());
        assert!(
            google_keys(&cache, "test-only", &clock, &source)
                .await
                .is_err()
        );
        assert!(cache.try_lock().unwrap().keys.is_empty());
        clock.0.set(1_162_000);
        source.elapsed.set(0);
        source.max_age.replace("max-age=60".into());
        google_keys(&cache, "test-only", &clock, &source)
            .await
            .unwrap();
        assert_eq!(source.calls.get(), 3);
    }
    #[test]
    fn google_cache_headers_key_validation_and_provider_binding() {
        let (config, _) = fixture();
        let bytes = jwks(&config, "test-only");
        for (control, age, expected) in [
            ("max-age=7200", None, Some(3_600_000)),
            ("public,max-age=10", Some("9"), Some(1000)),
            ("max-age=10", Some("10"), None),
            ("no-store,max-age=100", None, None),
            ("no-cache", None, None),
            ("max-age=0", None, None),
            ("max-age=10,max-age=20", None, None),
            ("max-age=NaN", None, None),
            ("max-age=10", Some("-1"), None),
        ] {
            let response = GoogleJwksResponse {
                body: bytes.clone(),
                cache_control: Some(control.into()),
                age: age.map(str::to_owned),
            };
            assert_eq!(cache_lifetime(&response).ok(), expected, "{control}");
        }
        let good: Value = serde_json::from_slice(&bytes).unwrap();
        for (field, value) in [
            ("kty", json!("EC")),
            ("alg", json!("HS256")),
            ("use", json!("enc")),
            ("key_ops", json!(["sign"])),
            ("n", json!("bad")),
            ("e", json!("Aw")),
            ("kid", json!("")),
        ] {
            let mut bad = good.clone();
            bad["keys"][0][field] = value;
            assert!(parse_google_keys(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(
            parse_google_keys(
                &serde_json::to_vec(&json!({"keys":[good["keys"][0],good["keys"][0]]})).unwrap()
            )
            .is_err()
        );
        let mut google = config;
        google.google_jwks = true;
        google.keys.clear();
        google.issuer = GOOGLE_ISSUER.into();
        google.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth".into();
        google.token_endpoint = "https://oauth2.googleapis.com/token".into();
        google.validate().unwrap();
        for endpoint in [
            "https://evil.example/token",
            "http://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com/token?x=1",
        ] {
            let mut bad = google.clone();
            bad.token_endpoint = endpoint.into();
            assert!(bad.validate().is_err());
        }
        google.issuer = "accounts.google.com".into();
        assert!(google.validate().is_err());
    }
    #[cfg(feature = "native")]
    #[tokio::test(flavor = "current_thread")]
    async fn google_verification_canonicalizes_only_google_and_uses_postfetch_clock() {
        let (pinned, private) = fixture();
        let clock = MovingClock(1_100_000.into());
        let source = fake(&clock, &pinned);
        let mut google = pinned.clone();
        google.google_jwks = true;
        google.keys.clear();
        google.issuer = GOOGLE_ISSUER.into();
        google.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth".into();
        google.token_endpoint = "https://oauth2.googleapis.com/token".into();
        for issuer in [GOOGLE_ISSUER, "accounts.google.com"] {
            GOOGLE_CACHE.with(|c| *c.try_lock().unwrap() = GoogleKeyCache::default());
            let mut claims = claims();
            claims["iss"] = json!(issuer);
            let signed = token(&private, claims.clone());
            let identity = google
                .verify_current(&signed, NONCE, &clock, &source)
                .await
                .unwrap();
            assert_eq!(identity.issuer, GOOGLE_ISSUER);
            assert!(pinned.verify(&signed, NONCE, clock.0.get()).is_err());
        }
        GOOGLE_CACHE.with(|c| *c.try_lock().unwrap() = GoogleKeyCache::default());
        let mut expiring = claims();
        expiring["iss"] = json!(GOOGLE_ISSUER);
        expiring["exp"] = json!(1101);
        source.elapsed.set(2000);
        assert!(
            google
                .verify_current(&token(&private, expiring), NONCE, &clock, &source)
                .await
                .is_err()
        );
        let before = source.calls.get();
        assert!(
            google
                .verify_current(
                    &signed(
                        &private,
                        json!({"alg":"RS256","kid":"test-only","jku":"https://evil.example"}),
                        claims()
                    ),
                    NONCE,
                    &clock,
                    &source
                )
                .await
                .is_err()
        );
        assert_eq!(source.calls.get(), before);
        GOOGLE_CACHE.with(|c| *c.try_lock().unwrap() = GoogleKeyCache::default());
    }
    #[test]
    fn valid_signed_identity_and_multi_audience() {
        let (config, private) = fixture();
        assert_eq!(
            config
                .verify(&token(&private, claims()), NONCE, 1_100_000)
                .unwrap(),
            VerifiedIdentity {
                issuer: config.issuer.clone(),
                subject: "immutable-subject".into()
            }
        );
        let mut c = claims();
        c["aud"] = json!(["waypost-test", "another"]);
        c["azp"] = json!("waypost-test");
        assert!(config.verify(&token(&private, c), NONCE, 1_100_000).is_ok());
    }
    #[test]
    fn rejects_claim_mismatch_expiry_future_and_stale_login() {
        let (config, private) = fixture();
        for (field, value) in [
            ("iss", json!("https://other.example")),
            ("aud", json!("other")),
            ("sub", json!("")),
            ("nonce", json!("other")),
            ("exp", json!(1100)),
            ("iat", json!(1131)),
            ("iat", json!(499)),
            ("nbf", json!(1131)),
            ("azp", json!("other")),
            ("aud", json!(["waypost-test", "other"])),
        ] {
            let mut c = claims();
            c[field] = value;
            assert!(
                config
                    .verify(&token(&private, c), NONCE, 1_100_000)
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn rejects_algorithm_confusion_unknown_keys_and_remote_key_headers() {
        let (config, private) = fixture();
        for header in [
            json!({"alg":"none","kid":"test-only"}),
            json!({"alg":"HS256","kid":"test-only"}),
            json!({"alg":"RS256","kid":"unknown"}),
            json!({"alg":"RS256","kid":"test-only","jku":"https://attacker.example/keys"}),
            json!({"alg":"RS256","kid":"test-only","crit":["b64"]}),
        ] {
            assert!(
                config
                    .verify(&signed(&private, header, claims()), NONCE, 1_100_000)
                    .is_err()
            );
        }
        let mut parts = token(&private, claims())
            .split('.')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut c = claims();
        c["sub"] = json!("attacker");
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap());
        assert!(config.verify(&parts.join("."), NONCE, 1_100_000).is_err());
    }
    #[test]
    fn authorization_request_uses_code_pkce_nonce_and_fixed_endpoint() {
        let (mut config, _) = fixture();
        let url = config
            .authorization_url(
                NONCE,
                NONCE,
                &"A".repeat(43),
                "https://waypost.example/account/callback",
            )
            .unwrap();
        let u = Url::parse(&url).unwrap();
        let pairs = u
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["scope"], "openid");
        config.authorization_endpoint = "http://issuer.example/auth".into();
        assert!(config.validate().is_err());
        config.authorization_endpoint = "https://issuer.example/auth?redirect_uri=evil".into();
        assert!(config.validate().is_err());
    }
}
