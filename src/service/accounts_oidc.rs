//! Optional OIDC code-flow verification. No discovery or token-controlled network access.
//!
//! The caller owns persisted single-use state/nonce, PKCE, browser binding and session
//! creation. Only a configured code-exchange transport can supply the signed ID token.
//! Reference: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{BigUint, RsaPublicKey, pkcs1v15, signature::Verifier, traits::PublicKeyParts};
use serde::Deserialize;
use sha2::Sha256;
use std::{future::Future, pin::Pin};
use url::Url;

/// Trusted runtime adapter, never constructed from browser-supplied endpoints.
/// Implementations must POST to a fixed HTTPS endpoint, reject redirects, bound the
/// response and timeout, and never log code, verifier, client secret or ID token.
/// The output is the signed `id_token`, not the access token or a caller-supplied subject.
/// A failed/ambiguous exchange must not be retried with a new login transaction.
pub trait OidcCodeExchange {
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
    pub keys: Vec<OidcRsaKey>,
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
            || !(1..=8).contains(&self.keys.len())
        {
            return Err(Error::invalid("Invalid OIDC client or key configuration."));
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
        if token.len() > 16384 || expected_nonce.len() < 32 || now_ms < 0 {
            return Err(rejected());
        }
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(rejected());
        }
        let header: Header =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| rejected())?)
                .map_err(|_| rejected())?;
        if header.alg != "RS256"
            || header.crit.is_some()
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.b64.is_some()
        {
            return Err(rejected());
        }
        let pinned = self
            .keys
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
        if claims.iss != self.issuer
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
            issuer: claims.iss,
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
                controller.abort();
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
