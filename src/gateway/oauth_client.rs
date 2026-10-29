//! Client identity checks for OAuth Client ID Metadata Documents (CIMD) and
//! RFC 7591 dynamic registration. Pure functions plus the bounded fetcher.
//!
//! Both runtimes enforce the same URL and host-name policy before any network
//! request. Native fetches additionally resolve the host, refuse non-public
//! addresses and pin the connection to the checked addresses. Workers cannot
//! resolve before connecting; there the host-name policy, Cloudflare egress and
//! the absence of private-network bindings are the boundary.
use crate::error::{Error, Result};
use serde_json::Value;
#[cfg(any(test, feature = "native"))]
use std::net::{IpAddr, Ipv4Addr};
use std::{future::Future, pin::Pin};
use url::{Host, Url};

pub(crate) const MAX_DOCUMENT_BYTES: usize = 5120;
pub(crate) const MAX_CLIENT_ID_BYTES: usize = 512;
pub(crate) const MAX_REDIRECT_URIS: usize = 8;
pub(crate) const FETCH_TIMEOUT_SECS: u64 = 5;
const MIN_CACHE_MS: i64 = 60_000;
const DEFAULT_CACHE_MS: i64 = 300_000;
const MAX_CACHE_MS: i64 = 86_400_000;
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];
const BLOCKED_SUFFIXES: [&str; 9] = [
    "localhost",
    "local",
    "internal",
    "lan",
    "home.arpa",
    "intranet",
    "corp",
    "private",
    "test",
];

fn rejected() -> Error {
    Error::new("invalid_client", "OAuth request could not be completed.")
}

/// A host name the policy allows: a dotted DNS name outside reserved suffixes.
/// IP literals are refused outright; legitimate client documents use names.
pub(crate) fn allowed_host(host: &Host<&str>) -> bool {
    let Host::Domain(name) = host else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    if name.len() > 253 || !name.contains('.') || name.ends_with('.') || name.starts_with('.') {
        return false;
    }
    let labels: Vec<_> = name.split('.').collect();
    if labels
        .iter()
        .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
        || labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    !BLOCKED_SUFFIXES
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

/// Validate a URL-formatted client_id. Returns the parsed URL on success.
pub(crate) fn metadata_document_url(raw: &str) -> Option<Url> {
    if raw.len() > MAX_CLIENT_ID_BYTES || !raw.starts_with("https://") {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    // Exact serialization rejects dot segments, default-port spelling, case
    // folding and other normalization that could make two strings one client.
    if url.as_str() != raw
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().is_empty()
        || url.path() == "/"
        || !allowed_host(&url.host()?)
    {
        return None;
    }
    Some(url)
}

/// Addresses a native fetch may connect to: globally routable unicast only.
#[cfg(any(test, feature = "native"))]
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_v4(v4);
            }
            let s = v6.segments();
            // Only 2000::/3 global unicast, minus documentation, Teredo,
            // 6to4 and NAT64 forms that embed other address spaces.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && !(s[0] == 0x2001 && s[1] == 0x0000)
                && s[0] != 0x2002
                && !(s[0] == 0x0064 && s[1] == 0xff9b)
        }
    }
}
#[cfg(any(test, feature = "native"))]
fn public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || o[0] >= 240)
}

/// A redirect URI a non-preregistered client may declare: HTTPS, or HTTP on a
/// literal loopback host. No query, fragment or user information.
pub(crate) fn declarable_redirect(raw: &str) -> bool {
    let Ok(u) = Url::parse(raw) else {
        return false;
    };
    raw.len() <= 2048
        && u.as_str() == raw
        && u.fragment().is_none()
        && u.query().is_none()
        && u.username().is_empty()
        && u.password().is_none()
        && match u.scheme() {
            "https" => u.host_str().is_some(),
            "http" => u.host_str().is_some_and(|h| LOOPBACK_HOSTS.contains(&h)),
            _ => false,
        }
}

/// RFC 8252 §7.3 for metadata-document and dynamically registered clients: a
/// loopback HTTP redirect may use any non-zero port at request time. Scheme,
/// host spelling (127.0.0.1, [::1] and localhost are distinct) and path stay exact.
pub(crate) fn redirect_matches(registered: &str, candidate: &str) -> bool {
    if registered == candidate {
        return true;
    }
    let (Ok(r), Ok(c)) = (Url::parse(registered), Url::parse(candidate)) else {
        return false;
    };
    c.as_str() == candidate
        && r.scheme() == "http"
        && c.scheme() == "http"
        && r.host_str().is_some_and(|h| LOOPBACK_HOSTS.contains(&h))
        && r.host_str() == c.host_str()
        && c.port().is_some_and(|p| p != 0)
        && r.path() == c.path()
        && c.query().is_none()
        && c.fragment().is_none()
        && c.username().is_empty()
        && c.password().is_none()
}

/// Whether every declared redirect is a loopback URI (MCP spec: warn the user,
/// any local process can bind such a port).
pub(crate) fn loopback_only(redirects: &[String]) -> bool {
    redirects.iter().all(|r| {
        Url::parse(r).is_ok_and(|u| {
            u.scheme() == "http" && u.host_str().is_some_and(|h| LOOPBACK_HOSTS.contains(&h))
        })
    })
}

pub(crate) fn display_host(uri: &str) -> String {
    Url::parse(uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

fn display_name(value: Option<&Value>) -> Option<String> {
    let name = value?.as_str()?.trim();
    (!name.is_empty() && name.len() <= 200 && !name.chars().any(char::is_control))
        .then(|| name.to_owned())
}

fn redirect_list(value: Option<&Value>) -> Option<Vec<String>> {
    let list = value?.as_array()?;
    if list.is_empty() || list.len() > MAX_REDIRECT_URIS {
        return None;
    }
    let mut out = Vec::new();
    for item in list {
        let uri = item.as_str()?;
        if !declarable_redirect(uri) || out.iter().any(|u| u == uri) {
            return None;
        }
        out.push(uri.to_owned());
    }
    Some(out)
}

/// Grant types must include the authorization-code grant. Refresh is allowed;
/// anything else is not part of this public-client profile.
fn grant_types_ok(value: Option<&Value>) -> bool {
    let Some(value) = value else { return true };
    let Some(list) = value.as_array() else {
        return false;
    };
    list.iter().any(|g| g == "authorization_code")
        && list
            .iter()
            .all(|g| g == "authorization_code" || g == "refresh_token")
}
fn response_types_ok(value: Option<&Value>) -> bool {
    value.is_none_or(|v| v.as_array().is_some_and(|l| l.len() == 1 && l[0] == "code"))
}
/// First version: public clients only. A declared private_key_jwt (or any other
/// method) is a different client contract, not something to negotiate down.
fn public_client(value: Option<&Value>) -> bool {
    value.is_none_or(|v| v == "none")
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ClientDocument {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

pub(crate) struct FetchedDocument {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
}

/// Validate a fetched metadata document against the URL it came from.
pub(crate) fn parse_document(client_id: &str, fetched: &FetchedDocument) -> Result<ClientDocument> {
    let json = fetched
        .content_type
        .as_deref()
        .and_then(|t| t.split(';').next())
        .map(|t| t.trim().to_ascii_lowercase())
        .is_some_and(|t| t == "application/json" || t.ends_with("+json"));
    if !json || fetched.body.len() > MAX_DOCUMENT_BYTES {
        return Err(rejected());
    }
    let doc = crate::json::parse(&fetched.body, MAX_DOCUMENT_BYTES).map_err(|_| rejected())?;
    let object = doc.as_object().ok_or_else(rejected)?;
    if doc.get("client_id").and_then(Value::as_str) != Some(client_id)
        || object.contains_key("client_secret")
        || object.contains_key("client_secret_expires_at")
        || !public_client(doc.get("token_endpoint_auth_method"))
        || !grant_types_ok(doc.get("grant_types"))
        || !response_types_ok(doc.get("response_types"))
    {
        return Err(rejected());
    }
    Ok(ClientDocument {
        client_name: display_name(doc.get("client_name")).ok_or_else(rejected)?,
        redirect_uris: redirect_list(doc.get("redirect_uris")).ok_or_else(rejected)?,
    })
}

/// Cache lifetime honoring Cache-Control within fixed bounds.
pub(crate) fn cache_ttl_ms(cache_control: Option<&str>) -> i64 {
    let Some(header) = cache_control else {
        return DEFAULT_CACHE_MS;
    };
    let mut ttl = None;
    for directive in header.split(',').map(|d| d.trim().to_ascii_lowercase()) {
        if directive == "no-store" || directive == "no-cache" {
            return MIN_CACHE_MS;
        }
        if let Some(seconds) = directive.strip_prefix("max-age=") {
            ttl = seconds.trim_matches('"').parse::<i64>().ok();
        }
    }
    ttl.map(|s| s.saturating_mul(1000))
        .unwrap_or(DEFAULT_CACHE_MS)
        .clamp(MIN_CACHE_MS, MAX_CACHE_MS)
}

/// RFC 7591 registration metadata accepted by this server.
#[derive(Debug, PartialEq)]
pub(crate) struct Registration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
}
/// Returns the RFC 7591 error code on failure.
pub(crate) fn parse_registration(body: &Value) -> std::result::Result<Registration, &'static str> {
    if !body.is_object() {
        return Err("invalid_client_metadata");
    }
    let redirect_uris = redirect_list(body.get("redirect_uris")).ok_or("invalid_redirect_uri")?;
    if !public_client(body.get("token_endpoint_auth_method"))
        || !grant_types_ok(body.get("grant_types"))
        || !response_types_ok(body.get("response_types"))
        || body.get("client_secret").is_some()
    {
        return Err("invalid_client_metadata");
    }
    let client_name = match body.get("client_name") {
        None => "Unnamed client".to_owned(),
        Some(v) => display_name(Some(v)).ok_or("invalid_client_metadata")?,
    };
    let grant_types = match body.get("grant_types").and_then(Value::as_array) {
        Some(list) => list
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        None => vec!["authorization_code".to_owned()],
    };
    Ok(Registration {
        client_name,
        redirect_uris,
        grant_types,
    })
}

/// Fetches a metadata document. Implementations must not follow redirects and
/// must stop reading beyond `MAX_DOCUMENT_BYTES`.
pub(crate) trait ClientMetadataFetch {
    fn fetch<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedDocument>> + 'a>>;
}

/// The production fetcher for the current runtime.
pub(crate) struct HttpMetadataFetcher;

#[cfg(feature = "native")]
impl HttpMetadataFetcher {
    async fn fetch_native(url: &Url) -> Result<FetchedDocument> {
        let host = url.host_str().ok_or_else(rejected)?.to_owned();
        let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), 443))
            .await
            .map_err(|_| rejected())?
            .collect();
        if addrs.is_empty() || addrs.iter().any(|a| !public_ip(a.ip())) {
            return Err(rejected());
        }
        // Pin to the checked addresses and bypass proxies, which would resolve
        // the name again outside this check.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(&host, &addrs)
            .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
            .build()
            .map_err(|_| rejected())?;
        let mut response = client
            .get(url.as_str())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|_| rejected())?;
        if response.status().as_u16() != 200 {
            return Err(rejected());
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let content_type = header("content-type");
        let cache_control = header("cache-control");
        if response
            .content_length()
            .is_some_and(|n| n > MAX_DOCUMENT_BYTES as u64)
        {
            return Err(rejected());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| rejected())? {
            if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                return Err(rejected());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchedDocument {
            body,
            content_type,
            cache_control,
        })
    }
}

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

#[cfg(all(not(feature = "native"), feature = "cloudflare"))]
impl HttpMetadataFetcher {
    async fn fetch_worker(url: &Url) -> Result<FetchedDocument> {
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
            worker::Request::new_with_init(url.as_str(), &init).map_err(|_| rejected())?;
        let controller = worker::AbortController::default();
        let signal = controller.signal();
        let guard = AbortOnDrop(Some(controller));
        let fetch = async {
            let mut response = worker::Fetch::Request(request)
                .send_with_signal(&signal)
                .await
                .map_err(|_| rejected())?;
            if response.status_code() != 200 {
                return Err(rejected());
            }
            let content_type = response
                .headers()
                .get("content-type")
                .map_err(|_| rejected())?;
            let cache_control = response
                .headers()
                .get("cache-control")
                .map_err(|_| rejected())?;
            let mut stream = response.stream().map_err(|_| rejected())?;
            let mut body = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| rejected())?;
                if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                    return Err(rejected());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(FetchedDocument {
                body,
                content_type,
                cache_control,
            })
        };
        let result = match select(
            Box::pin(fetch),
            Box::pin(worker::Delay::from(std::time::Duration::from_secs(
                FETCH_TIMEOUT_SECS,
            ))),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right(_) => Err(rejected()),
        };
        drop(guard);
        result
    }
}

impl ClientMetadataFetch for HttpMetadataFetcher {
    fn fetch<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedDocument>> + 'a>> {
        Box::pin(async move {
            // Re-check here so no caller can skip the policy.
            if metadata_document_url(url.as_str()).is_none() {
                return Err(rejected());
            }
            #[cfg(feature = "native")]
            {
                Self::fetch_native(url).await
            }
            #[cfg(all(not(feature = "native"), feature = "cloudflare"))]
            {
                Self::fetch_worker(url).await
            }
            #[cfg(not(any(feature = "native", feature = "cloudflare")))]
            {
                Err(rejected())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(value: Value) -> FetchedDocument {
        FetchedDocument {
            body: serde_json::to_vec(&value).unwrap(),
            content_type: Some("application/json; charset=utf-8".into()),
            cache_control: None,
        }
    }

    #[test]
    fn metadata_urls_require_https_path_and_public_names() {
        for ok in [
            "https://claude.ai/oauth/claude-code-client-metadata",
            "https://chatgpt.com/oauth/codex/client.json",
            "https://keys.miles1150.top/oauth/clients/keyenv-remote.json",
        ] {
            assert!(metadata_document_url(ok).is_some(), "{ok}");
        }
        for bad in [
            "http://claude.ai/oauth/client.json",
            "https://claude.ai",
            "https://claude.ai/",
            "https://claude.ai/a/../client.json",
            "https://claude.ai/./client.json",
            "https://Claude.ai/client.json",
            "https://claude.ai:443/client.json",
            "https://claude.ai:8443/client.json",
            "https://claude.ai/client.json?x=1",
            "https://claude.ai/client.json#x",
            "https://user@claude.ai/client.json",
            "https://127.0.0.1/client.json",
            "https://[::1]/client.json",
            "https://2130706433/client.json",
            "https://0x7f.0.0.1/client.json",
            "https://localhost/client.json",
            "https://foo.localhost/client.json",
            "https://printer.local/client.json",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://router.home.arpa/client.json",
            "https://intranet/client.json",
            "https://example.com./client.json",
            "https://1.2.3.4.5/client.json",
        ] {
            assert!(metadata_document_url(bad).is_none(), "{bad}");
        }
        assert!(metadata_document_url(&format!("https://a.example/{}", "x".repeat(600))).is_none());
    }

    #[test]
    fn only_global_unicast_addresses_are_public() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "192.0.0.8",
            "::",
            "::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "64:ff9b::7f00:1",
            "2001::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn documents_bind_client_id_and_public_auth() {
        let id = "https://claude.ai/oauth/claude-code-client-metadata";
        // The document as served by claude.ai on 2026-10-29.
        let claude = json!({"client_id":id,"client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"});
        let parsed = parse_document(id, &doc(claude.clone())).unwrap();
        assert_eq!(parsed.client_name, "Claude Code");
        assert_eq!(parsed.redirect_uris.len(), 2);
        let mut cases = vec![];
        for (key, value) in [
            ("client_id", json!("https://evil.example/client.json")),
            ("token_endpoint_auth_method", json!("private_key_jwt")),
            ("token_endpoint_auth_method", json!("client_secret_basic")),
            ("client_secret", json!("x")),
            ("grant_types", json!(["refresh_token"])),
            (
                "grant_types",
                json!(["authorization_code", "client_credentials"]),
            ),
            ("response_types", json!(["token"])),
            ("redirect_uris", json!([])),
            ("redirect_uris", json!(["http://evil.example/callback"])),
            ("redirect_uris", json!(["https://a.example/cb#x"])),
            ("redirect_uris", json!(["https://a.example/cb?x=1"])),
            ("redirect_uris", json!(["myapp://callback"])),
            ("client_name", json!("")),
            ("client_name", json!("bad\u{7}name")),
        ] {
            let mut v = claude.clone();
            v[key] = value;
            cases.push(v);
        }
        let mut missing = claude.clone();
        missing.as_object_mut().unwrap().remove("client_name");
        cases.push(missing);
        for case in cases {
            assert!(parse_document(id, &doc(case.clone())).is_err(), "{case}");
        }
        let mut html = doc(claude.clone());
        html.content_type = Some("text/html".into());
        assert!(parse_document(id, &html).is_err());
        let mut big = claude.clone();
        big["padding"] = json!("x".repeat(MAX_DOCUMENT_BYTES));
        assert!(parse_document(id, &doc(big)).is_err());
        let duplicate = FetchedDocument {
            body: format!(r#"{{"client_id":"{id}","client_id":"{id}","client_name":"x","redirect_uris":["http://127.0.0.1/callback"]}}"#).into_bytes(),
            content_type: Some("application/json".into()),
            cache_control: None,
        };
        assert!(parse_document(id, &duplicate).is_err());
    }

    #[test]
    fn loopback_redirects_allow_any_port_but_exact_host_and_path() {
        let r = "http://127.0.0.1/callback";
        assert!(redirect_matches(r, "http://127.0.0.1:53124/callback"));
        assert!(redirect_matches(r, r));
        assert!(redirect_matches(
            "http://127.0.0.1:8765/callback",
            "http://127.0.0.1:9000/callback"
        ));
        assert!(redirect_matches(
            "http://localhost/callback",
            "http://localhost:4000/callback"
        ));
        assert!(redirect_matches("http://[::1]/cb", "http://[::1]:4000/cb"));
        for bad in [
            "http://localhost:53124/callback",
            "http://[::1]:53124/callback",
            "http://127.0.0.2:53124/callback",
            "https://127.0.0.1:53124/callback",
            "http://127.0.0.1:53124/callback/x",
            "http://127.0.0.1:53124/callbac",
            "http://127.0.0.1:53124/callback?x=1",
            "http://127.0.0.1:53124/callback#x",
            "http://u@127.0.0.1:53124/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:53124/a/../callback",
            "http://2130706433:53124/callback",
        ] {
            assert!(!redirect_matches(r, bad), "{bad}");
        }
        // HTTPS redirects stay exact.
        assert!(!redirect_matches(
            "https://app.example/cb",
            "https://app.example:444/cb"
        ));
        assert!(loopback_only(&[r.into(), "http://localhost/cb".into()]));
        assert!(!loopback_only(&[r.into(), "https://app.example/cb".into()]));
    }

    #[test]
    fn cache_ttl_is_bounded() {
        assert_eq!(cache_ttl_ms(None), DEFAULT_CACHE_MS);
        assert_eq!(cache_ttl_ms(Some("public, max-age=600")), 600_000);
        assert_eq!(cache_ttl_ms(Some("max-age=1")), MIN_CACHE_MS);
        assert_eq!(cache_ttl_ms(Some("max-age=99999999")), MAX_CACHE_MS);
        assert_eq!(cache_ttl_ms(Some("no-store")), MIN_CACHE_MS);
        assert_eq!(cache_ttl_ms(Some("max-age=garbage")), DEFAULT_CACHE_MS);
    }

    #[test]
    fn registration_is_public_client_only() {
        let ok = parse_registration(&json!({"redirect_uris":["http://localhost:6274/callback"],"client_name":"Claude Code","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"waypost","software_id":"x"})).unwrap();
        assert_eq!(ok.client_name, "Claude Code");
        assert_eq!(
            parse_registration(
                &json!({"redirect_uris":["https://www.cursor.com/agents/mcp/oauth/callback"]})
            )
            .unwrap()
            .grant_types,
            vec!["authorization_code"]
        );
        for (body, error) in [
            (json!({}), "invalid_redirect_uri"),
            (
                json!({"redirect_uris":["http://evil.example/cb"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["http://127.0.0.1/cb","http://127.0.0.1/cb"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris":["http://127.0.0.1/cb"],"token_endpoint_auth_method":"client_secret_post"}),
                "invalid_client_metadata",
            ),
            (
                json!({"redirect_uris":["http://127.0.0.1/cb"],"grant_types":["implicit"]}),
                "invalid_client_metadata",
            ),
            (
                json!({"redirect_uris":["http://127.0.0.1/cb"],"response_types":["token"]}),
                "invalid_client_metadata",
            ),
            (
                json!({"redirect_uris":["http://127.0.0.1/cb"],"client_name":7}),
                "invalid_client_metadata",
            ),
            (json!([]), "invalid_client_metadata"),
        ] {
            assert_eq!(parse_registration(&body), Err(error), "{body}");
        }
    }
}
