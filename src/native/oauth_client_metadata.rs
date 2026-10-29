//! Native-only CIMD transport. All DNS answers are validated once and pinned to
//! this request; the URL hostname remains unchanged for TLS SNI/certificate checks.
//! Worker Fetch has no equivalent validated-address pinning here and must not use
//! this adapter's capability flag. No metadata fetch runs through a proxy.
use crate::{
    error::{Error, Result},
    service::oauth_client_registry::{
        OAuthClientMetadataDocument, OAuthClientMetadataFetcher, validate_cimd_url,
    },
};
use futures_util::StreamExt;
use reqwest::{Client, redirect::Policy};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::Duration,
};
use url::{Host, Url};

const MAX_BODY: usize = 16 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_AGE: u32 = 60;

#[derive(Default)]
pub struct NativeClientMetadataFetcher;
impl NativeClientMetadataFetcher {
    /// Known proxy policy makes direct DNS-pinned transport unavailable. Callers
    /// must omit CIMD capability rather than bypass the proxy or advertise it.
    pub fn supported_in_environment() -> bool {
        !proxy_configured()
    }
}
impl OAuthClientMetadataFetcher for NativeClientMetadataFetcher {
    fn fetch<'a>(
        &'a self,
        client_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClientMetadataDocument>> + 'a>> {
        Box::pin(async move {
            // Refuse rather than bypass an operator/platform-mandated proxy. The
            // client also disables implicit proxy discovery in the no-proxy case.
            if proxy_configured() {
                return Err(fetch_error());
            }
            fetch_with_deadline(client_id, &NativeTransport, FETCH_TIMEOUT).await
        })
    }
}
fn fetch_error() -> Error {
    Error::invalid("Client metadata could not be fetched safely.")
}
fn proxy_configured() -> bool {
    [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some_and(|v| !v.is_empty()))
}
struct Target {
    url: Url,
    host: String,
    addresses: Vec<SocketAddr>,
}
struct MetadataResponse {
    status: u16,
    content_type: String,
    encoding: Option<String>,
    cache_control: Vec<String>,
    age: Option<String>,
    expires_present: bool,
    body: Vec<u8>,
}
trait Transport {
    async fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>>;
    async fn get(&self, target: Target) -> Result<MetadataResponse>;
}
struct NativeTransport;
impl Transport for NativeTransport {
    async fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>> {
        let addresses = tokio::net::lookup_host((host, 443))
            .await
            .map_err(|_| fetch_error())?;
        Ok(addresses.take(65).collect())
    }
    async fn get(&self, target: Target) -> Result<MetadataResponse> {
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .timeout(FETCH_TIMEOUT)
            .connect_timeout(FETCH_TIMEOUT)
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(&target.host, &target.addresses)
            .user_agent("Waypost-CIMD/1")
            .build()
            .map_err(|_| fetch_error())?;
        let response = client
            .get(target.url)
            .header("accept", "application/json")
            .header("accept-encoding", "identity")
            .send()
            .await
            .map_err(|_| fetch_error())?;
        // Do not consume an error/redirect body, nor trust a length announcement as
        // the sole bound. Redirects never trigger a second destination fetch.
        if response.status().as_u16() != 200
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(fetch_error());
        }
        let headers = response.headers();
        let header = |name: &str| -> Result<Option<String>> {
            headers
                .get(name)
                .map(|v| v.to_str().map(str::to_owned).map_err(|_| fetch_error()))
                .transpose()
        };
        let content_type = header("content-type")?.ok_or_else(fetch_error)?;
        let encoding = header("content-encoding")?;
        let age = header("age")?;
        let expires_present = headers.contains_key("expires");
        let cache_control = headers
            .get_all("cache-control")
            .iter()
            .map(|v| v.to_str().map(str::to_owned).map_err(|_| fetch_error()))
            .collect::<Result<Vec<_>>>()?;
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| fetch_error())?;
            if chunk.len() > MAX_BODY.saturating_sub(body.len()) {
                return Err(fetch_error());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(MetadataResponse {
            status: 200,
            content_type,
            encoding,
            cache_control,
            age,
            expires_present,
            body,
        })
    }
}
async fn fetch_with_deadline<T: Transport>(
    client_id: &str,
    transport: &T,
    timeout: Duration,
) -> Result<OAuthClientMetadataDocument> {
    tokio::time::timeout(timeout, fetch_using(client_id, transport))
        .await
        .map_err(|_| fetch_error())?
}
async fn fetch_using<T: Transport>(
    client_id: &str,
    transport: &T,
) -> Result<OAuthClientMetadataDocument> {
    let started = tokio::time::Instant::now();
    let url = validate_cimd_url(client_id)?;
    // Defense in depth: this transport never broadens a core validator's policy.
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || url.path().is_empty()
        || url.path() == "/"
        || url.as_str() != client_id
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(fetch_error());
    }
    let host = url.host_str().ok_or_else(fetch_error)?.to_owned();
    let mut addresses = match url.host().ok_or_else(fetch_error)? {
        Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), 443)],
        Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), 443)],
        Host::Domain(name) => transport.resolve(name).await?,
    };
    if addresses.is_empty()
        || addresses.len() > 64
        || addresses
            .iter()
            .any(|a| a.port() != 443 || !public_address(a.ip()))
    {
        return Err(fetch_error());
    }
    addresses.sort();
    addresses.dedup();
    let response = transport
        .get(Target {
            url,
            host,
            addresses,
        })
        .await?;
    let mime = response
        .content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if response.status != 200
        || response.body.len() > MAX_BODY
        || response
            .encoding
            .as_deref()
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        || !(mime == "application/json"
            || (mime.starts_with("application/") && mime.ends_with("+json")))
    {
        return Err(fetch_error());
    }
    // Cache headers describe freshness at the origin, not after DNS/body waits.
    // Round elapsed time up so integer-second caching cannot extend that lifetime.
    let elapsed = started.elapsed();
    let elapsed_seconds = elapsed
        .as_secs()
        .saturating_add(u64::from(elapsed.subsec_nanos() != 0));
    let max_age_seconds =
        freshness(&response)?.saturating_sub(u32::try_from(elapsed_seconds).unwrap_or(u32::MAX));
    Ok(OAuthClientMetadataDocument {
        body: response.body,
        max_age_seconds,
    })
}
fn freshness(response: &MetadataResponse) -> Result<u32> {
    let mut max_age = None;
    let mut shared_age = None;
    for header in &response.cache_control {
        for directive in header.split(',') {
            let (name, value) = directive
                .trim()
                .split_once('=')
                .map(|(n, v)| (n.trim().to_ascii_lowercase(), Some(v.trim())))
                .unwrap_or_else(|| (directive.trim().to_ascii_lowercase(), None));
            if matches!(name.as_str(), "no-store" | "no-cache" | "private") {
                return Ok(0);
            }
            if name == "max-age" || name == "s-maxage" {
                let n = value
                    .ok_or_else(fetch_error)?
                    .trim_matches('"')
                    .parse::<u32>()
                    .map_err(|_| fetch_error())?;
                let slot = if name == "max-age" {
                    &mut max_age
                } else {
                    &mut shared_age
                };
                if slot.replace(n).is_some() {
                    return Err(fetch_error());
                }
            }
        }
    }
    let freshness = match (max_age, shared_age) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) if response.expires_present => 0,
        _ => DEFAULT_MAX_AGE,
    };
    let age = response
        .age
        .as_deref()
        .map(|s| s.parse::<u32>().map_err(|_| fetch_error()))
        .transpose()?
        .unwrap_or(0);
    Ok(freshness.saturating_sub(age))
}
/// Conservative public-unicast profile: reject all IANA special-purpose blocks,
/// including globally-routable exceptions, and IPv6 transition/mapped addresses.
/// Registry snapshots checked 2026-10-29; new allocations require policy review.
fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && ((b == 0 && (c == 0 || c == 2))
                        || b == 168
                        || (b == 31 && c == 196)
                        || (b == 52 && c == 193)
                        || (b == 88 && c == 99)
                        || (b == 175 && c == 48)))
                || (a == 198 && ((18..=19).contains(&b) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            ip.to_ipv4_mapped().is_none()
                && s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
                && !(s[0] == 0x3fff && s[1] & 0xf000 == 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Mock {
        answers: Vec<SocketAddr>,
        calls: Cell<usize>,
        target: RefCell<Option<Target>>,
        response: RefCell<Option<MetadataResponse>>,
    }
    impl Transport for Mock {
        async fn resolve(&self, _: &str) -> Result<Vec<SocketAddr>> {
            Ok(self.answers.clone())
        }
        async fn get(&self, target: Target) -> Result<MetadataResponse> {
            self.calls.set(self.calls.get() + 1);
            *self.target.borrow_mut() = Some(target);
            self.response.borrow_mut().take().ok_or_else(fetch_error)
        }
    }
    fn response() -> MetadataResponse {
        MetadataResponse {
            status: 200,
            content_type: "application/json".into(),
            encoding: None,
            cache_control: vec![],
            age: None,
            expires_present: false,
            body: b"{}".to_vec(),
        }
    }
    fn mock(ips: &[&str], response: MetadataResponse) -> Mock {
        Mock {
            answers: ips
                .iter()
                .map(|ip| SocketAddr::new(ip.parse().unwrap(), 443))
                .collect(),
            calls: Cell::new(0),
            target: RefCell::new(None),
            response: RefCell::new(Some(response)),
        }
    }
    #[test]
    fn special_use_and_mapped_addresses_are_rejected() {
        for ip in [
            "0.1.2.3",
            "10.2.3.4",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.2.3",
            "192.0.0.9",
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.168.1.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "2620:4f:8000::1",
            "3fff:fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_dns_answers_never_connect_and_public_answers_are_pinned() {
        let bad = mock(&["8.8.8.8", "127.0.0.1"], response());
        assert!(
            fetch_using("https://client.example/metadata.json", &bad)
                .await
                .is_err()
        );
        assert_eq!(bad.calls.get(), 0);
        let good = mock(&["8.8.8.8", "2606:4700:4700::1111"], response());
        let doc = fetch_using("https://client.example/metadata.json", &good)
            .await
            .unwrap();
        assert!((59..=60).contains(&doc.max_age_seconds));
        let borrow = good.target.borrow();
        let target = borrow.as_ref().unwrap();
        assert_eq!(target.host, "client.example");
        assert_eq!(target.url.as_str(), "https://client.example/metadata.json");
        assert_eq!(target.addresses.len(), 2);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn redirects_nonjson_encoding_and_oversized_bodies_fail() {
        for kind in 0..4 {
            let mut r = response();
            match kind {
                0 => r.status = 302,
                1 => r.content_type = "text/html".into(),
                2 => r.encoding = Some("gzip".into()),
                _ => r.body = vec![b'x'; MAX_BODY + 1],
            }
            let transport = mock(&["8.8.8.8"], r);
            assert!(
                fetch_using("https://client.example/metadata.json", &transport)
                    .await
                    .is_err()
            );
            assert_eq!(transport.calls.get(), 1);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn forbidden_urls_and_literal_addresses_never_connect() {
        for url in [
            "http://client.example/meta",
            "https://client.example/",
            "https://client.example:8443/meta",
            "https://client.example/meta?q=1",
            "https://client.example/meta#f",
            "https://user@client.example/meta",
            "https://127.0.0.1/meta",
            "https://[::ffff:8.8.8.8]/meta",
        ] {
            let t = mock(&["8.8.8.8"], response());
            assert!(fetch_using(url, &t).await.is_err(), "{url}");
            assert_eq!(t.calls.get(), 0);
        }
    }
    #[test]
    fn cache_freshness_honors_revalidation_age_and_duplicate_rejection() {
        let mut r = response();
        r.cache_control = vec!["public, max-age=120".into()];
        r.age = Some("30".into());
        assert_eq!(freshness(&r).unwrap(), 90);
        r.cache_control.push("no-store".into());
        assert_eq!(freshness(&r).unwrap(), 0);
        r.cache_control = vec!["no-cache".into()];
        assert_eq!(freshness(&r).unwrap(), 0);
        r.cache_control = vec!["max-age=120, max-age=130".into()];
        assert!(freshness(&r).is_err());
        r.cache_control.clear();
        r.expires_present = true;
        assert_eq!(freshness(&r).unwrap(), 0);
    }
    struct StalledTransport {
        dns_stalls: bool,
    }
    impl Transport for StalledTransport {
        async fn resolve(&self, _: &str) -> Result<Vec<SocketAddr>> {
            if self.dns_stalls {
                std::future::pending().await
            } else {
                Ok(vec!["8.8.8.8:443".parse().unwrap()])
            }
        }
        async fn get(&self, _: Target) -> Result<MetadataResponse> {
            std::future::pending().await
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn overall_deadline_covers_both_dns_and_response_waits() {
        for dns_stalls in [true, false] {
            assert!(
                fetch_with_deadline(
                    "https://client.example/metadata.json",
                    &StalledTransport { dns_stalls },
                    Duration::from_millis(1)
                )
                .await
                .is_err()
            );
        }
    }
}
