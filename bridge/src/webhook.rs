use super::private_file;
use anyhow::{Context, Result, ensure};
use reqwest::{blocking::Client, redirect::Policy};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use url::{Host, Url};

pub struct Reference<'a> {
    pub origin: &'a str,
    pub space: &'a str,
    pub actor: &'a str,
    pub consumer: &'a str,
    pub item: &'a str,
    pub message: &'a str,
}
pub struct Target {
    url_file: PathBuf,
    secret_file: PathBuf,
    test: bool,
    trusted: Vec<Cidr>,
    fingerprint: String,
}
fn read_private(path: &Path) -> Result<String> {
    private_file(path)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .context("private webhook file unavailable")?
        .take(8193)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8192, "private webhook file is too large");
    let text = std::str::from_utf8(&bytes)
        .context("invalid private webhook file")?
        .trim();
    ensure!(
        !text.is_empty() && !text.contains(['\n', '\r']),
        "invalid private webhook file"
    );
    Ok(text.to_owned())
}
fn fingerprint(url: &str, test: bool, trusted: &[Cidr]) -> String {
    // Empty trust keeps the original binding so existing state directories still match.
    let mut material = format!("webhook-v1\0{test}\0{url}");
    if !trusted.is_empty() {
        material.push_str("\0trusted-cidrs-v1");
        for cidr in trusted {
            material.push('\0');
            material.push_str(&cidr.to_string());
        }
    }
    format!("{:x}", Sha256::digest(material.as_bytes()))
}
impl Target {
    pub fn new(
        url_file: PathBuf,
        secret_file: PathBuf,
        test: bool,
        trusted_resolved_cidrs: &[String],
        token_file: &Path,
    ) -> Result<Self> {
        ensure!(
            url_file.is_absolute() && secret_file.is_absolute(),
            "webhook paths must be absolute"
        );
        ensure!(
            fs::canonicalize(&secret_file)? != fs::canonicalize(token_file)?,
            "webhook secret must be distinct from Waypost credential"
        );
        let url = read_private(&url_file)?;
        let secret = read_private(&secret_file)?;
        let token = read_private(token_file)?;
        ensure!(
            secret != token,
            "webhook secret must be distinct from Waypost credential"
        );
        let parsed = parse_url(&url, test)?;
        let trusted = parse_trusted_cidrs(trusted_resolved_cidrs)?;
        let fingerprint = fingerprint(parsed.as_str(), test, &trusted);
        Ok(Self {
            url_file,
            secret_file,
            test,
            trusted,
            fingerprint,
        })
    }
    pub fn binding(&self) -> String {
        self.fingerprint.clone()
    }
    pub fn prepare(&self, token_file: &Path, reference: Reference<'_>) -> Result<Prepared> {
        let Reference {
            origin,
            space,
            actor,
            consumer,
            item,
            message,
        } = reference;
        let url = read_private(&self.url_file)?;
        let parsed = parse_url(&url, self.test)?;
        ensure!(
            fingerprint(parsed.as_str(), self.test, &self.trusted) == self.fingerprint,
            "webhook target changed; use a separate state directory"
        );
        ensure!(
            fs::canonicalize(&self.secret_file)? != fs::canonicalize(token_file)?,
            "webhook secret must be distinct from Waypost credential"
        );
        let secret = read_private(&self.secret_file)?;
        ensure!(
            secret != read_private(token_file)?,
            "webhook secret must be distinct from Waypost credential"
        );
        let (host, port) = (
            parsed
                .host_str()
                .context("invalid webhook host")?
                .to_owned(),
            parsed
                .port_or_known_default()
                .context("invalid webhook port")?,
        );
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent("Waypost/0.1.0 bridge");
        if self.test {
            builder = builder.no_proxy();
        } else {
            for key in [
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ] {
                ensure!(
                    std::env::var_os(key).is_none_or(|v| v.is_empty()),
                    "webhook cannot securely pin targets through a proxy"
                );
            }
            match parsed.host().context("invalid webhook host")? {
                Host::Ipv4(ip) => {
                    ensure!(
                        public_ip(IpAddr::V4(ip)),
                        "webhook target is not a public address"
                    );
                }
                Host::Ipv6(ip) => {
                    ensure!(
                        public_ip(IpAddr::V6(ip)),
                        "webhook target is not a public address"
                    );
                }
                Host::Domain(_) => {
                    let addresses = system_lookup(&host, port)?;
                    let ips: Vec<IpAddr> = addresses.iter().map(SocketAddr::ip).collect();
                    match dial_plan(&ips, &self.trusted)? {
                        // Public answers stay pinned to this lookup.
                        Dial::Pin => {
                            builder = builder.resolve_to_addrs(&host, &addresses);
                        }
                        // Placeholder ranges are routed by hostname and SNI.
                        // Do not pin the pre-check address; resolve again at
                        // connect time and refuse anything outside the trusted ranges.
                        Dial::ByName => {
                            builder = builder.dns_resolver(Arc::new(TrustedResolver {
                                host: host.clone(),
                                port,
                                ranges: self.trusted.clone(),
                            }));
                        }
                    }
                }
            }
        }
        let client = builder.build()?;
        let binding = json!([
            "wpwake-v1",
            origin.trim_end_matches('/'),
            space,
            actor,
            consumer,
            item,
            self.fingerprint
        ])
        .to_string();
        let delivery_id = format!("wpwake_v1_{:x}", Sha256::digest(binding.as_bytes()));
        let body = json!({"version":1,"event":"waypost.message.available","delivery_id":delivery_id,"space_id":space,"actor_id":actor,"consumer_id":consumer,"item_id":item,"message_id":message});
        Ok(Prepared {
            client,
            url,
            secret,
            delivery_id,
            body,
        })
    }
}
fn parse_url(value: &str, test: bool) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid webhook URL"))?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid webhook URL"
    );
    if test {
        ensure!(
            url.scheme() == "http"
                && match url.host() {
                    Some(Host::Ipv4(ip)) => ip.octets()[0] == 127,
                    Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
                    _ => false,
                },
            "test webhook must be literal loopback HTTP"
        );
    } else {
        ensure!(
            url.scheme() == "https" && url.host().is_some(),
            "webhook requires public HTTPS"
        );
    }
    Ok(url)
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => {
            if v.to_ipv4_mapped().is_some() {
                return false;
            }
            let s = v.segments();
            // Global unicast, excluding documentation, translation, benchmarking and special-purpose blocks.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] <= 0x01ff))
                && !(s[0] == 0x2002)
                && !(s[0] == 0x3fff && s[1] & 0xf000 == 0)
        }
    }
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
        || (a == 198 && ((18..=19).contains(&b) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}
impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}
impl Cidr {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = ipv4_mask(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = ipv6_mask(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}
// Ranges that must not be opted into. Overlap, not just equality, so a wider
// prefix that contains loopback, link-local, or metadata is refused too.
const FORBIDDEN_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 3),
];
const FORBIDDEN_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::UNSPECIFIED, 128),
    (Ipv6Addr::LOCALHOST, 128),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
];
fn parse_trusted_cidrs(values: &[String]) -> Result<Vec<Cidr>> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        parsed.push(parse_trusted_cidr(value)?);
    }
    parsed.sort_by_key(cidr_sort_key);
    parsed.dedup();
    Ok(parsed)
}
fn parse_trusted_cidr(value: &str) -> Result<Cidr> {
    ensure!(
        !value.is_empty() && value.len() <= 128 && !value.contains(char::is_whitespace),
        "invalid trusted_resolved_cidrs entry {value}"
    );
    let (addr_text, prefix_text) = value
        .split_once('/')
        .context("invalid trusted_resolved_cidrs entry {value}")?;
    ensure!(
        !addr_text.is_empty()
            && !prefix_text.is_empty()
            && prefix_text.bytes().all(|b| b.is_ascii_digit()),
        "invalid trusted_resolved_cidrs entry {value}"
    );
    let addr: IpAddr = addr_text
        .parse()
        .context("invalid trusted_resolved_cidrs entry {value}")?;
    let prefix: u8 = prefix_text
        .parse()
        .context("invalid trusted_resolved_cidrs entry {value}")?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    ensure!(
        prefix <= max,
        "invalid trusted_resolved_cidrs entry {value}"
    );
    ensure!(
        prefix > 0,
        "trusted_resolved_cidrs entry {value} is too broad"
    );
    ensure!(
        network_address(addr, prefix),
        "trusted_resolved_cidrs entry {value} must be a network address"
    );
    let cidr = Cidr { addr, prefix };
    ensure!(
        !overlaps_forbidden(cidr),
        "trusted_resolved_cidrs entry {value} overlaps a refused range"
    );
    Ok(cidr)
}
fn cidr_sort_key(cidr: &Cidr) -> (u8, u128, u8) {
    match cidr.addr {
        IpAddr::V4(ip) => (4, u128::from(u32::from(ip)), cidr.prefix),
        IpAddr::V6(ip) => (6, u128::from(ip), cidr.prefix),
    }
}
fn network_address(addr: IpAddr, prefix: u8) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            let mask = ipv4_mask(prefix);
            u32::from(ip) & mask == u32::from(ip)
        }
        IpAddr::V6(ip) => {
            let mask = ipv6_mask(prefix);
            u128::from(ip) & mask == u128::from(ip)
        }
    }
}
fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}
fn overlaps_forbidden(cidr: Cidr) -> bool {
    match cidr.addr {
        IpAddr::V4(addr) => FORBIDDEN_V4.iter().any(|(net, prefix)| {
            ranges_overlap(
                span_v4(u32::from(addr), cidr.prefix),
                span_v4(u32::from(*net), *prefix),
            )
        }),
        IpAddr::V6(addr) => FORBIDDEN_V6.iter().any(|(net, prefix)| {
            ranges_overlap(
                span_v6(u128::from(addr), cidr.prefix),
                span_v6(u128::from(*net), *prefix),
            )
        }),
    }
}
fn ranges_overlap<T: Ord>(left: (T, T), right: (T, T)) -> bool {
    left.0 <= right.1 && right.0 <= left.1
}
fn span_v4(addr: u32, prefix: u8) -> (u32, u32) {
    let mask = ipv4_mask(prefix);
    let start = addr & mask;
    (start, start | !mask)
}
fn span_v6(addr: u128, prefix: u8) -> (u128, u128) {
    let mask = ipv6_mask(prefix);
    let start = addr & mask;
    (start, start | !mask)
}
enum Dial {
    Pin,
    ByName,
}
fn all_in_trusted(ips: &[IpAddr], trusted: &[Cidr]) -> bool {
    !ips.is_empty()
        && ips
            .iter()
            .all(|ip| trusted.iter().any(|cidr| cidr.contains(*ip)))
}
fn dial_plan(ips: &[IpAddr], trusted: &[Cidr]) -> Result<Dial> {
    ensure!(!ips.is_empty(), "webhook target is not a public address");
    if ips.iter().copied().all(public_ip) {
        return Ok(Dial::Pin);
    }
    // Mixed public and placeholder answers are rejected: pinning would keep the
    // fake address, and dialing by name would drop the public pin.
    ensure!(
        all_in_trusted(ips, trusted),
        "webhook target is not a public address"
    );
    Ok(Dial::ByName)
}
#[cfg(test)]
thread_local! {
    static DNS_FIXTURE: std::cell::RefCell<Option<Vec<IpAddr>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn fixture_ips() -> Option<Vec<IpAddr>> {
    DNS_FIXTURE.with(|slot| slot.borrow().clone())
}
fn system_lookup(domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
    #[cfg(test)]
    if let Some(ips) = fixture_ips() {
        return Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }
    Ok((domain, port)
        .to_socket_addrs()
        .context("webhook DNS resolution failed")?
        .collect())
}
fn enforce_trusted(host: &str, name: &str, port: u16, ranges: &[Cidr]) -> Result<Vec<IpAddr>> {
    let presented = name.trim_end_matches('.');
    ensure!(
        presented.eq_ignore_ascii_case(host),
        "webhook target is not a public address"
    );
    let ips: Vec<IpAddr> = system_lookup(presented, port)?
        .into_iter()
        .map(|addr| addr.ip())
        .collect();
    ensure!(
        all_in_trusted(&ips, ranges),
        "webhook target is not a public address"
    );
    Ok(ips)
}
struct TrustedResolver {
    host: String,
    port: u16,
    ranges: Vec<Cidr>,
}
impl reqwest::dns::Resolve for TrustedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let result = enforce_trusted(&self.host, name.as_str(), self.port, &self.ranges)
            .map(|ips| {
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0))) as reqwest::dns::Addrs
            })
            .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(std::io::Error::other(err))
            });
        Box::pin(std::future::ready(result))
    }
}
pub struct Prepared {
    client: Client,
    url: String,
    secret: String,
    delivery_id: String,
    body: serde_json::Value,
}
impl Prepared {
    pub fn send(self) -> bool {
        self.client
            .post(self.url)
            .bearer_auth(self.secret)
            .header("Idempotency-Key", self.delivery_id)
            .json(&self.body)
            .send()
            .is_ok_and(|r| r.status().is_success())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        thread,
    };
    fn file(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fixture(
        status: &'static str,
    ) -> (
        tempfile::TempDir,
        Target,
        PathBuf,
        thread::JoinHandle<(String, serde_json::Value)>,
    ) {
        let d = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/wake", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            let mut len = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                headers.push_str(&line);
            }
            let mut body = vec![0; len];
            reader.read_exact(&mut body).unwrap();
            write!(stream,"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\nLocation: http://127.0.0.1:1/\r\n\r\n").unwrap();
            (headers, serde_json::from_slice(&body).unwrap())
        });
        let url_file = d.path().join("url");
        let secret_file = d.path().join("secret");
        let token_file = d.path().join("token");
        file(&url_file, &url);
        file(&secret_file, "webhooksecret");
        file(&token_file, "waypostsecret");
        let target = Target::new(url_file, secret_file, true, &[], &token_file).unwrap();
        (d, target, token_file, handle)
    }
    #[test]
    fn webhook_reference_and_stable_id() {
        let (_d, t, token, handle) = fixture("200 OK");
        let p = t
            .prepare(
                &token,
                Reference {
                    origin: "https://service",
                    space: "space",
                    actor: "actor",
                    consumer: "consumer",
                    item: "item",
                    message: "message",
                },
            )
            .unwrap();
        let same = t
            .prepare(
                &token,
                Reference {
                    origin: "https://service",
                    space: "space",
                    actor: "actor",
                    consumer: "consumer",
                    item: "item",
                    message: "message",
                },
            )
            .unwrap();
        assert_eq!(p.delivery_id, same.delivery_id);
        assert!(p.send());
        let (headers, body) = handle.join().unwrap();
        assert!(
            headers
                .to_lowercase()
                .contains("authorization: bearer webhooksecret")
        );
        assert_eq!(body["event"], "waypost.message.available");
        assert_eq!(body.as_object().unwrap().len(), 8);
        assert_eq!(body["message_id"], "message");
    }
    #[test]
    fn redirects_and_failures_are_not_accepted() {
        for status in ["302 Found", "500 Internal Server Error"] {
            let (_d, t, token, h) = fixture(status);
            assert!(
                !t.prepare(
                    &token,
                    Reference {
                        origin: "https://service",
                        space: "s",
                        actor: "a",
                        consumer: "c",
                        item: "i",
                        message: "m"
                    }
                )
                .unwrap()
                .send()
            );
            h.join().unwrap();
        }
    }
    #[test]
    fn address_and_url_restrictions() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "198.19.255.255",
            "::1",
            "::ffff:8.8.8.8",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(parse_url("http://localhost/wake", true).is_err());
        assert!(parse_url("http://10.0.0.1/wake", true).is_err());
        assert!(parse_url("http://[::ffff:127.0.0.1]/", true).is_err());
        assert!(parse_url("http://127.0.0.1/wake", true).is_ok());
        assert!(parse_url("https://example.com/?secret=x", false).is_err());
    }
    #[test]
    fn secret_and_target_changes_are_rejected() {
        let (d, t, token, _h) = fixture("200 OK");
        file(&t.secret_file, "waypostsecret");
        assert!(
            t.prepare(
                &token,
                Reference {
                    origin: "https://service",
                    space: "s",
                    actor: "a",
                    consumer: "c",
                    item: "i",
                    message: "m"
                }
            )
            .is_err()
        );
        file(&t.secret_file, "different");
        file(&t.url_file, "http://127.0.0.1:1/different");
        assert!(
            t.prepare(
                &token,
                Reference {
                    origin: "https://service",
                    space: "s",
                    actor: "a",
                    consumer: "c",
                    item: "i",
                    message: "m"
                }
            )
            .is_err()
        );
        drop(d);
    }
    struct DnsFixture;
    impl DnsFixture {
        fn set(ips: &[&str]) -> Self {
            let parsed = ips.iter().map(|ip| ip.parse().unwrap()).collect();
            DNS_FIXTURE.with(|slot| *slot.borrow_mut() = Some(parsed));
            Self
        }
    }
    impl Drop for DnsFixture {
        fn drop(&mut self) {
            DNS_FIXTURE.with(|slot| *slot.borrow_mut() = None);
        }
    }
    fn reference() -> Reference<'static> {
        Reference {
            origin: "https://service",
            space: "space",
            actor: "actor",
            consumer: "consumer",
            item: "item",
            message: "message",
        }
    }
    fn production(cidrs: &[&str], url: &str) -> (tempfile::TempDir, Target, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let url_file = d.path().join("url");
        let secret_file = d.path().join("secret");
        let token_file = d.path().join("token");
        file(&url_file, url);
        file(&secret_file, "webhooksecret");
        file(&token_file, "waypostsecret");
        let owned: Vec<String> = cidrs.iter().map(|item| (*item).to_string()).collect();
        let target = Target::new(url_file, secret_file, false, &owned, &token_file).unwrap();
        (d, target, token_file)
    }
    #[test]
    fn trusted_benchmark_range_is_accepted_and_default_still_rejects_it() {
        let (_trusted_dir, trusted, trusted_token) =
            production(&["198.18.0.0/15"], "https://hooks.example/wake");
        let _guard = DnsFixture::set(&["198.18.0.1"]);
        assert!(trusted.prepare(&trusted_token, reference()).is_ok());
        drop(_guard);
        let _guard = DnsFixture::set(&["198.18.255.9", "198.19.0.1"]);
        assert!(trusted.prepare(&trusted_token, reference()).is_ok());
        drop(_guard);

        let (_strict_dir, strict, strict_token) = production(&[], "https://hooks.example/wake");
        let _guard = DnsFixture::set(&["198.18.0.1"]);
        let Err(err) = strict.prepare(&strict_token, reference()) else {
            panic!("default configuration accepted 198.18.0.1");
        };
        assert!(
            err.to_string()
                .contains("webhook target is not a public address")
        );
        drop(_guard);
        let _guard = DnsFixture::set(&["198.19.4.4"]);
        assert!(strict.prepare(&strict_token, reference()).is_err());
        drop(_guard);

        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.51.100.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::ffff:198.18.0.1",
        ] {
            let _guard = DnsFixture::set(&[ip]);
            assert!(
                trusted.prepare(&trusted_token, reference()).is_err(),
                "{ip}"
            );
        }
        let _guard = DnsFixture::set(&["198.18.0.1", "8.8.8.8"]);
        assert!(trusted.prepare(&trusted_token, reference()).is_err());
        drop(_guard);
        let _guard = DnsFixture::set(&["8.8.8.8"]);
        assert!(trusted.prepare(&trusted_token, reference()).is_ok());
    }
    #[test]
    fn literal_benchmark_address_is_rejected_even_when_the_range_is_trusted() {
        let (_d, target, token) = production(&["198.18.0.0/15"], "https://198.18.0.1/wake");
        let Err(err) = target.prepare(&token, reference()) else {
            panic!("literal benchmark address was accepted");
        };
        assert!(
            err.to_string()
                .contains("webhook target is not a public address")
        );
    }
    #[test]
    fn connect_time_lookup_stays_inside_trusted_ranges() {
        let ranges = parse_trusted_cidrs(&["198.18.0.0/15".into()]).unwrap();
        let _guard = DnsFixture::set(&["198.18.0.1"]);
        assert!(enforce_trusted("hooks.example", "hooks.example", 443, &ranges).is_ok());
        assert!(enforce_trusted("hooks.example", "Hooks.Example.", 443, &ranges).is_ok());
        drop(_guard);
        let _guard = DnsFixture::set(&["169.254.169.254"]);
        assert!(enforce_trusted("hooks.example", "hooks.example", 443, &ranges).is_err());
        drop(_guard);
        let _guard = DnsFixture::set(&["10.1.2.3"]);
        assert!(enforce_trusted("hooks.example", "hooks.example", 443, &ranges).is_err());
        drop(_guard);
        let _guard = DnsFixture::set(&["198.18.0.1"]);
        assert!(enforce_trusted("hooks.example", "other.example", 443, &ranges).is_err());
    }
    #[test]
    fn trusted_cidr_parsing_accepts_narrow_ranges_and_refuses_dangerous_ones() {
        assert!(parse_trusted_cidrs(&[]).unwrap().is_empty());
        let accepted = parse_trusted_cidrs(&[
            "198.18.0.0/15".into(),
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "100.64.0.0/10".into(),
            "2001:db8::/32".into(),
            "198.18.0.1/32".into(),
        ])
        .unwrap();
        assert_eq!(accepted.len(), 7);
        assert!(
            accepted
                .iter()
                .any(|cidr| cidr.contains("198.18.9.9".parse().unwrap()))
        );
        let single = parse_trusted_cidrs(&["198.18.0.1/32".into()]).unwrap();
        assert!(single[0].contains("198.18.0.1".parse().unwrap()));
        assert!(!single[0].contains("198.18.0.2".parse().unwrap()));
        let ordered = parse_trusted_cidrs(&["10.0.0.0/8".into(), "198.18.0.0/15".into()]).unwrap();
        let reversed = parse_trusted_cidrs(&["198.18.0.0/15".into(), "10.0.0.0/8".into()]).unwrap();
        assert_eq!(
            ordered.iter().map(ToString::to_string).collect::<Vec<_>>(),
            reversed.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
        let duplicated =
            parse_trusted_cidrs(&["198.18.0.0/15".into(), "198.18.0.0/15".into()]).unwrap();
        assert_eq!(duplicated.len(), 1);
        let url = "https://hooks.example/wake";
        let plain = format!(
            "{:x}",
            Sha256::digest(format!("webhook-v1\0false\0{url}").as_bytes())
        );
        assert_eq!(fingerprint(url, false, &[]), plain);
        assert_ne!(fingerprint(url, false, &ordered), plain);
        assert_eq!(
            fingerprint(url, false, &ordered),
            fingerprint(url, false, &reversed)
        );

        for bad in [
            "0.0.0.0/0",
            "::/0",
            "127.0.0.0/8",
            "127.0.0.1/32",
            "169.254.0.0/16",
            "169.254.169.254/32",
            "0.0.0.0/8",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "fe80::/10",
            "ff00::/8",
            "::ffff:0:0/96",
            "::ffff:198.18.0.0/112",
            "198.18.0.1/15",
            "198.18.0.0/33",
            "198.18.0.0",
            "not-a-cidr",
            "",
            "10.0.0.0/8/extra",
            " 198.18.0.0/15",
            "198.18.0.0/15 ",
        ] {
            let Err(err) = parse_trusted_cidrs(&[bad.into()]) else {
                panic!("accepted invalid CIDR {bad}");
            };
            assert!(
                err.to_string().contains("trusted_resolved_cidrs"),
                "{bad}: {err}"
            );
        }
    }
}
