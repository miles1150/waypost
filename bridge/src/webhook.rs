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
fn fingerprint(url: &str, test: bool) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("webhook-v1\0{test}\0{url}").as_bytes())
    )
}
impl Target {
    pub fn new(
        url_file: PathBuf,
        secret_file: PathBuf,
        test: bool,
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
        Ok(Self {
            url_file,
            secret_file,
            test,
            fingerprint: fingerprint(parsed.as_str(), test),
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
            fingerprint(parsed.as_str(), self.test) == self.fingerprint,
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
            let addresses: Vec<SocketAddr> = match parsed.host().context("invalid webhook host")? {
                Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
                Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
                Host::Domain(domain) => (domain, port)
                    .to_socket_addrs()
                    .context("webhook DNS resolution failed")?
                    .collect(),
            };
            ensure!(
                !addresses.is_empty() && addresses.iter().all(|a| public_ip(a.ip())),
                "webhook target is not a public address"
            );
            if matches!(parsed.host(), Some(Host::Domain(_))) {
                builder = builder.resolve_to_addrs(&host, &addresses);
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
        let target = Target::new(url_file, secret_file, true, &token_file).unwrap();
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
}
