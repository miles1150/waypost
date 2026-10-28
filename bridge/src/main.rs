mod codex;
mod webhook;

use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use regex::Regex;
use reqwest::{blocking::Client, redirect::Policy};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    config_version: Option<u32>,
    wake_adapter: Option<WakeAdapter>,
    base_url: String,
    token_file: PathBuf,
    state_dir: PathBuf,
    space_id: String,
    actor_id: String,
    consumer_id: String,
    thread_id: Option<String>,
    codex_path: Option<PathBuf>,
    codex_remote: Option<String>,
    codex_home: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WakeAdapter {
    Codex {
        thread_id: String,
        codex_path: PathBuf,
        codex_remote: Option<String>,
        codex_home: Option<PathBuf>,
    },
    Webhook {
        url_file: PathBuf,
        secret_file: PathBuf,
        #[serde(default)]
        allow_loopback_test: bool,
        #[serde(default)]
        trusted_resolved_cidrs: Vec<String>,
    },
}
struct Config {
    base_url: String,
    token_file: PathBuf,
    state_dir: PathBuf,
    space_id: String,
    actor_id: String,
    consumer_id: String,
    adapter: Adapter,
}
enum Adapter {
    Codex(codex::CodexConfig),
    Webhook(webhook::Target),
}

fn private_file(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(m.is_file(), "expected a regular private file");
    #[cfg(unix)]
    {
        ensure!(m.mode() & 0o077 == 0, "file must be private (mode 0600)");
        ensure!(
            m.uid() == unsafe_uid(),
            "file must be owned by the current user"
        );
    }
    Ok(())
}
#[cfg(unix)]
fn unsafe_uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn config(path: &Path) -> Result<Config> {
    private_file(path)?;
    let raw_value: Value = serde_json::from_slice(&fs::read(path)?)?;
    if raw_value.get("wake_adapter").is_some() {
        ensure!(
            ["thread_id", "codex_path", "codex_remote", "codex_home"]
                .iter()
                .all(|key| raw_value.get(*key).is_none()),
            "legacy and versioned adapter fields cannot be mixed"
        );
    }
    let raw: RawConfig = serde_json::from_value(raw_value)?;
    let adapter = match (raw.config_version, raw.wake_adapter) {
        (None, None) => Adapter::Codex(codex::CodexConfig {
            thread_id: raw.thread_id.context("missing thread_id")?,
            codex_path: raw.codex_path.context("missing codex_path")?,
            codex_remote: raw.codex_remote,
            codex_home: raw.codex_home,
        }),
        (
            Some(2),
            Some(WakeAdapter::Codex {
                thread_id,
                codex_path,
                codex_remote,
                codex_home,
            }),
        ) => Adapter::Codex(codex::CodexConfig {
            thread_id,
            codex_path,
            codex_remote,
            codex_home,
        }),
        (
            Some(2),
            Some(WakeAdapter::Webhook {
                url_file,
                secret_file,
                allow_loopback_test,
                trusted_resolved_cidrs,
            }),
        ) => Adapter::Webhook(webhook::Target::new(
            url_file,
            secret_file,
            allow_loopback_test,
            &trusted_resolved_cidrs,
            &raw.token_file,
        )?),
        _ => bail!("invalid configuration version or wake_adapter"),
    };
    let c = Config {
        base_url: raw.base_url,
        token_file: raw.token_file,
        state_dir: raw.state_dir,
        space_id: raw.space_id,
        actor_id: raw.actor_id,
        consumer_id: raw.consumer_id,
        adapter,
    };
    let url = url::Url::parse(&c.base_url)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.path() == "/" || url.path().is_empty()),
        "base_url must be an origin without credentials"
    );
    let loopback = url
        .host_str()
        .map(|h| h == "localhost" || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback()))
        .unwrap_or(false);
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "HTTPS required except for loopback HTTP"
    );
    for v in [&c.space_id, &c.actor_id, &c.consumer_id] {
        ensure!(
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'-'),
            "invalid identity or thread ID"
        );
    }
    ensure!(
        c.token_file.is_absolute() && c.state_dir.is_absolute(),
        "paths must be absolute"
    );
    if let Adapter::Codex(codex) = &c.adapter {
        ensure!(
            codex.codex_path.is_absolute(),
            "codex_path must be absolute"
        );
        ensure!(
            Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")?
                .is_match(&codex.thread_id),
            "thread_id must be an exact lowercase UUID"
        );
        if let Some(h) = &codex.codex_home {
            ensure!(h.is_absolute(), "codex_home must be absolute");
        }
        if let Some(r) = &codex.codex_remote {
            ensure!(
                r.starts_with("unix:///")
                    && !r.contains(['?', '#', '\n', '\r'])
                    && !r.contains("/../")
                    && !r.contains("/./"),
                "remote must be an absolute Unix socket URL"
            );
            let socket = Path::new(&r[7..]);
            ensure!(
                socket.components().all(|part| matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
                "remote socket path must be normalized"
            );
        }
    }
    private_file(&c.token_file)?;
    Ok(c)
}
fn db(c: &Config) -> Result<(Connection, fs::File)> {
    if !c.state_dir.exists() {
        fs::create_dir_all(&c.state_dir)?;
        #[cfg(unix)]
        fs::set_permissions(&c.state_dir, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(&c.state_dir)?;
    ensure!(
        metadata.is_dir(),
        "state directory must be a directory, not a symlink"
    );
    #[cfg(unix)]
    ensure!(
        metadata.uid() == unsafe_uid() && metadata.mode() & 0o077 == 0,
        "state directory must be owned by the current user and private"
    );
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let lock = opts.open(c.state_dir.join("lock"))?;
    lock.try_lock_exclusive()
        .context("another bridge owns this state directory")?;
    let path = c.state_dir.join("state.sqlite3");
    let f = opts.open(&path)?;
    drop(f);
    private_file(&path)?;
    let db = Connection::open(path)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS items (item_id TEXT PRIMARY KEY, resource_id TEXT NOT NULL, item_type TEXT NOT NULL, status TEXT NOT NULL, queue_id TEXT);")?;
    let binding = if let Adapter::Webhook(target) = &c.adapter {
        json!([
            "webhook-v1",
            c.base_url.trim_end_matches('/'),
            c.space_id,
            c.actor_id,
            c.consumer_id,
            target.binding()
        ])
        .to_string()
    } else if let Adapter::Codex(codex) = &c.adapter {
        json!([
            c.base_url.trim_end_matches('/'),
            c.space_id,
            c.actor_id,
            c.consumer_id,
            codex.thread_id,
            codex.codex_path,
            codex.codex_remote,
            codex.codex_home
        ])
        .to_string()
    } else {
        unreachable!()
    };
    let existing: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key='binding'", [], |r| {
            r.get(0)
        })
        .optional()?;
    ensure!(
        existing.as_deref().is_none_or(|v| v == binding),
        "state directory belongs to a different binding"
    );
    db.execute("INSERT OR IGNORE INTO meta VALUES ('binding',?)", [binding])?;
    db.execute(
        "UPDATE items SET status='ignored' WHERE status='pending' AND item_type<>'message'",
        [],
    )?;
    db.execute(
        "UPDATE items SET status='unknown' WHERE status='sending'",
        [],
    )?;
    Ok((db, lock))
}
fn request(
    client: &Client,
    c: &Config,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(u16, Value)> {
    private_file(&c.token_file)?;
    let mut token = String::new();
    fs::File::open(&c.token_file)?
        .take(8192)
        .read_to_string(&mut token)?;
    let token = token.trim();
    ensure!(!token.is_empty(), "empty credential");
    let url = format!("{}{}", c.base_url.trim_end_matches('/'), path);
    let mut req = if method == "GET" {
        client.get(url)
    } else {
        client.post(url)
    };
    req = req.bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b)
    }
    let response = req.send().context("Waypost request failed")?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    response.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 2 * 1024 * 1024, "Waypost response too large");
    let value: Value = serde_json::from_slice(&bytes).context("invalid Waypost response")?;
    Ok((status, value))
}
fn describe(client: &Client, c: &Config) -> Result<()> {
    let (s, v) = request(client, c, "GET", "/v0/describe", None)?;
    ensure!(s == 200, "describe failed (HTTP {s})");
    let d = &v["data"];
    ensure!(
        d["space_id"] == c.space_id
            && d["actor_id"] == c.actor_id
            && d["consumer_id"] == c.consumer_id,
        "credential identity does not match configuration"
    );
    Ok(())
}
fn scan(db: &mut Connection, client: &Client, c: &Config) -> Result<bool> {
    let mut reset = false;
    let mut any = false;
    let mut pages = 0;
    loop {
        let cursor: Option<String> = db
            .query_row("SELECT value FROM meta WHERE key='cursor'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let (status, v) = request(
            client,
            c,
            "POST",
            "/v0/inbox/read",
            Some(json!({"consumer_id":c.consumer_id,"cursor":cursor})),
        )?;
        if status != 200 {
            if !reset
                && cursor.is_some()
                && ["INVALID_CURSOR", "CURSOR_SCOPE_CHANGED", "CURSOR_EXPIRED"]
                    .iter()
                    .any(|code| v["error"]["code"] == *code)
            {
                describe(client, c)?;
                let tx = db.transaction()?;
                tx.execute("DELETE FROM meta WHERE key='cursor'", [])?;
                tx.execute(
                    "UPDATE items SET status='pending' WHERE status='blocked'",
                    [],
                )?;
                tx.commit()?;
                reset = true;
                continue;
            }
            bail!("inbox read failed (HTTP {status})");
        }
        let d = &v["data"];
        let items = d["items"].as_array().context("missing items")?;
        let next = d["next_cursor"].as_str().context("missing cursor")?;
        let more = d["has_more"].as_bool().context("missing has_more")?;
        let tx = db.transaction()?;
        for item in items {
            let id = item["item_id"].as_str().context("missing item id")?;
            let rid = item["resource_id"]
                .as_str()
                .context("missing resource id")?;
            let typ = item["item_type"].as_str().context("missing item type")?;
            ensure!(item["space_id"] == c.space_id, "unexpected space");
            ensure!(
                [id, rid, typ].iter().all(|s| !s.is_empty()
                    && s.len() <= 128
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')),
                "invalid reference"
            );
            let n=tx.execute("INSERT OR IGNORE INTO items (item_id,resource_id,item_type,status) VALUES (?,?,?,CASE WHEN ?='message' THEN 'pending' ELSE 'ignored' END)",params![id,rid,typ,typ])?;
            any |= n > 0;
        }
        tx.execute("INSERT INTO meta VALUES ('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[next])?;
        tx.commit()?;
        pages += 1;
        if !more || pages >= 10 {
            break;
        }
        ensure!(
            cursor.as_deref() != Some(next),
            "pagination did not advance"
        );
    }
    Ok(any)
}
enum PreparedAdapter<'a> {
    Codex(codex::Prepared<'a>),
    Webhook(webhook::Prepared),
}
enum AdapterOutcome {
    Accepted(Option<String>),
    Unknown,
    NotAttempted,
}
impl PreparedAdapter<'_> {
    fn send(self) -> AdapterOutcome {
        match self {
            Self::Webhook(p) => {
                if p.send() {
                    AdapterOutcome::Accepted(None)
                } else {
                    AdapterOutcome::Unknown
                }
            }
            Self::Codex(p) => p.send(),
        }
    }
}
fn send_pending(db: &Connection, client: &Client, c: &Config) -> Result<()> {
    let mut stmt = db.prepare(
        "SELECT item_id,resource_id,item_type FROM items WHERE status='pending' ORDER BY rowid",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.iter().any(|(_, _, typ)| typ == "message") {
        describe(client, c)?;
    }
    for (id, rid, typ) in rows {
        if typ != "message" {
            continue;
        }
        let (status, _) = request(client, c, "GET", &format!("/v0/messages/{rid}"), None)?;
        if status == 404 {
            db.execute("UPDATE items SET status='blocked' WHERE item_id=?", [&id])?;
            continue;
        }
        ensure!(
            status == 200,
            "message visibility check failed (HTTP {status})"
        );
        let reference = webhook::Reference {
            origin: &c.base_url,
            space: &c.space_id,
            actor: &c.actor_id,
            consumer: &c.consumer_id,
            item: &id,
            message: &rid,
        };
        let prepared = match &c.adapter {
            Adapter::Webhook(target) => {
                PreparedAdapter::Webhook(target.prepare(&c.token_file, reference)?)
            }
            Adapter::Codex(target) => {
                PreparedAdapter::Codex(codex::prepare(target, &c.space_id, &id, &rid)?)
            }
        };
        db.execute("UPDATE items SET status='sending' WHERE item_id=?", [&id])?;
        match prepared.send() {
            AdapterOutcome::Accepted(queue_id) => {
                db.execute(
                    "UPDATE items SET status='accepted',queue_id=? WHERE item_id=?",
                    params![queue_id, id],
                )?;
            }
            AdapterOutcome::Unknown => {
                db.execute("UPDATE items SET status='unknown' WHERE item_id=?", [id])?;
            }
            AdapterOutcome::NotAttempted => {
                db.execute("UPDATE items SET status='pending' WHERE item_id=?", [id])?;
                bail!("Codex CLI could not start; delivery not attempted")
            }
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() >= 4 && args[1] == "--config",
        "usage: waypost-bridge --config FILE run|once|scan|status [--items]|retry-blocked|reconcile [ITEM_ID accepted|pending]"
    );
    let c = config(Path::new(&args[2]))?;
    let (mut db, _lock) = db(&c)?;
    match args[3].as_str() {
        "retry-blocked" => {
            db.execute(
                "UPDATE items SET status='pending' WHERE status='blocked'",
                [],
            )?;
        }
        "status" if args.len() == 5 && args[4] == "--items" => {
            let mut stmt=db.prepare("SELECT item_id,status FROM items WHERE status IN ('pending','blocked','unknown') ORDER BY rowid")?;
            for row in
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            {
                let (id, status) = row?;
                println!("{status} {id}");
            }
        }
        "status" => {
            ensure!(args.len() == 4, "status accepts only --items");
            let mut stmt =
                db.prepare("SELECT status,count(*) FROM items GROUP BY status ORDER BY status")?;
            for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
                let (s, n) = row?;
                println!("{s}: {n}");
            }
        }
        "reconcile" if args.len() == 4 => match &c.adapter {
            Adapter::Codex(target) => codex::reconcile_read(&db, target)?,
            Adapter::Webhook(_) => bail!(
                "webhook reconciliation requires manual verification; use reconcile ITEM_ID accepted|pending"
            ),
        },
        "reconcile" => {
            ensure!(
                args.len() == 6 && ["accepted", "pending"].contains(&args[5].as_str()),
                "reconcile requires ITEM_ID and accepted or pending"
            );
            ensure!(
                db.execute(
                    "UPDATE items SET status=? WHERE item_id=? AND status='unknown'",
                    params![args[5], args[4]]
                )? == 1,
                "no unknown item found"
            );
        }
        "run" | "once" | "scan" => {
            let client = Client::builder()
                .user_agent("Waypost/0.1.0 bridge")
                .redirect(Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?;
            describe(&client, &c)?;
            let mut failures = 0u32;
            loop {
                match scan(&mut db, &client, &c).and_then(|found| {
                    if args[3] != "scan" {
                        send_pending(&db, &client, &c)?;
                    }
                    Ok(found)
                }) {
                    Ok(found) => {
                        failures = 0;
                        if args[3] == "once" || args[3] == "scan" {
                            break;
                        }
                        let base = if found { 30 } else { 60 };
                        let jitter =
                            SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos() as u64 % 6;
                        thread::sleep(Duration::from_secs(base + jitter));
                    }
                    Err(e) => {
                        if args[3] == "once" || args[3] == "scan" {
                            return Err(e);
                        }
                        eprintln!("bridge poll failed: {e:#}");
                        failures = failures.saturating_add(1);
                        let base = (30u64.saturating_mul(1u64 << failures.min(5))).min(900);
                        let jitter = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos()
                            as u64
                            % (base / 4 + 1);
                        thread::sleep(Duration::from_secs(base + jitter));
                    }
                }
            }
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
    };
    fn codex(c: &Config) -> &codex::CodexConfig {
        if let Adapter::Codex(ref x) = c.adapter {
            x
        } else {
            panic!("expected codex")
        }
    }
    fn codex_mut(c: &mut Config) -> &mut codex::CodexConfig {
        if let Adapter::Codex(ref mut x) = c.adapter {
            x
        } else {
            panic!("expected codex")
        }
    }
    fn fixture() -> (tempfile::TempDir, Config) {
        let d = tempfile::tempdir().unwrap();
        let token = d.path().join("token");
        fs::write(&token, "secret").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let cli = d.path().join("codex");
        fs::write(
            &cli,
            "#!/bin/sh\necho 'Queued message queue_id123 for thread 12345678-1234-1234-1234-123456789abc.'\n",
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let c = Config {
            base_url: "http://127.0.0.1".into(),
            token_file: token,
            state_dir: d.path().join("state"),
            space_id: "space".into(),
            actor_id: "actor".into(),
            consumer_id: "consumer".into(),
            adapter: Adapter::Codex(codex::CodexConfig {
                thread_id: "12345678-1234-1234-1234-123456789abc".into(),
                codex_path: cli,
                codex_remote: None,
                codex_home: None,
            }),
        };
        (d, c)
    }
    fn server(responses: Vec<Value>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let mut requests = vec![];
            for value in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let mut len = 0;
                loop {
                    let mut l = String::new();
                    reader.read_line(&mut l).unwrap();
                    if l == "\r\n" {
                        break;
                    }
                    if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                requests.push(format!("{}{}", first, String::from_utf8_lossy(&body)));
                let status = if value["error"]["code"] == "NOT_FOUND" {
                    "404 Not Found"
                } else if value.get("error").is_some() {
                    "400 Bad Request"
                } else {
                    "200 OK"
                };
                let b = value.to_string();
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    b.len(),
                    b
                )
                .unwrap();
            }
            requests
        });
        (url, handle)
    }
    #[test]
    fn cursor_recovery_deduplicates_and_queues_only_references() {
        let (_dir, mut c) = fixture();
        let item = json!({"item_id":"item12345","space_id":"space","resource_id":"resource1","item_type":"message","data":{"subject":"untrusted secret text"}});
        let page = json!({"data":{"items":[item],"next_cursor":"cursor1","has_more":false}});
        let empty = json!({"data":{"items":[],"next_cursor":"cursor1","has_more":false}});
        let describe =
            json!({"data":{"space_id":"space","actor_id":"actor","consumer_id":"consumer"}});
        let (url, server) = server(vec![
            page.clone(),
            describe.clone(),
            json!({"data":{}}),
            json!({"error":{"code":"CURSOR_SCOPE_CHANGED"}}),
            describe,
            page,
            empty,
        ]);
        c.base_url = url;
        let (mut db, _lock) = db(&c).unwrap();
        let client = Client::builder().redirect(Policy::none()).build().unwrap();
        assert!(scan(&mut db, &client, &c).unwrap());
        send_pending(&db, &client, &c).unwrap();
        assert!(!scan(&mut db, &client, &c).unwrap());
        assert!(!scan(&mut db, &client, &c).unwrap());
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM items WHERE status='accepted'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 7);
        assert!(requests.iter().any(|r| r.starts_with("GET /v0/describe")));
    }
    #[test]
    fn crash_and_invalid_receipt_become_unknown_without_resend() {
        let (_d, c) = fixture();
        let (first, lock) = db(&c).unwrap();
        first
            .execute(
                "INSERT INTO items VALUES ('one','res','message','sending',NULL)",
                [],
            )
            .unwrap();
        drop(first);
        drop(lock);
        let (db, _lock) = db(&c).unwrap();
        let status: String = db
            .query_row("SELECT status FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "unknown");
        db.execute(
            "INSERT INTO items VALUES ('two','res','message','pending',NULL)",
            [],
        )
        .unwrap();
        fs::write(&codex(&c).codex_path, "#!/bin/sh\necho invalid\n").unwrap();
        let (url, server) = server(vec![
            json!({"data":{"space_id":"space","actor_id":"actor","consumer_id":"consumer"}}),
            json!({"data":{}}),
        ]);
        let mut c = c;
        c.base_url = url;
        let client = Client::new();
        send_pending(&db, &client, &c).unwrap();
        server.join().unwrap();
        let n: i64 = db
            .query_row(
                "SELECT count(*) FROM items WHERE status='unknown'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
    }
    #[test]
    fn reconciliation_only_accepts_user_message_evidence() {
        let (_d, c) = fixture();
        fs::write(&codex(&c).codex_path, r##"#!/bin/sh
read -r line
printf '%s\n' '{"id":1,"result":{}}'
read -r line
read -r line
printf '%s\n' '{"id":2,"result":{"thread":{"id":"12345678-1234-1234-1234-123456789abc","turns":[{"items":[{"type":"userMessage","content":[{"type":"text","text":"[WAYPOST:seen]"}]},{"type":"agentMessage","content":[{"type":"text","text":"[WAYPOST:agent]"}]}]}]}}}'
"##).unwrap();
        let (db, _lock) = db(&c).unwrap();
        for id in ["seen", "agent", "absent"] {
            db.execute(
                "INSERT INTO items VALUES (?,'res','message','unknown',NULL)",
                [id],
            )
            .unwrap();
        }
        codex::reconcile_read(&db, codex(&c)).unwrap();
        for (id, expected) in [
            ("seen", "accepted"),
            ("agent", "unknown"),
            ("absent", "unknown"),
        ] {
            let status: String = db
                .query_row("SELECT status FROM items WHERE item_id=?", [id], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(status, expected);
        }
    }
    #[test]
    fn auth_failure_prevents_dispatch() {
        let (_d, mut c) = fixture();
        let (url, server) = server(vec![json!({"error":{"code":"UNAUTHORIZED"}})]);
        c.base_url = url;
        let (db, _lock) = db(&c).unwrap();
        db.execute(
            "INSERT INTO items VALUES ('item','res','message','pending',NULL)",
            [],
        )
        .unwrap();
        assert!(send_pending(&db, &Client::new(), &c).is_err());
        server.join().unwrap();
        let status: String = db
            .query_row("SELECT status FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "pending");
    }
    #[test]
    fn lock_and_binding_are_enforced() {
        let (_d, mut c) = fixture();
        let (connection, lock) = db(&c).unwrap();
        assert!(db(&c).is_err());
        drop(connection);
        drop(lock);
        codex_mut(&mut c).thread_id = "different".into();
        assert!(db(&c).is_err());
    }
    #[test]
    fn private_config_and_socket_are_checked() {
        use std::os::unix::net::UnixListener;
        let (d, c) = fixture();
        let config_path = d.path().join("config");
        fs::write(&config_path,json!({"base_url":c.base_url,"token_file":c.token_file,"state_dir":c.state_dir,"space_id":c.space_id,"actor_id":c.actor_id,"consumer_id":c.consumer_id,"thread_id":codex(&c).thread_id,"codex_path":codex(&c).codex_path}).to_string()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(config(&config_path).is_err());
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(config(&config_path).is_ok());
        let socket = d.path().join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let remote = format!("unix://{}", socket.display());
        assert!(codex::probe_remote(&remote).is_ok());
        drop(listener);
        assert!(codex::probe_remote(&remote).is_err());
    }
    #[test]
    fn unavailable_socket_never_starts_queue() {
        let (_d, mut c) = fixture();
        let (url, server) = server(vec![
            json!({"data":{"space_id":"space","actor_id":"actor","consumer_id":"consumer"}}),
            json!({"data":{}}),
        ]);
        c.base_url = url;
        codex_mut(&mut c).codex_remote = Some("unix:///nonexistent/waypost-bridge.sock".into());
        let (db, _lock) = db(&c).unwrap();
        db.execute(
            "INSERT INTO items VALUES ('item','res','message','pending',NULL)",
            [],
        )
        .unwrap();
        assert!(send_pending(&db, &Client::new(), &c).is_err());
        server.join().unwrap();
        let status: String = db
            .query_row("SELECT status FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "pending");
    }
    #[test]
    fn production_page_contract_and_cycle_bound() {
        let (_d, mut c) = fixture();
        let pages: Vec<Value> = (0..10)
            .map(
                |n| json!({"data":{"items":[],"next_cursor":format!("cursor{n}"),"has_more":true}}),
            )
            .collect();
        let (url, server) = server(pages);
        c.base_url = url;
        let (mut db, _lock) = db(&c).unwrap();
        scan(&mut db, &Client::new(), &c).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 10);
        for request in requests {
            let body = request.split_once("\r\n").unwrap().1;
            let parsed: Value = serde_json::from_str(body).unwrap();
            assert!(
                parsed.get("limit").is_none(),
                "server defaults to min(50, deployment max), including Worker max 20"
            );
        }
    }
    #[test]
    fn inaccessible_message_is_blocked() {
        let (_d, mut c) = fixture();
        let (url, server) = server(vec![
            json!({"data":{"space_id":"space","actor_id":"actor","consumer_id":"consumer"}}),
            json!({"error":{"code":"NOT_FOUND"}}),
        ]);
        c.base_url = url;
        let (db, _lock) = db(&c).unwrap();
        db.execute(
            "INSERT INTO items VALUES ('item','res','message','pending',NULL)",
            [],
        )
        .unwrap();
        send_pending(&db, &Client::new(), &c).unwrap();
        server.join().unwrap();
        let status: String = db
            .query_row("SELECT status FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "blocked");
    }
    #[test]
    fn nested_codex_keeps_legacy_binding_and_journal() {
        let (d, c) = fixture();
        let path = d.path().join("config");
        let uuid = codex(&c).thread_id.clone();
        let legacy = json!({"base_url":c.base_url,"token_file":c.token_file,"state_dir":c.state_dir,"space_id":c.space_id,"actor_id":c.actor_id,"consumer_id":c.consumer_id,"thread_id":uuid,"codex_path":codex(&c).codex_path,"codex_remote":null,"codex_home":null});
        fs::write(&path, legacy.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let c1 = config(&path).unwrap();
        let (db1, lock) = db(&c1).unwrap();
        db1.execute("INSERT INTO meta VALUES ('cursor','savedcursor')", [])
            .unwrap();
        for (id, status) in [("a", "accepted"), ("b", "unknown"), ("c", "sending")] {
            db1.execute(
                "INSERT INTO items VALUES (?,'res','message',?,NULL)",
                params![id, status],
            )
            .unwrap();
        }
        drop(db1);
        drop(lock);
        let nested = json!({"config_version":2,"base_url":c.base_url,"token_file":c.token_file,"state_dir":c.state_dir,"space_id":c.space_id,"actor_id":c.actor_id,"consumer_id":c.consumer_id,"wake_adapter":{"type":"codex","thread_id":codex(&c).thread_id,"codex_path":codex(&c).codex_path,"codex_remote":null,"codex_home":null}});
        fs::write(&path, nested.to_string()).unwrap();
        let c2 = config(&path).unwrap();
        let (db2, _lock) = db(&c2).unwrap();
        let cur: String = db2
            .query_row("SELECT value FROM meta WHERE key='cursor'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cur, "savedcursor");
        let statuses: Vec<String> = db2
            .prepare("SELECT status FROM items ORDER BY item_id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(statuses, vec!["accepted", "unknown", "unknown"]);
        let mut mixed = nested;
        mixed["codex_remote"] = Value::Null;
        fs::write(&path, mixed.to_string()).unwrap();
        assert!(config(&path).is_err());
    }
    fn private(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn webhook_config(dir: &Path, cidrs: Option<Value>) -> PathBuf {
        let token = dir.join("token");
        let url_file = dir.join("url");
        let secret = dir.join("secret");
        private(&token, "waypost-token");
        private(&url_file, "https://hooks.example/wake");
        private(&secret, "webhook-secret");
        let mut adapter = json!({
            "type": "webhook",
            "url_file": url_file,
            "secret_file": secret
        });
        if let Some(cidrs) = cidrs {
            adapter["trusted_resolved_cidrs"] = cidrs;
        }
        let body = json!({
            "config_version": 2,
            "base_url": "https://waypost.example.com",
            "token_file": token,
            "state_dir": dir.join("state"),
            "space_id": "space",
            "actor_id": "actor",
            "consumer_id": "consumer",
            "wake_adapter": adapter
        });
        let path = dir.join("config.json");
        private(&path, &body.to_string());
        path
    }
    #[test]
    fn webhook_trusted_resolved_cidrs_config_parses_valid_and_rejects_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let omitted = webhook_config(dir.path(), None);
        assert!(config(&omitted).is_ok());
        let empty = webhook_config(dir.path(), Some(json!([])));
        assert!(config(&empty).is_ok());
        let trusted = webhook_config(dir.path(), Some(json!(["198.18.0.0/15", "10.0.0.0/8"])));
        assert!(config(&trusted).is_ok());
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "127.0.0.0/8",
            "127.0.0.1/32",
            "169.254.0.0/16",
            "169.254.169.254/32",
            "198.18.0.1/15",
            "198.18.0.0/99",
            "not-a-cidr",
        ] {
            let path = webhook_config(dir.path(), Some(json!([bad])));
            let Err(err) = config(&path) else {
                panic!("accepted invalid trusted_resolved_cidrs {bad}");
            };
            let message = err.to_string();
            assert!(
                message.contains(bad) && !message.contains("{value}"),
                "{bad}: {message}"
            );
        }
        let path = webhook_config(dir.path(), Some(json!(["198.18.0.0/15", "0.0.0.0/0"])));
        let Err(err) = config(&path) else {
            panic!("accepted a list containing 0.0.0.0/0");
        };
        let message = err.to_string();
        assert!(
            message.contains("0.0.0.0/0") && !message.contains("{value}"),
            "{message}"
        );
    }
}
