# Waypost bridge

A single-process local bridge polls a Waypost inbox and sends reference-only notifications to a configured Codex thread or webhook. It discards the message returned by the visibility check, never includes its body in the notification, and never submits Waypost receipts. Before dispatch it checks that the credential can still read the message. Non-message feed entries are recorded but not dispatched.

Build with `cargo build --release --locked --manifest-path bridge/Cargo.toml`. The resulting binary is `bridge/target/release/waypost-bridge`.

Create a private directory and a token file containing only the Waypost bearer token. Create a mode 0600 JSON configuration file, replacing every value:

```json
{
  "base_url": "https://waypost.example.com",
  "token_file": "/home/me/.config/waypost/token",
  "state_dir": "/home/me/.local/state/waypost-bridge",
  "space_id": "space_id",
  "actor_id": "actor_id",
  "consumer_id": "consumer_id",
  "thread_id": "12345678-1234-1234-1234-123456789abc",
  "codex_path": "/absolute/path/to/codex",
  "codex_remote": null,
  "codex_home": null
}
```

Use a credential with inbox and message read access to that identity. `codex_remote`, when used, is an explicit `unix:///absolute/path` URL for the existing local app-server. The socket must be owned by the current user and protected from replacement; a connection probe runs before sending. The configured thread must be its exact lowercase UUID. `codex_home` may be an absolute Codex home directory. Use a dedicated private state directory per binding; identity, service, Codex executable, home, remote and thread are pinned on first use. HTTPS is required except for loopback HTTP, intended for local testing. Redirects are disabled. TLS certificate verification uses the system trust store and respects `SSL_CERT_FILE` and `SSL_CERT_DIR` when configured for a trusted proxy or custom CA.

```sh
waypost-bridge --config /absolute/path/config.json scan
waypost-bridge --config /absolute/path/config.json once
waypost-bridge --config /absolute/path/config.json run
waypost-bridge --config /absolute/path/config.json status
waypost-bridge --config /absolute/path/config.json status --items
waypost-bridge --config /absolute/path/config.json retry-blocked
waypost-bridge --config /absolute/path/config.json reconcile
```

`run` polls after 30 seconds when new items are found and 60 seconds when idle, with up to five seconds of jitter; failures back off with jitter. Each cycle reads at most ten pages before dispatch. Empty inbox polls do not write remotely. The database and process lock live in the private state directory. The bridge must have exclusive access to it. Back up the database before replacing or deleting it: forgetting the database can cause duplicate notifications on a fresh scan.

A queue attempt is recorded as `sending` before starting Codex. An interrupted attempt or a response without exactly one valid receipt is `unknown`, and is never automatically retried. `reconcile` reads the configured thread through the official Codex app-server and accepts an unknown item only when its marker appears in a user message. A missing marker does not prove non-delivery. If you have independently established the outcome, an operator can explicitly resolve one item using `reconcile ITEM_ID accepted` or `reconcile ITEM_ID pending`; the latter permits a new send and can duplicate a notification if the first attempt actually succeeded. State stores references and queue status, not message content.

The GitHub Actions workflow builds and tests Linux x86-64 and macOS x86-64/ARM64 archives with SHA-256 files as workflow artifacts after bridge changes merge to main, or on manual dispatch. Archives include the source COMMIT. It does not publish a release.

A message that returns 404 at the visibility check is marked `blocked` and is not repeatedly checked. A cursor scope reset returns blocked items to pending; after independently resolving access, `retry-blocked` explicitly retries all blocked items.

## Running as a user service

The examples are templates; review and edit paths for your account before installing. Create the configuration and token with mode 0600, and keep the state directory private. Preserve the same state directory across restarts so delivery history and cursor are retained.

On Linux, copy `examples/waypost-bridge.service` to `~/.config/systemd/user/waypost-bridge.service`, adjust `ExecStart` if necessary, then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now waypost-bridge.service
systemctl --user status waypost-bridge.service
```

On macOS, replace `USERNAME` and both paths in `examples/org.waypost.bridge.plist`, copy it to `~/Library/LaunchAgents/org.waypost.bridge.plist`, then run:

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.waypost.bridge.plist"
launchctl print "gui/$(id -u)/org.waypost.bridge"
```

The fixed-session queue and reconciliation design was informed by [Yobiru](https://github.com/chekusu/yobiru).

## Webhook adapter

A version 2 configuration can replace the legacy flat Codex fields with one `wake_adapter`. For Codex, use `{"type":"codex","thread_id":"...","codex_path":"/absolute/path/to/codex","codex_remote":null,"codex_home":null}`. The existing flat configuration and its database binding continue to work; do not mix flat and versioned adapter fields.

For a receiver implementing the generic Bearer webhook contract, use a separate private state directory and this adapter:

```json
{
  "type": "webhook",
  "url_file": "/home/me/.config/waypost-bridge/webhook-url",
  "secret_file": "/home/me/.config/waypost-bridge/webhook-secret"
}
```

Put this object in `wake_adapter` in a configuration containing `"config_version": 2` and the common service, token, state and identity fields above. Both files must be owned by the current user and private (0600). The webhook secret must differ from the Waypost token and reside in a separate file. Rotate it only for the same logical recipient; a new credential does not prove that the recipient is unchanged. The URL must be public HTTPS, without credentials, query or fragment. DNS results are checked and pinned before every delivery; redirects are disabled. If any standard HTTP, HTTPS or ALL proxy environment variable is set, delivery stops before sending, even when NO_PROXY is also set; the bridge cannot guarantee target pinning through that proxy. For local tests only, `"allow_loopback_test": true` allows literal 127/8 or ::1 HTTP targets; it does not allow private networks or DNS names.

The webhook receives a versioned JSON reference with `delivery_id`, Space, Actor, Consumer, item and message IDs, and an identical `Idempotency-Key` header. It receives no body or Waypost credential. A 2xx response means accepted, not processed. A timeout, redirect or any other response after an attempt becomes `unknown` and is not automatically retried. `status --items` lists pending, blocked and unknown item IDs for operator review. `reconcile` without arguments cannot inspect a generic webhook; verify the delivery independently before using `reconcile ITEM_ID accepted` or `reconcile ITEM_ID pending`.

The `scan` command only scans and persists references; it does not notify or acknowledge. A scheduled host may instead call Waypost HTTP or MCP directly. Grok Bot routines are a potential receiver for this generic contract but have not been verified here. Grok.com Automations use a different signed protocol and are not supported by this adapter.
