# Deploy Waypost on Cloudflare

Waypost runs as a Rust Worker (`wasm32-unknown-unknown`, `worker` 0.8.7) with metadata in D1 and blobs in a private R2 bucket. The native Tokio/SQLite binary stays the local runtime. This file is the deploy checklist. Day-to-day limits, backups, and the invitation flow are in [docs/deployment.md](docs/deployment.md) and [docs/production.md](docs/production.md).

Do not commit `wrangler.production.toml`, `.env.production`, or `.dev.vars`.

## Why this path

The domain core talks to a `Database` and an `ObjectStore`. The `cloudflare` feature implements those with D1 batches and R2. MCP is one JSON-RPC POST per call, so the Worker request model is enough. There is no server-side task loop and no WebSocket session.

Cloudflare Containers can run the native binary, but they require the Workers Paid plan and their local disk is ephemeral. SQLite in the container would not be durable storage. Durable Objects are unnecessary: each request re-checks the bearer token, and durable state already lives in D1 and R2.

## What works

- Dashboard, admin session, CSRF, invitations, and access requests
- HTTP API and stateless MCP at `POST /mcp` (initialize, tools/list, tools/call)
- Mailbox, receipts, memory, and encrypted blobs inside the Worker limits below
- `GET /health`, and `GET /ready` with the admin bearer (checks the ten migrations and an R2 read)
- Per-IP rate limits from the bindings in the Wrangler config

Verified locally with Wrangler 4.111.0, Workerd, local D1/R2, the official MCP SDK client, and `scripts/verify_deployment.py`. This repo does not deploy to a live account from CI.

## What is different on Cloudflare

| | Native | Worker |
|---|---:|---:|
| JSON body | 64 KiB | 16 KiB |
| One blob | 8 MiB | 256 KiB |
| Attachments per message | 16 | 4 |
| Inline / manifest memory changes | 500 / 10,000 | 8 / 8 |
| Active items + tombstones in one collection | 10,000 | 32 |
| Page size | 100 | 20 |

`waypost_describe` returns the live values. Production must set `WAYPOST_ENCRYPTION_KEYS`. With encryption on, blob bytes are buffered, checked, and stored as ciphertext. The unencrypted streaming upload/download path is only for local development.

These are the same on every deployment, including Cloudflare: no MCP SSE session, no WebSocket, no OAuth, no webhooks, no server-side full export, no cron. `waypost encrypt` migrates a local SQLite directory only. On a Worker, plaintext migration is `POST /admin/v0/maintenance/encrypt` (see [docs/security.md](docs/security.md)). D1 and R2 are not one transaction. Worker rollback does not roll back D1 or R2. Rate-limit counts are approximate and per Cloudflare location.

## Plan

Workers Free can run this. Workers Paid ($5/month minimum) is required only if you outgrow the free quotas. Containers are not used.

| Product | Free | Paid |
|---|---|---|
| Workers | 100,000 requests/day, 10 ms CPU/request, 50 subrequests/request | 10 million requests/month included, 30 s CPU default (max 5 min) |
| D1 | 50 queries/invocation, 500 MB/database, 5 million rows read/day, 100,000 rows written/day, 7-day Time Travel | 1,000 queries/invocation, 10 GB/database, higher monthly row allowances, 30-day Time Travel |
| R2 | 10 GB-month, 1 million Class A and 10 million Class B ops/month | Usage past the free allotment |
| Rate Limiting binding | Included. No separate product in the current docs | Same binding |

Encrypted requests and larger mailbox writes can pass 10 ms of CPU. If the dashboard shows exceeded CPU time, move the account to Workers Paid. The Worker profile is sized for the free 50-query D1 cap. Sources: [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/), [D1 limits](https://developers.cloudflare.com/d1/platform/limits/), [R2 pricing](https://developers.cloudflare.com/r2/pricing/), [Rate Limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/).

## Resources to create

1. A D1 database. The production template expects the name `waypost-production`.
2. A private R2 bucket, `waypost-production-objects`. Leave `r2.dev` and any public bucket domain off.
3. The Worker `waypost-production`, created by `wrangler deploy`. The production template attaches the custom domain `waypost.miles1150.top` and sets `workers_dev = false` and `preview_urls = false`.
4. Two rate-limit bindings, `ADMIN_RATE_LIMITER` (10/60s) and `API_RATE_LIMITER` (300/60s). Wrangler creates them from `namespace_id`. Pick IDs that no other Worker in the account uses. `1001` and `1002` are only examples.
5. Secrets, in a mode-`0600` file passed to `wrangler deploy --secrets-file`. Wrangler accepts a JSON object of strings, or a dotenv file. The commands below write JSON to `.env.production` (matched by `.gitignore`).
   - `WAYPOST_ADMIN_SECRET` — at least 32 characters
   - `WAYPOST_ENCRYPTION_KEYS` — required when `DEPLOYMENT_ENV=production`
   - `WAYPOST_CURSOR_SECRET` — optional, at least 32 characters, so admin rotation does not invalidate cursors

Encryption keyring shape (placeholder only):

```json
{"active":"v1","keys":{"v1":"<64 hex chars from 32 random bytes>"}}
```

`PUBLIC_ORIGIN` must be the exact `https` origin (`scheme://host`, no path, no trailing slash) of the URL clients use. The production template sets it to `https://waypost.miles1150.top`. A wrong origin makes browser calls fail the Origin check.

The zone `miles1150.top` has to be on the account before that deploy. The template registers the custom domain and turns `workers.dev` off in the same step. Confirm `https://waypost.miles1150.top/health` after deploy. If the hostname did not attach, turn `workers_dev` back on until it does.

Dashboard HTML, scripts, CSS, and locale files are Workers Static Assets, generated into `build/dashboard-assets` by `scripts/prepare_dashboard_assets.py` at the end of the Wrangler build command. Paths stay `/`, `/dashboard`, `/dashboard/`, and fingerprinted `/dashboard/*` files (for example `/dashboard/app.<hash>.js` and `/dashboard/locales/en.<hash>.json`). `/dashboard` redirects to `/dashboard/`. There is no new path prefix. A WAF allowlist of `/`, `/health`, `/ready`, `/mcp`, `/dashboard`, `/dashboard/*`, `/admin/*`, and `/v0/*` still covers every asset. Fingerprinted files send `cache-control: public, max-age=31536000, immutable`. HTML revalidates. Auth and API responses are produced by the Worker and stay `no-store`. Production logs use head sampling rate 1. Each error log is one JSON object with `error_code`, `route`, and `request_id` only. Traces stay at 0.1.

`compatibility_date` stays `2026-07-17`, the date this adapter was built and tested against.

## Local check

Requires Rust 1.91 or newer (`edition = "2024"`), the `wasm32-unknown-unknown` target, `worker-build` 0.8.7, and Wrangler 4.111.0 or newer. `worker-build` must invoke that Rust toolchain (`rustup default stable`, or `RUSTUP_TOOLCHAIN=stable`).

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.8.7 --locked
cp .dev.vars.example .dev.vars
chmod 600 .dev.vars
# Put your own WAYPOST_ADMIN_SECRET and WAYPOST_ENCRYPTION_KEYS in .dev.vars.
npx wrangler@4.111.0 d1 migrations apply waypost --local
npx wrangler@4.111.0 dev --local --port 8791
```

`wrangler.toml` sets `PUBLIC_ORIGIN` to `http://127.0.0.1:8791`. Open that origin. `GET /health` needs no credential. `GET /ready` needs `Authorization: Bearer <WAYPOST_ADMIN_SECRET>`.

```bash
npm ci --prefix examples/mcp-client --ignore-scripts
WAYPOST_URL=http://127.0.0.1:8791 \
  WAYPOST_ADMIN_SECRET='the value from .dev.vars' \
  node examples/mcp-client/demo.mjs
```

## Deploy

```bash
npx wrangler@4.111.0 login
npx wrangler@4.111.0 d1 create waypost-production
npx wrangler@4.111.0 r2 bucket create waypost-production-objects
cp wrangler.production.example.toml wrangler.production.toml
chmod 600 wrangler.production.toml
```

Edit `wrangler.production.toml`: `account_id`, `database_id` from the D1 create output, the bucket name if you changed it, both rate-limit `namespace_id`s, and `PUBLIC_ORIGIN`.

```bash
umask 077
python3 - <<'PY' > .env.production
import json, secrets
print(json.dumps({
    "WAYPOST_ADMIN_SECRET": secrets.token_hex(32),
    "WAYPOST_ENCRYPTION_KEYS": json.dumps({
        "active": "v1",
        "keys": {"v1": secrets.token_hex(32)},
    }),
}, indent=2))
PY
chmod 600 .env.production
npx wrangler@4.111.0 d1 migrations apply waypost-production --remote --config wrangler.production.toml
npx wrangler@4.111.0 deploy --dry-run --config wrangler.production.toml
npx wrangler@4.111.0 deploy --config wrangler.production.toml --secrets-file .env.production
```

Migrations are `migrations/0001_identity_mailbox.sql` through `migrations/0010_query_indexes.sql`. Apply them to the production database before serving traffic. Do not point the production config at a development database. `/ready` reports `schema_revision` 10 only after `0010_query_indexes.sql` is applied.

After deploy:

```bash
curl --fail --silent "https://waypost.miles1150.top/health"
python3 scripts/verify_deployment.py \
  --url "https://waypost.miles1150.top" \
  --admin-secret-file /path/to/admin-secret
```

## Update the live Worker

Copy the template's custom-domain route, `workers_dev = false`, `preview_urls = false`, `PUBLIC_ORIGIN`, `[observability.logs]`, `[assets]`, and build command into the gitignored `wrangler.production.toml`. Keep that file's real `account_id`, `database_id`, bucket name, and rate-limit namespace ids.

Apply migration `0010_query_indexes.sql` before the Worker that expects ten migrations, then redeploy. Omit `--secrets-file` unless the secrets are rotating.

```bash
npx wrangler@4.111.0 d1 migrations apply waypost-production --remote --config wrangler.production.toml
npx wrangler@4.111.0 deploy --dry-run --config wrangler.production.toml
npx wrangler@4.111.0 deploy --config wrangler.production.toml
curl --fail --silent "https://waypost.miles1150.top/health"
curl --fail --silent --header "Authorization: Bearer <admin secret>" "https://waypost.miles1150.top/ready"
```

`schema_revision` must be 10. Then open `https://waypost.miles1150.top/` and `https://waypost.miles1150.top/dashboard/`.

Store the admin secret and the keyring outside the data backup. Losing the keyring makes existing ciphertext unreadable. Redeploying the Worker keeps D1 and R2 data.
