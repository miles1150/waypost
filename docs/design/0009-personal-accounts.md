# Personal accounts and local plugin preview

Status: draft implementation, disabled by default. No production migration, identity-provider registration, credentials, deployment, plugin installation or public publication was performed for this change. This is **not yet a complete standard MCP OAuth product**. Invitations remain supported.

## Implemented boundary

- A fixed OIDC authorization-code provider authenticates a person. State is browser-bound and consumed once before exchange; nonce and S256 PKCE are required. RS256 verification uses explicitly pinned public keys, issuer, audience/azp and time checks. No email-based linking, token-directed discovery or identity-header trust.
- `accounts` identifies `(issuer, subject)`. `account_spaces` binds one owner account to a Space; accounts may claim multiple existing Spaces, while personal-space creation only creates a Space when the account has none. Existing Space/Actor/Consumer IDs and data stay unchanged.
- `/account` is a small separate setup UI with account sessions, space selection, explicit legacy-key claim/unlink, Agent identity creation, device inspection/approval/list/revocation. Account management authority never goes to a model.
- A custom device-pairing protocol approves an **existing** Actor/Consumer chosen by the owner. The client gets a normal 30-day Waypost bearer token, not an OIDC token or owner session. Device and human codes are separate; S256, expiry, polling bounds and transactional one-use redemption apply. Lost redemption responses require owner revocation and fresh pairing, not automatic duplicate issuance.
- Device tokens check the live account, Space binding and device state on authentication and at final write commit. Existing tokens keep their previous behavior. Revocation cannot erase content already downloaded by an authorized device.
- `plugins/waypost` is a portable local plugin prototype: stdio MCP forwarding and private device pairing. Claude Code can use the manual stdio configuration fallback; its plugin overlay and both real host installations remain unverified.

OIDC login and MCP authorization are separate protocols. The original account preview did not advertise OAuth. The subsequent [MCP OAuth profile](0010-mcp-oauth.md) adds discovery, standard grants and refresh families behind a separate opt-in; `describe.capabilities.oauth` is true only when that profile is configured. The local helper uses Waypost's custom JSON pairing. Packaging does not add a scheduler or fix concurrent routine processing.

## Runtime opt-in

Native: `WAYPOST_OIDC_CONFIG_FILE` points to a private ordinary file (0600, at most 64 KiB). Worker: `WAYPOST_OIDC_CONFIG` is a secret binding containing the same JSON. `WAYPOST_ACCOUNT_SIGNUP_LIMIT` defaults to `0`, which disallows new accounts while allowing existing identities to sign in; explicitly choose a total-account ceiling up to 100 for a controlled preview. Personal use can start with 1 after registering the intended IdP client. Raising the ceiling is an operator action, not an Agent tool.

```json
{
  "issuer": "https://YOUR-IDP-ISSUER",
  "client_id": "REGISTERED-CLIENT-ID",
  "authorization_endpoint": "https://YOUR-IDP/authorize",
  "token_endpoint": "https://YOUR-IDP/token",
  "client_secret": null,
  "keys": [{"kid": "PINNED-RS256-KEY-ID", "n": "BASE64URL-RSA-MODULUS", "e": "AQAB"}]
}
```

These are placeholders, not deployable credentials. Obtain keys and endpoints from the trusted provider configuration. Supported exchange is a public PKCE client or `client_secret_post`; client_secret_basic, dynamic JWKS discovery/rotation, multiple providers and refresh tokens are not implemented. Pinning an overlap of old/new keys is possible; an unknown key fails closed until trusted configuration is updated. Register the exact callback `https://YOUR-WAYPOST/account/callback`. Local tests allow literal `http://127.0.0.1:PORT`; upstream provider endpoints still require HTTPS.

Account login cookies are HttpOnly, SameSite=Lax and Secure on HTTPS, eight-hour expiry. HTTPS uses `__Host-waypost_account`, `__Host-waypost_login`, `__Host-waypost_oauth` and `__Host-waypost_admin`, all with `Path=/`, `Secure` and no Domain attribute, preventing sibling subdomains from injecting these cookies. Names are chosen from the configured public origin, never forwarded headers. Old unprefixed HTTPS cookies are ignored, so existing account and Dashboard sessions must sign in again and in-flight logins/consents must restart; database sessions, owner keys and bearer credentials are not rotated. Literal-loopback HTTP development retains unprefixed names (and the legacy admin path). Invalid current admin cookies or explicit Authorization credentials do not fall back to account authority. Login state lasts ten minutes. Mutations require same-origin and CSRF; ownership and device approval require a recent session. `/account` responses are no-store/no-referrer; never log callback query strings, form bodies or tokens. The transport rejects redirects, limits responses to 64 KiB and times out after 15 seconds without automatic exchange retry.

Public signup is not a launch-ready feature: provider eligibility/verification, abuse protection, recovery policy and cost limits need a product decision. Cloudflare retains its configured IP limiters; device polling uses the API limiter rather than the lower login limiter, plus per-device five-second spacing. Native production needs a trusted reverse proxy rate limit. Outstanding login/pairing records are bounded, but IP rates and long-term metadata retention still require operation policy.

## Safe adoption and recovery

1. Back up the existing database and objects using the normal maintenance process; verify restoration in isolation. For the current branch, apply additive migrations 0013 and 0014 in order before new application code (the original account-only preview used 0013). Native startup applies registered migrations automatically; Worker requires explicit D1 migration. This draft does neither in production.
2. Keep OIDC absent initially and verify old owners, invitations, tokens and bridge behavior. Configure a test provider and controlled signup only in staging first.
3. A new account may create a personal Space. An existing owner claims their existing Space using both a fresh account session and the **current Space owner key**. Agent tokens and the global operator secret are not accepted as claim proof. Do not create replacement identities for the existing bridge.
4. Select the Space. Create a new Agent identity or reuse the intended existing Actor/Consumer; inspect and approve only a code shown on your own device. Each computer pairs independently. Test describe, a harmless send/read, receipt and explicit one-reply limit.
5. Unlink requires both the account session and existing owner key. It preserves historical data and legacy credentials, clears selected Space sessions, revokes paired tokens and pending approved devices. Reclaiming cannot revive those approvals.
6. If the account is lost or compromised, `/account/spaces/recover` accepts the current legacy Space owner key without the lost account session and atomically detaches the binding and its device authority. The UI provides this operation. Rotating an owner key alone does **not** detach the account. New account-only Spaces have no legacy key: recovery requires the existing operator's owner-key reissue workflow and explicit human verification before emergency detach. This dependency is an activation decision, not automated account recovery.
7. Account-backed Dashboard access is deliberately limited: selected-Space reads, guarded memory edits and token routing. Unguarded legacy management writes reject account sessions. The setup UI provides guarded identity/device operations; legacy owner login remains for other management. Complete account-only Dashboard parity is outstanding.

## Rollback without restoring obsolete access

Prefer disabling new login and keeping the new runtime while resolving issues. **An old binary does not enforce account-device authority.** Before rolling back to an older application, enter maintenance and revoke every token referenced by `account_devices` and every OAuth-kind token in a transaction (review [maintenance SQL](../../scripts/account-rollback-revoke.sql)); verify zero active account-issued tokens. The current script requires schema 14; schema-13-only deployments must use the earlier matching script. Preserve account tables, audit and historical data, then switch application version. Legacy credentials continue working; paired devices must later be explicitly paired again. Do not delete `account_devices` records while their tokens remain valid: absence intentionally identifies legacy tokens.

A backup from before activation is not safe to overwrite a live database after new messages arrived. Quiesce writes, preserve post-activation data and rehearse recovery. No destructive down migration is supplied. The migration test proves existing rows survive additive upgrade and a pre-write backup can be restored; it does not prove production disaster recovery or post-write rollback.

## Verification and remaining gates

Automated evidence covers synthetic signed IdP tokens, real native HTTP login/callback/session roundtrip with a mock exchange, actual native token-endpoint HTTP transport, adversarial identity/nonce/algorithm/time validation, claim/unlink/recovery, account session guards, device authority and one-time redemption, migration preservation, UI and local stdio helper behavior. Existing protocol tests remain applicable.

Before activation: independently review this draft, exercise configured provider over real HTTPS including key rotation/outage, verify controlled signup and recovery with a real owner, exercise Worker account routes with staging D1, and load the plugin in actual Codex/Claude Code. The separately configured MCP OAuth profile still requires real-host interoperability acceptance. No mock test proves real provider, real host, background wake or exactly-once Agent execution.

### Local evidence for this draft

Final local checks: 92 Rust tests, 23 Python tests, 19 UI tests; native/Wasm strict clippy and formatting; release Worker build. Actual local Workerd/D1/R2 acceptance passed account session, device approval and S256 redemption, message send/read, received/processed ACK, local plugin stdio → MCP, and revoke → 401. The Workerd account session was seeded, **not** established through a real IdP. Native HTTP login callback uses a signed synthetic exchange.

To repeat the Worker slice, use an isolated local Wrangler profile at port 8793, apply migrations, load [local-only seed](../../tests/fixtures/account-preview-seed.sql), configure the synthetic fixture public key and provider placeholders from the OIDC tests, and run `python3 scripts/verify_account_preview.py` from repository root. Never load the seed/key in production. [Acceptance script](../../scripts/verify_account_preview.py) has a fixed literal loopback origin and does not provision cloud resources. Provider exchange, real host installation, live CF CPU quota and production performance remain unverified.
