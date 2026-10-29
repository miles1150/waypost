# MCP OAuth: preregistered public clients

> 本文保留原阶段设计与实验记录。新连接请按[标准 OAuth 接入](../mcp-oauth-setup.md)使用自动注册或客户端元数据文档；下方预注册 Client ID 配置用于历史兼容，不是当前默认步骤。

Local implementation, disabled by default. No production migration, deployment, provider registration or real host authorization is implied. This extends the [account preview](0009-personal-accounts.md); its custom device helper remains compatible and does not silently switch protocols.

## Trust boundary

OIDC authenticates the human owner. Waypost separately authorizes a public OAuth client to use one existing Space/Actor/Consumer, chosen by that owner. An OIDC token, account cookie, OAuth code and Waypost access token are not interchangeable. The sole scope `waypost` represents existing Space-member data access: messages, shared materials and attachments. It grants no account, connection or server administration.

The canonical resource is `<PUBLIC_ORIGIN>/mcp`. It represents the Waypost data service, including `/v0` auxiliary data APIs used alongside MCP, not `/admin` or `/account`. Every OAuth credential checks the exact resource, configured client, active token family, current account ownership and identity on authentication and final write commit. Removing configuration disables OAuth access without changing legacy credentials.

## Protocol profile

- Protected resource discovery: `/.well-known/oauth-protected-resource/mcp`; unauthenticated MCP responses advertise its URL in `WWW-Authenticate`.
- Authorization-server metadata: `/.well-known/oauth-authorization-server`.
- Authorization code: `/oauth/authorize`, explicit browser consent, S256 PKCE, exact registered redirect, short-lived single-use code; callback includes `iss` and supplied `state`.
- Token endpoint: `/oauth/token`, form encoded, public client authentication method `none`. Supply `client_id` and exact `resource` for every grant. Access lasts at most five minutes; refresh families have an absolute 30-day lifetime.
- Refresh rotates once. Reusing a consumed refresh token revokes its family and access tokens. Concurrent refresh or losing a successful response therefore requires authorization again; clients must serialize refresh.
- RFC 8628: `/oauth/device_authorization`, then human approval at `/account`, then the device-code grant at `/oauth/token`. Observe `interval`, `authorization_pending` and increasing `slow_down`. This is separate from `/account/devices/*`, the legacy custom JSON protocol.
- RFC 7009: `/oauth/revoke`, form encoded, `client_id` and `token`. Unknown tokens return success; only the owning client can revoke an identified family.

Webhooks, wake adapters and message acknowledgements are unaffected. OAuth authorization does not prove model execution or exactly-once message processing.

## Isolated setup

First configure accounts using the account preview instructions, retaining the existing signup cap and recovery plan. Apply additive migration 0014 only to an isolated database for evaluation. Configure public client metadata (not client secrets):

```json
{"clients":[{"client_id":"local-mcp-test","name":"Local MCP test","redirect_uris":["http://127.0.0.1:8765/callback"]}]}
```

Native: `WAYPOST_OAUTH_CLIENTS_FILE` points to this JSON file (maximum 64 KiB). Worker: `WAYPOST_OAUTH_CLIENTS` contains the JSON variable. Both require account/OIDC configuration. Production issuer origins require HTTPS; literal `http://127.0.0.1` is allowed for isolated development. Register the exact callback the client actually uses. Device-only clients may have an empty redirect list.

A standards-capable client should discover metadata from MCP's 401, use its preregistered client ID, generate and retain `state` and a PKCE verifier, and validate returned state and issuer before exchanging the code. Use a private OS credential store for refresh tokens. Never paste credentials into model prompts or logs. The browser must explicitly select the intended identity and approve.

## Deliberate limits

This is a bounded preregistered-client profile. Dynamic registration and Client ID Metadata Documents were added later as opt-in switches; see [0017](0017-gateway-cimd-dcr-keys.md). Loopback port variation is now an explicit per-client opt-in for HTTP literal `127.0.0.1` or `[::1]` only (see [native client compatibility](0012-native-oauth-compatibility.md)); registered `localhost` remains exact-port. Redirect query strings, confidential client authentication and browser cross-origin token requests are not supported. Do not claim automatic interoperability with a host requiring these capabilities. Production Codex/Claude OAuth setup and a real external IdP still require separate acceptance with the host's real callback and client registration behavior.

Existing custom-device listing does not represent OAuth families. RFC revocation and unlink/recovery provide cancellation; a complete owner-facing OAuth session-management UI is a remaining product step. Keep invitations until the account and recovery flow has been validated for intended users.

## Normative references

Profile pinned to [MCP 2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html), [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009). Tests demonstrate the implemented profile, not independent standards certification.

Authorization requests have a global cap of 1,000 live entries. Known public clients can contend for this capacity; retain deployment rate limiting and do not enable unrestricted public signup as part of this profile. Expired device request tombstones are retained for 24 hours so ordinary late polls report `expired_token`.

The rollback SQL in this revision requires schema 14 and revokes custom-device tokens and all OAuth-kind tokens, including orphaned mappings. A schema-13-only deployment must use its matching earlier rollback script. No destructive down migration is provided.

## Local verification

This revision passed 114 Rust tests, 23 Python tests and 22 UI tests, native/Wasm strict Clippy, formatting, generated-document checks and a release Worker build. Independent review preceded implementation; cross-review then checked authorization and token modules and led to fixes for expired device errors, callback removal and Space-switch consent state.

`python3 scripts/verify_oauth_preview.py` exercises discovery, browser consent, PKCE, MCP, refresh replay, standard device grant and revocation on an isolated Workerd/D1 instance. `node scripts/verify_oauth_sdk.mjs` uses the installed official MCP JavaScript SDK for discovery, authorization-code exchange, MCP calls, refresh and revocation. Install the pinned example dependencies with `npm ci --prefix examples/mcp-client` first. Both scripts target only `127.0.0.1:8793` and use the synthetic seeded account session described in the account preview. The SDK script creates a synthetic local Agent identity. Do not reuse the fixtures in a real deployment.

The original checks above did not validate a real identity provider or installed host. The subsequent [native compatibility check](0012-native-oauth-compatibility.md) validates isolated Codex CLI login; real IdP, Claude, browser OAuth CORS, live Cloudflare quotas and production migration remain unverified. The smallest next interoperability step is to confirm a real host's client ID/callback requirements against this preregistered profile in a separately approved staging deployment.

See the subsequent [independent security review](0011-account-oauth-security-review.md) for confirmed fixes and residual risks. HTTPS browser cookies now require host-bound names; upgrading this preview requires signing in again in existing browser sessions. Agent bearer credentials are unaffected.
