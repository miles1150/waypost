# Automatic MCP OAuth acceptance (2026-10-29)

This is an isolated acceptance record, not evidence of production login or a live Google identity-provider flow. Design and limitations are in [0017](0017-oauth-client-discovery.md); deployment uses the [migration guide](../oauth-client-migration.md).

## Verified

- Actual `codex-cli 0.162.1`, in a disposable scratch container with no preconfigured client ID, discovered the local Workerd authorization server, registered through DCR, completed S256 authorization-code login and used `app-server` `mcpServerStatus/list` with `toolsAndAuthOnly` to discover **11 tools** and OAuth authentication status. No model invocation or message send occurred.
- Actual Claude Code 2.1.296, with no preconfigured client ID, completed DCR, S256 PKCE and synthetic account consent, then reported `Connected` through `mcp get`. Its `--no-browser` login requires a PTY; the earlier PIPE-based fixture failure was resolved by supplying one.
- The server was actual compiled Workerd with D1/R2 bindings. Its Google-shaped account/session was synthetic, seeded only into an isolated database. No real Google sign-in, user grant or production credential was used.
- Separate Workerd checks exercised invalid redirects, mismatched resource, cross-space consent rejection, code exchange, refresh rotation, revocation and rejection of revoked access/refresh tokens. Expected client errors are logged as bounded protocol codes, without response bodies or secrets.
- **159 Rust tests**, **31 Python tests**, **40 UI tests**, native and Wasm strict Clippy, formatting and the release Worker build passed. Tests include additive schema-15 preservation, legacy client import, registry revision invalidation, native DNS/pinning transport boundaries, bounded registration and safe metadata reclamation.
- Independent security review found no remaining confirmed blocking defect after the cache lifetime, D1 integer precision, registry authority, metadata reclamation and lookup-index fixes.

The repeatable scripts are `tests/oauth_client_discovery_worker.mjs` and `scripts/verify_auto_oauth_clients.py --codex-binary /ABS/codex`. They require local tooling and use only an isolated loopback fixture. Client configuration and test credentials are temporary; the harness destroys its container/image and fixture after execution. CI runs the Workerd regression; the separately installed real Codex binary is not an implicit CI dependency.

## Limits

Worker advertises DCR only. Native CIMD transport has mock DNS/connection-boundary tests and actual native startup tests, but no verified live provider metadata/TLS flow in this environment. Do not report arbitrary CIMD on Cloudflare as supported.

Claude acceptance verifies automatic registration, PKCE login and MCP connection health only. Claude `tools/list`, model invocation and real Google sign-in against production remain unverified. Add `--claude-binary /ABS/claude` to the client harness to repeat the PTY-based check; it uses a temporary `CLAUDE_CONFIG_DIR` and does not change host `HOME`.

Anonymous registration can still exhaust quotas temporarily. Metadata linked to any authorization family, disabled records and authorization history are intentionally retained; long-term capacity requires operational review. CIMD cache expiry plus a failed refresh denies access rather than extending stale authority.
