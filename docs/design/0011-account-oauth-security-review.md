# Independent review of account and OAuth preview

Reviewed baseline: `c1b1930`. Local-only follow-up; no production changes or real credentials. Review was split across OIDC/account identity, OAuth authorization/compatibility, and token state transitions/storage. Passing tests were treated as evidence for individual cases, not a security certification.

## Confirmed findings and fixes

1. **Conditional browser session fixation through sibling subdomains.** The original HTTPS account/login/authorization cookies lacked host-bound prefixes. An attacker controlling a sibling HTTPS subdomain could plant a parent-domain cookie containing their own valid account session. A victim with no competing host cookie could then perform a genuine Space claim into the attacker's account. Exact Origin and CSRF checks do not prevent this: the victim is interacting with the genuine application under the injected session. HTTPS now uses `__Host-` names, `Path=/`, `Secure`, and no Domain; old names are not accepted as account authority. The same mitigation is applied to the legacy management session. Loopback HTTP development retains its distinct unprefixed behavior. Existing HTTPS browser sessions must sign in again; bearer credentials and database identities are unchanged.
2. **Concurrent device polls could terminate a valid grant.** A delayed approved poll could have its claim nonce replaced by another interval-eligible poll. Its failed claim then reported terminal `invalid_grant`. The response now remains `authorization_pending` only while the request and current authority remain valid; expiry, denial and consumption retain their terminal errors. The stored polling interval is still enforced.
3. **Edge throttling used the wrong OAuth error shape.** Cloudflare's pre-dispatch limiter returned a generic Waypost error envelope. OAuth routes now return a flat `temporarily_unavailable` error, HTTP 429, `Retry-After`, and no-store headers. This was a client-compatibility defect, not an authorization bypass.

## Reviewed invariants

OIDC uses fixed trusted endpoints and pinned RS256 keys, verifies issuer, audience/authorized party, nonce and time, and consumes browser-bound state before exchange. OAuth public clients are preregistered; exact callbacks and S256 are required, and exchange checks the callback is still registered. Browser approval requires the current account session, CSRF, selected Space ownership and Actor/Consumer binding inside the final conditional write.

Code consumption and issuance share a batch. Refresh rotation retains used digests and revokes the family on replay. Access checks require the current family, account ownership, resource, configured client and identity; the same authority condition applies at final write. Unlink/recovery revokes grants rather than merely hiding account ownership. Legacy bearer credentials keep their separate behavior.

Native batches use SQLite immediate transactions. The Worker uses `D1DatabaseSession.batch` and a `first-primary` session. [Cloudflare's documented batch contract](https://developers.cloudflare.com/d1/worker-api/d1-database/) states that a failed statement rolls back the sequence. That supports the implementation's atomicity assumptions; separate awaited calls are not one transaction. Tests exercise native rollback/unknown commit and local Workerd requests, not remote D1 failure behavior.

## Residual risks and limits

- Real IdP and actual Codex/Claude host interoperability remain unverified. Pre-registration is a bounded profile; dynamic registration, client metadata documents and browser cross-origin clients remain unsupported.
- A recent Waypost session is not proof of recent IdP authentication or MFA. No `max_age`/`auth_time` step-up guarantee is advertised.
- Known public client IDs can contend for the global outstanding-request cap. Deployment rate limits remain necessary; this is not an unrestricted public-signup design.
- One browser authorization cookie means parallel authorization tabs may invalidate one another.
- Removing a configured client suspends its access; re-adding the same ID may restore unrevoked, unexpired grants. Use explicit revocation/unlink for permanent cancellation.
- Refresh responses lost after a successful commit, including benign concurrent refresh, can cause replay revocation and require reauthorization. This is deliberate fail-closed behavior.
- Local concurrency tests cover selected schedules. They do not exhaust all interleavings or verify remote D1 failover, latency, replica behavior or unknown-result injection.
- Browser prefix protection depends on conforming browser behavior. Local HTTP development is not a production security profile.

## Regression evidence

- Full suite: 122 Rust tests passed. After the final HTTP cookie-path compatibility adjustment, all 56 library tests and 3 native HTTP OAuth tests passed again. Existing HTTP login and OAuth paths are preserved to avoid duplicate legacy-path cookies during local upgrades.
- 23 Python and 22 UI tests passed; native and Wasm strict Clippy, formatting, document checks and release Worker build passed. The deployment verifier was updated and compiled, but not run against production.
- Added controlled-await device-poll race, independent-connection concurrent code/refresh redemption, final-statement rollback and successful-commit/lost-response tests.
- Actual isolated Workerd/D1 passed the OAuth smoke, official MCP JavaScript SDK and new `scripts/verify_oauth_races.mjs`: concurrent code/refresh and revoke-versus-refresh in both launch orders leave the expected authorization state. Tests use synthetic seeded account sessions, not real login credentials.
- Cookie fixes received a second read-only cross-review, which caught the HTTP-path compatibility issue before completion. HTTPS rejected injected old names and preserved explicit credential precedence in regression tests.

No schema change is required beyond the existing preview migration 0014. No push, merge, deployment, remote migration or production verification was performed.
