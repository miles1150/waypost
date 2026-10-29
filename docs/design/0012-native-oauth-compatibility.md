# Native OAuth client compatibility

Local follow-up to `9d79df7`; no deployment or real IdP registration. The plugin task supplied isolated Codex observations and a Claude localhost callback requirement. This task checks the backend and independently exercises installed Codex CLI 0.163.0 against isolated Workerd with a synthetic owner session.

## Backend contract

| Item | Behavior |
|---|---|
| Issuer | Metadata `issuer` is the canonical public origin; `authorization_response_iss_parameter_supported` is true. Success, explicit denial and safe error redirects contain that exact `iss`. Invalid clients/callbacks remain local errors. |
| Redirects | Exact registered URI by default. Explicit localhost HTTP callbacks are accepted. No wildcard host/path, query, fragment or user-info. |
| Native ports | `allow_loopback_port_variation: true` permits a different nonzero explicit port only for HTTP literal `127.0.0.1` or `[::1]`. Scheme, host and path remain exact. It is false when omitted. Localhost is not an IP alias and remains exact-port. |
| Code binding | The actual requested redirect, including chosen port, is stored in the grant. Exchange requires that exact URI, even when another port would be valid for a new authorization. Current registration is rechecked. |
| PKCE | S256 required; missing/wrong verifier cannot consume a valid code. |
| Resource | Exact service resource `<origin>/mcp` throughout authorization, exchange, refresh and access. Identical repeated resource parameters collapse to one; different targets and other duplicate parameters are rejected. |
| Client registration | Preregistered public clients only. No DCR, metadata-document registration or confidential client authentication. |
| Refresh/revoke | Rotating refresh; reuse revokes family. Revoke invalidates access and refresh; current account/Space binding is still checked. |

Example trusted server-side registration (client IDs are public configuration, not secrets):

```json
{"clients":[
  {"client_id":"codex-personal","name":"Codex","redirect_uris":["http://127.0.0.1:8765/callback/EXACT_OBSERVED_SUFFIX"],"allow_loopback_port_variation":true},
  {"client_id":"claude-personal","name":"Claude","redirect_uris":["http://localhost:8766/callback"]}
]}
```

Register the actual path observed for that server/client version. Do not copy the placeholder suffix or assume that declaring issuer support removes all suffixes. This environment's Codex 0.163.0 `--no-browser` path included a stable server-specific suffix despite issuer metadata. A different client/version/mode may use `/callback`; register it only when it is the intended client contract. Do not broaden path matching to accommodate guesses.

For Codex 0.163.0 the preregistration setting is nested:

```toml
[mcp_servers.waypost]
url = "https://YOUR-WAYPOST/mcp"
[mcp_servers.waypost.oauth]
client_id = "codex-personal"
```

The CLI's `mcp add --oauth-client-id ...` generates this shape. An unsupported flat `oauth_client_id` key was ignored during the isolated test and caused attempted dynamic registration. An explicit `oauth_resource` is usually redundant with discovery; this version can send it twice when both sources are present. Backend handling accepts only identical duplicates, without expanding the authorized audience.

## Evidence and limits

Native HTTP regression exercises fixed localhost and dynamic literal-IP callbacks through consent, issuer response, code exchange and MCP; switching ports during exchange fails without consuming the code. Unit negatives cover host aliases, other loopback addresses, suffix changes, user-info, query/fragment, noncanonical URLs and omitted opt-in. Existing refresh/revocation, cross-Space and race tests remain applicable.

Actual Codex evidence is a local CLI login, using callback paste and synthetic owner consent; it does not prove real browser/IdP login, model execution or production TLS. Official MCP SDK covers MCP calls, refresh and revocation separately. Claude CLI is not installed here: localhost backend tests and the plugin-side report are not a real Claude end-to-end test. Claude versions that require dynamic localhost ports still need fixed callback configuration or a separately reviewed compatibility extension.

References: [RFC 8252 loopback redirects](https://www.rfc-editor.org/rfc/rfc8252.html#section-7.3), [RFC 9207 issuer response](https://www.rfc-editor.org/rfc/rfc9207.html#section-2), [RFC 8707 resource indicators](https://www.rfc-editor.org/rfc/rfc8707).

Regression: 124 Rust tests passed, including new native-callback and duplicate-resource cases; native/Wasm strict Clippy passed. No schema migration is needed for this compatibility change. Existing registrations omit the new boolean and remain exact-match.

Actual CLI results: login succeeded with a dynamically chosen port and the exact suffix path; the explicit-resource configuration sent two identical resource parameters. Removing `iss` or replacing it with another origin caused Codex to reject the callback with an issuer-specific error. Official SDK refresh/revocation and local Workerd concurrency regressions also passed after these changes. No claim is made that Codex itself exercised refresh or model/tool execution in this login test.

Deployment preparation and exact experiment registration are collected in the [local handoff](0013-local-handoff.md).
