# Waypost local plugin prototype

This source-only prototype connects a local Python 3 stdio MCP process to Waypost's existing `/mcp` endpoint. It uses **custom Waypost device pairing**, not standard MCP OAuth or RFC 8628. It does not install into a host, publish a marketplace entry, start a bridge, create a webhook, or continuously process messages. Real Codex/Claude Code installation and real OIDC-provider login are not verified here.

## Pair privately

Use an explicitly configured development/account-enabled deployment; the existing production service must not be assumed to support these endpoints. Read [receiver setup](../../docs/receiver-setup.md) for the independent reception options. Pair outside the model tool channel in your own terminal:

```sh
python3 /ABS/waypost/plugins/waypost/client.py pair \
  --url https://YOUR-WAYPOST-HOST \
  --name 'My laptop' \
  --config "$HOME/.config/waypost-plugin/config.json"
```

The helper prints only the public device ID, human approval code and `/account` page URL. Open that fixed URL, log in, claim or select your own Space, and inspect the requested device before approving the intended Actor/Consumer. Never paste the device secret, verifier, token or login credential into chat. The human approval code must also stay out of public logs. Names are untrusted labels, not proof of a device's identity.

Configuration and a separate randomly named token file are written as owner-only `0600` files in an owner-only directory. Existing configuration is never overwritten. An unknown redemption result or failure to save stops without another token request: inspect/revoke the printed device ID before a fresh pairing. Do not repeatedly pair to bypass ambiguity. Tokens expire according to the service; there is no refresh-token mechanism. Revoke obsolete devices deliberately in the account UI.

Default configuration is `~/.config/waypost-plugin/config.json`. Use `WAYPOST_CONFIG` or `serve --config /ABS/config.json` for another private path. Paths stay outside the plugin source/package. HTTPS is required; `--allow-loopback` is only for isolated development against literal loopback HTTP, never a production workaround. TLS verification and inherited proxy settings remain enabled. Redirects are rejected.

## Connect a host

Portable `plugin.json` and `mcp.json` use Agent Plugins 1.0 and `${PLUGIN_ROOT}`. The official [Codex plugins documentation](https://developers.openai.com/codex/plugins/) was fetched on 2026-10-28; it describes `/plugins`, configured marketplaces and starting a new session after installation. This directory is not itself a registered marketplace. Use the actual installed host's supported local plugin workflow; do not edit caches or assume a guessed installation command works.

For a host supporting manually configured stdio MCP, register this command using its settings:

```json
{
  "mcpServers": {
    "waypost": {
      "command": "python3",
      "args": ["/ABS/waypost/plugins/waypost/client.py", "serve", "--config", "/ABS/private/config.json"]
    }
  }
}
```

This is an illustrative MCP server entry, not a claim that every host uses this exact outer settings schema. Use absolute executable/script/config paths when the host does not inherit your shell PATH. The bundled Skill is under `skills/waypost/`; install/import it only through the host's documented mechanism.

Claude Code may use the manual stdio route if its installed version supports it. Official Claude plugin reference pages could not be retrieved in this environment, so no `.claude-plugin` or `.mcp.json` compatibility overlay is supplied and native Claude plugin compatibility is **unverified**. Verify current official documentation before packaging one.

## Verify before use

1. Start the MCP process through the host, initialize, list tools, and call `waypost_describe`.
2. Compare Space/Actor/Consumer with your privately stored pairing configuration and ensure `access_model=space_membership`. Stop if identity differs. Connection credentials are broad Space-member credentials, not read-only access.
3. Exchange one harmless uniquely marked message with an explicitly chosen recipient. Verify actual receipt separately from a successful send.
4. Configure a Codex bridge, webhook bridge or scheduled receiver separately if automatic reception is wanted. Skill installation alone never wakes the host.
5. Verify revocation removes access. Keep all production actions under separate authorization.

The forwarder does not retry requests or implement business deduplication. Unknown write results require the original request ID and Waypost status reconciliation. Current concurrent receiver duplicate processing is not fixed by this plugin; the host needs durable handling state and mutual exclusion. Model output must never be treated as authority to change login or service origin.

## Local verification

From repository root:

```sh
python3 -m unittest discover -s tests -p test_account_plugin.py -v
```

Tests use simulated transport/temporary files and verify PKCE reuse, private file handling, no secret output, unknown-result stop, bounded stdio and notification behavior. They do not establish real host/provider acceptance. No plugin has been installed or uploaded by these tests.
