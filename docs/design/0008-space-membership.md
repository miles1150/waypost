# Space membership replaces connection permissions

Status: implemented locally, not deployed. Supersedes connection scopes and resource grants in earlier RFCs/designs, including 0006. The user explicitly chose shared messages/materials/attachments while retaining the management boundary.

A connection authenticates one Space, Actor and Consumer. It has an expiry, revocation state and optional default message destination, but no scopes or resource allowlists. The authentication query already joins all three identities and verifies the Consumer belongs to the Actor, so no additional membership lookup is needed. Four grant aggregation subqueries and their runtime tables are removed rather than replaced with synthetic full-access grants.

## Rules

- Any active connection may send to active Actors in its own Space, read its directed inbox, acknowledge its own Consumer, and read/write shared collections and sealed attachments. Message bodies remain visible to their producer and recipients; removing connection permissions does not turn directed messages into broadcasts. Existing thread membership remains a thread consistency constraint: use a new message/thread to contact a participant outside an existing thread.
- Resource reads and writes remain scoped to the authenticated Space. IDs in input never change identity. Pending uploads remain bound to their producer; sealed bytes are immutable. Collection revision CAS, deduplication and submission recovery remain.
- Expired/revoked connections and disabled Actors/Consumers are rejected. Atomic commit-time identity checks remain necessary because revocation can happen after initial authentication.
- Ordinary connections cannot manage identities, issue credentials, change Space configuration or use the management observation view. A primary assistant has no management privilege.
- The default recipient is only routing. Omission selects that destination (or the user entry); an idempotent retry retains its originally reserved destination. Replies continue to require explicit recipients. Management-only `/tokens/{id}/routing` replaces `/permissions` for existing connections, retaining CAS and audit.
- Delivery, wake acceptance, received and processed are separate facts. External messages do not grant permission to execute tools. Sender/receiver loop budgets remain the host's responsibility.

Shared sealed attachments mean publishing a redacted copy does not hide the original sealed blob from another member who knows its ID. Privacy filtering still controls the published copy; it is not an intra-Space confidentiality boundary.

## API and clients

`describe` returns `access_model: "space_membership"`; it no longer returns `scopes`, `resource_grants` or `allowed_recipient_ids`. Token creation rejects those obsolete fields rather than suggesting ignored restrictions still work. HTTP and MCP use the same domain behavior. Dashboard connection management offers identity, default destination, expiry and revocation, not permission editing.

New feed cursors use f4 and memory cursors m2. Valid old cursors return CURSOR_SCOPE_CHANGED: rescan while retaining stable item IDs and processing records. Bridge identity/adapter bindings and journal stay intact. The example Python consumer rejects an unidentifiable legacy binding instead of silently discarding deduplication; consult its migration guidance before reuse.

## Migration and release

0012 drops token_scopes, token_recipients, token_collections and token_blob_grants. It preserves original credentials, identities, expiry/revocation, destinations, messages and receipts. token_permission_changes stays as historical audit only; token_routing_changes records future routing edits.

This broadens existing connections at upgrade time. It cannot be safely applied while the old Worker is serving requests, and a Worker-only rollback will not restore old authorization. Follow the maintenance/backup/paired rollback procedure in DEPLOY-CLOUDFLARE.md. No production migration or deployment was executed during this implementation.

## Review and verification

Independent review required retaining management race guards, proving old database preservation and cursor migration, and correcting the old deploy-before/after migration assumptions. Tests cover routing CAS and owner revocation/session races, same-Space sharing, cross-Space and management rejection, immutable uploads, cursor recovery and populated schema-11 migration. HTTP/MCP acceptance uses the actual bridge binary with simulated Codex transport; this does not establish real Codex or Grok execution. Exact completed checks are recorded in docs/validation.md.
