-- Schema 14 maintenance-only prerequisite BEFORE reverting to a binary without
-- account/OAuth guards. Back up and rehearse first; preserve tables and history.
-- Execute these statements in ONE transaction/batch using the runtime's API.
-- For a schema-13-only database use that version's script before upgrading.
UPDATE tokens SET revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,
 authority_version=authority_version+1
 WHERE revoked_at IS NULL AND (
   credential_kind='oauth'
   OR token_id IN(SELECT token_id FROM account_devices WHERE token_id IS NOT NULL)
   OR token_id IN(SELECT token_id FROM oauth_access_tokens)
 );
UPDATE account_devices SET state='revoked' WHERE state IN('approved','consumed');
UPDATE oauth_requests SET status='denied' WHERE status IN('pending','approved');
UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER)*1000);
-- Required verification: must return 0, including OAuth tokens missing a mapping.
SELECT count(*) AS active_account_tokens FROM tokens
 WHERE revoked_at IS NULL AND (
   credential_kind='oauth'
   OR token_id IN(SELECT token_id FROM account_devices WHERE token_id IS NOT NULL)
   OR token_id IN(SELECT token_id FROM oauth_access_tokens)
 );
