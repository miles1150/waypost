-- Maintenance-only prerequisite BEFORE switching to a binary without account guards.
-- Back up and rehearse first. Preserve account tables and all message/history data.
-- Execute these statements in ONE transaction/batch using the runtime's supported API.
UPDATE tokens SET revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,
 authority_version=authority_version+1
 WHERE revoked_at IS NULL AND token_id IN(SELECT token_id FROM account_devices WHERE token_id IS NOT NULL);
UPDATE account_devices SET state='revoked' WHERE state IN('approved','consumed');
-- Required verification: must return 0.
SELECT count(*) AS active_account_tokens FROM tokens
 WHERE revoked_at IS NULL AND token_id IN(SELECT token_id FROM account_devices WHERE token_id IS NOT NULL);
