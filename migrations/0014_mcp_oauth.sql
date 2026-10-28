-- Additive OAuth grant records; OIDC accounts and legacy credentials are unchanged.
CREATE TABLE oauth_requests (
 request_id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN('code','device')),
 client_id TEXT NOT NULL,resource TEXT NOT NULL,scope TEXT NOT NULL,
 redirect_uri TEXT,client_state TEXT,code_challenge TEXT,browser_digest BLOB,
 user_digest BLOB UNIQUE,device_digest BLOB UNIQUE,code_digest BLOB UNIQUE,
 status TEXT NOT NULL CHECK(status IN('pending','approved','denied','consumed')),
 created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,next_poll_at INTEGER NOT NULL,
 interval_sec INTEGER NOT NULL DEFAULT 5,claim_nonce TEXT UNIQUE,
 account_id TEXT REFERENCES accounts(account_id),space_id TEXT REFERENCES spaces(space_id),
 actor_id TEXT,consumer_id TEXT,approved_at INTEGER,family_id TEXT,
 FOREIGN KEY(space_id,actor_id) REFERENCES actors(space_id,actor_id),
 FOREIGN KEY(space_id,consumer_id) REFERENCES consumers(space_id,consumer_id)
);
CREATE INDEX oauth_requests_expiry ON oauth_requests(expires_at,status);
CREATE TABLE oauth_families (
 family_id TEXT PRIMARY KEY,client_id TEXT NOT NULL,resource TEXT NOT NULL,scope TEXT NOT NULL,
 account_id TEXT NOT NULL REFERENCES accounts(account_id),space_id TEXT NOT NULL REFERENCES spaces(space_id),
 actor_id TEXT NOT NULL,consumer_id TEXT NOT NULL,created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,revoked_at INTEGER,
 FOREIGN KEY(space_id,actor_id) REFERENCES actors(space_id,actor_id),
 FOREIGN KEY(space_id,consumer_id) REFERENCES consumers(space_id,consumer_id)
);
CREATE INDEX oauth_families_owner ON oauth_families(account_id,space_id);
CREATE TABLE oauth_refresh_tokens (
 token_digest BLOB PRIMARY KEY CHECK(length(token_digest)=32),family_id TEXT NOT NULL REFERENCES oauth_families(family_id),
 expires_at INTEGER NOT NULL,used_at INTEGER,redeem_nonce TEXT UNIQUE
);
CREATE INDEX oauth_refresh_family ON oauth_refresh_tokens(family_id);
CREATE TABLE oauth_access_tokens (
 token_id TEXT PRIMARY KEY REFERENCES tokens(token_id),family_id TEXT NOT NULL REFERENCES oauth_families(family_id)
);
CREATE INDEX oauth_access_family ON oauth_access_tokens(family_id);
ALTER TABLE tokens ADD COLUMN credential_kind TEXT NOT NULL DEFAULT 'legacy' CHECK(credential_kind IN ('legacy','oauth'));
