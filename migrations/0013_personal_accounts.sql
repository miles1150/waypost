-- Additive: legacy owners, invites, tokens and message identities remain unchanged.
CREATE TABLE accounts (
 account_id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1)),created_at INTEGER NOT NULL,
 UNIQUE(issuer,subject)
);
CREATE TABLE account_spaces (
 space_id TEXT PRIMARY KEY REFERENCES spaces(space_id),
 account_id TEXT NOT NULL REFERENCES accounts(account_id),created_at INTEGER NOT NULL
);
CREATE INDEX account_spaces_owner ON account_spaces(account_id);
CREATE TABLE account_sessions (
 session_digest BLOB PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(account_id),
 selected_space_id TEXT REFERENCES spaces(space_id),created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL
);
CREATE TABLE account_login_attempts (
 state_digest BLOB PRIMARY KEY,browser_digest BLOB NOT NULL,nonce TEXT NOT NULL,verifier TEXT NOT NULL,
 expires_at INTEGER NOT NULL,consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1))
);
CREATE TABLE account_audit (
 event_id TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(account_id),
 space_id TEXT NOT NULL,action TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE TABLE account_devices (
 device_id TEXT PRIMARY KEY, device_digest BLOB NOT NULL UNIQUE CHECK(length(device_digest)=32),
 user_digest BLOB NOT NULL UNIQUE CHECK(length(user_digest)=32), code_challenge TEXT NOT NULL,
 display_name TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','approved','consumed','revoked','denied')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, next_poll_at INTEGER NOT NULL,
 poll_nonce TEXT, account_id TEXT REFERENCES accounts(account_id), space_id TEXT REFERENCES spaces(space_id),
 actor_id TEXT, consumer_id TEXT, token_id TEXT REFERENCES tokens(token_id), approved_at INTEGER,
 FOREIGN KEY(space_id,actor_id) REFERENCES actors(space_id,actor_id),
 FOREIGN KEY(space_id,consumer_id) REFERENCES consumers(space_id,consumer_id)
);
CREATE INDEX account_devices_owner ON account_devices(account_id,created_at);
CREATE INDEX account_devices_expiry ON account_devices(expires_at);
CREATE TABLE account_agent_requests (
 account_id TEXT NOT NULL REFERENCES accounts(account_id),request_id TEXT NOT NULL,
 space_id TEXT NOT NULL REFERENCES spaces(space_id),display_name TEXT NOT NULL,
 actor_id TEXT NOT NULL,consumer_id TEXT NOT NULL,created_at INTEGER NOT NULL,
 PRIMARY KEY(account_id,request_id)
);

CREATE UNIQUE INDEX account_devices_token ON account_devices(token_id);
