-- Additive: tables of the keys product (keyenv-remote). A Waypost deployment
-- leaves them empty. Values are AES-256-GCM ciphertext (base64url text so one
-- statement can write many fields); data keys live in Worker secrets.
CREATE TABLE key_entries (
 entry_id TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(account_id),
 name TEXT NOT NULL,purpose TEXT NOT NULL DEFAULT '',
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1)),expires TEXT,
 created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,write_nonce TEXT,
 UNIQUE(account_id,name)
);
CREATE TABLE key_fields (
 entry_id TEXT NOT NULL REFERENCES key_entries(entry_id),name TEXT NOT NULL,
 kid TEXT NOT NULL,nonce TEXT NOT NULL CHECK(length(nonce)=16),ciphertext TEXT NOT NULL,
 updated_at INTEGER NOT NULL,PRIMARY KEY(entry_id,name)
);
-- One consent per approved authorization request; refresh keeps the same consent.
CREATE TABLE key_consents (
 request_id TEXT PRIMARY KEY REFERENCES oauth_requests(request_id),
 account_id TEXT NOT NULL REFERENCES accounts(account_id),
 can_create INTEGER NOT NULL CHECK(can_create IN(0,1)),
 all_read INTEGER NOT NULL CHECK(all_read IN(0,1)),
 all_write INTEGER NOT NULL CHECK(all_write IN(0,1)),created_at INTEGER NOT NULL
);
CREATE TABLE key_consent_entries (
 request_id TEXT NOT NULL REFERENCES key_consents(request_id),
 entry_id TEXT NOT NULL REFERENCES key_entries(entry_id),
 can_read INTEGER NOT NULL CHECK(can_read IN(0,1)),
 can_write INTEGER NOT NULL CHECK(can_write IN(0,1)),
 PRIMARY KEY(request_id,entry_id)
);
CREATE TABLE key_oauth_families (
 family_id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE REFERENCES key_consents(request_id),
 client_id TEXT NOT NULL,resource TEXT NOT NULL,scope TEXT NOT NULL,
 account_id TEXT NOT NULL REFERENCES accounts(account_id),
 created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER
);
CREATE INDEX key_oauth_families_owner ON key_oauth_families(account_id);
CREATE TABLE key_oauth_refresh_tokens (
 token_digest BLOB PRIMARY KEY CHECK(length(token_digest)=32),
 family_id TEXT NOT NULL REFERENCES key_oauth_families(family_id),
 expires_at INTEGER NOT NULL,used_at INTEGER,redeem_nonce TEXT UNIQUE
);
CREATE INDEX key_oauth_refresh_family ON key_oauth_refresh_tokens(family_id);
CREATE TABLE key_access_tokens (
 token_digest BLOB PRIMARY KEY CHECK(length(token_digest)=32),
 family_id TEXT NOT NULL REFERENCES key_oauth_families(family_id),
 scope TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL
);
CREATE INDEX key_access_family ON key_access_tokens(family_id);
-- Who used which entry and how. Never values.
CREATE TABLE key_audit (
 event_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,family_id TEXT NOT NULL,
 client_id TEXT NOT NULL,action TEXT NOT NULL,entry_name TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE INDEX key_audit_account ON key_audit(account_id,created_at);
