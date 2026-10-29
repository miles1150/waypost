-- Public client metadata only; no registration conveys Space authority.
CREATE TABLE oauth_dynamic_clients (
 client_id TEXT PRIMARY KEY, source TEXT NOT NULL CHECK(source IN('dcr','cimd','legacy')),
 metadata_json TEXT NOT NULL, security_fingerprint TEXT NOT NULL,
 allow_loopback_port_variation INTEGER NOT NULL DEFAULT 0 CHECK(allow_loopback_port_variation IN(0,1)),
 revision INTEGER NOT NULL CHECK(revision>=0), valid_until INTEGER NOT NULL,
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1)),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX oauth_dynamic_clients_expiry ON oauth_dynamic_clients(valid_until);
CREATE TABLE oauth_client_budget (
 bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, used INTEGER NOT NULL,
 nonce TEXT NOT NULL
);
ALTER TABLE oauth_requests ADD COLUMN client_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_families ADD COLUMN client_revision INTEGER NOT NULL DEFAULT 0;

CREATE INDEX oauth_requests_client_lifecycle ON oauth_requests(client_id,status,expires_at);
CREATE INDEX oauth_families_client ON oauth_families(client_id);
