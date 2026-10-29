-- Additive: OAuth clients identified by metadata documents (cache only) or
-- registered dynamically (RFC 7591). Existing grants and credentials are unchanged.
CREATE TABLE oauth_client_documents (
 client_id TEXT PRIMARY KEY,client_name TEXT NOT NULL,redirect_uris TEXT NOT NULL,
 fetched_at INTEGER NOT NULL,expires_at INTEGER NOT NULL
);
CREATE INDEX oauth_client_documents_expiry ON oauth_client_documents(expires_at);
CREATE TABLE oauth_registered_clients (
 client_id TEXT PRIMARY KEY,client_name TEXT NOT NULL,redirect_uris TEXT NOT NULL,
 grant_types TEXT NOT NULL,created_at INTEGER NOT NULL,
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1))
);
CREATE INDEX oauth_registered_clients_created ON oauth_registered_clients(created_at);
CREATE INDEX oauth_requests_client ON oauth_requests(client_id,status);
