-- Connection identity remains; legacy permission audit is retained as historical evidence only.
DROP TABLE token_scopes;
DROP TABLE token_recipients;
DROP TABLE token_collections;
DROP TABLE token_blob_grants;

CREATE TABLE token_routing_changes (
 change_id TEXT PRIMARY KEY,space_id TEXT NOT NULL,token_id TEXT NOT NULL,
 request_id TEXT NOT NULL,fingerprint TEXT NOT NULL,authority_version INTEGER NOT NULL,
 manager TEXT NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL,created_at INTEGER NOT NULL,
 UNIQUE(space_id,token_id,request_id),UNIQUE(token_id,authority_version),
 FOREIGN KEY(token_id,space_id) REFERENCES tokens(token_id,space_id)
);
