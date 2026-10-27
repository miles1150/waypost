-- Equality lookups that otherwise scan the table:
-- messages.body_ref and submissions.body_ref (object cleanup and encryption migration),
-- message_attachments (space_id, blob_id),
-- memory_revisions (space_id, manifest_blob_id).
-- blobs.object_key and uploads.object_key are already UNIQUE.
CREATE INDEX IF NOT EXISTS messages_body_ref ON messages(body_ref);
CREATE INDEX IF NOT EXISTS submissions_body_ref ON submissions(body_ref);
CREATE INDEX IF NOT EXISTS message_attachments_blob ON message_attachments(space_id, blob_id);
CREATE INDEX IF NOT EXISTS memory_revisions_manifest ON memory_revisions(space_id, manifest_blob_id);
