pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_identity_mailbox.sql",
        include_str!("../../migrations/0001_identity_mailbox.sql"),
    ),
    (
        "0002_receipts.sql",
        include_str!("../../migrations/0002_receipts.sql"),
    ),
    (
        "0003_blobs_memory.sql",
        include_str!("../../migrations/0003_blobs_memory.sql"),
    ),
    (
        "0004_privacy.sql",
        include_str!("../../migrations/0004_privacy.sql"),
    ),
    (
        "0005_admin_sessions.sql",
        include_str!("../../migrations/0005_admin_sessions.sql"),
    ),
    (
        "0006_grant_integrity.sql",
        include_str!("../../migrations/0006_grant_integrity.sql"),
    ),
    (
        "0007_object_maintenance.sql",
        include_str!("../../migrations/0007_object_maintenance.sql"),
    ),
    (
        "0008_user_administration.sql",
        include_str!("../../migrations/0008_user_administration.sql"),
    ),
    (
        "0009_onboarding.sql",
        include_str!("../../migrations/0009_onboarding.sql"),
    ),
    (
        "0010_query_indexes.sql",
        include_str!("../../migrations/0010_query_indexes.sql"),
    ),
    (
        "0011_token_permissions.sql",
        include_str!("../../migrations/0011_token_permissions.sql"),
    ),
    (
        "0012_space_membership.sql",
        include_str!("../../migrations/0012_space_membership.sql"),
    ),
    (
        "0013_personal_accounts.sql",
        include_str!("../../migrations/0013_personal_accounts.sql"),
    ),
    (
        "0014_mcp_oauth.sql",
        include_str!("../../migrations/0014_mcp_oauth.sql"),
    ),
    (
        "0015_oauth_client_registry.sql",
        include_str!("../../migrations/0015_oauth_client_registry.sql"),
    ),
];

#[cfg(test)]
mod tests {
    #[test]
    fn query_indexes_match_lookup_columns() {
        let sql = super::MIGRATIONS
            .iter()
            .find(|(name, _)| *name == "0010_query_indexes.sql")
            .expect("0010 registered")
            .1;
        for statement in [
            "CREATE INDEX IF NOT EXISTS messages_body_ref ON messages(body_ref);",
            "CREATE INDEX IF NOT EXISTS submissions_body_ref ON submissions(body_ref);",
            "CREATE INDEX IF NOT EXISTS message_attachments_blob ON message_attachments(space_id, blob_id);",
            "CREATE INDEX IF NOT EXISTS memory_revisions_manifest ON memory_revisions(space_id, manifest_blob_id);",
        ] {
            assert!(sql.contains(statement), "{statement}");
        }
    }
}
