-- Account removal is reversible inventory archival, never provider-account deletion.
ALTER TABLE relay_connections ADD COLUMN archived_at timestamptz;
