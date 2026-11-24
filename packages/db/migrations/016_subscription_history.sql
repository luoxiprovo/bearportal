CREATE TABLE billing_subscription_history (
  subscription_id text PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  snapshot jsonb NOT NULL
);
ALTER TABLE billing_subscription_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_subscription_history FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_subscription_history_system ON billing_subscription_history
  USING (bearportal_actor()='platform_administrator')
  WITH CHECK (bearportal_actor()='platform_administrator');
GRANT SELECT, INSERT ON billing_subscription_history TO bearportal_app;

ALTER TABLE server_assignments ADD COLUMN inventory_label text;
ALTER TABLE server_assignments ADD COLUMN inventory_address inet;
ALTER TABLE relay_assignments ADD COLUMN inventory_label text;
ALTER TABLE relay_assignments ADD COLUMN inventory_account text;

-- Preserve the names and addresses of historical assignments independently of inventory edits.
DO $$
DECLARE previous_actor text := current_setting('bearportal.actor', true);
BEGIN
  PERFORM set_config('bearportal.actor', 'platform_administrator', true);
  UPDATE server_assignments a SET inventory_label=s.label, inventory_address=s.public_ipv4
    FROM servers s WHERE s.id=a.server_id;
  UPDATE relay_assignments a SET inventory_label=r.label, inventory_account=r.provider_account_id
    FROM relay_connections r WHERE r.id=a.relay_connection_id;
  PERFORM set_config('bearportal.actor', coalesce(previous_actor, ''), true);
END $$;

-- A new deployment can recreate addresses while the old mailbox rows remain.
ALTER TABLE mailboxes ADD COLUMN archived_at timestamptz;
ALTER TABLE mailboxes DROP CONSTRAINT mailboxes_address_key;
CREATE UNIQUE INDEX mailboxes_address_key ON mailboxes(address) WHERE archived_at IS NULL;
