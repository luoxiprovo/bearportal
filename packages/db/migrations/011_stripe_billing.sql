-- Existing inventory remains assigned; billing never automatically releases tenant resources.
ALTER TABLE users ADD COLUMN billing_trial_used_at timestamptz;
ALTER TABLE organizations ADD COLUMN billing_required boolean NOT NULL DEFAULT false;
CREATE TABLE billing_subscriptions (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id text UNIQUE,
  subscription_id text UNIQUE,
  checkout_id text UNIQUE,
  checkout_started_at timestamptz NOT NULL DEFAULT now(),
  checkout_attempt integer NOT NULL DEFAULT 1,
  status text NOT NULL DEFAULT 'pending',
  trial_used_at timestamptz,
  trial_ends_at timestamptz,
  access_until timestamptz,
  cancel_requested_at timestamptz,
  cleanup_required boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE billing_events (
  id text PRIMARY KEY,
  processed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE billing_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_read ON billing_subscriptions FOR SELECT
 USING (bearportal_privileged() OR organization_id=bearportal_org() OR bearportal_actor() IN ('allocator','inventory_worker'));
CREATE POLICY billing_insert ON billing_subscriptions FOR INSERT
 WITH CHECK (bearportal_actor()='platform_administrator');
CREATE POLICY billing_update ON billing_subscriptions FOR UPDATE
 USING (bearportal_actor()='platform_administrator') WITH CHECK (bearportal_actor()='platform_administrator');
ALTER TABLE billing_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_events FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_events_system ON billing_events
 USING (bearportal_actor()='platform_administrator') WITH CHECK (bearportal_actor()='platform_administrator');
GRANT SELECT,INSERT,UPDATE ON billing_subscriptions,billing_events TO bearportal_app;
