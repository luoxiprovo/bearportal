-- Durable customer consent and retries for the guided onboarding flow.
CREATE TABLE onboarding_requests (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  domain_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'waiting_resources', 'installing', 'installed', 'attention')),
  missing_resource text CHECK (missing_resource IN ('server', 'relay', 'server_and_relay')),
  consented_at timestamptz NOT NULL DEFAULT now(),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_expires_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains(organization_id, id)
);
ALTER TABLE onboarding_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY onboarding_requests_iso ON onboarding_requests
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (bearportal_privileged() OR organization_id = bearportal_org());
GRANT SELECT, INSERT, UPDATE ON onboarding_requests TO bearportal_app;
