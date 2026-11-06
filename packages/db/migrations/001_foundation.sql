-- BearPortal control-plane foundation. Secret values are not stored in these tables.

CREATE TABLE users (
  id uuid PRIMARY KEY,
  identity_subject text NOT NULL UNIQUE,
  verified_email text,
  email_verified boolean NOT NULL DEFAULT false,
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE plans (
  id uuid PRIMARY KEY,
  code text NOT NULL,
  revision integer NOT NULL,
  server_profile_code text NOT NULL,
  minimum_host_capacity jsonb NOT NULL,
  mailbox_limit integer NOT NULL,
  mailbox_quota_bytes bigint NOT NULL,
  daily_send_limit integer NOT NULL,
  agent_budget integer NOT NULL,
  budget_estimate_minor integer NOT NULL,
  currency text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (code, revision)
);

CREATE TABLE organizations (
  id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL REFERENCES users (id),
  name text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'cancelled')),
  plan_id uuid REFERENCES plans (id),
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX organizations_one_active_owner
  ON organizations (owner_user_id)
  WHERE status <> 'cancelled';

CREATE TABLE operator_roles (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  role text NOT NULL CHECK (role IN (
    'support', 'infrastructure_operator', 'platform_administrator'
  )),
  granted_by uuid,
  reason text NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX operator_roles_active
  ON operator_roles (user_id, role)
  WHERE revoked_at IS NULL;

CREATE TABLE invitations (
  id uuid PRIMARY KEY,
  bound_email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by uuid REFERENCES users (id),
  created_by uuid NOT NULL REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE allocation_requests (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations (id),
  profile_code text NOT NULL,
  verified_registered_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('waiting_for_server', 'allocated', 'cancelled')),
  assignment_id uuid,
  cancelled_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX allocation_one_open
  ON allocation_requests (organization_id)
  WHERE state <> 'cancelled';

CREATE TABLE servers (
  id uuid PRIMARY KEY,
  label text NOT NULL,
  public_ipv4 inet NOT NULL,
  profile_code text NOT NULL,
  provider_reference text,
  operator_contact text NOT NULL,
  state text NOT NULL CHECK (state IN (
    'pending_validation', 'available', 'reserved', 'assigned', 'quarantined', 'retired'
  )),
  available_since timestamptz,
  preparation_attestations jsonb NOT NULL DEFAULT '{}'::jsonb,
  readiness_report jsonb,
  validated_at timestamptz,
  last_heartbeat_at timestamptz,
  tenant_tainted_at timestamptz,
  hosting_estimate_minor integer,
  cleanup_evidence jsonb,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX servers_live_ip
  ON servers (public_ipv4)
  WHERE state <> 'retired';

CREATE TABLE server_assignments (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations (id),
  server_id uuid NOT NULL REFERENCES servers (id),
  deployment_id uuid,
  allocated_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  reason text NOT NULL,
  generation integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX server_assignments_live_server
  ON server_assignments (server_id)
  WHERE released_at IS NULL;

CREATE UNIQUE INDEX server_assignments_live_org
  ON server_assignments (organization_id)
  WHERE released_at IS NULL;

CREATE TABLE domains (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations (id),
  normalized_name text NOT NULL,
  existing_mail boolean NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'verified', 'retired')),
  verified_at timestamptz,
  nameservers text[] NOT NULL DEFAULT ARRAY[]::text[],
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX domains_one_active_name
  ON domains (normalized_name)
  WHERE state <> 'retired';

CREATE TABLE secret_refs (
  id uuid PRIMARY KEY,
  organization_id uuid REFERENCES organizations (id),
  purpose text NOT NULL,
  file_name text NOT NULL UNIQUE,
  key_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'retired')),
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  UNIQUE (organization_id, id)
);

CREATE TABLE dns_connections (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  domain_id uuid NOT NULL,
  provider text NOT NULL CHECK (provider IN ('namecom', 'hostinger', 'godaddy')),
  zone_id text NOT NULL,
  secret_ref uuid NOT NULL REFERENCES secret_refs (id),
  state text NOT NULL CHECK (state IN ('stored', 'validated', 'rejected')),
  validated_at timestamptz,
  last_error_code text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id),
  FOREIGN KEY (organization_id, secret_ref) REFERENCES secret_refs (organization_id, id)
);

CREATE TABLE relay_connections (
  id uuid PRIMARY KEY,
  provider text NOT NULL CHECK (provider = 'brevo'),
  label text NOT NULL,
  provider_account_id text NOT NULL,
  api_secret_ref uuid REFERENCES secret_refs (id),
  smtp_secret_ref uuid REFERENCES secret_refs (id),
  smtp_login text NOT NULL,
  daily_limit integer NOT NULL,
  state text NOT NULL CHECK (state IN ('inactive', 'available', 'assigned', 'disabled')),
  validation_report jsonb,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_account_id)
);

CREATE TABLE deployments (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations (id),
  domain_id uuid,
  generation integer NOT NULL DEFAULT 1,
  desired_state text NOT NULL DEFAULT 'draft',
  onboarding_stage text NOT NULL DEFAULT 'draft',
  lifecycle_state text NOT NULL DEFAULT 'draft',
  health_state text NOT NULL DEFAULT 'unknown',
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id)
);

CREATE UNIQUE INDEX deployments_one_live
  ON deployments (organization_id)
  WHERE lifecycle_state <> 'deleted';

CREATE TABLE jobs (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid,
  generation integer NOT NULL DEFAULT 1,
  kind text NOT NULL,
  state text NOT NULL,
  checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_code text,
  attempt_count integer NOT NULL DEFAULT 0,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id) REFERENCES organizations (id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE backups (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid,
  server_id uuid,
  generation integer NOT NULL DEFAULT 1,
  external_reference text,
  evidence_source text NOT NULL,
  state text NOT NULL,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id) REFERENCES organizations (id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE outbox_events (
  id uuid PRIMARY KEY,
  event_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  payload jsonb NOT NULL,
  dedupe_key text NOT NULL UNIQUE,
  dispatched_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY,
  actor_type text NOT NULL,
  actor_id uuid,
  organization_id uuid,
  deployment_id uuid,
  action text NOT NULL,
  target text NOT NULL,
  job_id uuid,
  approval_id uuid,
  request_id uuid NOT NULL,
  redacted_diff jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL,
  route text NOT NULL,
  key text NOT NULL,
  request_hash text NOT NULL,
  response jsonb NOT NULL,
  status_code integer NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (principal_id, route, key)
);

INSERT INTO plans (
  id, code, revision, server_profile_code, minimum_host_capacity,
  mailbox_limit, mailbox_quota_bytes, daily_send_limit, agent_budget,
  budget_estimate_minor, currency
) VALUES (
  '00000000-0000-4000-8000-000000000001',
  'beta',
  1,
  'e2-micro',
  '{"minMemoryMb": 1024, "minDiskGb": 20}'::jsonb,
  5,
  1073741824,
  250,
  20,
  0,
  'USD'
);

-- Row level security. The application role cannot bypass it.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE operator_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE allocation_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE allocation_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE domains FORCE ROW LEVEL SECURITY;
ALTER TABLE secret_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_refs FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployments FORCE ROW LEVEL SECURITY;
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE backups FORCE ROW LEVEL SECURITY;
ALTER TABLE server_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;

-- Servers and relay inventory are operator-only. Plans are readable by any authenticated actor.
ALTER TABLE servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE servers FORCE ROW LEVEL SECURITY;
ALTER TABLE relay_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE plans FORCE ROW LEVEL SECURITY;
ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION bearportal_actor() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('bearportal.actor', true), '')
$$;

CREATE OR REPLACE FUNCTION bearportal_org() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('bearportal.organization_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION bearportal_user() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('bearportal.user_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION bearportal_email() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT lower(coalesce(current_setting('bearportal.email', true), ''))
$$;

CREATE OR REPLACE FUNCTION bearportal_privileged() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support')
    OR current_setting('bearportal.bootstrap', true) = '1'
$$;

CREATE POLICY users_iso ON users
  USING (
    bearportal_privileged()
    OR id = bearportal_user()
    OR identity_subject = coalesce(current_setting('bearportal.subject', true), '')
  )
  WITH CHECK (bearportal_privileged() OR id = bearportal_user());

CREATE POLICY organizations_iso ON organizations
  USING (bearportal_privileged() OR id = bearportal_org() OR owner_user_id = bearportal_user())
  WITH CHECK (bearportal_privileged() OR owner_user_id = bearportal_user());

CREATE POLICY operator_roles_iso ON operator_roles
  USING (bearportal_actor() = 'platform_administrator' OR user_id = bearportal_user() OR current_setting('bearportal.bootstrap', true) = '1')
  WITH CHECK (bearportal_actor() = 'platform_administrator' OR current_setting('bearportal.bootstrap', true) = '1');

CREATE POLICY invitations_iso ON invitations
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR lower(bound_email) = bearportal_email()
  )
  WITH CHECK (
    bearportal_actor() = 'platform_administrator'
    OR (
      bearportal_actor() = 'customer'
      AND lower(bound_email) = bearportal_email()
      AND consumed_at IS NOT NULL
    )
  );

CREATE POLICY allocation_iso ON allocation_requests
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (
    bearportal_actor() = 'platform_administrator'
    OR organization_id = bearportal_org()
  );

CREATE POLICY domains_iso ON domains
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (organization_id = bearportal_org() OR bearportal_actor() = 'platform_administrator');

CREATE POLICY secrets_iso ON secret_refs
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY dns_iso ON dns_connections
  USING (
    (bearportal_privileged() AND bearportal_actor() <> 'support')
    OR organization_id = bearportal_org()
  )
  WITH CHECK (organization_id = bearportal_org() OR bearportal_actor() = 'platform_administrator');

CREATE POLICY deployments_iso ON deployments
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (organization_id = bearportal_org() OR bearportal_actor() = 'platform_administrator');

CREATE POLICY jobs_iso ON jobs
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator') OR organization_id = bearportal_org());

CREATE POLICY backups_iso ON backups
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator') OR organization_id = bearportal_org());

CREATE POLICY assignments_iso ON server_assignments
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'customer'));

CREATE POLICY audit_iso ON audit_events
  USING (
    bearportal_privileged()
    OR organization_id = bearportal_org()
    OR actor_id = bearportal_user()
  )
  WITH CHECK (true);

CREATE POLICY idempotency_iso ON idempotency_keys
  USING (principal_id = bearportal_user() OR bearportal_actor() = 'platform_administrator')
  WITH CHECK (principal_id = bearportal_user() OR bearportal_actor() = 'platform_administrator');

CREATE POLICY servers_iso ON servers
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'));

CREATE POLICY relays_iso ON relay_connections
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'))
  WITH CHECK (bearportal_actor() = 'platform_administrator');

CREATE POLICY plans_iso ON plans
  USING (bearportal_actor() <> '')
  WITH CHECK (bearportal_actor() = 'platform_administrator');

CREATE POLICY outbox_iso ON outbox_events
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'customer'));

GRANT USAGE ON SCHEMA public TO bearportal_app;
GRANT SELECT, INSERT, UPDATE ON
  users, plans, organizations, operator_roles, invitations, allocation_requests,
  servers, server_assignments, domains, secret_refs, dns_connections, relay_connections,
  deployments, jobs, backups, outbox_events, idempotency_keys
TO bearportal_app;
GRANT INSERT, SELECT ON audit_events TO bearportal_app;
REVOKE UPDATE, DELETE ON audit_events FROM bearportal_app;
