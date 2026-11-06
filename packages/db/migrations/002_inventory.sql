-- Inventory, host identity, and domain-proof constraints. BearPortal still does not write DNS.

DROP INDEX domains_one_active_name;

CREATE UNIQUE INDEX domains_one_verified_name
  ON domains (normalized_name)
  WHERE state = 'verified';

ALTER TABLE domains
  ADD COLUMN recheck_required boolean NOT NULL DEFAULT false,
  ADD COLUMN dns_connection_id uuid;

ALTER TABLE servers
  ADD COLUMN auth_epoch integer NOT NULL DEFAULT 1,
  ADD COLUMN host_identity_id uuid;

CREATE UNIQUE INDEX servers_live_provider_reference
  ON servers (provider_reference)
  WHERE provider_reference IS NOT NULL AND state <> 'retired';

CREATE UNIQUE INDEX servers_one_host_identity
  ON servers (host_identity_id)
  WHERE host_identity_id IS NOT NULL AND state <> 'retired';

ALTER TABLE allocation_requests
  ADD COLUMN cancellation_requested_at timestamptz;

ALTER TABLE jobs
  ADD COLUMN lease_owner text,
  ADD COLUMN lease_expires_at timestamptz,
  ADD COLUMN fencing_token bigint NOT NULL DEFAULT 1,
  ADD COLUMN cancel_requested_at timestamptz;

CREATE TABLE host_identities (
  id uuid PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id),
  public_key text NOT NULL,
  fingerprint text NOT NULL,
  enrollment_epoch integer NOT NULL DEFAULT 1,
  state text NOT NULL CHECK (state IN ('pending_confirmation', 'confirmed', 'revoked')),
  confirmed_by uuid,
  confirmed_at timestamptz,
  revoked_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX host_identities_public_key ON host_identities (public_key);

CREATE UNIQUE INDEX host_identities_one_active
  ON host_identities (server_id)
  WHERE state <> 'revoked';

CREATE TABLE host_enrollments (
  id uuid PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id),
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  requested_by uuid NOT NULL REFERENCES users (id),
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE host_auth_challenges (
  id uuid PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id),
  host_identity_id uuid NOT NULL REFERENCES host_identities (id),
  nonce_hash text NOT NULL UNIQUE,
  audience text NOT NULL,
  enrollment_epoch integer NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE inventory_jobs (
  id uuid PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id),
  kind text NOT NULL,
  state text NOT NULL,
  checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
  lease_owner text,
  lease_expires_at timestamptz,
  fencing_token bigint NOT NULL DEFAULT 1,
  result jsonb,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE required_actions (
  id uuid PRIMARY KEY,
  scope text NOT NULL CHECK (scope IN ('tenant', 'inventory')),
  organization_id uuid REFERENCES organizations (id),
  server_id uuid REFERENCES servers (id),
  deployment_id uuid,
  job_id uuid,
  inventory_job_id uuid,
  audience text NOT NULL CHECK (audience IN ('operator', 'customer')),
  code text NOT NULL,
  instructions text NOT NULL,
  state text NOT NULL CHECK (state IN ('open', 'resolved')),
  resolved_by uuid,
  resolved_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX required_actions_one_shortage
  ON required_actions (code)
  WHERE state = 'open' AND code = 'inventory.shortage';

CREATE UNIQUE INDEX required_actions_open_org_code
  ON required_actions (organization_id, code)
  WHERE state = 'open' AND organization_id IS NOT NULL;

CREATE UNIQUE INDEX required_actions_open_server_code
  ON required_actions (server_id, code)
  WHERE state = 'open' AND server_id IS NOT NULL;

CREATE TABLE recovery_bindings (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations (id),
  deployment_id uuid,
  replacement_server_id uuid NOT NULL REFERENCES servers (id),
  restore_job_id uuid,
  approval_id uuid,
  state text NOT NULL CHECK (state IN ('pending', 'promoted', 'released')),
  expires_at timestamptz,
  fencing_evidence jsonb,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX recovery_one_pending_server
  ON recovery_bindings (replacement_server_id)
  WHERE state = 'pending';

CREATE TABLE relay_assignments (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations (id),
  deployment_id uuid,
  relay_connection_id uuid NOT NULL REFERENCES relay_connections (id),
  assigned_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX relay_assignments_live_org
  ON relay_assignments (organization_id)
  WHERE released_at IS NULL;

CREATE UNIQUE INDEX relay_assignments_live_relay
  ON relay_assignments (relay_connection_id)
  WHERE released_at IS NULL;

CREATE TABLE dns_plans (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  domain_id uuid NOT NULL,
  generation integer NOT NULL DEFAULT 1,
  purpose text NOT NULL,
  base_fingerprint text NOT NULL,
  desired_records jsonb NOT NULL,
  operations jsonb NOT NULL,
  plan_hash text NOT NULL,
  state text NOT NULL,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, domain_id) REFERENCES domains (organization_id, id)
);

CREATE TABLE host_commands (
  id uuid PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id),
  inventory_job_id uuid REFERENCES inventory_jobs (id),
  job_id uuid,
  organization_id uuid,
  deployment_id uuid,
  generation integer NOT NULL DEFAULT 1,
  auth_epoch integer NOT NULL,
  command_type text NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL,
  state text NOT NULL,
  expires_at timestamptz NOT NULL,
  result jsonb,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (((inventory_job_id IS NOT NULL)::int + (job_id IS NOT NULL)::int) = 1),
  FOREIGN KEY (organization_id, job_id) REFERENCES jobs (organization_id, id)
);

DROP POLICY assignments_iso ON server_assignments;
CREATE POLICY assignments_iso ON server_assignments
  USING (
    bearportal_privileged()
    OR bearportal_actor() = 'allocator'
    OR organization_id = bearportal_org()
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'allocator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

DROP POLICY outbox_iso ON outbox_events;
CREATE POLICY outbox_iso ON outbox_events
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'allocator', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN (
    'platform_administrator', 'infrastructure_operator', 'customer', 'allocator', 'inventory_worker'
  ));

CREATE POLICY organizations_allocator ON organizations
  FOR SELECT
  USING (bearportal_actor() = 'allocator');

CREATE POLICY allocation_allocator ON allocation_requests
  USING (bearportal_actor() = 'allocator')
  WITH CHECK (bearportal_actor() = 'allocator');

CREATE POLICY servers_worker ON servers
  USING (bearportal_actor() IN ('allocator', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN ('allocator', 'inventory_worker'));

CREATE POLICY servers_customer_read ON servers
  FOR SELECT
  USING (
    bearportal_actor() = 'customer'
    AND EXISTS (
      SELECT 1 FROM server_assignments a
      WHERE a.server_id = servers.id
        AND a.released_at IS NULL
        AND a.organization_id = bearportal_org()
    )
  );

ALTER TABLE host_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE host_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_enrollments FORCE ROW LEVEL SECURITY;
ALTER TABLE host_auth_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_auth_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE inventory_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE required_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE required_actions FORCE ROW LEVEL SECURITY;
ALTER TABLE recovery_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE relay_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE host_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_commands FORCE ROW LEVEL SECURITY;

CREATE POLICY host_identities_iso ON host_identities
  USING (bearportal_actor() IN (
    'platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker', 'allocator'
  ))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY host_enrollments_iso ON host_enrollments
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY host_challenges_iso ON host_auth_challenges
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY inventory_jobs_iso ON inventory_jobs
  USING (bearportal_actor() IN (
    'platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker', 'allocator'
  ))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY required_actions_iso ON required_actions
  USING (
    bearportal_actor() IN (
      'platform_administrator', 'infrastructure_operator', 'support', 'allocator', 'inventory_worker'
    )
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'allocator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY recovery_iso ON recovery_bindings
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'allocator')
    OR organization_id = bearportal_org()
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY relay_assignments_iso ON relay_assignments
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR organization_id = bearportal_org()
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'));

CREATE POLICY dns_plans_iso ON dns_plans
  USING (bearportal_privileged() OR organization_id = bearportal_org())
  WITH CHECK (organization_id = bearportal_org() OR bearportal_actor() = 'platform_administrator');

CREATE POLICY host_commands_iso ON host_commands
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (organization_id IS NOT NULL AND organization_id = bearportal_org())
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

GRANT SELECT, INSERT, UPDATE ON
  host_identities, host_enrollments, host_auth_challenges, inventory_jobs, required_actions,
  recovery_bindings, relay_assignments, dns_plans, host_commands
TO bearportal_app;
