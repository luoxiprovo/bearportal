-- Installation evidence, mailboxes, and short-lived mailbox credentials.
-- BearPortal still does not write customer DNS. The installer result is evidence only.

ALTER TABLE deployments
  ADD COLUMN server_id uuid,
  ADD COLUMN release_id text,
  ADD COLUMN observed_ip inet,
  ADD COLUMN ip_observed_at timestamptz,
  ADD COLUMN active_job_id uuid,
  ADD COLUMN activated_at timestamptz,
  ADD COLUMN plan_snapshot jsonb,
  ADD COLUMN mail_hostname text,
  ADD COLUMN webmail_hostname text,
  ADD COLUMN first_mailbox_local_part text,
  ADD COLUMN test_mail_consent boolean NOT NULL DEFAULT false,
  ADD COLUMN mx_authorized_at timestamptz,
  ADD COLUMN installer_operation_id uuid,
  ADD COLUMN installer_input_hash text,
  ADD COLUMN brevo_records jsonb,
  ADD COLUMN relay_connection_id uuid,
  ADD COLUMN previous_mx jsonb,
  ADD COLUMN published_records jsonb,
  ADD COLUMN installer_status text,
  ADD COLUMN dns_writes_accepted boolean NOT NULL DEFAULT false,
  ADD COLUMN brevo_authenticated boolean NOT NULL DEFAULT false,
  ADD COLUMN brevo_verified boolean NOT NULL DEFAULT false,
  ADD COLUMN backup_reported_at timestamptz,
  ADD COLUMN admin_secret_ref uuid,
  ADD COLUMN mail_verified boolean NOT NULL DEFAULT false;

CREATE TABLE mailboxes (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  local_part text NOT NULL,
  address text NOT NULL,
  principal_id text,
  kind text NOT NULL CHECK (kind IN ('customer', 'system_test', 'system_admin', 'system_alias')),
  state text NOT NULL,
  receive_enabled boolean NOT NULL DEFAULT true,
  login_enabled boolean NOT NULL DEFAULT false,
  send_enabled boolean NOT NULL DEFAULT false,
  credential_reset_required boolean NOT NULL DEFAULT true,
  quota_bytes bigint,
  usage_bytes bigint NOT NULL DEFAULT 0,
  last_observed_at timestamptz,
  credential_secret_ref uuid,
  credential_expires_at timestamptz,
  alias_for uuid,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  UNIQUE (address),
  UNIQUE (deployment_id, local_part),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE installer_runs (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  generation integer NOT NULL,
  mode text NOT NULL CHECK (mode IN ('dry_run', 'apply')),
  status text NOT NULL,
  exit_code integer,
  retryable boolean NOT NULL DEFAULT false,
  error_code text,
  previous_mx jsonb,
  published_records jsonb NOT NULL DEFAULT '[]'::jsonb,
  dns_writes_accepted boolean NOT NULL DEFAULT false,
  result jsonb NOT NULL,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  UNIQUE (deployment_id, operation_id, mode),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE dns_observations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  matches boolean NOT NULL,
  mx_mismatch boolean NOT NULL DEFAULT false,
  apex_changed boolean NOT NULL DEFAULT false,
  observed jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

ALTER TABLE mailboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailboxes FORCE ROW LEVEL SECURITY;
ALTER TABLE installer_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE installer_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_observations FORCE ROW LEVEL SECURITY;

CREATE POLICY mailboxes_iso ON mailboxes
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY installer_runs_iso ON installer_runs
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY dns_observations_iso ON dns_observations
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

-- The expiry worker may retire only mailbox passwords. It cannot read DNS or relay secrets.
CREATE POLICY secrets_mailbox_expiry ON secret_refs
  USING (bearportal_actor() = 'inventory_worker' AND purpose = 'mailbox-credential')
  WITH CHECK (bearportal_actor() = 'inventory_worker' AND purpose = 'mailbox-credential');

GRANT SELECT, INSERT, UPDATE ON mailboxes, installer_runs, dns_observations TO bearportal_app;
