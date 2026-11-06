-- Oversight sessions, pinned steps, health, and recovery mode.
-- Live mail verification stays false. BearPortal still does not write customer DNS.

CREATE TABLE control_plane_state (
  id integer PRIMARY KEY CHECK (id = 1),
  mode text NOT NULL CHECK (mode IN ('normal', 'recovery')),
  reason text,
  entered_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO control_plane_state (id, mode) VALUES (1, 'normal');

CREATE TABLE oversight_sessions (
  id uuid PRIMARY KEY,
  organization_id uuid,
  deployment_id uuid,
  server_id uuid,
  scope text NOT NULL CHECK (scope IN ('tenant', 'inventory')),
  generation integer NOT NULL,
  auth_epoch integer NOT NULL,
  lease_fencing_token text NOT NULL,
  state text NOT NULL CHECK (state IN ('open', 'terminated')),
  tool_requests integer NOT NULL DEFAULT 0,
  invocations integer NOT NULL DEFAULT 0,
  usage_tokens integer,
  usage_provenance text NOT NULL DEFAULT 'unknown' CHECK (usage_provenance IN ('reported', 'unknown')),
  started_at timestamptz NOT NULL DEFAULT now(),
  terminated_reason text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (scope <> 'tenant' OR organization_id IS NOT NULL),
  CHECK (scope <> 'inventory' OR organization_id IS NULL),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE operation_steps (
  id text PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES oversight_sessions (id),
  organization_id uuid,
  operation_key text NOT NULL,
  operation_version text NOT NULL,
  handler text NOT NULL,
  digest text NOT NULL,
  requested_key text,
  requested_version text,
  requested_handler text,
  requested_digest text,
  arguments jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'succeeded', 'blocked', 'retryable_error', 'permanent_error')),
  code text NOT NULL,
  message text NOT NULL,
  job_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE TABLE diagnoses (
  id uuid PRIMARY KEY,
  organization_id uuid,
  deployment_id uuid,
  session_id uuid,
  summary text NOT NULL,
  evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);

CREATE TABLE approvals (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid,
  action_code text NOT NULL,
  plan_hash text NOT NULL,
  generation integer NOT NULL,
  resource_id text NOT NULL,
  dns_fingerprint text NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'invalidated', 'expired')),
  approver_id uuid,
  expires_at timestamptz NOT NULL,
  in_flight boolean NOT NULL DEFAULT false,
  executed boolean NOT NULL DEFAULT false,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE health_observations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  probe text NOT NULL,
  state text NOT NULL CHECK (state IN ('pass', 'fail', 'partial', 'absent')),
  disk_percent integer,
  observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE incidents (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  probe text NOT NULL,
  state text NOT NULL CHECK (state IN ('open', 'closed')),
  consecutive_failures integer NOT NULL DEFAULT 0,
  consecutive_successes integer NOT NULL DEFAULT 0,
  opened_at timestamptz,
  closed_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, deployment_id, probe),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE notifications (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid,
  incident_id uuid,
  kind text NOT NULL CHECK (kind IN ('incident', 'recovery')),
  dedupe_key text NOT NULL UNIQUE,
  recipient_source text NOT NULL CHECK (recipient_source IN ('owner_recovery', 'operator')),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE TABLE hosting_estimates (
  id uuid PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id),
  amount_minor integer NOT NULL,
  currency text NOT NULL,
  source text NOT NULL CHECK (source = 'operator'),
  billing_system text NOT NULL CHECK (billing_system = 'not_google_billing'),
  recorded_by uuid NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE provider_attempts (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  operation_key text NOT NULL,
  attempt integer NOT NULL,
  status integer,
  accepted boolean NOT NULL DEFAULT false,
  reconciled boolean NOT NULL DEFAULT false,
  next_delay_ms integer,
  action text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION bearportal_mail_verified_locked() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.mail_verified IS TRUE THEN
    RAISE EXCEPTION 'mail_verified stays false until live mail evidence exists';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS deployments_mail_verified_lock ON deployments;
CREATE TRIGGER deployments_mail_verified_lock
  BEFORE INSERT OR UPDATE ON deployments
  FOR EACH ROW EXECUTE FUNCTION bearportal_mail_verified_locked();

ALTER TABLE control_plane_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_plane_state FORCE ROW LEVEL SECURITY;
ALTER TABLE oversight_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE oversight_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE operation_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE operation_steps FORCE ROW LEVEL SECURITY;
ALTER TABLE diagnoses ENABLE ROW LEVEL SECURITY;
ALTER TABLE diagnoses FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE health_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE health_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
ALTER TABLE hosting_estimates ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting_estimates FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY control_plane_read ON control_plane_state
  FOR SELECT
  USING (bearportal_actor() <> '');

CREATE POLICY control_plane_write ON control_plane_state
  FOR UPDATE
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY oversight_sessions_iso ON oversight_sessions
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    (
      bearportal_actor() IN ('platform_administrator', 'infrastructure_operator')
      AND scope = 'inventory'
      AND organization_id IS NULL
    )
    OR bearportal_actor() = 'inventory_worker'
    OR (
      bearportal_actor() = 'customer'
      AND scope = 'tenant'
      AND organization_id = bearportal_org()
    )
  );

CREATE POLICY operation_steps_iso ON operation_steps
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY diagnoses_iso ON diagnoses
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY approvals_iso ON approvals
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY health_observations_iso ON health_observations
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY incidents_iso ON incidents
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY notifications_iso ON notifications
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY hosting_estimates_iso ON hosting_estimates
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'));

CREATE POLICY provider_attempts_iso ON provider_attempts
  USING (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'))
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY deployments_worker_read ON deployments
  FOR SELECT
  USING (bearportal_actor() = 'inventory_worker');

CREATE POLICY deployments_worker_update ON deployments
  FOR UPDATE
  USING (bearportal_actor() = 'inventory_worker')
  WITH CHECK (bearportal_actor() = 'inventory_worker');

CREATE POLICY jobs_worker ON jobs
  USING (bearportal_actor() = 'inventory_worker')
  WITH CHECK (bearportal_actor() = 'inventory_worker');

GRANT SELECT, UPDATE ON control_plane_state TO bearportal_app;
GRANT SELECT, INSERT, UPDATE ON
  oversight_sessions, operation_steps, diagnoses, approvals, health_observations,
  incidents, notifications, hosting_estimates, provider_attempts
TO bearportal_app;
