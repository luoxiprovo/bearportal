-- Operator-reported lifecycle evidence. BearPortal does not call cloud snapshot or deletion APIs.
-- mail_verified stays false. A backup reference is not restore_verified by itself.

ALTER TABLE backups
  ADD COLUMN reported_by uuid,
  ADD COLUMN evidence_ref text,
  ADD COLUMN release_id text,
  ADD COLUMN schema_version text,
  ADD COLUMN consistency_state text,
  ADD COLUMN size_bytes bigint,
  ADD COLUMN started_at timestamptz,
  ADD COLUMN completed_at timestamptz,
  ADD COLUMN restore_verified_at timestamptz,
  ADD COLUMN expires_at timestamptz,
  ADD COLUMN reported_at timestamptz,
  ADD COLUMN cloud_verified boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT backups_consistency_known CHECK (
    consistency_state IS NULL OR consistency_state IN ('consistent', 'failed', 'unknown')
  ),
  ADD CONSTRAINT backups_cloud_unverified CHECK (cloud_verified = false);

CREATE TABLE cancellation_schedules (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  approval_id uuid UNIQUE,
  reason text,
  plan_hash text NOT NULL,
  generation integer NOT NULL,
  state text NOT NULL CHECK (state IN ('proposed', 'scheduled', 'revoked', 'stopped', 'completed')),
  execute_at timestamptz NOT NULL,
  window_ends_at timestamptz NOT NULL,
  proceed_without_final_backup boolean NOT NULL DEFAULT false,
  stop_queued boolean NOT NULL DEFAULT false,
  stop_job_id uuid,
  isolation_required boolean NOT NULL DEFAULT false,
  service_stopped boolean NOT NULL DEFAULT false,
  service_stopped_at timestamptz,
  isolation_evidence text,
  cloud_api_called boolean NOT NULL DEFAULT false CHECK (cloud_api_called = false),
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id)
);

CREATE UNIQUE INDEX cancellation_one_open
  ON cancellation_schedules (deployment_id)
  WHERE state IN ('proposed', 'scheduled', 'stopped');

CREATE TABLE restore_requests (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  backup_id uuid NOT NULL,
  approval_id uuid,
  plan_hash text NOT NULL,
  state text NOT NULL CHECK (state IN ('requested', 'ready', 'promoted', 'rejected')),
  acknowledge_data_loss boolean NOT NULL,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id),
  FOREIGN KEY (organization_id, backup_id) REFERENCES backups (organization_id, id)
);

CREATE UNIQUE INDEX restore_requests_one_open
  ON restore_requests (deployment_id)
  WHERE state IN ('requested', 'ready');

CREATE TABLE upgrade_plans (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  deployment_id uuid NOT NULL,
  approval_id uuid,
  to_release_id text NOT NULL,
  compatible boolean NOT NULL,
  irreversible boolean NOT NULL,
  new_mail_accepted boolean NOT NULL,
  checks_failed boolean NOT NULL,
  pre_upgrade_backup_id uuid,
  rollback_policy text NOT NULL CHECK (rollback_policy IN ('blocked', 'preserve_new_mail', 'binary_rollback')),
  state text NOT NULL CHECK (state IN ('blocked', 'preserve_required', 'rollback_required', 'pending')),
  executed boolean NOT NULL DEFAULT false,
  data_rollback boolean NOT NULL DEFAULT false,
  binaries_executed boolean NOT NULL DEFAULT false,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id),
  CONSTRAINT upgrade_plans_not_executed CHECK (executed = false AND data_rollback = false AND binaries_executed = false)
);

CREATE TABLE cleanup_reports (
  id uuid PRIMARY KEY,
  organization_id uuid,
  deployment_id uuid,
  server_id uuid NOT NULL REFERENCES servers (id),
  outcome text NOT NULL CHECK (outcome IN ('deleted', 'reimaged')),
  data_removed_at timestamptz NOT NULL,
  backup_retention_satisfied boolean NOT NULL,
  credentials_revoked boolean NOT NULL,
  evidence_ref text NOT NULL,
  operator_attestation text NOT NULL,
  reported_by uuid NOT NULL,
  cloud_verified boolean NOT NULL DEFAULT false,
  returned_available boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES deployments (organization_id, id),
  CONSTRAINT cleanup_reports_not_cloud CHECK (cloud_verified = false AND returned_available = false)
);

ALTER TABLE cancellation_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE cancellation_schedules FORCE ROW LEVEL SECURITY;
ALTER TABLE restore_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE restore_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE upgrade_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE upgrade_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE cleanup_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE cleanup_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY cancellation_iso ON cancellation_schedules
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR organization_id = bearportal_org()
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY restore_requests_iso ON restore_requests
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR organization_id = bearportal_org()
  )
  WITH CHECK (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker')
    OR (bearportal_actor() = 'customer' AND organization_id = bearportal_org())
  );

CREATE POLICY upgrade_plans_iso ON upgrade_plans
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR organization_id = bearportal_org()
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'inventory_worker'));

CREATE POLICY cleanup_reports_iso ON cleanup_reports
  USING (
    bearportal_actor() IN ('platform_administrator', 'infrastructure_operator', 'support', 'inventory_worker')
    OR (organization_id IS NOT NULL AND organization_id = bearportal_org())
  )
  WITH CHECK (bearportal_actor() IN ('platform_administrator', 'infrastructure_operator'));

CREATE POLICY backups_worker_read ON backups
  FOR SELECT
  USING (bearportal_actor() = 'inventory_worker');

CREATE POLICY assignments_worker_read ON server_assignments
  FOR SELECT
  USING (bearportal_actor() = 'inventory_worker');

GRANT SELECT, INSERT, UPDATE ON
  cancellation_schedules, restore_requests, upgrade_plans, cleanup_reports
TO bearportal_app;
