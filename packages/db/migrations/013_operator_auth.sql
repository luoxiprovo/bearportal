-- Explicit server-approved identity linking and independently verified operator MFA.
ALTER TABLE users ADD COLUMN operator_mfa_reset_at timestamptz;
CREATE TABLE operator_authorizations (
  id uuid PRIMARY KEY,
  issuer text NOT NULL,
  email text NOT NULL CHECK (email=lower(email)),
  target_user_id uuid REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('support','infrastructure_operator','platform_administrator')),
  reason text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX operator_authorizations_pending ON operator_authorizations(issuer,email) WHERE consumed_at IS NULL;

CREATE TABLE operator_totp (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret bytea NOT NULL,
  enrolled_at timestamptz,
  enrollment_expires_at timestamptz,
  enrollment_token_hash text,
  last_counter bigint NOT NULL DEFAULT -1,
  recovery_hashes text[] NOT NULL DEFAULT '{}',
  failed_attempts integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE operator_mfa_sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  identity_issuer text NOT NULL,
  identity_subject text NOT NULL,
  first_factor_auth_time bigint NOT NULL,
  authenticated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX operator_mfa_sessions_user ON operator_mfa_sessions(user_id);

ALTER TABLE operator_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_authorizations_admin ON operator_authorizations
 USING (bearportal_actor()='platform_administrator') WITH CHECK (bearportal_actor()='platform_administrator');
ALTER TABLE operator_totp ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_totp FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_totp_admin ON operator_totp
 USING (bearportal_actor()='platform_administrator') WITH CHECK (bearportal_actor()='platform_administrator');
ALTER TABLE operator_mfa_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_mfa_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_mfa_sessions_read ON operator_mfa_sessions FOR SELECT
 USING (bearportal_actor()='platform_administrator' OR user_id=bearportal_user());
CREATE POLICY operator_mfa_sessions_write ON operator_mfa_sessions FOR ALL
 USING (bearportal_actor()='platform_administrator') WITH CHECK (bearportal_actor()='platform_administrator');
GRANT SELECT,INSERT,UPDATE,DELETE ON operator_authorizations,operator_totp,operator_mfa_sessions TO bearportal_app;
