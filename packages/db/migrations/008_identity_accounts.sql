-- Bind verified Identity Platform UIDs to stable application users, preserving legacy ownership.
CREATE TABLE identity_accounts (
  issuer text NOT NULL,
  subject text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id),
  provider text NOT NULL CHECK (provider IN ('password','google.com')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(issuer,subject)
);
CREATE INDEX identity_accounts_user ON identity_accounts(user_id);
ALTER TABLE identity_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_accounts_control_plane ON identity_accounts
  USING (bearportal_actor()='platform_administrator')
  WITH CHECK (bearportal_actor()='platform_administrator');
GRANT SELECT,INSERT ON identity_accounts TO bearportal_app;
