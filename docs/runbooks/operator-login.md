# Production operator access

Operators use **/operator/login**, sign in with Google or verified email/password,
then verify a BearPortal authenticator code at **/operator/security**. The first
visit enrolls an authenticator and displays ten one-time recovery codes. There is
no operator email or password in application code and no subscription requirement.
Google-account two-step verification and BearPortal's operator authenticator are
separate. This flow does not require enabling Identity Platform MFA in the console.

## Authorize the first administrator

Run these commands from the repository root on the trusted server:

```sh
node --env-file=.data/trial/env --import tsx packages/db/src/migrate.ts
pnpm operator:authorize --email you@example.com --role platform_administrator --reason "Initial production administrator"
```

The command reads `.data/trial/env`, or the file supplied with `--env-file`. It
uses `MIGRATION_DATABASE_URL` and `BEARPORTAL_IDENTITY_PROJECT_ID`; keep the database
owner credentials private. Public browser requests cannot create these approvals.
The approval expires after 24 hours and is consumed by a fresh verified sign-in.
It grants access only for the approved issuer/email. Ownership must be established
with authoritative Google sign-in (for example Gmail) or verified email/password.

For this repository's older development deployment, add `--reuse-bootstrap-admin`
to explicitly link the one existing, unlinked administrator to the approved
identity. Its user ID, permissions and audit history are retained. This flag fails
when there is not exactly one eligible bootstrap administrator. Existing managed
accounts are selected by their exact verified email instead; accounts are never
silently merged. An account bound to a different managed identity is not relinked.

Open `/operator/login`, sign in using the approved email, choose **Set up
authenticator**, scan the QR code, enter the six-digit code, save the recovery
codes, then choose **Open operator inventory**. The inventory contains **Add
server** and **Add Brevo account**. Setup keys and recovery codes should be saved
by the operator privately, not shared with an assistant or placed in chat.

## Additional operators and other deployments

Use the same command with a different email and the intended role:

```sh
pnpm operator:authorize --email staff@example.com --role infrastructure_operator --reason "Authorized infrastructure staff"
```

Available roles are `support`, `infrastructure_operator` and
`platform_administrator`. Existing role checks still determine which operations
are permitted. Use platform administrator for the initial owner who manages all
inventory, including Brevo. Reissuing an authorization does not remove other roles;
use the role-revocation workflow when withdrawing access.

A new database has no authorized operators until this command is run. A restored
database preserves authorizations, identity bindings, roles and enrolled factors.
Restore the same encryption key with it, retain the Identity Platform project, and
configure the new site's Google authorized domain/origin and HTTPS environment.
Changing a server configuration value alone does not transfer privileges to a new
email. Authorize that email explicitly. Bindings and roles persist through service
restarts; the 24-hour deadline applies only to an unconsumed approval.

## MFA and recovery

The MFA secret is AES-256-GCM encrypted using the existing application encryption
key. Recovery codes contain 128 random bits and are stored only as SHA-256 hashes.
MFA sessions use opaque, hashed server records plus an HttpOnly cookie (Secure on
HTTPS), bound to the verified Identity Platform issuer, UID and sign-in time.
Role revocation and disabled-user checks continue to apply on every operation.
Google/custom `amr` claims cannot replace an independently verified operator MFA
session. Session lifetime is two hours; existing sensitive operations can require
verification within 15 minutes. Sign-out revokes the current MFA session. Refreshing
an ID token does not itself renew MFA. Inventory errors link to verification in a
new tab so the original form remains available for retry.

A used authenticator time step cannot be replayed, including across browsers.
An unused recovery code can replace a code from the authenticator once. Five
incorrect attempts lock verification for five minutes; the counter and lockout
persist in the database. Pending enrollment expires in ten minutes and is bound
to the browser that started it. Enrolling requires a recent first-factor sign-in.

If the operator loses both the authenticator and recovery codes, a trusted server
administrator can explicitly reset it after checking the operator's identity:

```sh
pnpm operator:authorize --email you@example.com --reset-mfa --reason "Verified operator recovery after lost device"
```

This deletes the factor and revokes every MFA session for that account. Its role
and managed identity remain. The operator must sign in again and enroll a new
factor. Reset and authorization actions are audited; no seed, code or session token
is included in the audit. There is no public email-only MFA reset endpoint.

Production keeps `BEARPORTAL_ALLOW_TEST_ISSUER=0`. `pnpm trial:login` is for the
separate development issuer only; production never accepts its token as MFA.
