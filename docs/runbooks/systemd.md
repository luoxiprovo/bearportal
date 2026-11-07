# systemd deployment

The supplied unit is [../../infra/systemd/bearportal-api.service](../../infra/systemd/bearportal-api.service). It uses `/opt/bearportal`, reads `/etc/bearportal/api.env`, and starts `node_modules/.bin/tsx apps/api/src/main.ts`. It requires local PostgreSQL, restarts on failure, and sets `NoNewPrivileges=true` and `PrivateTmp=true`.

The unit starts the API that wires live SSH and installation. Startup resumes due saved onboarding work and HTTPS checks, so it can contact providers or mail servers without a new browser request. The API includes a persistent onboarding-request processor with a 30-second retry interval. There is no separate worker unit, general outbox dispatcher, monitor timer or platform-mail sender. Apply all migrations, including `006_onboarding.sql`, `007_inventory_management.sql` and `008_identity_accounts.sql`, before startup.

Ensure the service identity can read its configured JWT/encryption material and encrypted secret directory, read `/var/lib/bearportal/ssh/id_ed25519`, update `/var/lib/bearportal/ssh/known_hosts`, and write `/var/lib/bearportal/work`. The API creates/checks the work directory at startup and fails before accepting setups if it is inaccessible. Prepare ownership before startup, for example `sudo install -d -m 700 -o SERVICE_USER -g SERVICE_GROUP /var/lib/bearportal/work`. A missing or unwritable directory can otherwise stop provisioning. Keep private files at mode `0600` and private directories at `0700`; set ownership for the actual service identity. The template does not set `User=` and should be reviewed before production use.

The remote login is `bearadmin` with noninteractive sudo. Its remote policy is separate from the local API unit's hardening. Remote staging uses `/var/lib/bearportal/install`, on a filesystem that allows executable artifacts.

Internal scheduler routes require `BEARPORTAL_SCHEDULER_TOKEN`; configure the external caller separately. The admin waitlist reconciliation route uses operator authentication and still runs in recovery mode, unlike the paused internal allocator.

Expose the loopback API through an appropriately configured HTTPS endpoint. Managed Identity Platform cookies use `Secure` for HTTPS origins and rotating Google verification keys; the older static development cookie path lacks `Secure`. Immediate upstream revocation checks and the upstream MFA challenge UI are not implemented; the template alone is not production authentication hardening. See [../../SPEC.md](../../SPEC.md).
