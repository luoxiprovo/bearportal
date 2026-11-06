# systemd deployment

The supplied unit is [../../infra/systemd/bearportal-api.service](../../infra/systemd/bearportal-api.service). It uses `/opt/bearportal`, reads `/etc/bearportal/api.env`, and starts `node_modules/.bin/tsx apps/api/src/main.ts`. It requires local PostgreSQL, restarts on failure, and sets `NoNewPrivileges=true` and `PrivateTmp=true`.

The unit starts the API that wires live SSH and installation. Provider/host actions occur when the corresponding requests run, not simply because the service starts. The API includes a persistent onboarding-request processor with a 30-second retry interval. There is no separate worker unit, general outbox dispatcher, monitor timer or platform-mail sender. Apply migration `006_onboarding.sql` before startup.

Ensure the service identity can read its configured JWT/encryption material and encrypted secret directory, read `/var/lib/bearportal/ssh/id_ed25519`, update `/var/lib/bearportal/ssh/known_hosts`, and write `/var/lib/bearportal/work`. A missing or unwritable directory can stop provisioning. Keep private files at mode `0600` and private directories at `0700`; set ownership for the actual service identity. The template does not set `User=` and should be reviewed before production use.

The remote login is `bearportal-control-plane` with noninteractive sudo. Its remote policy is separate from the local API unit's hardening. Remote staging uses `/var/lib/bearportal/install`, on a filesystem that allows executable artifacts.

Internal scheduler routes require `BEARPORTAL_SCHEDULER_TOKEN`; configure the external caller separately. The admin waitlist reconciliation route uses operator authentication and still runs in recovery mode, unlike the paused internal allocator.

Expose the loopback API through an appropriately configured HTTPS endpoint. The current application cookie lacks `Secure`, and identity-key refresh/revocation integration is incomplete; the template alone is not production authentication hardening. See [../../SPEC.md](../../SPEC.md).
