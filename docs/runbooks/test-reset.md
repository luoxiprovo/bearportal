# Reset development test data

Use this only when deliberately starting over with test customers and fresh inventory. Ordinary startup and automated tests do not need a reset. This supports both local trial sign-in and real Google Identity Platform sign-in in **development mode**, including `https://app.bearos.si`. Keep the test issuer disabled on the public website.

## Public development website: four steps

1. **Cancel test subscriptions first, while the API is still running.** Use the customer's cancellation option or the Stripe Dashboard in the correct test environment. Choose immediate cancellation, not cancellation at the end of the billing period. Allow webhooks to arrive so BearPortal records the subscriptions as `canceled`. Trialing subscriptions also need cancellation. The reset refuses any subscription with a Stripe ID whose local status is not `canceled`.

2. From the BearPortal checkout, stop the API service:

   ```bash
   cd ~/bearportal
   sudo systemctl stop bearportal-api
   ```

3. Back up and clear test records:

   ```bash
   pnpm reset:test-data --confirm-clear-test-data
   ```

   Wait for `Cleared local customer and inventory data` and the private backup path. If this fails, no database deletion is committed. Read the error, restart the API if needed to resolve subscriptions or installations, then retry. Do not change to the local test issuer to run this command.

4. Start the service again:

   ```bash
   sudo systemctl start bearportal-api
   ```

   Open `https://app.bearos.si` and sign in normally. Operator access is preserved. Add fresh or properly cleaned servers and Brevo accounts, then test the customer journey again. New inventory names start at `s-1` and `b-1`.

Use the actual checkout path if different; migrations default to `/opt/bearportal`. Stop/start the service, rather than killing its process, because systemd would otherwise restart it automatically. HTTPS remains configured through Caddy; the website can show a temporary gateway error while the API is stopped.

## Local trial

Stop the terminal running `pnpm trial:start`, run the same reset command, then use `pnpm trial:start` again. `pnpm trial:reset --confirm-clear-test-data` is an alias for the same reset implementation. Other `trial:*` commands still require the local test issuer; Google-authenticated deployments should keep using systemd and their normal Google operator login.

## What is protected and cleared

The command reads `.data/trial/env`, including quoted values. It requires `BEARPORTAL_ENV=development`, a supported local database, a stopped API listener, an active operator, no active installation/job, and canceled Stripe subscriptions. Live Stripe credentials, production mode and migration-fenced deployments are refused.

Before clearing anything it writes a PostgreSQL custom-format dump and copies encrypted credential files into a private `.data/backups/test-reset-*` directory. Backup failure aborts the reset. Database deletion is transactional. Operator users, roles, authenticators and linked managed identities remain, along with plans, migrations, control-plane configuration, SSH keys and application settings. Customer users/identities, organizations, domains, DNS credentials, deployments, mailboxes, assignments, all server/Brevo inventory and credential references, and operational/audit history are cleared. Inventory name counters return to zero. Active encrypted credential files and stale walkthrough references are removed after the database commits. Backups intentionally retain old test data; protect or remove them according to your retention needs.

This affects local BearPortal records only. It does not delete cloud VMs, uninstall remote BearMail, modify domain DNS, remove Brevo provider-side domains, delete Stripe customers or cancel subscriptions, or delete Google Identity Platform accounts. Existing Google/email accounts can sign in again and receive fresh BearPortal customer records. Use fresh or properly cleaned servers for retesting; deleting a database record does not make an installed mail server clean.

For a local PostgreSQL container, `BEARPORTAL_BACKUP_DATABASE_URL` in `.data/trial/env` can supply a database-administrator connection for the backup. It must target the exact same host, port and database as `MIGRATION_DATABASE_URL`. Use PostgreSQL 17 client tools with a PostgreSQL 17 server. The database owner remains the connection used for the reset transaction; elevated credentials are used only for the dump. Without an explicit backup connection, the script tries the migration connection, then the local Unix-socket PostgreSQL administrator.
