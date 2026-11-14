# Reset development test data

Use this only when deliberately starting over with test customers and fresh inventory. Ordinary startup and automated tests do not need a reset. This supports both local trial sign-in and real Google Identity Platform sign-in in **development mode**, including `https://app.bearos.si`. Keep the test issuer disabled on the public website.

## Public development website: four steps

1. **Cancel test subscriptions first.** No customer login is needed. From the BearPortal checkout, preview subscriptions:

   ```bash
   pnpm stripe:cancel-test-subscriptions
   ```

   Then cancel the listed subscriptions immediately:

   ```bash
   pnpm stripe:cancel-test-subscriptions --confirm-cancel-test-subscriptions
   ```

   To target one customer, add `--email user@example.com` to both commands. The default previews all uncanceled subscriptions recorded in this development database, not every subscription in the Stripe account. The script reads `.data/trial/env`, requires development mode and test keys, and checks each subscription's test-mode flag, customer, organization metadata and configured price before any cancellation. It sets `invoice_now=false` and `prorate=false` ([Stripe cancellation API](https://docs.stripe.com/api/subscriptions/cancel)). It reconciles local records and opens normal operator cleanup tasks even if a webhook is delayed. It does not delete customers, refund invoices, or clean mail resources. On failure, earlier successful cancellations remain canceled; rerun the preview and retry. Repeating a completed cancellation is safe.

   Alternatively, cancel through the customer's portal or the correct Stripe test Dashboard and wait for webhooks. Choose immediate cancellation rather than cancellation at period end. Trialing subscriptions also need cancellation. The reset refuses any subscription with a Stripe ID whose local status is not `canceled`.

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

## Also delete Google Identity test accounts

Use `pnpm reset:test-data:google` when you want users to register again from scratch. This deletes their **Identity Platform accounts in the configured project**, including password and Google sign-in bindings. It does not delete their personal Google/Gmail accounts. Operator emails, operator-authorized emails and operator UIDs are protected. The ordinary reset command continues to leave Google unchanged.

### One-time Google admin access

The script uses the active Google Cloud CLI account. The existing VM credentials currently lack the required admin access/OAuth scopes. On the server, authenticate as an administrator of the **Identity Platform project**, which can differ from the VM project:

```bash
gcloud auth login --no-launch-browser
```

Complete the browser instructions using an authorized Google Cloud administrator. The account needs `firebaseauth.users.get` and `firebaseauth.users.delete` on that project; the **Firebase Authentication Admin** role (`roles/firebaseauth.admin`) includes them. The script checks both permissions before deletion. The normal application's web API key cannot administer/delete other users, and does not need changing. Keep admin credentials private; no new secret belongs in Git. If organization policy disallows interactive login on the VM, use an approved admin identity with these same permissions instead.

### Preview, then perform the combined reset

First cancel test subscriptions using the earlier steps. Preview Google accounts while the API is still available:

```bash
pnpm reset:test-data:google
```

By default, selection includes customer emails still present in the local database. It never lists or deletes every user in the Google project. The preview prints the exact project ID and selected accounts. To include a Google account left after an earlier local reset or an unverified signup, explicitly supply its email:

```bash
pnpm reset:test-data:google --email luoxi@bearos.si
```

Repeat `--email` to select multiple addresses. When supplied, `--email` restricts **Google deletions only**. The confirmed command still clears **all local customers and inventory**, just like the ordinary reset.

After reviewing the preview, stop the service and run the combined reset. Replace `PROJECT_ID` with the project printed by the preview; keep the same `--email` selections, if any:

```bash
sudo systemctl stop bearportal-api
pnpm reset:test-data:google --project PROJECT_ID --confirm-delete-google-users --confirm-clear-test-data
sudo systemctl start bearportal-api
```

For example, to include the previously registered address above, append `--email luoxi@bearos.si` to the reset command. No cloud user is deleted merely by previewing. Both confirmation flags and the matching project ID are mandatory. Passwords, hashes and tokens from Google's lookup response are discarded, rather than written to the preview or deletion receipt.

The combined flow checks Google admin permissions, operator protection and local reset prerequisites, then makes the normal private database/credential backup **before any Google deletion**. It rechecks email-to-UID bindings before deleting. If Google deletion fails, local database data is retained; earlier Google deletions cannot be rolled back. A private `google-identity-cleanup.json` in the backup directory records planned and completed UIDs. Rerun the preview and repeat the confirmed command after correcting the error; already missing Google accounts are skipped. Never blindly run an old receipt as a deletion list.

Google deletion and local SQL cannot form one atomic transaction. A local database backup does **not** restore a deleted Google password or sign-in account. If deletion has begun and any subsequent step fails, inspect the receipt and retry; do not assume that restoring PostgreSQL will restore Google access. After a successful combined reset, customers can register again. Existing browser sessions should sign out and start a fresh sign-in.

References: [Google account lookup](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/lookup), [Google account deletion](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/delete), [permission preflight](https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions).

## Local trial

Stop the terminal running `pnpm trial:start`, run the same reset command, then use `pnpm trial:start` again. `pnpm trial:reset --confirm-clear-test-data` is an alias for the same reset implementation. Other `trial:*` commands still require the local test issuer; Google-authenticated deployments should keep using systemd and their normal Google operator login.

## What is protected and cleared

The command reads `.data/trial/env`, including quoted values. It requires `BEARPORTAL_ENV=development`, a supported local database, a stopped API listener, an active operator, no active installation/job, and canceled Stripe subscriptions. Live Stripe credentials, production mode and migration-fenced deployments are refused.

Before clearing anything it writes a PostgreSQL custom-format dump and copies encrypted credential files into a private `.data/backups/test-reset-*` directory. Backup failure aborts the reset. Database deletion is transactional. Operator users, roles, authenticators and linked managed identities remain, along with plans, migrations, control-plane configuration, SSH keys and application settings. Customer users/identities, organizations, domains, DNS credentials, deployments, mailboxes, assignments, all server/Brevo inventory and credential references, and operational/audit history are cleared. Inventory name counters return to zero. Active encrypted credential files and stale walkthrough references are removed after the database commits. Backups intentionally retain old test data; protect or remove them according to your retention needs.

This affects local BearPortal records only. It does not delete cloud VMs, uninstall remote BearMail, modify domain DNS, remove Brevo provider-side domains, delete Stripe customers or cancel subscriptions, or delete Google Identity Platform accounts. Existing Google/email accounts can sign in again and receive fresh BearPortal customer records. Use fresh or properly cleaned servers for retesting; deleting a database record does not make an installed mail server clean.

For a local PostgreSQL container, `BEARPORTAL_BACKUP_DATABASE_URL` in `.data/trial/env` can supply a database-administrator connection for the backup. It must target the exact same host, port and database as `MIGRATION_DATABASE_URL`. Use PostgreSQL 17 client tools with a PostgreSQL 17 server. The database owner remains the connection used for the reset transaction; elevated credentials are used only for the dump. Without an explicit backup connection, the script tries the migration connection, then the local Unix-socket PostgreSQL administrator.
