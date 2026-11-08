# Reset local test data

Use this only when deliberately starting over with test customers and fresh inventory. Ordinary startup and automated tests do not need a reset.

1. Stop the BearPortal API (`Ctrl+C` in the terminal running `pnpm trial:start`, or stop its service).
2. From the BearPortal repository, run:

   ```sh
   pnpm reset:test-data --confirm-clear-test-data
   ```

3. Start the API again:

   ```sh
   pnpm trial:start
   ```

4. Open the operator portal using `pnpm trial:login`, then add new servers and Brevo accounts. Register/sign in as a customer and submit the test domain again.

The command reads `.data/trial/env`. It supports the local development database only, refuses a responding API or a running installation, and requires an existing active operator. `pnpm trial:reset --confirm-clear-test-data` runs the same script.

Before clearing anything it writes a PostgreSQL custom-format dump and copies encrypted credential files into a private `.data/backups/test-reset-*` directory. Backup failure aborts the reset. Database deletion is transactional. Operator users, roles and linked managed identities remain, along with plans, migrations, control-plane configuration, SSH keys and application settings. Customer users/identities, organizations, domains, DNS credentials, deployments, mailboxes, assignments, all server/Brevo inventory and credential references, and operational/audit history are cleared. Active encrypted credential files and stale walkthrough references are removed after the database commits. Backups intentionally retain old test data; protect or remove them according to your retention needs.

This affects local BearPortal records only. It does not delete cloud VMs, uninstall remote Bearmail, modify domain DNS, remove Brevo provider-side domains or delete Google Identity Platform accounts. Existing Google/email accounts can sign in again and receive fresh BearPortal customer records. Use fresh or properly cleaned servers for retesting.

For a local PostgreSQL container, `BEARPORTAL_BACKUP_DATABASE_URL` in `.data/trial/env` can supply a database-administrator connection for the backup. It must target the exact same host, port and database as `MIGRATION_DATABASE_URL`. Use PostgreSQL 17 client tools with a PostgreSQL 17 server. The database owner remains the connection used for the reset transaction; elevated credentials are used only for the dump. Without an explicit backup connection, the script tries the migration connection, then the local Unix-socket PostgreSQL administrator.
