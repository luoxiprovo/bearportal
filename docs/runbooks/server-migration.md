# Move BearPortal to a new server

Use this for the current production deployment: Debian 13, PostgreSQL 17 on the same host, Node.js 22, systemd and Caddy. Keep the same `https://app.bearos.si` address, Google Identity Platform project and Stripe account. Existing BearMail servers stay where they are; this moves the portal and its database.

There is a maintenance window while the database is copied and checked. Existing mail servers continue running. After the move, the old web server forwards requests to the new server, so cached DNS and Stripe webhooks reach the new database.

## Recommended: run from the new server

### 1. Prepare access

Use a **fresh Debian 13 server**, with enough disk space for the database, its backup and dependencies. Reserve a stable public IPv4 address. Allow inbound TCP **80 and 443** in its cloud firewall. The new server also needs outbound internet access and SSH access to your existing mail servers. If mail-server firewalls restrict SSH by source IP, allow the new IP first.

Install Python 3, Git, OpenSSH client and OpenSSL if missing:

```bash
sudo apt-get update
sudo apt-get install -y python3 git openssh-client openssl
```

Both the old checkout and the running old API must contain this migration feature. Update/restart the old API before migration, while no installation is running. Its `/healthz` response must contain `"migrationProtocol":1`. Commit any source code changes first; ignored `.data` files are kept private and are copied separately.

On the new server, check that your normal login user can SSH to the old server and run passwordless sudo:

```bash
ssh luoxi23vr@136.86.167.25 'sudo -n true'
```

Verify the old server's SSH fingerprint through your provider console when first connecting. The scripts require a trusted host key and a noninteractive SSH key; they do not disable verification or request passwords. Keep that key with your normal login user, and run the commands below using `sudo` from that user's shell.

### 2. Get the scripts and check readiness

Clone the BearPortal repository on the new server into your home directory, then enter it:

```bash
git clone https://github.com/luoxiprovo/bearportal.git ~/bearportal-migration
cd ~/bearportal-migration
```
 Use a release that contains these scripts. This checkout supplies the migration tools; the restored production application will be installed separately at `/opt/bearportal`.

```bash
sudo python3 scripts/migrate-import.py --from luoxi23vr@136.86.167.25 --check
```

On Google Compute Engine, the new public IP is detected automatically. Elsewhere, append `--public-ip YOUR_NEW_PUBLIC_IPV4` to **both** commands in steps 2 and 3.

The check reads the old deployment, checks SSH access to the mail servers using the existing key, and tests the new server's ports 80/443 **from the old server**. It does not stop the old API or install the application. Ports 80/443 must be free for the temporary check listeners. Fix any failed check before proceeding.

### 3. Move the portal

```bash
sudo python3 scripts/migrate-import.py --from luoxi23vr@136.86.167.25
```

The script installs the runtime and database tools, then:

1. Blocks new requests and waits for active installations/transactions to finish on the old server.
2. Stops and disables the old API, and prevents accidental startup.
3. Transfers an exact code snapshot, PostgreSQL data, private configuration, encrypted credentials, encryption key, operator authentication data, SSH identity and the existing HTTPS certificate over SSH.
4. Restores into a fresh database with new local database passwords. Checks table counts, row security, credential decryption and HTTPS before enabling writes.
5. Makes the old HTTPS server forward to the new server, then enables the new API and background work.

No new Stripe keys, Google OAuth client or operator approval is needed when retaining the same domain and accounts. The script preserves the direct Stripe webhook configuration. Do not run `stripe listen` on the new production server.

Wait for `"complete": true`. The script prints the new IP and the next DNS action. If it stops with an error, follow **Interrupted migration** below; do not change DNS yet.

### 4. Change DNS

Change the **A record for `app.bearos.si`** to the new server's public IPv4. If the hostname has an AAAA record, remove or update it so IPv6 users are not sent to an obsolete server; these scripts configure an IPv4 destination.

Open `https://app.bearos.si`, sign in, and check your subscription, domains and operator inventory. Existing sessions and account identifiers are preserved. Test a normal operator SSH refresh and Stripe test-mode subscription flow as appropriate.

Keep the old server and Caddy running for at least the previous DNS TTL, preferably 24–48 hours, to cover cached DNS. Its API remains disabled. After traffic has moved, retire the old server. Do not restart its old API/database as a fallback after the new server has accepted writes.

The new service is `bearportal-api.service`. Configuration is at `/opt/bearportal/.data/trial/env`; encrypted credential files are alongside it. SSH access is at `/var/lib/bearportal/ssh`. Keep these private. Future updates should use the `/opt/bearportal` checkout and preserve these paths.

## Interrupted migration

Read the local checkpoint:

```bash
sudo python3 scripts/migrate-import.py --status
```

Correct the reported issue, then repeat your original command with `--resume`, keeping the same source, destination and options:

```bash
sudo python3 scripts/migrate-import.py --from luoxi23vr@136.86.167.25 --resume
```

The importer checkpoints its progress and refuses to overwrite an unrelated database or restore again over an activated target. An interrupted transfer can be retried. An incomplete archive extraction is discarded and repeated. Do not delete checkpoint files to force a new import.

Before the old proxy has switched, an abandoned migration can be rolled back **only after you stop the destination API and ensure it cannot restart**. On the old server:

```bash
sudo python3 scripts/migrate-export.py --resume-source --confirm-target-stopped
```

This deliberately refuses rollback once forwarding has begun: the new database may already contain writes. At that point, repair/resume the target. To move back later, perform a new migration using the current server as the source, carrying its latest data.

If a timeout occurs while waiting for an installation, the old API is left running and its temporary maintenance block is removed. Investigate the installation before retrying. If the API has already stopped, its startup block remains until a successful handoff or explicit safe rollback.

## Optional: export separately on the old server

The recommended importer automatically runs the export over SSH. For a separate export:

```bash
# Old server, from the production checkout. This STARTS the maintenance window.
sudo python3 scripts/migrate-export.py --output /home/luoxi23vr/bearportal-export.tar.gz
```

Transfer that file securely to the new server, then use:

```bash
sudo python3 scripts/migrate-import.py --from luoxi23vr@136.86.167.25 --archive /home/YOUR_USER/bearportal-export.tar.gz
```

The new server still needs SSH access to the old server to verify the export receipt and configure forwarding. A standalone export is not an online backup: it leaves the source stopped and fenced to prevent competing writers. Prefer the automatic flow so dependency and network checks happen before downtime.

## Files and verification

- Entry points: [migrate-import.py](../../scripts/migrate-import.py), [migrate-export.py](../../scripts/migrate-export.py).
- Shared implementation: [server_migration.py](../../scripts/server_migration.py).
- Credential verification: [migration-verify.ts](../../scripts/migration-verify.ts).
- Destination checkpoint and private archive: `/var/lib/bearportal-migration/`.
- Startup/maintenance marker: `.data/server-migration-source.lock` in each production checkout. Do not remove it by hand.
- Old Caddy forwarding config: `/etc/caddy/bearportal-migration-forward.json`, enabled by a Caddy systemd drop-in; unrelated Caddy sites are preserved.

Archives contain database data and **all production secrets**. They have private permissions and travel over verified SSH. Keep them off Git and public storage. Expanded temporary copies are removed on success; the private archive is retained for recovery. Choose an appropriate protected backup retention policy after confirming the migration.

Automated checks cover actual isolated PostgreSQL dump/restore (including FORCE RLS and grants), archive validation, encrypted credential verification, maintenance behavior, handoff ordering and interrupted-import resume. Cloud firewall rules and a complete two-VM production cutover still depend on the deployment environment. Scripts cannot create missing cloud permissions or provider firewall rules.
