# BearPortal agent setup and operations guide

Read this first when taking over a fresh GitHub checkout. This guide covers an
empty public test deployment, an empty production deployment, local development,
and moving an existing production deployment. Commands that create accounts,
databases or keys are **first-install commands**, not an update procedure.

Reviewed against the repository and the deployed test server on 2026-11-23.
Source code is authoritative when older runbooks describe a different behavior.
Never commit filled environment files, passwords, provider keys, MFA recovery
codes, database dumps or migration archives.

## 1. Choose the deployment before running commands

| Purpose | Runtime setting | Google identity | Stripe | Data/resources |
|---|---|---|---|---|
| Public test/staging | `BEARPORTAL_ENV=production` | Separate test project/client | `test`, test keys and objects | Empty test database; dedicated test servers, Brevo and domains |
| Public production | `BEARPORTAL_ENV=production` | Production project/client | `live`, live keys and objects | Production database and inventory |
| Private local development | `BEARPORTAL_ENV=development` | Managed test project, or local development issuer | Test only | Disposable development data/resources |
| Move existing production | Preserve exported configuration | Preserve project and identities | Preserve account, keys and webhook | Use migration, not an empty installation |

There is no `test` runtime environment switch that simulates infrastructure.
`BEARPORTAL_ENV`, `BEARPORTAL_STRIPE_MODE` and the Identity Platform project are
independent settings. Normal API startup always wires live SSH, Brevo, DNS and
installer integrations. Stripe test mode does not make DNS or mail installations
safe simulations. Automated tests inject fake integrations separately.

For an existing service, inspect its systemd unit and configuration paths before
editing anything. A clone does not include its database, `.data`, environment,
encryption key, operator MFA, SSH key, DNS credentials or Stripe webhook secret.

### Existing deployment map (verify before using)

| Item | Production | Public test |
|---|---|---|
| Origin | `https://app.bearos.si` | `https://testapp.bearos.si` |
| Server IPv4 | `34.55.136.86` | `136.86.167.25` |
| Google project | `natural-iridium-506117-i4` | `bearportal-test` |
| Service | `bearportal-api` | `bearportal-test` |
| Checkout | `/opt/bearportal` | `/opt/bearportal-test` |
| Environment | `/opt/bearportal/.data/trial/env` | `/etc/bearportal-test/api.env` |
| Local API | `127.0.0.1:8088` | `127.0.0.1:8089` |
| Database | Migrated production database | `bearportal_staging`, cluster `17/bearportaltest`, port `5433` |
| Stripe | Live | Test |

The old production checkout at `/home/luoxi23vr/bearportal` is a source/development
checkout, **not** the running public test application. Its original
`bearportal-api` service is disabled and migration-fenced. Do not restart it.
The test host retains the old database and private migration archives for recovery;
its test service cannot read the old production environment or SSH private key.

The test host's active Caddy configuration is
`/etc/caddy/bearportal-test-proxy.json`, selected by a systemd drop-in. It also
forwards cached production-hostname traffic to the new production server.
Editing `/etc/caddy/Caddyfile` alone does not change that active configuration.
Private, host-specific notes are at `/etc/bearportal-test/README.md`.

The fresh-install examples below use `/opt/bearportal`, `/etc/bearportal/api.env`
and a dedicated host. Do not apply them over either existing deployment.

## 2. Repository map and application flow

| Path | Responsibility |
|---|---|
| `apps/api/src/main.ts` | Startup validation, migration fence, live adapters, loopback listener |
| `apps/api/src/server.ts` | Fastify routes and background onboarding/HTTPS processing |
| `apps/api/src/config.ts` | Required environment and runtime safeguards |
| `apps/api/src/browser-auth*`, `identity-*`, `operator-*` | Managed identity, cookies, account bindings, roles and TOTP |
| `apps/api/src/billing.ts` | Stripe Checkout, entitlement, webhooks and cancellation |
| `apps/api/src/portal.ts`, `onboarding-queue.ts`, `installation*.ts`, `inventory.ts` | Customer pages, persistent setup and resource allocation |
| `packages/db/migrations`, `packages/db/src/migrate.ts` | Ordered SQL migrations, RLS and database grants |
| `packages/secrets` | Encrypted credential files and AES key handling |
| `packages/servers` | SSH readiness, artifact download and remote Bearmail installation |
| `packages/providers` | DNS-provider and Brevo integrations |
| `packages/operations`, `packages/contracts`, `packages/domain` | Operation policy, contracts and domain rules |
| `scripts` | Migration, local development, operator authorization, reset and DNS tools |
| `tests`, `scripts/test.ts` | Disposable-database tests and provider/installer fakes |
| `infra/systemd`, `.env.example` | Starting templates; not a complete configured deployment |

One Node.js process serves pages/APIs and retries saved onboarding work, normally
every 30 seconds. No separate frontend build, Redis queue or resident general
worker is required. The normal installer downloads a resolved commit and release
artifacts from `luoxiprovo/bearmail`; a sibling Bearmail checkout is not required
for normal deployment and local edits there do not change downloaded artifacts.

Customer flow: managed verified sign-in → Stripe subscription → domain and DNS
credential/consent → server/Brevo allocation → Brevo domain/DNS verification → SSH
installation → HTTPS readiness → customer retrieves administrator credentials.
Mail delivery must be tested separately. Operators use `/operator/login` and
BearPortal's own TOTP enrollment, independently of their Google-account MFA.

## 3. Fresh public test or production installation

Use a fresh **Debian 13** machine, **Node.js 22**, **pnpm 10.15.0** and
**PostgreSQL 17**. The API host is separate from customer Bearmail hosts. Reserve
a stable public IP; allow inbound 80/443 and administrator SSH. Keep PostgreSQL
and the API listener private. Allow outbound HTTPS/DNS and SSH to mail hosts.

Have these ready before enabling customer signup:

- Portal hostname and DNS control.
- Environment-specific Identity Platform project, web API key and OAuth web client.
- Environment-specific Stripe permanent secret/publishable keys, price, portal
  configuration and direct webhook signing secret.
- Operator email to authorize; no operator password is bundled in GitHub.
- Dedicated mail-server and Brevo inventory when installation is required.

### 3.1 Install tools and clone

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 openssl openssh-client \
  xz-utils postgresql-17 postgresql-client-17 caddy
```

Install a reviewed Node.js 22 release from the official distribution. The example
below pins the runtime used during migration; review patch updates separately.
Run these commands from a temporary download directory as your normal login user:

```bash
node_release=v22.21.1
case "$(uname -m)" in
  x86_64) node_arch=x64 ;;
  aarch64) node_arch=arm64 ;;
  *) echo 'Unsupported CPU architecture'; exit 1 ;;
esac
node_archive="node-${node_release}-linux-${node_arch}.tar.xz"
curl -fSLO "https://nodejs.org/dist/${node_release}/${node_archive}"
curl -fSLo SHASUMS256.txt "https://nodejs.org/dist/${node_release}/SHASUMS256.txt"
awk -v name="$node_archive" '$2 == name {print}' SHASUMS256.txt > node-checksum.txt
test -s node-checksum.txt && sha256sum --check node-checksum.txt
```

Continue only after the checksum succeeds:

```bash
sudo install -d -m 755 /opt/bearportal-runtime
sudo tar -xJf "$node_archive" -C /opt/bearportal-runtime --strip-components=1
sudo env PATH=/opt/bearportal-runtime/bin:/usr/bin:/bin \
  /opt/bearportal-runtime/bin/npm install --global \
  --prefix /opt/bearportal-runtime pnpm@10.15.0
sudo chmod -R a+rX /opt/bearportal-runtime
export PATH=/opt/bearportal-runtime/bin:$PATH
node --version
pnpm --version
```

The permission adjustment applies only to public runtime software. Do not apply
it to private configuration, SSH keys, `.data`, database files or a user's whole
home directory. Restrictive installation umasks can otherwise make pnpm or its
JavaScript package tree inaccessible to the service account.

```bash
sudo useradd --system --user-group --home-dir /var/lib/bearportal \
  --create-home --shell /usr/sbin/nologin bearportal
sudo git clone https://github.com/luoxiprovo/bearportal.git /opt/bearportal
sudo chown -R bearportal:bearportal /opt/bearportal
sudo -u bearportal env HOME=/var/lib/bearportal \
  PATH=/opt/bearportal-runtime/bin:/usr/bin:/bin \
  /opt/bearportal-runtime/bin/pnpm --dir /opt/bearportal install --frozen-lockfile
```

Dependencies currently live in `devDependencies`, including the runtime TypeScript
loader. Do not install with `--prod` or omit development dependencies. No `pnpm
build` step exists. If the account or checkout already exists, inspect it instead
of recreating it or recursively replacing its ownership.

### 3.2 Create database roles and private configuration

The SQL migrations grant rights to the literal role `bearportal_app`; create it
before applying migrations. The runtime role must not be a superuser, database
owner or RLS-bypass role. Keep schema-owner and runtime connections separate.

This first-install block creates the database and generates credentials privately.
It uses the fresh host's default local PostgreSQL cluster on port 5432. It fails
if these roles/database already exist; do not drop existing data to make it pass.

```bash
sudo python3 - <<'PY'
from pathlib import Path
import secrets, subprocess

owner_password = secrets.token_hex(24)
app_password = secrets.token_hex(24)
sql = f"""
CREATE ROLE bearportal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{owner_password}';
CREATE ROLE bearportal_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{app_password}';
CREATE DATABASE bearportal OWNER bearportal;
REVOKE CONNECT ON DATABASE bearportal FROM PUBLIC;
GRANT CONNECT ON DATABASE bearportal TO bearportal, bearportal_app;
"""
subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-p', '5432',
                '-v', 'ON_ERROR_STOP=1'], input=sql, text=True,
               check=True, stdout=subprocess.DEVNULL)
directory = Path('/etc/bearportal')
directory.mkdir(mode=0o700)
env = {
    'DATABASE_URL': f'postgres://bearportal_app:{app_password}@127.0.0.1:5432/bearportal',
    'MIGRATION_DATABASE_URL': f'postgres://bearportal:{owner_password}@127.0.0.1:5432/bearportal',
    'BEARPORTAL_SECRET_KEY': secrets.token_hex(32),
    'BEARPORTAL_JWT_PUBLIC_KEY_FILE': '/var/lib/bearportal/identity-public.pem',
    'BEARPORTAL_SECRETS_DIR': '/var/lib/bearportal/secrets',
    'BEARPORTAL_ENV': 'production',
    'BEARPORTAL_ALLOW_TEST_ISSUER': '0',
    'BEARPORTAL_TEST_SKIP_SSH_HOST_KEY_CHECK': '0',
    'BEARPORTAL_BIND_HOST': '127.0.0.1',
    'PORT': '8088',
    'BEARPORTAL_STRIPE_MODE': 'test',
    'BEARPORTAL_STRIPE_TAX_ENABLED': '0',
}
path = directory / 'api.env'
path.write_text(''.join(f'{key}={value}\n' for key, value in env.items()))
path.chmod(0o600)
print('Database created; generated credentials saved privately in /etc/bearportal/api.env')
PY
sudo install -d -m 700 -o bearportal -g bearportal \
  /var/lib/bearportal/secrets /var/lib/bearportal/ssh /var/lib/bearportal/work
```

`BEARPORTAL_SECRET_KEY` is 32 random bytes represented by 64 hex characters.
Retain it with the database and encrypted files: replacing it makes existing DNS,
SMTP, administrator and operator TOTP ciphertext unreadable.

The loader still requires a readable static JWT public-key file when using managed
Identity Platform, although managed tokens use Google's rotating verification
keys. Generate a placeholder public key without enabling local identity signing:

```bash
sudo python3 - <<'PY'
from pathlib import Path
import subprocess, pwd
private = subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA',
                         '-pkeyopt', 'rsa_keygen_bits:2048'], check=True,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
public = subprocess.run(['openssl', 'pkey', '-pubout'], input=private,
                        check=True, stdout=subprocess.PIPE).stdout
path = Path('/var/lib/bearportal/identity-public.pem')
path.write_bytes(public)
path.chmod(0o600)
user = pwd.getpwnam('bearportal')
import os
os.chown(path, user.pw_uid, user.pw_gid)
PY
```

### 3.3 Configure Google identity

Use separate Google Cloud projects and OAuth clients for public test and production.
The same administrator Google account can own both. Enable Identity Platform,
Google and Email/Password providers in the selected project. Configure a minimum
12-character password policy, verification email/reset templates and enumeration
protection. Use the default tenant.

Google has two different allowlists:

- Identity Platform authorized domain: hostname, e.g. `testapp.example.com`.
- OAuth web client's authorized JavaScript origin: full origin, e.g.
  `https://testapp.example.com`, with no path or trailing slash.

Store the OAuth client secret in Google's provider settings, not BearPortal.
Use the project's web API key; API restrictions must permit Identity Toolkit and
Secure Token. Browser-referrer restrictions block the backend's API requests;
source-IP restrictions must allow this server's outbound address.

Edit privately with `sudoedit /etc/bearportal/api.env` and append these settings,
replacing all examples:

```dotenv
BEARPORTAL_IDENTITY_PROJECT_ID=YOUR_ENVIRONMENT_PROJECT
BEARPORTAL_IDENTITY_API_KEY=YOUR_ENVIRONMENT_API_KEY
BEARPORTAL_GOOGLE_CLIENT_ID=YOUR_WEB_CLIENT.apps.googleusercontent.com
BEARPORTAL_AUTH_ORIGINS=https://YOUR_PORTAL_HOSTNAME
BEARPORTAL_JWT_ISSUER=https://securetoken.google.com/YOUR_ENVIRONMENT_PROJECT
BEARPORTAL_JWT_AUDIENCE=YOUR_ENVIRONMENT_PROJECT
```

Use plain `NAME=value` lines, one per variable, without shell `export`, duplicate
keys or multiline values. This format is compatible with systemd, Node and the
operator CLI's simple file reader. Do not source the application environment into
your normal shell. `pnpm auth:configure` targets the local `.data/trial/env`; it is
not the configuration mechanism for this separate service file.

### 3.4 Configure Stripe in the selected mode

Create the product/price and customer portal in the same Stripe account and mode
as the runtime keys. Price requirements are **USD 2000 cents, recurring monthly,
active, tax-exclusive**. Configure immediate cancellation, invoice access and
payment-method updates; do not enable plan switching/promotions for this fixed plan.

Append the matching settings to the private environment:

```dotenv
STRIPE_SECRET_KEY=YOUR_PERMANENT_TEST_OR_LIVE_SECRET_KEY
STRIPE_PUBLISHABLE_KEY=YOUR_MATCHING_PUBLISHABLE_KEY
STRIPE_PRICE_ID=price_YOUR_ENVIRONMENT_PRICE
STRIPE_WEBHOOK_SECRET=whsec_YOUR_DIRECT_ENDPOINT_SECRET
STRIPE_PORTAL_CONFIGURATION_ID=bpc_YOUR_ENVIRONMENT_CONFIGURATION
BEARPORTAL_BILLING_ORIGIN=https://YOUR_PORTAL_HOSTNAME
```

Keep `BEARPORTAL_STRIPE_MODE=test` for public testing, with `sk_test_`/`rk_test_`
and `pk_test_` keys. For production, set it to `live` **and** replace keys, price,
portal configuration and webhook secret with their live counterparts. CLI OAuth
login does not replace the permanent application key. Restricted keys need the
permissions described in [billing.md](docs/runbooks/billing.md).

Create a direct Stripe webhook at `https://YOUR_PORTAL_HOSTNAME/webhooks/stripe`.
Use snapshot events compatible with the installed SDK; the current code uses
`2026-10-28.endive`. Subscribe to all eight:

```text
checkout.session.completed
customer.subscription.created
customer.subscription.updated
customer.subscription.deleted
invoice.paid
invoice.payment_failed
invoice.finalization_failed
invoice.payment_action_required
```

The current implementation uses Checkout `ui_mode: form` and requires a
publishable key for the embedded browser form. Automatic tax is hardcoded off in
Checkout creation; setting `BEARPORTAL_STRIPE_TAX_ENABLED=1` does not enable it.
Older billing text about hosted-only Checkout or enabling tax through that flag
does not describe the current path. Do not promise tax collection from this guide.

`pnpm stripe:listen` is a local-development helper that rewrites the trial env's
signing secret. Do not run it for a public service using a direct endpoint.

### 3.5 Apply schema and prepare SSH

Run all pending SQL migrations, not a remembered subset:

```bash
cd /opt/bearportal
sudo env PATH=/opt/bearportal-runtime/bin:/usr/bin:/bin \
  /opt/bearportal-runtime/bin/node --env-file=/etc/bearportal/api.env \
  --import tsx packages/db/src/migrate.ts
sudo -u bearportal ssh-keygen -q -t ed25519 -N '' \
  -C bearportal-control-plane -f /var/lib/bearportal/ssh/id_ed25519
sudo -u bearportal touch /var/lib/bearportal/ssh/known_hosts
sudo chmod 600 /var/lib/bearportal/ssh/known_hosts
```

Generate the SSH key only for a new deployment. Public key:
`/var/lib/bearportal/ssh/id_ed25519.pub`. Install it in each intended mail server's
`bearadmin` authorized keys. Verify host fingerprints independently before trusting
them. Never set `BEARPORTAL_TEST_SKIP_SSH_HOST_KEY_CHECK=1` on a public service.

Normal paths are fixed in the application:

```text
/var/lib/bearportal/ssh/id_ed25519
/var/lib/bearportal/ssh/known_hosts
/var/lib/bearportal/work
```

Two services on the same host need separate directories exposed through systemd
`BindPaths`/mount namespaces, or separate VMs/containers. Inventing an environment
variable for these paths does not override them. The existing public test service
binds its own `/var/lib/bearportal-test/{ssh,work}` onto these fixed paths.

### 3.6 Install the service and HTTPS proxy

Create `/etc/systemd/system/bearportal-api.service`:

```ini
[Unit]
Description=BearPortal API
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=bearportal
Group=bearportal
WorkingDirectory=/opt/bearportal
Environment=HOME=/var/lib/bearportal
Environment=PATH=/opt/bearportal-runtime/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=/etc/bearportal/api.env
ExecStart=/opt/bearportal-runtime/bin/node --import tsx apps/api/src/main.ts
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
```

Systemd reads the root-private environment before dropping privileges. Start only
after the environment has real values and migrations succeed:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bearportal-api
curl -fsS http://127.0.0.1:8088/healthz
```

Point the portal's A record at the server. Remove/update an obsolete AAAA record.
On a fresh host, configure `/etc/caddy/Caddyfile`, replacing the hostname:

```caddyfile
YOUR_PORTAL_HOSTNAME {
    reverse_proxy 127.0.0.1:8088
}
```

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
curl -fsS https://YOUR_PORTAL_HOSTNAME/healthz
```

On an existing server, inspect `sudo systemctl cat caddy` first and preserve other
sites and production forwarding. A systemd drop-in may select a JSON config instead.

### 3.7 Authorize the first operator

From `/opt/bearportal`, substitute the intended operator email:

```bash
sudo env PATH=/opt/bearportal-runtime/bin:/usr/bin:/bin \
  /opt/bearportal-runtime/bin/node --import tsx scripts/operator-access.ts \
  --env-file /etc/bearportal/api.env \
  --email YOU@example.com --role platform_administrator \
  --reason 'Initial deployment administrator'
```

The approval lasts 24 hours and is consumed by a fresh verified sign-in at
`https://YOUR_PORTAL_HOSTNAME/operator/login`. Enroll the BearPortal authenticator
and store recovery codes privately. Google-account two-step verification is
separate. Operator access does not require a Stripe subscription.

A new database has no operators until authorized. A restored database retains its
identity bindings and MFA when its encryption key is preserved. Do not run
`trial:bootstrap`, `trial:login` or `--reuse-bootstrap-admin` as a substitute for
fresh public operator authorization.

### 3.8 Add inventory and verify the complete flow

Use `/operator` to add servers and Brevo accounts. The CLI `pnpm inventory` is a
development helper, not a public deployment administration login.

Mail hosts need Linux/systemd, x86-64 for the normal engine artifacts, nominal
1 GiB RAM (probe threshold 900 MiB), root disk capacity at least 20 GiB, and no
unrelated data in `/var/lib/stalwart`. Prepare `bearadmin` with noninteractive sudo,
the correct environment's SSH public key, and executable remote staging at
`/var/lib/bearportal/install`. Allow inbound mail/web ports 25, 80, 443, 465 and
993; restrict SSH to control-plane/admin sources. Allow outbound Brevo SMTP 587
and DNS/HTTPS. See [preparation](docs/runbooks/preparation.md) and
[enrollment](docs/runbooks/enrollment.md) for the complete attestations/firewall.

Brevo inventory requires an account email, REST API key, SMTP login, distinct SMTP
key and operator-entered daily allowance. Use dedicated test accounts and domains
for staging; do not share production assignments. Supported guided DNS providers
are Name.com, Hostinger and GoDaddy; actual API access must work for the account.

Acceptance checks:

1. `/healthz`, `/login`, `/register` and `/operator/login` respond over HTTPS.
2. `/auth/options` reports configured sign-in; verify Google and verified
   email/password login in a real browser. A provider-config probe is not a browser
   sign-in test. Unverified email must not gain installation access.
3. The authorized operator can enroll MFA and view inventory.
4. Stripe keys/price/webhook match the intended account and test/live mode. Verify
   webhook signatures and successful deliveries. Use test cards only on test Stripe.
5. A test customer cannot install before subscription confirmation, then can use
   dedicated inventory after test Checkout. Capacity waits resume without duplicate
   consent; available capacity shows allocation rather than a false shortage.
6. Domain verification, Brevo authentication, installation and both HTTPS mail
   hostnames succeed. Send/receive actual mail separately; HTTPS is not delivery proof.
7. Cancellation blocks new installation and creates manual operator cleanup work;
   it does not delete servers, Brevo accounts or DNS records automatically.

## 4. Private local development and automated tests

Use a separate development checkout/host or cluster. Install the same Node/pnpm
versions, PostgreSQL, and dependencies. Create `bearportal` (schema owner),
`bearportal_app` (restricted application role), and a development database owned
by `bearportal`. `trial:prepare` does **not** create PostgreSQL roles/database.

For a fresh, disposable, loopback-only development cluster, this matches the
helpers' built-in credentials (never run over existing roles or use publicly):

```bash
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE bearportal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'bearportal';
CREATE ROLE bearportal_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'bearportal_app';
CREATE DATABASE bearportal OWNER bearportal;
SQL
```

```bash
pnpm install --frozen-lockfile
pnpm trial:prepare
```

Privately edit generated `.data/trial/env` to match the development database
passwords and paths. Its generated default passwords are examples for disposable
local use, not public deployments. Preserve existing encryption/signing keys if
retaining data. Then:

```bash
pnpm trial:migrate
pnpm trial:bootstrap
pnpm trial:start
```

For real test Google sign-in, configure the test project using `pnpm auth:configure`
and the full issuer/audience settings. For local preview without managed identity,
the generated test issuer can sign local identities without email verification;
keep that setup private. Never expose it as public staging authentication.

Use a tunnel from the browser's machine:

```bash
ssh -N -L 8088:127.0.0.1:8088 YOUR_USER@DEV_SERVER
```

Open `http://localhost:8088`. Configure the Google OAuth client with both
`http://localhost` and `http://localhost:8088`; application origins include the
actual origin with port. `pnpm trial:login` prints a private five-minute one-use
development operator link. It does not work for public managed-identity operators.

Verification:

```bash
pnpm typecheck
pnpm test
```

The default test launcher creates/deletes a `bearportal_test_*` database on local
port 5432. It assumes local roles/passwords `bearportal:bearportal` and
`bearportal_app:bearportal_app` plus noninteractive `sudo -u postgres`. Do not change
a retained deployment's passwords to satisfy those defaults. For custom passwords
or a different cluster, provision a disposable `bearportal_test_*` database and
set all three URLs to that same database: `DATABASE_URL`,
`MIGRATION_DATABASE_URL`, `BEARPORTAL_SUPER_DATABASE_URL`. The third connection
needs fixture administrative privileges. Never use a retained staging or production
database. See [tests/README.md](tests/README.md).

Run tests from a development/admin account, not the locked-down runtime account.
Do not source the ordinary application environment for integration tests.
`python3 tests/server_migration_checks.py` runs migration checks separately; its
real PostgreSQL check can be skipped when administrator setup is unavailable.
Report skips and actual verification limits rather than claiming a cloud cutover
or real provider flow from mocked tests.

## 5. Move existing production instead of creating an empty service

Use [server-migration.md](docs/runbooks/server-migration.md) for the full protocol.
On the new server, authorize its normal login user's SSH public key in the old
server user's `~/.ssh/authorized_keys`. Verify the old host fingerprint and check:

```bash
ssh ADMIN@OLD_SERVER_IP 'sudo -n true'
```

The command must succeed without password prompts. It checks preconfigured SSH
and passwordless sudo; it does not grant them. The migration-tools checkout can
have any directory name and is separate from the `/opt/bearportal` destination.

```bash
git clone https://github.com/luoxiprovo/bearportal.git ~/bearportal-migration
cd ~/bearportal-migration
sudo python3 scripts/migrate-import.py \
  --from ADMIN@OLD_SERVER_IP --public-ip NEW_SERVER_IP --check
sudo python3 scripts/migrate-import.py \
  --from ADMIN@OLD_SERVER_IP --public-ip NEW_SERVER_IP
```

Fresh Debian 13 and open/free target ports 80/443 are required. The old running
API must report `migrationProtocol: 1` in `/healthz`. Use committed source code.
The importer installs prerequisites before source shutdown and copies the exact
source snapshot, database, encryption key/files, operator/MFA records, SSH private
key/known hosts, configuration and HTTPS certificates. Mail hosts remain in place;
their SSH firewalls must allow the new portal IP. Retain the same Google project,
Stripe account and public origin for this migration.

Wait for `"complete": true` before changing the portal A record. Keep the old
Caddy forwarding for at least the old DNS TTL, preferably 24–48 hours. Do not
restart the old API once the destination can accept writes.

On failure, keep checkpoints and fences, inspect `--status`, then repeat the same
import command with `--resume`. During `preparing`, resume can safely fast-forward
a clean destination checkout to a newer source snapshot. Once exported, keep the
snapshot unchanged; update only the migration-tools checkout to obtain recovery
fixes. A `restored` checkpoint resumes configuration without restoring the database
again. Do not delete `/var/lib/bearportal-migration` or manually remove fences.

Known fixes required by the demonstrated cutover are included in current `main`:
runtime parent permissions (`ab2056b`), preparation snapshot reconciliation
(`684e27c`), installed pnpm permissions (`0209921`), and the application env path
after Caddy setup (`b4266b2`). Start with current tools, not an older copied script.

## 6. Routine updates, backups and troubleshooting

### Updates

Identify the **running** checkout, service account, runtime and environment first:

```bash
sudo systemctl cat bearportal-api
sudo systemctl show bearportal-api --property=WorkingDirectory,User,MainPID
sudo systemctl cat caddy
```

Use `bearportal-test` for the existing public test service. A `git pull` in
`~/bearportal` does not update `/opt/bearportal-test` or `/opt/bearportal`.
Run Git as the checkout owner to avoid dubious-ownership errors; do not add broad
global safe-directory exceptions. Stop the API only after checking that no remote
installation is running. Then fast-forward the selected code, install the frozen
lockfile as its service user, apply pending migrations using its owner URL, restart
and verify. Preserve all private settings, database identities and encryption keys.
Do not run `trial:migrate` for an environment marked `production`; invoke
`packages/db/src/migrate.ts` with the real environment as in section 3.5.

### Backups

Back up PostgreSQL, environment/encryption key, encrypted secret files, operator
MFA data, SSH identity/known hosts, service/proxy configuration and release commit.
Keep these together in protected storage and test restoration. The migration
export is an offline handoff that fences/stops the source, not an online backup.
Do not assume the application's lifecycle/backup APIs create cloud snapshots.

### Common failures

| Symptom | Check/action |
|---|---|
| pnpm/Node/esbuild permission denied | Inspect every ancestor and executable mode; runtime files must be traversable/readable/executable as appropriate. Do not recursively chmod a home directory or pnpm store: package hardlinks can propagate permission changes into `node_modules`. |
| Application dependency installation failed with hidden output | Rerun only the exact pnpm command as the service user with the same PATH/HOME and working directory; inspect private output locally. Do not change the lockfile or guess at credentials. |
| Wrong migration snapshot | Inspect checkpoint phase and source/destination commit as their owners. Resume preparation with current tools; never reset an activated target. |
| Node exit 9 before migrations | Inspect runtime flags and `--env-file` path/permissions. This can occur before any SQL; it is not itself a database error. |
| Sign-in unavailable or origin mismatch | Check all four identity variables, JWT issuer/audience, provider enablement, exact OAuth JavaScript origin, authorized hostname and API-key restrictions. Restart after env changes. |
| Already-existing email after local reset | Identity Platform users are separate from PostgreSQL users. Sign in/reset the account or use a scoped test-project cleanup; never delete production identities to fix staging. |
| Google admin permission/scope error | Runtime sign-in configuration does not grant Cloud admin rights. Administrative requests may need an authorized user token and `x-goog-user-project` quota-project header. VM default scopes can be insufficient. |
| Checkout unavailable/mode mismatch | Verify the process's active env, permanent key mode/account, publishable key, price, portal config, webhook secret and origin as one set. |
| Capacity wait | Add and SSH-validate a free server and an eligible dedicated Brevo account; saved onboarding retries in-process. |
| SSH/installer failure | Check key ownership, verified host identity, remote `bearadmin` sudo, source-IP allowlist, executable staging, and sanitized installer evidence. |
| Browser page updated but process not | Check service WorkingDirectory/ExecStart; update the deployed checkout and restart the correct unit. |

Logs: `sudo journalctl -u SERVICE -n 100 --no-pager`. Health:
`curl -fsS https://YOUR_PORTAL_HOSTNAME/healthz`. Do not dump environment files,
`/proc/.../environ`, signed operator links or raw provider error payloads into chat.

### Reset and cleanup commands

`reset:test-data`, `reset:test-data:all`, `google:delete-users`,
`stripe:cancel-test-subscriptions` and `dns:cleanup` are deliberate maintenance
tools, not installation/update prerequisites. Read each command's help and
[test-reset.md](docs/runbooks/test-reset.md) / [dns-cleanup.md](docs/runbooks/dns-cleanup.md)
before use. Target the intended test database/project/Stripe account explicitly.
Local reset does not delete Google users, cancel Stripe subscriptions or clean
remote mail hosts/DNS. A Google-user reset can also clear all local customers and
inventory despite an email filter. DNS cleanup preserves only `@` and `www` A
records and deletes other editable records after its confirmation; it is not a
normal repair command for a live customer domain.

## 7. Completion report for the next agent

Report the selected mode, hostname, running service/checkout/env paths, database
isolation, Google project, Stripe mode, SSH identity location, checks actually run,
and any pending credentials/browser or mail-delivery tests. Do not include keys.
The app is not ready for end-to-end installation merely because `/healthz` passes.
Read [SPEC.md](SPEC.md) for remaining lifecycle/monitoring/adapter limits and use
the [runbook index](docs/runbooks/README.md) for focused procedures.
