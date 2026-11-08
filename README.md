# BearPortal

BearPortal installs Bearmail on operator-prepared servers and manages customer setup, DNS credentials and resource assignments. It is a TypeScript/Fastify application with PostgreSQL and server-rendered customer and operator pages. Bearmail is a separate project, normally checked out beside this repository as `../bearmail`.

The code is authoritative. [SPEC.md](SPEC.md) describes the current implementation and its limits.

## Accounts and service URLs

| Service | Purpose | Default address |
|---|---|---|
| BearPortal | Registration, domain setup and inventory | Configured portal origin |
| Stalwart / BearOS-webui | Administrator console and mailbox management | `https://mail.<domain>` |
| Bearmail-webui | Normal mailbox users send and receive email | `https://bearmail.<domain>` |

Google and email/password signup use **Google Cloud Identity Platform directly**, without the Firebase SDK. Email/password accounts must verify their address before setup. Verification emails, password reset, sign-out and verified linking of ordinary legacy accounts are supported. BearPortal does not store account passwords locally.

After installation, the owner can reveal the generated administrator username/password in `/portal`, then create mailbox accounts at `mail.<domain>`. Normal users sign into `bearmail.<domain>` with their full mailbox address and mailbox password. BearPortal registration and mailbox login are separate. Existing deployments retain their saved hostnames.

## Customer setup

1. Register or sign in, then enter the domain to use with Bearmail.
2. BearPortal detects the DNS provider and offers a credential form for Name.com, Hostinger or GoDaddy.
3. Submit the provider credential and authorize domain verification, Brevo authentication, mail routing, installation and a setup test once. BearPortal encrypts the credential and retains the domain-specific authorization across retries.
4. The persistent backend queue claims an exclusively allocated server and Brevo account. Missing capacity produces a saved wait; no resubmission is needed. Stale, unused SSH inventory is rechecked automatically before allocation.
5. The backend creates/checks the Brevo domain, publishes its TXT/CNAME verification records and waits for authenticated/verified results. DNS propagation waits do not consume the provider-failure retry budget.
6. BearPortal downloads a resolved Bearmail `main` commit and runs the noninteractive Python program `bearmail-install` for dry-run and apply over SSH as `bearadmin`.
7. The installer configures services and mail DNS. BearPortal records results, checks both HTTPS hostnames and clears TLS-pending status when they are ready. Installation and HTTPS success do not establish mail delivery.

The customer portal shows seven setup milestones: account, domain, provider connection, resource allocation, domain authentication, Bearmail installation and secure connections. It highlights the current step, explains waits or review needs, and gives timing guidance without promising a completion deadline. Installation is shown as complete after HTTPS checks succeed; mailbox access and mail delivery still require testing.

The customer can close the browser during setup. Known retryable failures continue automatically; interrupted host operations with unknown outcomes require operator review. Backend installation issues do not ask the customer to authorize each step again or resubmit a working credential.

## Operator inventory

At `/operator`, operators can search and review servers, Brevo accounts and registered users with their live resource assignments. Infrastructure operators manage servers; platform administrators also manage Brevo accounts. Support access is read-only and excludes Brevo inventory. User records are read-only in this workspace.

Add, edit, SSH-check, pause, remove and restore actions follow the resource's permissions and state. Assigned resources are protected. Removing inventory retains its history and does not delete the VM or provider account. Inventory mutations require verified identity and TOTP authentication within two hours; other protected operations retain their own windows.

Development command-line additions use the same APIs:

```sh
pnpm inventory servers add --file /path/to/server.json
pnpm inventory brevo add --file /path/to/brevo.json
pnpm inventory servers list
pnpm inventory brevo list
```

See [inventory management](docs/runbooks/inventory.md) and the templates in [examples/inventory](examples/inventory).

## Run and validate

```sh
pnpm install --frozen-lockfile
pnpm trial:prepare
pnpm trial:migrate
pnpm trial:bootstrap
pnpm trial:start
```

Apply all migrations, including `007_inventory_management.sql` and `008_identity_accounts.sql`. Normal startup uses live SSH, Brevo and installer integrations. Development mode does not simulate those operations. Do not run `trial:reset` on retained data.

Configure Identity Platform after enabling its Google and Email/Password providers:

```sh
pnpm auth:configure
```

This prompts for project settings without an editor, preserves existing database/encryption/signing settings and creates a private environment backup. Restart the API afterward. See the [Identity Platform guide](docs/runbooks/identity-platform.md) for OAuth origins, verification and account linking.

For local Mac access, use an SSH tunnel and open **http://localhost:8088**. The localhost Google button/origin check passed in the current deployment; the `127.0.0.1` browser variant has not passed that check. Run `pnpm trial:login` on the server for a private, one-use development operator link valid for five minutes. Its signed session lasts two hours.

```sh
pnpm typecheck
pnpm test
```

Tests create and remove their own `bearportal_test_*` database. Explicit connections must all target the same dedicated test database; the working database is rejected. See [tests/README.md](tests/README.md).

## Implementation limits

- The API processes onboarding, stale SSH readiness and post-install HTTPS checks. There is no separate general-purpose dispatcher, resident mail-host agent or complete health-monitoring service.
- Generic domain-proof, relay validation and DNS-observer adapters remain unavailable. Guided setup uses the working provider integrations instead.
- Live model generation is disabled. Deterministic backend code performs installation.
- Portal mailbox synchronization and queued lifecycle commands remain undelivered. Create mailbox accounts in the installed administrator console.
- Backup, restore, upgrade and cleanup APIs largely record plans/evidence. BearPortal does not create or manage cloud VMs, disks, firewalls or snapshots.
- `mail_verified` remains database-locked false. The release checklist is incomplete; a working web UI does not close it.
- Normal installation resolves published GitHub artifacts. Local Bearmail edits do not automatically change that download path, and retries are not a permanent release pin.
- Upstream Identity Platform MFA challenges and per-request upstream revocation checks are not implemented. Application account disablement is checked during managed identity resolution.

## Documentation

- [Current implementation](SPEC.md)
- [Development startup and Mac access](docs/try-it.md)
- [Identity Platform configuration](docs/runbooks/identity-platform.md)
- [Inventory and user allocations](docs/runbooks/inventory.md)
- [SSH preparation and installation](docs/runbooks/ssh-install.md)
- [Credentials and installed-service login](docs/runbooks/credentials.md)
- [Noninteractive installer contract](docs/BEARMAIL_NONINTERACTIVE_INSTALLER.md)
- [All operator runbooks](docs/runbooks/README.md)
- [Current validation and remaining gaps](docs/local-validation.md)
- [Dated installation evidence](docs/release-evidence/README.md)
