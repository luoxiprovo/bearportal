# BearPortal

BearPortal assigns operator-prepared servers to customer organizations and installs Bearmail over SSH. The control plane is a TypeScript/Fastify application with PostgreSQL and server-rendered customer and operator pages. Bearmail is a separate project; its neighboring checkout is `../bearmail` in this development environment.

The code is the source of truth. [SPEC.md](SPEC.md) describes the current implementation and its limits, rather than an unimplemented target architecture.

## Products and default URLs

| Component | Role | Default hostname |
|---|---|---|
| BearPortal | Customer/operator portal and control-plane API | Control-plane origin |
| Stalwart / BearOS-webui | Mail engine, administration and account UI | `mail.<domain>` |
| Bearmail-webui | Human email and calendar UI | `bearmail.<domain>` |

Existing deployments retain their saved webmail hostname, including older `webmail.<domain>` installations. BearPortal login and mailbox login are separate.

## Current installation flow

1. An operator prepares a Linux server, opens the required ports, and installs BearPortal's SSH public key for `bearportal-control-plane` with passwordless sudo.
2. The operator saves the server in inventory. BearPortal probes it over SSH and allocates eligible servers exclusively to waiting organizations.
3. The customer saves a domain and DNS credentials. BearPortal can create/check the Brevo domain and publish its verification records through Name.com, Hostinger, or GoDaddy.
4. A deployment provisioning request authorizes MX replacement. BearPortal resolves a Bearmail `main` commit, downloads the noninteractive `bearmail-install` program and release artifacts, and runs dry-run then apply over SSH.
5. The customer confirms mail routing and setup checks. A persistent onboarding request authenticates Brevo, creates the deployment and runs installation automatically. If server or Brevo inventory is unavailable, the page explains that capacity is tight and the backend retries without another submission.
6. The installer configures Bearmail and publishes mail DNS. BearPortal records the result; successful installation is separate from verified mail delivery.

The executable is named `bearmail-install`, without `.sh`. It is a Python program that invokes Bearmail's `install.sh` and `mcp_install.sh` without interactive input. Remote staging uses `/var/lib/bearportal/install/<operationId>` because `/run` may be mounted `noexec`.

## Run and validate

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
```

`pnpm test` creates a disposable `bearportal_test_*` database when database variables are unset. Explicit test connections must all target the same dedicated test database. Tests reject the working `bearportal` database. See [tests/README.md](tests/README.md).

The customer UI is a responsive, Apple-inspired email → domain → provider-credential flow. Registration uses email alone; the organization label is derived automatically. Production identity remains externally configured.

Start the development control plane using [docs/try-it.md](docs/try-it.md). Its startup wires live SSH and installer adapters: development mode is not a fake-provider sandbox. Do not run `trial:reset` on data you want to retain.

## Implementation limits

- Automatic onboarding runs inside the API process, checking saved requests every 30 seconds and after submission. There is no separate general-purpose worker/dispatcher service, resident mail-host agent, monitoring timer or platform notification sender.
- Live Grok generation is disabled. Operation/session/approval policy exists, but an agent is not running the installation.
- Host-command dispatch records `delivered: false`; mailbox synchronization and queued lifecycle commands are not verified engine changes.
- Backup, restore, upgrade and cleanup workflows largely record operator evidence and plans. BearPortal does not manage cloud VMs, firewalls, disks or snapshots.
- `mail_verified` is database-locked false. The release checklist is a static incomplete checklist; a working web UI does not close it.
- Normal startup downloads published GitHub artifacts. The installer fixes used during the live run were subsequently published in Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. Local source edits still do not automatically change the default download path.

## Documentation

- [Current implementation specification](SPEC.md)
- [Local setup](docs/try-it.md)
- [SSH install runbook](docs/runbooks/ssh-install.md)
- [Installer contract](docs/BEARMAIL_NONINTERACTIVE_INSTALLER.md)
- [Operator runbooks](docs/runbooks/README.md)
- [Validation and limitations](docs/local-validation.md)
- [Live development installation evidence](docs/release-evidence/2026-11-05-ssh-install.md)

Implementation starts at [apps/api/src/main.ts](apps/api/src/main.ts), [apps/api/src/installation.ts](apps/api/src/installation.ts), and [packages/servers/src/mail-install.ts](packages/servers/src/mail-install.ts).
