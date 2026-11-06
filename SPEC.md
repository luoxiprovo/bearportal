# BearPortal: current implementation

Reviewed against the local code on 2026-11-05. This document replaces the earlier milestone proposal. It describes behavior that exists and identifies incomplete integrations explicitly. Runtime schemas, migrations and route implementations take precedence if they change.

## 1. Product and scope

BearPortal is a control plane for Bearmail installations on saved, operator-prepared servers. One active organization belongs to one owner, and one server has at most one live organization assignment. A customer may wait for inventory without a server being created.

Operators manage cloud accounts, machines, disks, firewall rules, external backups and infrastructure cleanup outside BearPortal. The application does not accept cloud account credentials or call VM, firewall, resize, reboot, disk or snapshot APIs.

| Component | Default endpoint |
|---|---|
| BearPortal | Separately configured control-plane origin |
| Stalwart / BearOS-webui | `mail.<domain>` |
| Bearmail-webui | `bearmail.<domain>` |

Deployment creation saves both hostnames. Provisioning fingerprints, installer inputs and address repair reuse the saved webmail hostname. Existing `webmail.<domain>` deployments are preserved. Literal reserved example hostnames are rejected for actual installation.

## 2. Repository and runtime

| Path | Implemented responsibility |
|---|---|
| `apps/api/src/main.ts` | Loads configuration and wires live SSH probing and installation |
| `apps/api/src/server.ts` | Fastify, authentication, authorization, sessions, secrets and route composition |
| `apps/api/src/portal.ts` | HTML rendering; there is no Next.js application |
| `apps/api/src/inventory.ts` | Servers, allocation, DNS credentials and Brevo account/domain forms |
| `apps/api/src/onboarding.ts` | Persistent, consented setup requests and automatic capacity/provider retries |
| `apps/api/src/installation.ts` | Deployments, installer orchestration, mailbox records and credentials |
| `apps/api/src/oversight.ts` | Session/tool policy, approvals, health observations and recovery records |
| `apps/api/src/lifecycle.ts` | Backup/restore/upgrade/cancellation records and portal views |
| `packages/contracts/src/` | Zod schemas and OpenAPI definitions |
| `packages/db/migrations/` | PostgreSQL schema, constraints, RLS and audit restrictions |
| `packages/servers/src/` | SSH plans/probes, release downloads, installer runner and allocation |
| `packages/providers/` | Brevo HTTP calls, nameserver detection and DNS planning/publication |
| `packages/secrets/src/` | AES-256-GCM encrypted secret files |
| `packages/operations/src/` | Operation catalog, gateway, budgets, lifecycle policy and disabled harness |
| `scripts/local-trial.ts` | Development configuration, bootstrap, tokens and compatibility walk |
| `scripts/test.ts` | Disposable integration-test database launcher |
| `infra/systemd/bearportal-api.service` | API service template |

Dependencies are locked by pnpm. The project uses Node.js 22 and pnpm 10.15.0. There is one API service template, no separate worker/dispatcher unit, and no supplied general scheduler timer. The API runs an in-process onboarding queue against persistent PostgreSQL requests, polling every 30 seconds. Other jobs/outbox records still do not establish a general-purpose executor.

## 3. Startup dependencies

Normal `main.ts` startup provides:

- `liveSshProbe` for saved-server validation.
- `liveMailInstall` with database-backed secret resolution.
- GitHub `main` commit resolution when no explicit release/test runner is supplied.
- Actual Brevo account/domain HTTP functions and Brevo DNS-record publication through the customer forms.

Several similarly named interfaces remain unavailable by default:

| Interface | Normal behavior |
|---|---|
| `ZoneReader` | Legacy domain-proof read returns unavailable |
| `RelayChecker` | Generic relay validation returns unavailable |
| `DnsObserver` | DNS recheck has no live observer |
| `BrevoClient` in provisioning | Domain create/authenticate methods throw; distinct from the working account-form integration |
| Host-command dispatcher | Records an attempt with `delivered: false` |
| Grok model generation | Explicitly disabled |

Tests can inject substitutes. Calling `buildServer` without the dependencies wired by `main.ts` can therefore behave differently from `pnpm start:api`.

## 4. Identity and secrets

The API verifies JWTs against a configured public key, issuer and audience. Production configuration requires an Identity Platform issuer. Role grants come from database rows. Privileged mutations generally require a verified operator and a recent TOTP-backed identity; customer credential changes require recent authentication.

The development registration form asks only for email and derives an organization label when none is supplied. Development registration is enabled only with the development issuer/private key configuration. It signs local identities and marks their email verified without sending a verification message. It is not a production Google/email signup implementation. Production signup, password recovery, token revocation integration and key refresh are not supplied here.

`POST /v1/session` exchanges an identity token for an HttpOnly, SameSite=Lax cookie. Cookie mutations require `x-bearportal-csrf: 1` or form `csrf=1`. Bearer requests do not use that check. The current cookie has no `Secure` attribute; deployment hardening remains necessary.

Secrets are AES-256-GCM encrypted files, mode `0600`, with a database file reference and key ID. The encryption key is separate from PostgreSQL. Responses redact credential material. SSH keys are local files, not database secrets or model inputs. Keep service-owned directories private; the implementation does not require every file to be owned by root.

## 5. Saved servers and allocation

Operators register a public unicast IPv4 with label, profile, contact, optional provider reference and preparation attestations. Normal startup probes the saved address immediately over SSH. Validation can be retried through the admin route.

The login is `bearportal-control-plane`, port 22, with a local private key and known-hosts file. First contact can accept a new host key; subsequent connections enforce it. `sudo -n` fails rather than prompting.

The six probe commands inspect OS, architecture, PID 1, memory, root filesystem size and `/var/lib/stalwart`. The SSH path accepts Linux/systemd on x64 or arm64, at least 900 MiB reported memory and 20 GiB total root-filesystem size. A missing data directory passes; existing entries fail the clean-server probe. These commands do not test every mail port or authenticate to the relay. Although readiness accepts arm64, the current downloaded Stalwart artifact validator requires an x86-64 ELF binary.

Successful validation can allocate the server immediately. Allocation is FIFO by verified registration within profile `e2-micro`, serialized by an advisory lock and protected by unique live-assignment indexes. Candidates need validation newer than five minutes, no taint, no assignment and no pending recovery binding. SSH-source reports bypass the older confirmed-device/heartbeat eligibility branch.

States are `pending_validation`, `available`, `reserved`, `assigned`, `quarantined`, `retired`. Failed or cancelled installation does not automatically release a server. There is no general automatic taint-clearing/reimage-to-available workflow.

Signed host enrollment, identity and heartbeat routes remain for compatibility and tests. They are not prerequisites for the normal SSH install, and no host-agent package or poller is delivered by this repository.

## 6. Domain, DNS and Brevo

The customer domain form saves one non-retired domain and detects its authoritative nameservers. Supported providers are `namecom`, `hostinger` and `godaddy`; mixed/unknown nameservers do not receive a provider credential form.

A platform administrator stores Brevo login email, API key, SMTP login, SMTP key and daily allowance. New accounts are `inactive`. The domain form can exclusively claim the oldest free inactive account and create/read its domain through Brevo. The generic admin relay-assignment flow instead uses `available` accounts.

The DNS credential form stores the credential, publishes Brevo verification records, and then calls Brevo authenticate/read. Publication supports returned TXT and CNAME records. This form does not replace MX. SMTP and API credentials are different: the installer receives the SMTP key, never the Brevo REST API key.

On the source-install path, a stored DNS credential is enough to proceed while the domain row remains pending. It does not mark the domain verified. The legacy domain-proof API still depends on the unavailable `ZoneReader`.

Provisioning uses any saved compatible three-TXT Brevo record set, otherwise the source path can omit `brevoDnsRecords`. The schema accepts zero or three records, not an arbitrary partial set. Modern CNAME verification records are published separately by the domain credential form.

## 7. Guided setup and installation over SSH

The customer UI follows email registration, domain entry, provider detection and a provider-specific credential form. It uses system typography, restrained colors, responsive cards and progressive disclosure. Customers do not supply Brevo credentials or select inventory. A pre-credential domain typo can be corrected before DNS credentials or setup records exist.

The guided credential form explicitly collects mail-routing and setup-test consent and persists `onboarding_requests`. It returns to the customer's status page rather than requiring manual deployment API calls. Missing server or Brevo capacity produces a saved waiting state; the API automatically checks again, including after a restart. Provider/authentication retries are bounded; uncertain interrupted installs require review instead of replaying host changes blindly.

`onboarding.ts` reuses deployment/provisioning services, validates current ownership, pauses in recovery mode, checks nameservers, publishes Brevo verification records and waits for strict authenticated/verified booleans. Administrator secrets are committed before the live runner resolves them through a separate database connection. The automatic path passes its actual Brevo result into provisioning, avoiding the unavailable generic Brevo client.

The normal check interval is 30 seconds. `POST /internal/onboarding/run` permits an explicitly scheduler-authenticated check; tests can disable the interval through a dependency override. No customer token or raw credential is persisted in the queue. Capacity waits do not count toward the 20 provider-attempt limit. Long-interrupted installs enter `attention` after their lease expires.



`POST /v1/deployments` creates draft records and mailbox requests. `POST /v1/deployments/:id/provision` checks organization, version, domain credentials, assigned server and plan, then records MX authorization. That request is the installation decision; no second MX approval is required.

The source path resolves the current `luoxiprovo/bearmail` `main` SHA and uses that SHA for one preparation's files. It downloads `bearmail-install`, `install.sh`, `stalwart`, `bearmail-webui.tar.gz` and `mcp_install.sh`, validates basic artifact structure, and writes checksums. This is not a fixed production release pin or a signed-release verification system. A later preparation/retry can resolve a newer main SHA.

The local runner stages under `/var/lib/bearportal/work/<operationId>` by default. The remote directory is `/var/lib/bearportal/install/<operationId>` with a commit-named artifact directory. Executable artifacts need an executable filesystem: `/run` is intentionally not used.

Credentials are separate mode-0600 files. Installer JSON contains absolute remote file paths. BearPortal runs dry-run and, if valid, apply, fetches the JSON result, stores its normalized status/DNS evidence and attempts remote cleanup. Local work is removed in a `finally` block. SSH/spawn exceptions can leave remote files, so inspect cleanup after interrupted runs.

The legacy provision API runs downloads and SSH synchronously. The guided UI instead submits a persistent request; its in-process onboarding worker invokes those same services in the background. An install job and compatibility host-command row do not mean a background worker performed the install. Retrying the same installation fingerprint can reuse the operation ID; recorded successful/TLS-pending DNS acceptance can short-circuit another provisioning call.

The Bearmail program configures the engine, web UI, MCP, administrator credential and quota; it publishes mail A/MX/SPF/DKIM and applicable verification records. The detailed contract is [docs/BEARMAIL_NONINTERACTIVE_INSTALLER.md](docs/BEARMAIL_NONINTERACTIVE_INSTALLER.md).

## 8. Results and mailboxes

Installer statuses are `dry_run`, `succeeded`, `tls_pending`, `dns_partial` and `failed`. The runner combines process exit status and JSON; normalized `succeeded`/`tls_pending` results count as accepted DNS writes. This is not proof of authoritative propagation or mail delivery.

Caddy can obtain certificates after the installer has returned `tls_pending`. BearPortal does not automatically refresh that saved status when certificates appear. Repeated early certificate requests can hit issuer rate limits.

The beta customer mailbox limit is four, with a default 1 GiB quota. `postmaster`, `abuse` and `bearportal-*` are reserved. Deployment creation stores the first customer mailbox, two aliases and a test identity; these records do not prove those identities exist in the engine.

Mailbox create/update/password actions queue allowlisted commands. Dispatch remains undelivered. The first installation configures its engine administrator, but the general portal-to-engine mailbox management adapter is incomplete. Password secrets expire after 15 minutes.

`mail_verified` is locked false by a database trigger. Activation policy also checks installer/DNS, Brevo, backup and mail evidence, but this build cannot establish full active mail service through the portal. The legacy provisioning Brevo client may report false even after the separate credential form authenticated the domain. The guided worker supplies the actual authenticated provider result for its install.

## 9. Oversight and operations

The immutable operation catalog validates keys, versions, handlers and metadata digests. The digest hashes catalog identifiers; it is not a hash of executable handler bytes. The gateway rejects arbitrary shell/code, secrets, caller-selected tenant context and unregistered tools.

The harness module can construct a Grok Build `HarnessAgent`, but live generation is explicitly disabled even when a dedicated key exists. Only a wrapped state-read tool is installed in that constructor. The broader gateway tool catalog and session APIs are policy/recording infrastructure, not a running operations agent.

Policy limits include five minutes, 20 tool requests and three invocations per failing checkpoint. Approvals last 30 minutes and bind to a plan hash. Queued/accepted model requests do not count as executed operations. No arbitrary DNS-write capability is exposed to the agent; trusted customer forms and the installer have their own DNS publication code.

## 10. Health and lifecycle

Health is derived from submitted observations, not an installed monitoring daemon. No observations means unknown. SMTP/engine failure means unavailable. Incident policy uses two failures to open and three successes to close. Disk thresholds are 75/85/90 percent. Notifications are database rows and required actions, without a platform mail sender.

Backup rows are operator reports, not cloud checks. A complete consistent report can count toward freshness; a bare reference does not prove a usable backup. Restore promotion requires owner approval, replacement reservation and fencing evidence, and transfers the sole live assignment. It does not restore a disk.

Upgrade plans record compatibility and backup evidence. Database constraints keep `executed`, `binaries_executed` and `data_rollback` false. Cancellation uses a seven-day grace period, a 24-hour execution window, and backup/waiver checks. Execution queues a stop command; operator isolation evidence establishes the reported stop. Cleanup requires the retention interval and operator attestations, leaving the server retired or quarantined, never automatically available.

Recovery mode pauses the checked mutation paths. The admin waitlist reconcile route is an exception and still allocates. Recovery watchdog/reconcile endpoints record decisions; they are not a database backup or restore service.

## 11. Data and API references

Migrations are authoritative for table names and invariants. There is no `ssh_host_keys` table: SSH pins live in the local known-hosts file, with fingerprint metadata in probe reports. Legacy `host_identities`, `host_enrollments` and `host_auth_challenges` tables/routes still exist.

Tenant isolation uses transaction-local context, RLS and composite foreign keys. Mutable routes use version checks where defined and idempotency keys where required. Server/relay inventory is operator-scoped. Audit rows are append-only to the application role; an external superuser database reset is outside that guarantee.

Use route registration in `apps/api/src/{server,inventory,installation,oversight,lifecycle}.ts` for the actual API surface. `packages/contracts/src/openapi.ts` is a contract description, not proof that every described operation has a route. There is no implemented generic relay-rotation endpoint or mailbox-delete executor merely because a plan/contract mentions one.

## 12. Development, testing and evidence

Use [docs/try-it.md](docs/try-it.md) for startup and [tests/README.md](tests/README.md) for tests. `pnpm test` uses disposable databases; every explicit integration connection must target the same `bearportal_test_*` database. Working databases are rejected before fixture resets. `trial:reset` remains a separate explicitly destructive development command.

The pre-UI 2026-11-05 local suite passed 79 tests and TypeScript checking. The controlled SSH installation demonstrated services and HTTPS, with local Bearmail script fixes. It did not validate every provider, mail delivery, calendar, restore, upgrade, cancellation execution, capacity soak or a live Grok worker. See [docs/local-validation.md](docs/local-validation.md) and [the installation record](docs/release-evidence/2026-11-05-ssh-install.md).

`GET /v1/admin/release-checklist` hardcodes `liveEvidence: false` and the historical labels `A07-A16`, `A19`, `A20`, `A21`, `A22`, `A25`, `A31`. Those labels refer to host/provider integration, outage/recovery, backup/restore, upgrades, cancellation, capacity and live Grok execution. They are not dynamically closed by the API. Historical M1–M6/Axx names in tests are retained test identifiers, not a claim that the old proposed specification has been delivered.

The live-run installer fixes were subsequently published in Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. Remaining work includes completing mailbox execution and live mail evidence, wiring the unavailable adapters, implementing actual background execution/monitoring, validating lifecycle operations and securing production identity/cookie deployment. No current document claims production readiness or a demonstrated e2-micro capacity target.
