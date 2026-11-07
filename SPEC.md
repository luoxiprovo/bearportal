# BearPortal: current implementation

Reviewed against the local code on 2026-11-07. This document replaces the earlier milestone proposal. It describes behavior that exists and identifies incomplete integrations explicitly. Runtime schemas, migrations and route implementations take precedence if they change.

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
| `apps/api/src/browser-auth.ts`, `identity-platform-client.ts`, `identity-accounts.ts` | Identity Platform REST sign-in, browser sessions and verified identity binding |
| `apps/api/src/portal.ts` | HTML rendering; there is no Next.js application |
| `apps/api/src/operator-inventory.ts` | Versioned inventory edits, archival and operator form actions |
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

Google/email-password browser authentication uses Google Cloud Identity Platform directly, without the Firebase SDK. The browser uses Google Identity Services for its Google button; the API brokers password, verification/reset email, Google token exchange and refresh through Identity Platform REST endpoints. Google and project ID tokens require pinned issuers/audiences, RS256 signatures and rotating Google public keys. Google callbacks also require a signed, browser-bound nonce. Local development identities retain the configured static key/issuer/audience path; production never signs local identities.

With all four `BEARPORTAL_IDENTITY_PROJECT_ID`, `BEARPORTAL_IDENTITY_API_KEY`, `BEARPORTAL_GOOGLE_CLIENT_ID` and `BEARPORTAL_AUTH_ORIGINS` settings present, `/register` offers Google or email/password and `/login` supports returning users, verification/resend, reset email and refresh. Email verification is required before application registration/allocation. Passwords are managed by Identity Platform rather than stored locally. Activation requires both the BearPortal settings and the Cloud-side provider/origin configuration; saving local settings alone does not enable a disabled provider or authorize an OAuth origin. See [docs/runbooks/identity-platform.md](docs/runbooks/identity-platform.md).

Migration 008 binds verified project issuer/UID pairs to application users. Verified email/password proof or authoritative Gmail/Workspace Google proof can link an existing ordinary `local:<email>` user without changing organization, deployment or inventory IDs. Operator-role accounts are excluded from automatic email matching. Role grants remain database-controlled. Disabled accounts, unverified addresses, wrong-project tokens, nondefault tenants and unsupported providers are rejected. Additional Identity Platform MFA challenges are not implemented and are rejected rather than bypassed. Inventory TOTP freshness is two hours; other protected operations keep their own windows.

The email-only development registration form remains only when no managed identity configuration is supplied and a development signing key is enabled. It does not verify email and is not production authentication. Once Identity Platform is configured, that route is disabled. `pnpm auth:configure` preserves existing database/encryption/signing settings and writes a private configuration backup before saving the new fields.

Managed `/auth/*` mutations require a signed login CSRF value, a matching HttpOnly cookie and an exact allowed Origin. Identity/refresh tokens remain in HttpOnly cookies; HTTPS origins use Secure cookies and refresh cookies are scoped to `/auth`. Tokens/passwords are not placed in browser storage or returned in sign-in JSON. The legacy `/v1/session` exchange remains for static/test identities and rejects direct managed-token browser exchanges. Other cookie mutations still require `x-bearportal-csrf: 1` or form `csrf=1`; Bearer requests do not. Local static-session cookies lack Secure in development. Upstream revocation is checked through refresh/expiry rather than queried on every API call; backend application-account disablement is checked for each managed identity resolution.

Development operator access also supports `pnpm trial:login`: it writes a private, short-lived login grant for the existing bootstrap identity. The printed URL carries a random code in its fragment; the page removes the fragment and redeems the code once. The server rechecks operator authorization and uses the normal session endpoint. These login routes are disabled without development identity signing. Production continues to require external identity authentication. The link expires after five minutes and works once. Its development session lasts two hours.

Secrets are AES-256-GCM encrypted files, mode `0600`, with a database file reference and key ID. The encryption key is separate from PostgreSQL. Routine responses redact credential material; the installed-service owner can explicitly reveal the generated mail administrator login through its audited no-store endpoint. SSH keys are local files, not database secrets or model inputs. Keep service-owned directories private; the implementation does not require every file to be owned by root.

## 5. Saved servers and allocation

Operators register a public unicast IPv4 with label, profile, contact, optional provider reference and preparation attestations. Normal startup probes the saved address immediately over SSH. Validation can be retried through the admin route.

The login is `bearadmin`, port 22, with a local private key and known-hosts file. First contact can accept a new host key; subsequent connections enforce it. `sudo -n` fails rather than prompting.

The six probe commands inspect OS, architecture, PID 1, memory, root filesystem size and `/var/lib/stalwart`. The SSH path accepts Linux/systemd on x64 or arm64, at least 900 MiB reported memory and 20 GiB total root-filesystem size. A missing data directory passes; existing entries fail the clean-server probe. These commands do not test every mail port or authenticate to the relay. Although readiness accepts arm64, the current downloaded Stalwart artifact validator requires an x86-64 ELF binary.

Successful validation can allocate the server immediately. Allocation is FIFO by verified registration within profile `e2-micro`, serialized by an advisory lock and protected by unique live-assignment indexes. Candidates need validation newer than five minutes, no taint, no assignment and no pending recovery binding. SSH-source reports bypass the older confirmed-device/heartbeat eligibility branch.

Before processing a due customer setup that lacks a server, the onboarding worker can refresh one stale available SSH server. It keeps the five-minute allocation freshness gate, probes outside transactions, and compares the saved version/address and ownership/taint/recovery eligibility before accepting results. Failures become pending validation, not automatically retried failed inventory. Recovery mode pauses refreshes. Customer capacity messages distinguish a missing server from a missing relay.

States are `pending_validation`, `available`, `reserved`, `assigned`, `quarantined`, `retired`. Failed or cancelled installation does not automatically release a server. There is no general automatic taint-clearing/reimage-to-available workflow.

Signed host enrollment, identity and heartbeat routes remain for compatibility and tests. They are not prerequisites for the normal SSH install, and no host-agent package or poller is delivered by this repository.

## 6. Domain, DNS and Brevo

The customer domain form saves one non-retired domain and detects its authoritative nameservers. Supported providers are `namecom`, `hostinger` and `godaddy`; mixed/unknown nameservers do not receive a provider credential form.

A platform administrator stores Brevo login email, API key, SMTP login, SMTP key and daily allowance. New accounts are `inactive`. The domain form can exclusively claim the oldest free inactive account and create/read its domain through Brevo. The generic admin relay-assignment flow instead uses `available` accounts.

The DNS credential form stores the credential, publishes Brevo verification records, and then calls Brevo authenticate/read. Publication supports returned TXT and CNAME records. This form does not replace MX. SMTP and API credentials are different: the installer receives the SMTP key, never the Brevo REST API key.

On the source-install path, a stored DNS credential is enough to proceed while the domain row remains pending. It does not mark the domain verified. The legacy domain-proof API still depends on the unavailable `ZoneReader`.

Provisioning uses any saved compatible three-TXT Brevo record set, otherwise the source path can omit `brevoDnsRecords`. The schema accepts zero or three records, not an arbitrary partial set. Modern CNAME verification records are published separately by the domain credential form.

## 7. Guided setup and installation over SSH

The operator UI at `/operator` provides server and Brevo inventory tables, search, filters, capacity summaries and add/edit/review dialogs. Its Users tab lists every registered user, including users without customer organizations, alongside email verification, organization/domain, setup state and live resource assignments. Resource links open the corresponding inventory dialogs; user records are read-only. Infrastructure operators manage servers; platform administrators also manage Brevo accounts. Support is read-only and cannot view Brevo inventory or allocation details. Inventory changes require verified identity, TOTP authentication within two hours, idempotency and version checks. Other protected operations retain the default 15-minute MFA window. Assigned resources are protected from removal. Unused servers are retired and free Brevo accounts archived without deleting external infrastructure; archived Brevo accounts can be restored. Credential fields are write-only; assigned Brevo connection settings cannot be changed here. Migration 007 adds relay archival.

The development inventory CLI (`pnpm inventory servers|brevo add --file …` and `list`) reads the private trial configuration, signs the existing administrator identity, validates JSON with the API contracts and calls the same admin endpoints as operator forms. Add requests use idempotency keys, server registration runs the configured SSH check, and Brevo credentials are encrypted by the API. Credential values and bearer tokens are redacted from CLI responses. No recovery import is part of this workflow.

The customer UI follows Google or verified email/password registration (email-only in the unconfigured development preview), domain entry, provider detection and a provider-specific credential form. It uses system typography, restrained colors, responsive cards and progressive disclosure. Customers do not supply Brevo credentials or select inventory. A pre-credential domain typo can be corrected before DNS credentials or setup records exist.

Guided setup captures authorization once when the user submits the provider credential, covering domain verification, Brevo authentication, mail-routing DNS changes, installation and a setup test. The encrypted credential and domain-specific consent persist across backend retries and credential replacement; a different domain needs separate authorization. DNS propagation waits reset the provider-error retry counter. Explicitly retryable installation results and proven local work-root preflight permission failures retry automatically. Interrupted/ambiguous host outcomes remain operator review cases and never prompt for repeated customer consent or silently replay unknown writes. The API checks work-root access at startup.

`onboarding.ts` reuses deployment/provisioning services, validates current ownership, pauses in recovery mode, checks nameservers, publishes Brevo verification records and waits for strict authenticated/verified booleans. Administrator secrets are committed before the live runner resolves them through a separate database connection. The automatic path passes its actual Brevo result into provisioning, avoiding the unavailable generic Brevo client.

The normal check interval is 30 seconds. `POST /internal/onboarding/run` permits an explicitly scheduler-authenticated check; tests can disable the interval through a dependency override. No customer token or raw credential is persisted in the queue. Capacity waits do not count toward the 20 provider-attempt limit, and successful provider responses waiting for DNS reset that failure counter. Long-interrupted installs enter `attention` after their lease expires.


`POST /v1/deployments` creates draft records and mailbox requests. `POST /v1/deployments/:id/provision` checks organization, version, domain credentials, assigned server and plan, then records MX authorization. That request is the installation decision; no second MX approval is required.

The source path resolves the current `luoxiprovo/bearmail` `main` SHA and uses that SHA for one preparation's files. It downloads `bearmail-install`, `install.sh`, `stalwart`, `bearmail-webui.tar.gz` and `mcp_install.sh`, validates basic artifact structure, and writes checksums. This is not a fixed production release pin or a signed-release verification system. A later preparation/retry can resolve a newer main SHA.

The local runner stages under `/var/lib/bearportal/work/<operationId>` by default. The remote directory is `/var/lib/bearportal/install/<operationId>` with a commit-named artifact directory. Executable artifacts need an executable filesystem: `/run` is intentionally not used.

Credentials are separate mode-0600 files. Installer JSON contains absolute remote file paths. BearPortal runs dry-run and, if valid, apply, fetches the JSON result, stores its normalized status/DNS evidence and attempts remote cleanup. Local work is removed in a `finally` block. SSH/spawn exceptions can leave remote files, so inspect cleanup after interrupted runs.

The legacy provision API runs downloads and SSH synchronously. The guided UI instead submits a persistent request; its in-process onboarding worker invokes those same services in the background. Compatibility host-command rows remain undelivered; installer results provide the execution evidence. Retrying the same installation fingerprint can reuse the operation ID; recorded successful/TLS-pending DNS acceptance can short-circuit another provisioning call.

The Bearmail program configures the engine, web UI, MCP, administrator credential and quota; it publishes mail A/MX/SPF/DKIM and applicable verification records. The detailed contract is [docs/BEARMAIL_NONINTERACTIVE_INSTALLER.md](docs/BEARMAIL_NONINTERACTIVE_INSTALLER.md).

## 8. Results and mailboxes

Installer statuses are `dry_run`, `succeeded`, `tls_pending`, `dns_partial` and `failed`. The runner combines process exit status and JSON; normalized `succeeded`/`tls_pending` results count as accepted DNS writes. This is not proof of authoritative propagation or mail delivery.

Caddy can obtain certificates after the installer has returned `tls_pending`. The onboarding worker verifies both HTTPS hostnames on the assigned server and updates deployment status when they are ready. Historical installer-run results are retained. Repeated early certificate requests can hit issuer rate limits.

After installation, the customer page separates administration at the saved `mail.<domain>` hostname from normal webmail at the saved `bearmail.<domain>` hostname. An owner-only POST endpoint reveals the encrypted generated administrator credential on explicit request; it checks organization/deployment ownership, active secret scope, installation status, verification, CSRF and rate limits. The secret is not embedded in page HTML, returned in overview APIs, placed in browser storage or included in audit records. The owner creates regular mailbox accounts/passwords in the mail administrator console. A background HTTPS probe verifies both hostnames on the assigned public IP before clearing installer TLS-pending status; it does not establish mail delivery or replay installation.

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

Use all route modules under `apps/api/src/`, including browser authentication, inventory and administrator-credential routes, for the actual API surface. `packages/contracts/src/openapi.ts` is a contract description, not proof that every described operation has a route. There is no implemented generic relay-rotation endpoint or mailbox-delete executor merely because a plan/contract mentions one.

## 12. Development, testing and evidence

Use [docs/try-it.md](docs/try-it.md) for startup and [tests/README.md](tests/README.md) for tests. `pnpm test` uses disposable databases; every explicit integration connection must target the same `bearportal_test_*` database. Working databases are rejected before fixture resets. `trial:reset` remains a separate explicitly destructive development command.

The current suite passes 86 tests and TypeScript checking. Browser coverage includes operator/customer flows and mocked Identity Platform signup. Live activation checks confirmed the password provider and Google sign-in prompt at localhost; a real user’s complete authentication remains unverified. Controlled SSH installations demonstrated services, HTTPS and administrator authentication. The dated 2026-11-05 evidence used local Bearmail script fixes. It did not validate every provider, mail delivery, calendar, restore, upgrade, cancellation execution, capacity soak or a live Grok worker. See [docs/local-validation.md](docs/local-validation.md) and [the installation record](docs/release-evidence/2026-11-05-ssh-install.md).

`GET /v1/admin/release-checklist` hardcodes `liveEvidence: false` and the historical labels `A07-A16`, `A19`, `A20`, `A21`, `A22`, `A25`, `A31`. Those labels refer to host/provider integration, outage/recovery, backup/restore, upgrades, cancellation, capacity and live Grok execution. They are not dynamically closed by the API. Historical M1–M6/Axx names in tests are retained test identifiers, not a claim that the old proposed specification has been delivered.

The live-run installer fixes were subsequently published in Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. Remaining work includes completing mailbox execution and live mail evidence, wiring the unavailable adapters, completing general-purpose background execution and health monitoring, validating lifecycle operations and securing production identity/cookie deployment. No current document claims production readiness or a demonstrated e2-micro capacity target.
