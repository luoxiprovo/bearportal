# Validation status

Reviewed on 2026-11-05. Code-level tests and a controlled live installation are different kinds of evidence.

## Local automated checks

The latest full `pnpm test` run passed **80 tests**; `pnpm typecheck` passed. Tests cover contracts, tenant isolation/RLS, inventory and FIFO allocation, DNS planning/provider fixtures, installer orchestration, oversight policy and lifecycle records.

The guided-onboarding integration test covers email-only development registration, provider detection, explicit consent, separate capacity shortages, persistence across an API restart, recovery mode, provider/authentication retry, committed administrator credentials, duplicate triggers, tenant isolation and interrupted-install review.

The suite includes regression tests for `bearmail.<domain>` as the new web UI default and preserving a saved legacy webmail hostname. Database-safety tests reject missing connections, the working database, mismatched targets and connection-parameter overrides.

`pnpm test` provisions a disposable `bearportal_test_*` database when no connection variables are supplied and removes it afterward. Explicit application, migration and administrative connections must all name the same dedicated test database. See [../tests/README.md](../tests/README.md). `trial:reset` is separate and destructive.

CI uses an explicitly named disposable test database. Provider fakes in tests do not establish that every provider works live. The tests do not contact arbitrary customer mailboxes or run a model.

Desktop and mobile browser checks covered eight rendered views (registration, domain entry, provider connection and waiting status). They found no horizontal overflow or browser script errors. These rendering checks used preview data; the integration suite separately exercised the real API flow with injected provider/installer adapters.

## Controlled live development run

A real saved server was reached with BearPortal's SSH key, and the provisioning code invoked Bearmail's noninteractive installer. DNS writes were accepted, four services ran, saved administrator authentication worked, and the webmail/admin HTTPS endpoints were checked after certificate issuance.

That run used **locally patched Bearmail installer scripts**, with the other artifacts downloaded from a resolved GitHub commit. Those fixes were subsequently published in Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`; arbitrary later main revisions still need their own validation. The detailed record and limitations are in [release-evidence/2026-11-05-ssh-install.md](release-evidence/2026-11-05-ssh-install.md).

## Still unverified or incomplete

- External inbound/outbound delivery, calendar/MCP permissions and all-interface sending limits.
- General portal mailbox synchronization and credential delivery to the engine.
- Every DNS provider and generic production DNS/relay observer wiring.
- A real backup/restore drill, executed binary upgrade, observed cancellation stop and full cleanup.
- An e2-micro capacity soak or any production SLA/capacity promise.
- Live Grok generation and a staging operation worker.

The API release checklist remains hardcoded incomplete, including `liveEvidence: false`. Installed services and a passing unit suite do not change that. The database still prevents `mail_verified = true`.
