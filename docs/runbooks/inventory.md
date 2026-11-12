# Inventory, assignment and reservations

Only verified organizations that have authorized Bearmail installation join the capacity queue. Registration, subscription and domain entry do not reserve a server or Brevo account. Registration and allocation do not create a VM or invoke a model. Public inventory belongs to operators; customer reads follow the live assignment.

## Operator webpage

Open `/operator` with an authenticated operator session. The **Servers** and **Brevo accounts** tabs show all saved inventory, including assigned resources, with capacity, assignment, connection details and status. The **Users** tab lists registered users (including those without an organization), email verification, account status, organization, domains, setup status and live server/Brevo allocations. Choose **View user** for identifiers and registration details, or select an allocated resource to review/manage it. User records are read-only here; resource edits use the normal inventory forms. Support cannot see Brevo allocation details. Search by name, address, email or customer; use the filter to include removed resources.

Infrastructure operators and platform administrators can add, review and edit servers. Only platform administrators can manage Brevo credentials. Support access is read-only and excludes Brevo inventory. Inventory mutations require a verified identity and TOTP authentication within the preceding two hours. Other protected operations retain their own MFA windows. A login link still expires after five minutes and works once; its session token expires after two hours.

New servers are checked over SSH automatically before the add request finishes, in both the portal and CLI. The portal shows **Checking SSH access…** while saving. A failed check leaves the server unavailable and shows **SSH check failed** with the cause. For a host-key mismatch, verify the machine’s fingerprint through a trusted channel before updating the control plane’s known_hosts; do not automatically accept a changed key.

1. Choose **Add server**, enter its public IPv4 address, contact and provider reference, and confirm the preparation checklist. BearPortal checks SSH immediately. A passing check can assign the server to a waiting customer.


2. Choose **Review / edit** to change metadata. Changing an unused server's address resets readiness; choose **Check SSH access** afterward. Assigned, recovery-reserved or tainted servers retain their address and cannot be removed here.
3. Choose **Add Brevo account** and enter its account email, SMTP login, separate API and SMTP keys, and recorded daily allowance. Keys are encrypted and never displayed again. Blank replacement fields preserve existing keys. This allowance is operator-entered, not live remaining quota.
4. Review a free Brevo account to pause it, replace credentials or remove it. Assigned accounts permit label and allowance edits only. Credential edits do not update an installed mail server automatically.
5. Expand the removal section and confirm deletion. Removing a clean unused server retires its inventory record; removing a free Brevo account archives it. Neither action deletes a cloud VM or provider account. Archived Brevo accounts can be restored from the removed-resource filter.

Changes are audited, idempotent and checked against the resource version. If another operator changed a resource, reload before saving again. Apply `007_inventory_management.sql` with the other migrations before using this page. See [../try-it.md](../try-it.md) for operator sessions.

## Command-line inventory

Run these commands on the BearPortal server from the repository root. Keep the API running with `pnpm trial:start`. The CLI reads `.data/trial/env`, signs a fresh development administrator identity, and submits requests to that environment's API. It does not insert database rows directly or create cloud servers/Brevo accounts. Production uses externally issued operator tokens with the same admin API; the development signing helper is not a production login method.

Copy the templates to private files outside the repository:

```sh
install -m 600 examples/inventory/server.example.json "$HOME/bearportal-server.json"
install -m 600 examples/inventory/brevo.example.json "$HOME/bearportal-brevo.json"
```

Edit both files with your real values. For the server, use its public IPv4 address and your contact email; confirm that all five preparation attestations are true before submitting. For Brevo, supply the actual account email, REST API key, SMTP login and separate SMTP key. The examples are placeholders, not usable credentials. Keep filled credential files private and out of Git.

```sh
pnpm inventory servers add --file "$HOME/bearportal-server.json"
pnpm inventory brevo add --file "$HOME/bearportal-brevo.json"
pnpm inventory servers list
pnpm inventory brevo list
```

The CLI also accepts `--file -` for JSON on standard input. Add `--idempotency-key YOUR_UNIQUE_KEY` to reuse the same request after an uncertain response; reuse a key only with the same resource input. The successful output includes the request's key. Server creation reports the SSH result and resulting state; an SSH failure leaves the saved server pending validation. Review it in `/operator`, correct the connection and run **Check SSH access**. Brevo creation stores an inactive account for customer setup; it does not authenticate a domain at this step.

Both CLI and browser additions appear immediately in the same operator inventory. The **Users** tab shows assignments when a customer requests setup. Check `pnpm inventory --help` for command syntax.

## Allocation

The allocator serializes work per profile and selects the oldest eligible installation request and oldest eligible available server. `install_requested_at` is set when the customer authorizes setup (or creates a deployment through the installation API), and remains unchanged on retries. Ordinary registration records and paused setup requests are excluded from allocation and the operator waitlist. Apply migrations 014–015 before using this rule. Migration 015 performs the historical-consent backfill under FORCE RLS without changing an existing request timestamp. Partial unique indexes prevent duplicate live assignments. A pending recovery binding, existing owner or tenant taint excludes a server. Validation must be newer than five minutes. When a saved onboarding request is due and lacks a server, the API worker rechecks one stale, unused SSH-validated server before allocation. It probes outside database transactions and applies the result only if the resource version/address and eligibility are unchanged. A successful check resumes allocation automatically; a failure changes the server to pending validation for operator attention. Assigned, tainted and recovery-reserved servers are excluded, and recovery mode pauses this work. The operator table labels stale available inventory **Needs SSH refresh**. SSH-source readiness bypasses the older confirmed-device/fresh-heartbeat branch.

Successful SSH registration/validation can immediately allocate new capacity to eligible installation requests. `POST /v1/admin/server-waitlist/reconcile` uses an MFA operator; `POST /internal/allocate` requires the scheduler token. There is no supplied general minute-by-minute reconciliation service. Guided onboarding has its own 30-second in-process retry loop, which runs the allocator for eligible saved setup requests. The admin reconcile path still allocates in recovery mode; use it deliberately.

## Reservation safety

`reserved` already means exclusive ownership. There is no automatic reservation expiry. A failed install, job expiry or cancellation does not clear `tenant_tainted_at` or return the machine to the pool.

`POST /v1/admin/servers/:id/release-reservation` requires the route's cancellation/untouched-reservation checks. It returns a released clean reservation to pending validation and changes its authorization epoch; it does not make used inventory available. Older host identity rows can be revoked as part of this compatibility machinery.

Quarantine retains ownership and taint. Cleanup outcome `deleted` retires the server; `reimaged` leaves it quarantined and tainted. Current code has no general operation to clear taint and return that same used row to available. Prepare and validate replacement inventory through the supported clean-server flow rather than editing ownership fields manually.

Source: [../../packages/servers/src/allocate.ts](../../packages/servers/src/allocate.ts), [../../apps/api/src/inventory.ts](../../apps/api/src/inventory.ts), [lifecycle.md](lifecycle.md).

The portal reads the configured application database only. Records held in a separate recovery database do not appear automatically. Reconstructed records require review and an explicit import; a recovery review database is not a complete backup.

## Replacing test servers at the same IP

For disposable development servers, set `BEARPORTAL_TEST_SKIP_SSH_HOST_KEY_CHECK=1` in `.data/trial/env` and restart the API. This mode neither remembers nor verifies server host keys: readiness probes, SSH installer commands and SCP transfers use `/dev/null` for both host-key lists. Existing `known_hosts` entries remain intact but are ignored. The control-plane private key, `bearadmin` login and sudo requirements still apply. This disables protection against server impersonation; use it only for disposable tests. Startup rejects this setting unless `BEARPORTAL_ENV=development`. Omit it or set it to `0` to restore normal host-key checking.

Legacy reservations made before installation authorization require a conservative review: release only an untouched, untainted reservation with no setup, deployment, job, or host-command activity. Keep the account and allocation history, audit the release, invalidate old host authorization, and validate SSH/cleanliness before returning capacity. Existing installations and authorized setups retain their assignments. Never release a used server or externally configured Brevo account through this cleanup.
