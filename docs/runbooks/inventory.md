# Inventory, assignment and reservations

Verified organizations can wait for a server. Registration and allocation do not create a VM or invoke a model. Public inventory belongs to operators; customer reads follow the live assignment.

## Allocation

The allocator serializes work per profile and selects the oldest eligible verified waiting request and oldest eligible available server. Partial unique indexes prevent duplicate live assignments. A pending recovery binding, existing owner or tenant taint excludes a server. Validation must be newer than five minutes. SSH-source readiness bypasses the older confirmed-device/fresh-heartbeat branch.

Successful SSH registration/validation can immediately allocate new capacity. `POST /v1/admin/server-waitlist/reconcile` uses an MFA operator; `POST /internal/allocate` requires the scheduler token. There is no supplied general minute-by-minute reconciliation service. Guided onboarding has its own 30-second in-process retry loop, which runs the allocator for eligible saved setup requests. The admin reconcile path still allocates in recovery mode; use it deliberately.

## Reservation safety

`reserved` already means exclusive ownership. There is no automatic reservation expiry. A failed install, job expiry or cancellation does not clear `tenant_tainted_at` or return the machine to the pool.

`POST /v1/admin/servers/:id/release-reservation` requires the route's cancellation/untouched-reservation checks. It returns a released clean reservation to pending validation and changes its authorization epoch; it does not make used inventory available. Older host identity rows can be revoked as part of this compatibility machinery.

Quarantine retains ownership and taint. Cleanup outcome `deleted` retires the server; `reimaged` leaves it quarantined and tainted. Current code has no general operation to clear taint and return that same used row to available. Prepare and validate replacement inventory through the supported clean-server flow rather than editing ownership fields manually.

Source: [../../packages/servers/src/allocate.ts](../../packages/servers/src/allocate.ts), [../../apps/api/src/inventory.ts](../../apps/api/src/inventory.ts), [lifecycle.md](lifecycle.md).
