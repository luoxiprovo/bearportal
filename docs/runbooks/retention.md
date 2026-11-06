# Retention and deletion evidence

BearPortal stores operator reports. It does not independently delete cloud disks, backup objects, mailbox stores or DNS zones.

## Cancellation retention

Cancellation policy uses a seven-day grace period before execution and a 24-hour execution window. The execution route requires the configured scheduler token and backup/waiver checks. It queues a stop command; a queued stop is not an observed stop.

An operator isolation report establishes the reported stop with `hostObserved: false`. Cleanup then waits seven days after the recorded stop and requires backup-retention and credential-revocation attestations. Missing host or heartbeat evidence does not substitute for isolation.

Outcome `deleted` retires inventory. Outcome `reimaged` leaves it quarantined and tainted. Cleanup evidence is not a cloud verification, does not stop provider billing and does not return a machine automatically to available capacity.

## Mailbox and audit records

`POST /v1/mailboxes/:id/delete-plan` creates an approval; it is not an engine deletion executor. System aliases remain represented in mailbox records. There is no general mailbox deletion/reassignment worker in this repository.

Audit rows are append-only to the application role. That does not protect them from privileged database reset/restore tools. Development `trial:reset` deliberately truncates operational/audit tables; automated integration tests must use disposable test databases instead. Keep real backup retention outside the application and do not treat surviving encrypted files as a complete database backup.

Sources: [../../apps/api/src/lifecycle.ts](../../apps/api/src/lifecycle.ts), [../../packages/db/migrations/005_lifecycle.sql](../../packages/db/migrations/005_lifecycle.sql), [../../tests/README.md](../../tests/README.md).
