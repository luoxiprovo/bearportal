# Backup, restore, upgrades and cancellation

The lifecycle APIs record operator evidence and plans. They do not call cloud snapshot/restore/delete APIs. Their implementation is [../../apps/api/src/lifecycle.ts](../../apps/api/src/lifecycle.ts); backup report handling also exists in [../../apps/api/src/installation.ts](../../apps/api/src/installation.ts).

## Backups

A bare evidence reference is a recorded report, not proof of a consistent backup. A completed report needs the route's timestamps and consistency fields. A failed report does not replace the last usable report. `restore_verified` is an operator attestation, not an independent cloud check. Freshness policy uses 26 hours.

Use internal evidence references, not arbitrary fetchable URLs. External backup creation, object retention and verification remain operator work. Backup evidence alone never marks mail verified or activates the deployment.

## Replacement restore

1. The owner requests a backup restore and acknowledges possible data loss.
2. An operator records a plan for a different clean compatible server. The replacement is quarantined with a pending recovery binding, not a second ordinary assignment.
3. The operator supplies application-stop or external-isolation fencing evidence. Missing heartbeat is insufficient.
4. The owner approves the bound plan within the approval window.
5. Promotion transfers the sole live assignment, changes authorization epochs and retains/quarantines the old server.

This sequence coordinates records and ownership; it does not execute a disk restore, send new credentials or publish DNS. Verify the restored application externally before claiming restored mail.

## Upgrade plans

Upgrade-plan recording requires the named fresh consistent backup. Compatibility, irreversible migrations, newly accepted mail and check results determine `blocked`, `preserve_required`, `rollback_required` or `pending`.

These are plan states. The database forces `executed`, `binaries_executed` and `data_rollback` false, and the plan route does not queue an executed upgrade. No binary/data rollback has been demonstrated by that API.

## Cancellation

The owner proposes and approves a cancellation. Policy uses a seven-day grace period, a 24-hour execution-start window and a 30-minute approval window. At execution time the scheduler-authorized route checks backup evidence or a waiver and queues one `stop_mail_services` command.

A queued command does not prove services stopped; host dispatch remains undelivered. An operator isolation report records the reported stop. Cleanup waits seven days after that stop and requires retention/revocation attestations. `deleted` retires the server; `reimaged` keeps it quarantined and tainted. Billing and provider resources remain the operator's responsibility.

The release checklist is hardcoded incomplete and does not change merely because reports or plans exist. See [retention.md](retention.md) and [release-rollback.md](release-rollback.md).
