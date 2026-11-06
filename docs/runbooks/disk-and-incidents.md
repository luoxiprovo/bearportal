# Disk, health and incidents

Health derives from submitted records in [../../packages/operations/src/policy.ts](../../packages/operations/src/policy.ts) and routes in [../../apps/api/src/oversight.ts](../../apps/api/src/oversight.ts). This repository does not install an autonomous monitor timer or probing daemon.

## Disk and health

Disk thresholds are warning at 75%, degraded at 85%, and operator action at 90%. BearPortal does not delete mail or snapshots to free space. The operator investigates storage outside the portal.

No observations means unknown. SMTP/engine failure means unavailable; stale, partial or missing required evidence prevents a healthy result. The group of heartbeat/reachability/HTTPS/JMAP/IMAPS/SMTP/engine observations has a 30-minute freshness window; its historical `FIVE_MINUTE_PROBES` name is not proof that a scheduler runs every five minutes. Relay freshness is two hours; certificate, delivery and backup freshness is 26 hours.

Two consecutive failures open an incident and three successes close it under the policy. API acceptance of a message is not proof of delivery. The live installation record includes HTTPS/services, not a passing end-to-end delivery probe.

## Notifications and response

Notifications and required actions are database records. There is no independent platform mail sender; a notification row does not mean an email was sent. Do not use a customer's broken relay to claim independent incident notification.

Read the observation timestamps and required actions. Fix host, network or storage failures outside BearPortal, then obtain fresh evidence. A page refresh is not a health check. Quarantine and address repair preserve ownership; they do not grant cloud reboot or replacement permissions.

Recovery mode pauses the mutation paths that check it without changing running mail's local policy. The admin allocator is an explicit exception. There is no running agent restart worker; restart budgets in policy are constraints on a future verified executor, not observed restarts.
