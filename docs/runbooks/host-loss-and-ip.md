# Host loss, address changes and recovery

The operator changes infrastructure outside BearPortal. The application does not discover replacement IPs, reboot a VM or restore a disk.

## Address change

`POST /v1/admin/servers/:id/ip-change` takes a public IPv4, reason and expected version. It rejects a colliding live inventory address and updates the existing server row.

For a reserved/assigned/quarantined owned server, the route calls `repairAssignedAddress` when enough saved deployment/domain/relay/admin data exists. That helper can run the installer over SSH immediately, using a new operation/generation, the new address and the deployment's saved webmail hostname. It is not merely a future queued DNS promise. If the input is incomplete, the route can instead record a `dns.address_update` job with `installerStarted: false`.

Inspect `installerStarted` and the actual result. The IP-update route does not first perform a fresh SSH readiness probe; a rejected SSH session can leave the database pointing at the newly submitted address. The installer is responsible for its mail DNS writes. A successful database update alone does not prove repaired DNS or the correct host identity.

## Host loss and replacement

Quarantine retains the owner and tenant taint. Use the restore-request/replacement-plan/restore-ready/restore-promote workflow in [lifecycle.md](lifecycle.md). The replacement is reserved through a recovery binding, outside the normal allocator. Fencing requires application-stop or external-isolation evidence; an absent heartbeat is not fencing.

Promotion transfers the one live assignment and changes authorization epochs. It does not copy data or publish DNS. Retain recovery material until the operator has completed the external work and cleanup requirements.

## Control-plane recovery

`POST /internal/recovery/enter` requires the scheduler token and records recovery mode, invalidating approvals that are not in flight. Checked lifecycle, host-command, gateway, automatic onboarding and internal-allocation paths pause. The admin waitlist reconcile path still allocates; do not invoke it when preserving frozen ownership is necessary.

Recovery reconcile returns status with `resumed: false` and `replayed: 0`. The watchdog records a thaw decision/event, not an automatic database restore. These endpoints do not provide a backup, reconstruct lost rows, or reconcile every external resource automatically. Preserve PostgreSQL backups, encrypted files, encryption keys and SSH identity independently.

Sources: [../../apps/api/src/inventory.ts](../../apps/api/src/inventory.ts), [../../apps/api/src/installation.ts](../../apps/api/src/installation.ts), [../../apps/api/src/oversight.ts](../../apps/api/src/oversight.ts).
