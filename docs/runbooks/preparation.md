# Operator server preparation

The operator creates and maintains the machine, disks, firewall and external backup process. BearPortal stores an inventory row and uses SSH; it has no cloud infrastructure credentials.

## Before saving the server

1. Prepare Linux with systemd and enough capacity for the selected profile. `e2-micro` is the current allocation profile, not a demonstrated capacity guarantee.
2. Use x86-64 for the normal download path. The SSH probe accepts arm64, but the downloaded engine validator currently rejects non-x86-64 binaries.
3. Provide at least 20 GiB total root-filesystem capacity. The SSH probe accepts reported memory of at least 900 MiB to accommodate nominal 1 GiB machines. It does not measure a production workload or prove sufficient free space.
4. Leave `/var/lib/stalwart` missing or empty of unrelated mail data. There is no requirement to mount it separately. Dry-run does not create it; apply creates it if missing. BearPortal does not format, partition or resize storage.
5. Create `bearadmin`, install the control-plane SSH public key in its authorized keys, and configure passwordless sudo for the required operations. Keep the private key on the control plane.
6. Configure the firewall in [enrollment.md](enrollment.md). Arrange backups outside BearPortal.
7. Ensure `/var/lib/bearportal/install` is on an executable filesystem with sufficient space for the staged release. `/run` may be `noexec` and is not used.

Save the server with `POST /v1/admin/servers`: label, public IPv4, profile code, operator contact, preparation attestations, and optional provider reference. Normal startup immediately runs the SSH probe. A successful probe can return a server already reserved for a waiting customer; a failed one remains pending validation.

A provider reference is metadata for human lookup, not a cloud API identifier that BearPortal operates on. Public IP and live provider-reference uniqueness are enforced. Do not create a second inventory row merely to change an existing server's IP.

Source: [../../apps/api/src/inventory.ts](../../apps/api/src/inventory.ts), [../../packages/servers/src/ssh-probe.ts](../../packages/servers/src/ssh-probe.ts).
