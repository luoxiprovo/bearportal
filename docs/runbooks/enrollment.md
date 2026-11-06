# SSH access, readiness and compatibility enrollment

Normal startup uses SSH to a saved server. It does not install a BearPortal supervisor or poller on the mail host. See [ssh-install.md](ssh-install.md).

## Network preparation

The operator manages firewall rules. Bearmail's intended public inbound TCP ports are 25, 80, 443, 465 and 993. Permit SSH 22 from the control-plane address. The Brevo relay connection is outbound TCP 587 with STARTTLS. Allow required outbound HTTPS, DNS and operating-system dependencies. Engine HTTP ports such as 8080/8081 and HTTP MCP should remain on loopback rather than be exposed publicly.

These port settings are operator responsibilities. The SSH readiness probe does not validate every mail port or prove relay authentication. Check externally before claiming working mail.

## SSH readiness

Install the control-plane public key for `bearportal-control-plane` and configure noninteractive sudo before registration. The API uses port 22, `BatchMode`, `IdentitiesOnly` and a private known-hosts file. First contact can accept a new host key; later connections require a match.

The six sudo commands read `uname -s`, `uname -m`, `/proc/1/exe`, `/proc/meminfo`, root filesystem size and names under `/var/lib/stalwart`. A missing data directory passes and is not created. Existing entries or an unreadable directory fail clean-server validation. A directory existing does not prove that it is a separate mount.

Retry an eligible untainted server with `POST /v1/admin/servers/:id/validate` and its expected version. Fix SSH, sudo, OS or capacity problems outside BearPortal. Review a host-key change independently rather than blindly deleting the known-hosts entry.

## Older enrollment APIs

Enrollment tokens, confirmed device identities and signed heartbeat routes remain implemented for compatibility and tests. Allocation and install checks accept either their older confirmed-identity evidence or an SSH-source report, as defined in code. There is no delivered resident host agent, and these routes are not required by the normal SSH flow.

Source: [../../packages/servers/src/ssh-probe.ts](../../packages/servers/src/ssh-probe.ts), [../../apps/api/src/inventory.ts](../../apps/api/src/inventory.ts).
