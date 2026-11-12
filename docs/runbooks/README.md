# Operator runbooks

These procedures describe the current code. They do not imply that every lifecycle action has a running host worker or live external verification. Start with [../../SPEC.md](../../SPEC.md) and [../try-it.md](../try-it.md).

| Topic | Runbook |
|---|---|
| Local startup and adapters | [local-setup.md](local-setup.md) |
| systemd service | [systemd.md](systemd.md) |
| Prepare a mail server | [preparation.md](preparation.md) |
| SSH readiness and legacy enrollment | [enrollment.md](enrollment.md) |
| Install over SSH | [ssh-install.md](ssh-install.md) |
| Google and email/password authentication | [identity-platform.md](identity-platform.md) |
| Inventory and reservations | [inventory.md](inventory.md) |
| Brevo inventory and domain verification | [brevo.md](brevo.md) |
| DNS results and TLS | [installer-dns.md](installer-dns.md) |
| Host loss and address repair | [host-loss-and-ip.md](host-loss-and-ip.md) |
| Credentials | [credentials.md](credentials.md) |
| Health, disk and incidents | [disk-and-incidents.md](disk-and-incidents.md) |
| Backup, restore, upgrades, cancellation | [lifecycle.md](lifecycle.md) |
| Retention and cleanup evidence | [retention.md](retention.md) |
| Artifact versions and rollback plans | [release-rollback.md](release-rollback.md) |
| Execution and capability limits | [capability-manifest.md](capability-manifest.md) |
| Oversight sessions and model limits | [oversight.md](oversight.md) |

BearPortal can write Brevo verification DNS through trusted forms and execute Bearmail over SSH. The installer publishes mail DNS including MX. Guided setup has an in-process persistent onboarding queue with automatic capacity retries. There is no live Grok loop, general host-command delivery worker, cloud lifecycle adapter or platform notification sender. Read [../local-validation.md](../local-validation.md) for demonstrated coverage.

Production operator access: [operator-login.md](operator-login.md).
