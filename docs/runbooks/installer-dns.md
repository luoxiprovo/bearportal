# Installer DNS and TLS results

BearPortal has two trusted DNS publication paths: the customer credential form publishes Brevo verification records, and the remote Bearmail installer publishes mail DNS including MX. The operation gateway's ban on model-requested `dns.write` does not disable those trusted paths.

Provisioning is the customer's MX authorization. It runs dry-run then apply without a second approval. A source install resolves a GitHub main SHA and uses it for that preparation's artifacts. Explicit fixture/release injection is a separate `buildServer` mode with its own release-layout checks.

The source path accepts a stored DNS credential while the domain is pending. The legacy proof/recheck APIs still require their configured read adapters, which are unavailable in normal startup. A saved credential alone does not change the domain's verified state.

## Reading results

- `dry_run`: plan only; apply has not happened.
- `succeeded`: completed installer result.
- `tls_pending`: accepted DNS writes, certificates not yet observed by the installer.
- `dns_partial` / `failed`: inspect the error and partial publication evidence.

BearPortal derives `dnsWritesAccepted` from normalized `succeeded`/`tls_pending` status. It is not a propagation or mail-delivery check. The installer preserves prior MX in its result and rejects ambiguous SPF changes. The portal does not automatically compensate a partial publish by changing MX back.

`POST /v1/deployments/:id/dns-recheck` compares supplied observer results rather than writing the zone. Its default DNS observer is unavailable. A recheck cannot by itself prove receipt or delivery of mail.

## TLS checks

Caddy may obtain certificates after apply returns. Verify authoritative/public host records, public 80/443 access and Caddy's journal before retrying. Early attempts before DNS exists can hit an issuer retry window. Respect the observed retry time rather than repeatedly reinstalling the mail stack.

Check both `mail.<domain>` and the deployment's saved Bearmail web UI hostname. New deployments use `bearmail.<domain>`; old deployments can use `webmail.<domain>`. A local resolver can cache the previous address; an explicit-resolution check of the new server is useful evidence but is not proof that every client has updated DNS.

Later certificate issuance does not automatically refresh a saved `tls_pending` result. `mail_verified` remains database-locked false, even if HTTPS works. A complete installation and an active mail service are different claims.

See [../BEARMAIL_NONINTERACTIVE_INSTALLER.md](../BEARMAIL_NONINTERACTIVE_INSTALLER.md) and [ssh-install.md](ssh-install.md).
