# Controlled SSH installation: 2026-11-05

This development run exercised BearPortal's provisioning route and `liveMailInstall` against one saved server and an operator-controlled domain. It does not qualify a production release.

## Source and scope

- Bearmail artifact base commit: `54f84634935f47eb6d9ad07c756ad3604eafd248`.
- Operation: `32682aaf-539a-4828-8393-618f72bfc854`.
- Local overrides: `../bearmail/bearmail-install` and `../bearmail/install.sh`; the remaining artifacts came from the resolved commit.
- The existing deployment used the older `webmail.<domain>` hostname. New deployments now default to `bearmail.<domain>`; this run did not migrate the existing deployment.

Local fixes addressed executable staging outside `noexec /run`, administrator management through `x:Account` with map-shaped credentials, noninteractive reuse of saved administrator credentials, and RSA selection when the engine emits RSA and Ed25519 DKIM records. The related Bearmail fixture/noninteractive tests passed. The four installer/test files were subsequently published to Bearmail `main` as `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`; the remote branch hash was verified after push.

## Observations

- SSH login and noninteractive sudo worked.
- Installer dry-run passed, then apply published mail A, MX, SPF and RSA DKIM records through the configured GoDaddy integration.
- Stalwart, Caddy, `bearmail-webui` and `bearmail-mcp` were active.
- The saved administrator credential authenticated through the engine's `x:Account/query` API.
- The installer returned `tls_pending` with DNS writes accepted.
- After DNS propagation and an issuer retry window, Caddy obtained valid certificates. Webmail returned HTTP 200 and the mail/admin origin returned HTTP 302 to `/account`. The latter check explicitly resolved the new server address because a local resolver retained the previous address.
- The certificate synchronization service was invoked. Remote temporary staging was cleaned up and the temporary recovery override was removed.

The recorded installer result remained `tls_pending`; later certificate issuance does not automatically update BearPortal's stored result.

## Limits and current local state

End-to-end mail delivery, the initial requested mailbox's engine provisioning, calendar behavior, capacity, backup/restore and live Grok execution were not verified. The deployment's provisioning Brevo flags remained false despite the separate account/domain integration. Mail stayed unverified in BearPortal.

A subsequent integration-test reset accidentally cleared the working trial database. Encrypted secret files and the remote installation survived. The working database was left empty; a partial reconstruction was validated separately in `bearportal_recovery_review`, with private recovery material under `.data/recovery/`. This historical record is not a current inventory snapshot or a complete database restore. The test launcher now creates disposable databases and refuses the working database and mismatched test connections.
