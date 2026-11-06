# Credentials and rotation

[SecretStore](../../packages/secrets/src/store.ts) encrypts stored values with AES-256-GCM and writes mode-0600 files. PostgreSQL stores file references and key metadata. Preserve the encryption key independently of database backups; restoring rows without their files/key does not restore credential access.

The live installer temporarily decrypts only the referenced DNS, SMTP and admin credentials into private local/remote staging files. Inputs and commands use paths, not credential values. Keep these directories private and check cleanup after interruptions. Never put credentials in documentation, logs, URLs or a shell command line.

## DNS

Name.com uses username/token; Hostinger and GoDaddy use token. The customer DNS form saves the selected provider credential, publishes Brevo verification records and retains that secret for installation. It does not replace MX.

The generic `/v1/dns-connections` and `/:id/rotate` routes are separate from the form's live provider path. They use schema/version/idempotency checks and the configured legacy read adapter where required. Failed rotation keeps the old working reference. Credential creates/rotations have per-user rate limits.

## Brevo and installer administrator

The operator account form stores `brevo-api` and `brevo-smtp` secrets. Re-submitting an existing Brevo login email replaces those stored keys without changing the relay's assignment state. There is no generic relay-rotation route.

Provision generates an administrator credential once under purpose `installer-admin`; it is not returned to the portal. The installer receives it through `admin.json`. The locally fixed Bearmail wrapper aligns it through `x:Account` and supports noninteractive retries with the saved credential. The default downloader does not automatically use local source edits; verify the published version separately.

A temporary Stalwart recovery override was used during the development install to recover from an earlier wrapper failure and was removed afterward. It is not an implemented BearPortal credential-rotation workflow.

## Mailbox passwords

`POST /v1/mailboxes/:id/credential` requires recent authentication and stores a short-lived `mailbox-credential` secret. The queued `set_mailbox_credential` command has empty parameters. Host delivery remains unimplemented, so the response does not prove the engine password changed and login remains disabled in the portal.

Those secrets expire after 15 minutes; the scheduler-authorized expiration route retires them. Job/lease expiry can mean an unknown outcome rather than successful delivery. Request a new password rather than inventing one.

`rotate_admin_credential` remains an allowlisted command name with no current route that delivers an admin rotation. Authorization, idempotency and recorded intent are separate from host execution.
