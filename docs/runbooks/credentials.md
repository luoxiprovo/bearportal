# Credentials and rotation

[SecretStore](../../packages/secrets/src/store.ts) encrypts stored values with AES-256-GCM and writes mode-0600 files. PostgreSQL stores file references and key metadata. Preserve the encryption key independently of database backups; restoring rows without their files/key does not restore credential access.

The live installer temporarily decrypts only the referenced DNS, SMTP and admin credentials into private local/remote staging files. Inputs and commands use paths, not credential values. Keep these directories private and check cleanup after interruptions. Never put credentials in documentation, logs, URLs or a shell command line.

## DNS

Name.com uses username/token; Hostinger and GoDaddy use token. The customer DNS form saves the selected provider credential, publishes Brevo verification records and retains that secret for installation. It does not replace MX.

The generic `/v1/dns-connections` and `/:id/rotate` routes are separate from the form's live provider path. They use schema/version/idempotency checks and the configured legacy read adapter where required. Failed rotation keeps the old working reference. Credential creates/rotations have per-user rate limits.

## Brevo and installer administrator

The inventory page stores `brevo-api` and `brevo-smtp` secrets, rejects duplicate account emails and supports versioned credential replacement only on free accounts. The older `/operator/brevo-account` compatibility endpoint retains email-based upsert behavior. There is no general rotation workflow that applies new credentials to an assigned, running mail server.

Provision generates an administrator credential once under purpose `installer-admin`. After installation, the owning verified BearPortal account can choose **Show administrator login** in `/portal`. The audited POST reveal endpoint checks deployment ownership, active organization and secret scope, installed status, CSRF for cookie sessions and a per-user rate limit. It returns the generated username/password with no-store headers; the password is absent from initial page HTML, ordinary overview responses, logs, audit payloads and browser storage. Other users and operators cannot reveal another organization’s credential through this endpoint. The installer receives it through `admin.json`. The locally fixed Bearmail wrapper aligns it through `x:Account` and supports noninteractive retries with the saved credential. The default downloader does not automatically use local source edits; verify the published version separately.

A temporary Stalwart recovery override was used during the development install to recover from an earlier wrapper failure and was removed afterward. It is not an implemented BearPortal credential-rotation workflow.

## Mailbox passwords

`POST /v1/mailboxes/:id/credential` requires recent authentication and stores a short-lived `mailbox-credential` secret. The queued `set_mailbox_credential` command has empty parameters. Host delivery remains unimplemented, so the response does not prove the engine password changed and login remains disabled in the portal.

Those secrets expire after 15 minutes; the scheduler-authorized expiration route retires them. Job/lease expiry can mean an unknown outcome rather than successful delivery. Request a new password rather than inventing one.

`rotate_admin_credential` remains an allowlisted command name with no current route that delivers an admin rotation. Authorization, idempotency and recorded intent are separate from host execution.

## Using the installed service

Open `https://mail.<domain>` for the administrator console. Reveal the generated login in BearPortal, then use that login to create and enable regular mailbox accounts and set their passwords. Open `https://bearmail.<domain>` for normal webmail; users sign in with their full mailbox address and mailbox password. BearPortal registration does not itself create an engine mailbox. Password changes made directly in the mail administrator console are not synchronized back to the initially generated BearPortal secret.

The background worker checks HTTPS on both hostnames against the currently assigned server, including certificate validation. When both are ready, it clears the installer’s TLS-pending status. This does not mark mail delivery verified or reinstall Bearmail.
