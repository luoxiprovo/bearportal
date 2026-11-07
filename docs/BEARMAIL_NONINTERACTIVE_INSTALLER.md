# Bearmail noninteractive installer contract

Reviewed against BearPortal and the neighboring Bearmail source on 2026-11-05. `bearmail-install` already exists; this is its integration contract, not a request to build an interactive installer. Runtime input validation is in [../packages/contracts/src/index.ts](../packages/contracts/src/index.ts), transport in [../packages/servers/src/mail-install.ts](../packages/servers/src/mail-install.ts), and parsing in [../packages/servers/src/installer.ts](../packages/servers/src/installer.ts).

## Program and invocation

`bearmail-install` is an executable Python 3 script in the separate Bearmail repository. It wraps the existing `install.sh` and `mcp_install.sh`. BearPortal neither drives their prompts nor sends credential values through command arguments.

```text
sudo -n -- <remoteDir>/bearmail-install --dry-run --input <remoteDir>/input.json --result <remoteDir>/result.json
sudo -n -- <remoteDir>/bearmail-install --input <remoteDir>/input.json --result <remoteDir>/result.json
```

`remoteDir` is `/var/lib/bearportal/install/<operationId>`. The SSH login is `bearadmin`, and stdin is closed. The filesystem must permit execution of the installer and staged engine binary. `/run` may be `noexec` and is not the staging location.

The control plane resolves one GitHub `main` SHA for a preparation and downloads these files at that SHA:

- `bearmail-install`
- `install.sh`
- `stalwart`
- `bearmail-webui.tar.gz`
- `mcp_install.sh`

The four release artifacts are placed in `<remoteDir>/<sha>` with `SHA256SUMS` calculated by BearPortal. The source script and artifacts undergo basic type/size/content checks; checksums generated from those downloads are not an independent signature or trust root. The current engine validator requires x86-64 ELF.

## Inputs

BearPortal builds a strict schema-version-1 object with these fields:

| Field | Value or constraint |
|---|---|
| `schemaVersion` | `1` |
| `operationId`, `deploymentId` | UUIDs |
| `generation` | Positive integer |
| `mxCutoverAuthorized` | `true` in BearPortal's input schema |
| `domain` | Customer's primary domain |
| `mailHostname` | `mail.<domain>` for new deployments |
| `webmailHostname` | `bearmail.<domain>` for new deployments; existing saved hostname retained |
| `publicIpv4` | Assigned server's public unicast IPv4 |
| `publicIpv6` | Address or `null`; current portal input uses `null` |
| `dataPath` | Exactly `/var/lib/stalwart` |
| `dns` | `{ provider, zone, credentialFile }` |
| `brevoDnsRecords` | Optional; empty or three compatible TXT records |
| `relay` | `{ host, port, tls, login, credentialFile }` |
| `adminCredentialFile` | Separate administrator credential file |
| `mailboxQuotaBytes` | Positive integer |
| `release` | `{ id, artifactDir, checksumFile }` |

Supported DNS provider values are `namecom`, `hostinger`, `godaddy`. The relay is `smtp-relay.brevo.com`, port `587`, TLS mode `starttls-required`. Its login is the saved Brevo SMTP login, not the Brevo account email or API key.

The release ID on the normal source path is a 40-character Git commit SHA. `artifactDir` is `<remoteDir>/<sha>` and `checksumFile` is `<artifactDir>/SHA256SUMS`.

Before transport, credential fields contain `secret:<uuid>` references. `rewriteInstallerInput` replaces them with absolute paths on the mail server. The input JSON never embeds credential values.

The Bearmail script requires distinct mail/webmail hostnames within the primary domain and a DNS zone containing that domain. Literal `bearmail.example.*` and `webmail.example.*` demonstration hosts are refused for normal apply. Use actual customer domains, not example values.

### Credential files

| File | JSON shape |
|---|---|
| `dns.json`, Name.com | `{ "username": "<username>", "token": "<token>" }` |
| `dns.json`, Hostinger/GoDaddy | `{ "token": "<token>" }` |
| `relay.json` | `{ "smtpKey": "<SMTP key>" }` |
| `admin.json` | `{ "username": "<admin login>", "password": "<password>" }` |

Files are mode `0600`; the operation directory is mode `0700`. The script is mode `0700`; release executable files are `0755` and the archive/checksum file are `0644`. The remote staging directory is owned by the SSH login for file transfer; the installer runs under sudo. The result is returned to that login before SCP fetch.

The REST API key remains on the control plane. The local runner decrypts the referenced credentials just before staging. Temporary plaintext files are operational secrets and require cleanup after interrupted sessions.

## Dry-run and apply

Dry-run validates input, separate credentials and checksums, checks existing data compatibility, reads the DNS zone and returns a plan. It does not create the mail data directory or publish the plan.

After a valid dry-run, BearPortal invokes apply through the same provisioning service. The direct API does this within the request; the guided UI uses a persistent background onboarding request. There is no second customer DNS approval. Apply requires MX authorization, checks SMTP relay authentication, configures the mail stack, obtains the engine's DKIM information, publishes DNS, and checks services/TLS. It creates `/var/lib/stalwart` if missing and refuses unrelated existing mail data. It does not partition, format or resize storage.

The local Bearmail wrapper writes a private noninteractive answer file for `install.sh` and passes its path in `BEARMAIL_NONINTERACTIVE_FILE`. Values include domain, hostnames and relay settings. The latest local fix also supplies saved administrator credentials for retries. It removes the answer file after the child process, logs redacted output to `/var/lib/stalwart/bearmail-install.log`, installs MCP, aligns administrator credentials and applies quota through the engine management API.

Current local fixes use `x:Account/query` and `x:Account/set`, map-shaped password credentials, and the generated administrator identity from the reminder file. The reminder is removed after successful alignment. These source fixes were published in Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. Local edits still require publication before the default downloader receives them.

## DNS behavior

The customer credential form can already have published Brevo verification TXT/CNAME records. The installer publishes mail host A records, MX, SPF, engine DKIM and applicable supplied Brevo records. Its contract's `brevoDnsRecords` remains a legacy three-TXT representation; do not convert a returned CNAME into a TXT record just to fill it.

The plan preserves unrelated records and website apex/`www` addresses unless those names are explicitly managed hostnames. Existing MX is recorded before replacement. SPF merges must remain unambiguous; a conflict fails before apply. Valid existing DMARC policy is preserved according to the planner. Partial provider writes are reported as partial/failure rather than compensated by a portal MX rewrite.

Modern engine setup can emit both RSA and Ed25519 DKIM records. The current local wrapper selects RSA deterministically for its single-engine-key result contract. A missing usable key fails apply.

## Result and exit status

The script writes JSON containing `schemaVersion`, operation/generation, `status`, installed versions, service checks, DNS records and previous MX, TLS state, `errorCode`, `errorMessage`, and `retryable`. Results and logs must not contain credential values.

| Script status | Process exit | Meaning |
|---|---|---|
| `dry_run` | `0` | Plan returned; no apply |
| `succeeded` | `0` | Apply and checks completed |
| `tls_pending` | `10` | DNS accepted; certificate checks pending |
| `dns_partial` | `10` or `1` | Retryable or final partial DNS failure |
| `failed` | `1` | Apply failure |

The script can also exit `2` for CLI/input errors. BearPortal's runner normalizes unsupported combinations to a failed result. It derives retryability from the accepted exit/status combination, not just the script's boolean field.

`resultFrom` currently returns a reduced object containing status, exit code, retryability, error code and DNS data. It discards the script's detailed error message, service checks, TLS objects and installed-version details. The API stores that normalized evidence; retaining the raw sanitized result separately is useful during a controlled diagnostic run.

`parseInstallerResult` checks status/exit/retry consistency and DNS shape. `succeeded` and `tls_pending` count as `dnsWritesAccepted`; that flag is derived, not a separate installer attestation of propagation. `mail_verified` remains false.

Caddy can issue certificates after the result file was written. The portal does not automatically change an earlier `tls_pending` row when HTTPS starts working. Check both the saved result and current endpoint.

## Retry and cleanup limits

The Bearmail state file is `/var/lib/stalwart/bearmail-install-state.json`. It binds an operation to its installation identity and can return a completed result for a matching successful operation. A different identity under the same operation is a conflict. Partial/TLS-pending retries may still rerun installation work.

The portal can reuse an operation ID for a matching fingerprint and can short-circuit a recorded accepted install. This is not a general crash-safe background retry worker. Downloads and SSH execute synchronously; a database rollback cannot undo host or DNS side effects.

Normal completion attempts remote directory removal and always removes the local work directory. A thrown transport/spawn exception or interrupted process can leave remote material. Check the exact operation directory; preserve useful evidence and remove only that operation's temporary files.

See [runbooks/ssh-install.md](runbooks/ssh-install.md), [runbooks/installer-dns.md](runbooks/installer-dns.md), and [local-validation.md](local-validation.md).
