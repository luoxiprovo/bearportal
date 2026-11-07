# SSH installation

The production entry point wires `liveSshProbe` and `liveMailInstall`. BearPortal runs the noninteractive Python program **`bearmail-install`**, without `.sh`, on the server assigned to the organization. A host-agent enrollment is not required for an SSH-validated server.

## Access and staging

The control-plane defaults are:

| Item | Location/value |
|---|---|
| SSH account | `bearadmin` |
| Private key | `/var/lib/bearportal/ssh/id_ed25519` |
| Known hosts | `/var/lib/bearportal/ssh/known_hosts` |
| Local work | `/var/lib/bearportal/work/<operationId>` |
| Remote work | `/var/lib/bearportal/install/<operationId>` |

The runner's hooks can override local key, known-hosts and work-root paths in an explicitly configured invocation. The normal environment loader does not expose those hook overrides as environment variables.

The API identity needs private local storage and write access to the default work root. Startup creates/checks that directory and fails if access is unavailable. The remote account needs noninteractive sudo and a known SSH host key. SSH/SCP use port 22 and argument arrays. A changed host key blocks the session.

The remote operation directory is mode `0700` and owned by the SSH login for uploads. Credentials/input are `0600`; the installer is `0700`; staged release executables are `0755`. The remote filesystem must allow execution of both the script and engine artifact. Using `/run` caused a real `noexec` failure; it has been replaced with disk staging.

The guided browser flow submits a persistent onboarding request and runs this sequence in the API’s background queue after Brevo authentication. It retries capacity waits every 30 seconds and does not require the customer to call deployment APIs manually. The sequence below also describes the lower-level provision API. Apply all migrations before using the flow; migrations 006, 007 and 008 add onboarding, inventory archival and identity-account bindings.

## Provisioning sequence

The guided worker creates/provisions the deployment using the authorization already saved with the domain credential. These API calls describe its lower-level implementation; customers do not need to invoke them or approve each stage.

1. Create the deployment and submit `POST /v1/deployments/:id/provision` with version and idempotency key. This authorizes MX replacement.
2. Check the saved server/assignment, selected plan, stored DNS credential and relay. On the source path, the domain can still be pending and a compatible saved Brevo TXT set is optional.
3. Resolve a GitHub `main` SHA and download the script plus four release artifacts for that preparation. Build `SHA256SUMS`.
4. Decrypt the referenced DNS, SMTP and admin credentials locally and rewrite the JSON to absolute remote paths.
5. Upload, run `sudo -n -- <remoteDir>/bearmail-install --dry-run --input ... --result ...`, fetch the result and clean staging.
6. If the dry-run is valid, prepare/upload for apply, run the same program without `--dry-run`, fetch the result and attempt cleanup again.
7. Persist normalized installer status, previous MX and published records. The route also records a job and compatibility host command; the SSH execution already took place synchronously.

Both invocations run with stdin closed. Each preparation can download again; retries are not a fixed production artifact pin. The script name and files come from `luoxiprovo/bearmail`, not from a copied Bearmail checkout by default.

## Diagnose failures

Inspect the request's error code, stored installer runs, SSH permissions, exact staging path and `/var/lib/stalwart/bearmail-install.log`. The runner currently discards the script's detailed `errorMessage`, TLS/service-check objects and version details when normalizing its result. Capture a sanitized raw result in a controlled diagnostic invocation when needed; keep credentials private.

A thrown command or interrupted API process can leave remote temporary files. Inspect and clean only the affected operation directory. Local work is removed in the runner's `finally` block. Database rollback does not undo an installation or DNS changes already made.

The recent successful development run used local Bearmail script overrides for administrator API, retry credentials and multiple DKIM keys. The tested script fixes were subsequently published as Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. Ordinary startup downloads published main. See [../release-evidence/2026-11-05-ssh-install.md](../release-evidence/2026-11-05-ssh-install.md) for the exact tested source overrides; the publication is recorded with its commit hash.

Sources: [../../packages/servers/src/ssh-install.ts](../../packages/servers/src/ssh-install.ts), [../../packages/servers/src/mail-install.ts](../../packages/servers/src/mail-install.ts), [../../apps/api/src/installation.ts](../../apps/api/src/installation.ts).
