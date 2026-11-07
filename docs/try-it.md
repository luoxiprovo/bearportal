# Run the development control plane

Run commands from the repository root. Development startup uses the same live SSH and installer wiring as `apps/api/src/main.ts`. Saving a real server or submitting real provider credentials can contact those systems.

## Prerequisites

- Node.js 22, pnpm 10.15.0 and local PostgreSQL.
- Database `bearportal`, owned by a migration role, plus a restricted application role. The development helper defaults to local roles `bearportal` and `bearportal_app`; configure matching passwords/URLs before startup.
- A private local `.data/trial/env`; it contains encryption and development identity keys. Keep existing keys when retaining encrypted secrets.

```sh
pnpm install --frozen-lockfile
pnpm trial:prepare
pnpm trial:migrate
pnpm trial:bootstrap
pnpm trial:start
```

`trial:prepare` creates the local environment and signing keys without overwriting an existing environment. Inspect the generated connection settings privately before migration. `trial:migrate` applies schema changes; bootstrap creates the privileged administrator or accepts the same existing bootstrap identity. The API normally listens on `http://127.0.0.1:8088`.

There is deliberately no reset in this startup sequence. `pnpm trial:reset` truncates operational tables, including users, saved servers, credential references, deployments and audit history, in the configured trial database. It is not a prerequisite for tests or ordinary startup. It does not restore those records from surviving encrypted files.

## Pages and identity

Open `/register` for customer registration, `/login` for returning users, `/portal` for the customer account and `/operator` for inventory and user allocations. With Identity Platform configured, customers can use Google or verified email/password accounts. Without it, the email-only form is a development preview that locally signs identities without email confirmation. Production rejects test identity signing.

The current deployment has Identity Platform configured and its email/password provider enabled. Use **http://localhost:8088** through the Mac tunnel for Google sign-in; its Google origin/button check passed. The 127.0.0.1 browser variant still reported an OAuth origin restriction. See [runbooks/identity-platform.md](runbooks/identity-platform.md) for new-project setup and `pnpm auth:configure`.

For simple development operator access, run `pnpm trial:login` on the server and open the printed `http://localhost:8088/operator/login#…` link on your Mac through the SSH tunnel. The link works once, expires after five minutes, and signs in the existing bootstrap administrator. Each new link replaces the previous one. This route is disabled without development identity signing. Keep the link private.

For lower-level operator access, `pnpm --silent trial:token admin` mints a development token for the bootstrap identity. `POST /v1/session` accepts `{ "idToken": "..." }` and sets `bp_session`. Cookie mutations require `x-bearportal-csrf: 1` or form `csrf=1`. Bearer requests are also supported. Keep generated tokens out of shared logs and files.

On your Mac, keep an SSH port forward open (replace the SSH destination with your control-plane host):

```sh
ssh -N -L 8088:127.0.0.1:8088 YOUR_SSH_USER@YOUR_BEARPORTAL_SERVER
```

Then open `http://localhost:8088/register`, `/login` or the generated operator link in the Mac browser. Run the tunnel command on the Mac; run `pnpm trial:login` on the server. Operator sessions last two hours, matching the inventory MFA window. The one-use link itself expires after five minutes.

Portal sessions do not log a user into Bearmail. After installation, use **Show administrator login** in `/portal`, manage mailboxes at `mail.<domain>` and use mailbox addresses/passwords at `bearmail.<domain>`.

## Configure a real installation

1. Prepare a separate mail server using [runbooks/preparation.md](runbooks/preparation.md). Put the control-plane public key in the remote SSH account and ensure the API process can read its private key and known-hosts file.
2. Save the server using **Add server** at `/operator` (or the admin inventory API). A normal startup probes it over SSH and can allocate it to an existing waiting organization.
3. Store a Brevo account through the operator form, including separate API and SMTP credentials.
4. Submit the customer domain. Follow the detected DNS provider's credential form; it can publish Brevo verification TXT/CNAME records.
5. Authorize domain verification, Brevo authentication, mail routing, installation and the setup test once when submitting the provider credential, then choose **Connect & set up Bearmail**. The guided flow encrypts and saves the credential and retains that authorization across retries. It saves a request, authenticates the mail service, and creates/provisions the deployment automatically. Missing capacity is shown as a wait and retried after resources arrive; the browser can be closed.
6. Return to `/portal` for progress. Mailboxes and technical connection details are expandable. Installed/TLS-pending status still does not prove mail delivery.

The lower-level `POST /v1/deployments` and `/:id/provision` APIs remain available to authenticated callers, but are no longer required for browser onboarding. Apply all migrations, including `006_onboarding.sql`, `007_inventory_management.sql` and `008_identity_accounts.sql`, before starting the new UI. The queue is processed by the API itself; a separate worker service is not required.

New hostnames are `mail.<domain>` and `bearmail.<domain>`. Existing deployments keep their saved webmail hostname. Do not submit placeholder domains/credentials to a live flow expecting simulated success.

Normal startup still has unavailable generic domain-proof, relay-check and DNS-observer adapters. Guided setup uses the working account-form provider functions and its actual authentication result; it does not rely on the generic placeholder Brevo client. The working customer Brevo/DNS forms and SSH installer are separate integrations. Details are in [../SPEC.md](../SPEC.md).

The API process needs writable local work storage at `/var/lib/bearportal/work` by default. Remote staging is `/var/lib/bearportal/install/<operationId>` on an executable filesystem. See [runbooks/ssh-install.md](runbooks/ssh-install.md).

## Tests and the older trial walk

```sh
pnpm typecheck
pnpm test
```

With database URL variables unset, tests create and remove their own disposable database. Explicit connections must all target the same dedicated `bearportal_test_*` database; ordinary trial database URLs are refused. See [../tests/README.md](../tests/README.md). Tests no longer require resetting the trial application afterward.

`pnpm trial:walk` exercises the older signed enrollment/heartbeat API using documentation-only IP data and placeholder credentials. It is a compatibility exercise, not the supported live SSH onboarding guide or proof of an installation. Its historical transcript is intentionally omitted because normal startup now wires live adapters.

Stop the API with Ctrl-C. Logs and secret files are private operational data. Current validation and the limited live-install record are in [local-validation.md](local-validation.md).
