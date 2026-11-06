# Brevo account inventory and domain verification

The operator prepares Brevo accounts outside BearPortal and stores the account email, REST API key, SMTP login, SMTP key and daily allowance. The REST and SMTP keys are separate encrypted secrets. New rows are inactive; updating the same account email replaces keys while retaining its state. Responses do not expose the keys.

## Working customer form integration

A platform administrator uses `/operator/brevo-account`. The customer then submits a domain through `/portal/domain`. That path can exclusively claim the oldest free inactive account and call Brevo to create/read the domain. If no account is free, the domain can remain saved with a visible wait. Failed requests do not establish authentication or release the assignment.

The customer DNS credential form publishes the returned verification TXT/CNAME set, then calls the Brevo authenticate endpoint and reads the domain. Only actual returned booleans establish `authenticated` and `verified`. It stores the same DNS secret for installation and does not publish MX.

Name.com, Hostinger and GoDaddy credentials are offered when all detected nameservers match the supported provider. The code accepts GoDaddy as `{ token }` and its current HTTP adapters use Bearer authentication. This describes the implementation, not a promise that every credential/API flavor works.

## Guided setup

The guided domain form detects the provider before running external mail setup. Once the user submits credentials and consents, a persistent onboarding request waits for server and Brevo capacity. The in-process worker claims inventory, creates/reads the Brevo domain, publishes TXT/CNAME verification records, authenticates it and waits for both returned flags to be true before installation. The customer does not enter a Brevo account or API key.

The status page explains capacity shortages and resumes without another credential submission. Invalid provider/credential responses receive bounded retries and then a visible review state. The worker uses the actual authentication result for provisioning; the older generic interface below remains separate.

## Separate generic interfaces

The generic admin relay validator still uses an unavailable default checker; it does not establish a live SMTP login. Generic admin assignment uses available relays, while the customer domain form can claim inactive accounts.

Provisioning's `BrevoClient` remains a throwing placeholder in normal startup. It is separate from the working account-form HTTP calls. Consequently, provisioning can save false deployment Brevo flags even after the credential form authenticated the domain. Inspect which record/path produced a flag.

The source-install path can proceed with the saved SMTP login/key without a three-TXT Brevo set. A compatible saved legacy set is copied to `brevoDnsRecords`; otherwise it is omitted. Do not turn a CNAME DKIM record into TXT. The installer receives no REST API key.

## Limits

Exclusive relay-assignment indexes prevent sharing a live account. The row's daily allowance is operator-entered; it is not measured remaining quota. Per-mailbox sender verification and a durable all-interface sending limiter are not established by this control plane. There is no generic relay-rotation route; use the existing operator account form to update its stored keys.

Sources: [../../packages/providers/brevo/src/index.ts](../../packages/providers/brevo/src/index.ts), [../../apps/api/src/inventory.ts](../../apps/api/src/inventory.ts), [../../apps/api/src/installation.ts](../../apps/api/src/installation.ts).
