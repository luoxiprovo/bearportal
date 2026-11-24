# Subscription cancellation and resubscription handoff

BearPortal should retain the customer account when a subscription is canceled, show both allocated resources as **Canceled by users**, and let authorized operators remove them from inventory after service cleanup and retention. Returning customers should be able to subscribe again and start setup with fresh resources. Previous subscription, assignment, and mailbox records should remain available.

## Work in this branch

- Billing cancellation flags the existing resource assignments for operator cleanup and closes pending setup and allocation requests. The inventory status is derived from the cancellation flag and live assignments. This keeps the resources out of the allocation pool while cleanup is pending.
- Operators can use the existing inventory removal forms for canceled assignments. BearPortal releases the assignments, retires the server entry, and archives the Brevo entry. Operators handle the external service cleanup.
- The operator's user details show historical server names and addresses and Brevo inventory names and logins. Migration 016 backfills the labels for existing assignments and adds billing history and mailbox archival.
- After operator cleanup and final Stripe cancellation, checkout can reopen for the same customer without issuing another free trial. The previous subscription is archived and its later webhooks are ignored. Old deployment and mailbox records are retained, and archived mailboxes no longer block reuse of the same address.
- The billing regression test exercises both inventory removal forms, the user history, a second checkout, a stale webhook, and reuse of a mailbox address.

## Verification and remaining work

- An initial focused billing test run and type check passed before the final mailbox regression assertion and small follow-up edits.
- A full suite attempt ended with 138 passing tests and 13 failures. A lost tool session may have left two runs using the same disposable database. The billing failure occurred before cancellation when the test organization could not be found. The run also reported a Caddy certificate-fixture failure and a portal copy assertion. The copy was corrected afterward.
- Rerun `pnpm typecheck` and the billing and portal copy tests with one process using a fresh disposable PostgreSQL database. Then run `pnpm test` with a fresh database and investigate any reproducible failures. Review a returning customer's setup through fresh server and Brevo allocation before release.
- No deployment or production database change was made. Apply migration 016 with the normal release procedure once the branch is ready.
