# Stripe subscriptions

For the current development setup and account-matched listener, follow [STRIPE_INTEGRATION_TODO.md](../../STRIPE_INTEGRATION_TODO.md). This runbook describes the broader billing lifecycle.

BearPortal requires a confirmed `trialing` or `active` subscription before offering or starting a new Bearmail installation. The plan is USD $20 per month plus applicable tax. The first calendar month is free, with a payment method required at Checkout. Cancel during that month to avoid the first charge. Cancellation is immediate, with no final invoice or proration requested. Existing installed resources are retained for manual operator cleanup.

## Test-mode setup

1. In Stripe test mode, create a BearPortal product with an active recurring price: **USD $20 every month, with tax behavior set to exclusive**. Use its `price_...` identifier. The server verifies the amount, currency, interval, quantity and subscription state rather than accepting plan information from the browser.
2. Add these private settings to `.data/trial/env` for `pnpm trial:start`, or to the service environment for a deployed API:

   ```dotenv
   STRIPE_SECRET_KEY=rk_test_...
   STRIPE_PRICE_ID=price_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   BEARPORTAL_BILLING_ORIGIN=http://localhost:8088
   BEARPORTAL_STRIPE_MODE=test
   STRIPE_PORTAL_CONFIGURATION_ID=bpc_...
   BEARPORTAL_STRIPE_TAX_ENABLED=0
   ```

   Use the actual browser origin, with no trailing slash. Deployed origins must use HTTPS. Never commit populated environment files. Hosted Checkout does not need a browser publishable key; BearPortal never receives card details.
3. Configure a Stripe webhook endpoint at `https://YOUR_PORTAL/webhooks/stripe`. Subscribe to `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`, `invoice.payment_failed`, `invoice.finalization_failed` and `invoice.payment_action_required`. Use the endpoint's signing secret above. For local testing, the Stripe CLI can forward events:

   ```sh
   pnpm stripe:listen
   ```

   The helper reads the same test runtime key as BearPortal and writes its matching signing secret into `.data/trial/env`. Restart BearPortal after the helper saves the secret. The handler verifies original request bytes and rejects invalid signatures and test/live mismatches. Configure event payloads compatible with the installed Stripe SDK's API version (`2026-10-28.endive`).
4. Enable Stripe's customer billing portal in test mode for payment-method and invoice management. Disable plan switching and promotions to retain the fixed $20 plan. If enabling portal cancellation, configure immediate cancellation; BearPortal also provides its own immediate cancellation form.
5. Run `pnpm trial:migrate`, then restart with `pnpm trial:start`. If Stripe is absent, new installations stay locked and the customer sees that subscriptions need configuration.
6. Register a fresh verified test customer. Confirm that installation is unavailable before checkout. Complete hosted Checkout with Stripe's test card `4242 4242 4242 4242`, a future expiration date and a test CVC. Confirm $0 due now, a one-month trial, then USD $20 monthly. Returning from Checkout retrieves the subscription from Stripe; the browser cannot grant its own access.
7. Cancel from the customer account. Confirm Stripe reports `canceled`, installation is blocked, and the operator sees the manual cleanup notice. No remote resource is deleted. Test trial-to-paid and failed renewal with Stripe test clocks in a separate Stripe test scenario; local automated tests inject Stripe responses and do not create Stripe accounts or charge cards.

Restricted `rk_test_`/`rk_live_` keys are supported alongside full secret keys. Prefer a restricted runtime key. Only test keys are accepted unless `BEARPORTAL_STRIPE_MODE=live` is explicitly set. Switching to live mode requires live credentials, a live price and a live webhook secret. No live Stripe objects are created by this implementation task.

## Restricted keys and Stripe Tax

CLI OAuth is for development commands and does not replace the application's permanent runtime key. Give the runtime restricted key only the access it needs: Customers write, Prices read, Checkout Sessions write/read, Subscriptions write/read, Customer Portal sessions write and configurations read, Invoices read (for expanded latest-invoice reconciliation), and Tax Settings/Registrations read if automatic tax is enabled. Confirm the permission labels in the Stripe Dashboard and validate with a test Checkout. Keep development and production keys separate. For the Google Cloud service, use Secret Manager and load credentials only into the service process; never commit a populated environment file or paste keys in chat.

The current test account and provisioned catalog are documented in [the integration plan](stripe-integration-plan.md). Automatic tax remains disabled because the test account is missing a head-office address and active registrations. Confirm the merchant's existing sales-tax registrations before recording any in Stripe; recording a Stripe registration does not register a business with a tax authority.

The Tax flag affects new Checkout Sessions; it does not retrofit automatic tax onto existing subscriptions. Review existing subscriptions separately before a tax migration.

After head-office details and at least one active registration are verified in the selected account, set `BEARPORTAL_STRIPE_TAX_ENABLED=1`. The application checks these prerequisites before creating a checkout and returns `TAX_NOT_READY` if either is absent. It collects the customer's business name, billing address and tax ID, saves address/name onto the existing customer, and uses the tax-exclusive price. Tax is collected only in jurisdictions with an active registration; zero tax elsewhere does not establish that no tax obligation exists.

Invoice finalization errors (including insufficient tax location) and payment-authentication requirements block new installation and direct the customer to billing management. The handler retrieves the current invoice from Stripe, so a delayed paid event cannot clear an unresolved invoice problem. A genuinely paid latest invoice clears the issue. The portal exposes invoice history and invoice documents through Stripe-hosted pages; the application does not create duplicate invoices.

## Operator cancellation workflow

The operator page shows **Subscription cancellations · manual cleanup required**, with the customer email, organization, assigned server and Brevo account. A durable `billing.manual_release` action is created once. Replayed webhooks and repeated cancellation requests do not create duplicate actions or release resources.

Manually stop the service and follow the existing isolation, retention and cleanup procedures. Release server and Brevo assignments only after those checks. Select **Mark cleanup complete** afterward; BearPortal refuses this acknowledgement while either assignment remains active. The acknowledgement resolves the operator task; it does not contact cloud providers or Brevo.

Cancellation can race with an installation already in progress. An installation authorized before cancellation may already be running; cancellation blocks subsequent installation requests and opens manual cleanup. Do not assume cancellation proves that the mail server has stopped.

## Recovery and duplicates

Checkout has a durable per-organization intent, stable Stripe idempotency keys and a row lock. Repeated clicks reuse the open Checkout session; completed subscriptions cannot start another trial. Each account receives at most one completed trial. Creating another application user with the same normalized email is rejected, and an existing account is never merged into a different identity based only on its email.

Webhook event IDs are deduplicated transactionally. The handler retrieves the current subscription under a database lock, so delayed events do not reinstate old state. A cancellation request remains terminal for installation even if a later snapshot appears active. Payment failure blocks new installation; a verified paid renewal restores eligibility. If event delivery stops, access expires at the last confirmed trial or billing period end. Retry failed webhook deliveries from Stripe after fixing configuration or connectivity.

The local reset command refuses to remove active subscription records; cancel them in Stripe first. Resetting local records never cancels subscriptions remotely. Back up billing data with the rest of PostgreSQL.

Reference: [Stripe Checkout free trials](https://docs.stripe.com/payments/checkout/free-trials), [webhook delivery and signatures](https://docs.stripe.com/events/manage-webhook-endpoints), [subscription cancellation](https://docs.stripe.com/api/subscriptions/cancel).
