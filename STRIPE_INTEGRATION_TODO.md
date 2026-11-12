# Finish the Stripe test setup

Use this guide for your **existing BearPortal development server**. The embedded Checkout code, test product, $20/month test price and billing portal are already prepared. You do not need to create them again.

Everything below uses **test mode**. No real money is collected. The first calendar month remains free; a payment method is required. **Automatic tax is currently off**, as configured in Checkout Studio.

## Current Server Checks

The account mismatch has been repaired using the server's existing test runtime key. Private/public API keys were not replaced. The matching test catalog is now in `acct_1UaonvJx2CYKdb9U`:

- Price: `price_1UaqG9Jx2CYKdb9UeitXklKd` — USD $20 monthly, tax-exclusive.
- Portal: `bpc_1UaqG9Jx2CYKdb9UpSDbehEk` — invoice history, payment updates and immediate cancellation.
- These two identifiers have been saved in `.data/trial/env`. A private backup was made before that configuration update.

The CLI's default OAuth account may still be the old sandbox. Use `pnpm stripe:listen` below: it reads the same test key as BearPortal, obtains the matching webhook signing secret, saves it privately, and forwards events from the correct account. It does not print private keys or signing secrets.

## Setup and Next Steps

### 1. Check the application keys

Your server's test key is already accepted by Stripe. Keep it and its matching `pk_test_...` publishable key from the same account. If you are configuring another server, open [Stripe API keys](https://dashboard.stripe.com/apikeys) in that same test account and obtain both keys. CLI login alone does not configure application keys.

For a new private key, select **Create secret key** and custom permissions (sometimes called **Create restricted key**). Allow Customers, Checkout Sessions, Subscriptions and Customer Portal write access, plus Prices and Invoices read access. Other unrelated permissions can remain disabled. Write includes read access. The current Checkout call does not need Tax API permissions because automatic tax is off.

### 2. Check `.data/trial/env` in terminal 2

```sh
cd /home/luoxi23vr/bearportal
nano .data/trial/env
```

Keep all existing database, authentication and encryption settings. Do not replace the whole file with `.env.example`. Edit existing Stripe entries rather than adding duplicates.

The relevant settings are:

```dotenv
STRIPE_PUBLISHABLE_KEY=REPLACE_WITH_YOUR_REAL_PK_TEST_KEY_IF_NOT_ALREADY_SET
STRIPE_SECRET_KEY=REPLACE_WITH_YOUR_REAL_PRIVATE_TEST_KEY_IF_NOT_ALREADY_SET
STRIPE_PRICE_ID=price_1UaqG9Jx2CYKdb9UeitXklKd
STRIPE_PORTAL_CONFIGURATION_ID=bpc_1UaqG9Jx2CYKdb9UpSDbehEk
BEARPORTAL_BILLING_ORIGIN=http://localhost:8088
BEARPORTAL_STRIPE_MODE=test
```

Do not replace already-correct keys with the `REPLACE_...` examples. The listener in step 3 writes `STRIPE_WEBHOOK_SECRET` for you; leave the value it writes unchanged.

- Use one unquoted `NAME=value` per line. No `export` and no comments after values.
- The private key must start with `rk_test_` or `sk_test_`, the public key with `pk_test_`, and the Price ID with `price_`.
- The browser origin has no path or trailing slash. Keep `http://localhost:8088` for the existing SSH-tunnel setup.
- Keep private values out of chat and GitHub. `.data/` is gitignored; the root `.env` is not automatically loaded by `trial:start`.
- Values in `.data/trial/env` override the same names exported in the shell.

In nano, save with **Ctrl+O**, **Enter**, then **Ctrl+X**. Protect the file:

```sh
chmod 600 .data/trial/env
```

### 3. Start the account-matched listener in terminal 1

Stop any old manual `stripe listen` process with **Ctrl+C** in its terminal. Then run:

```sh
cd /home/luoxi23vr/bearportal
pnpm stripe:listen
```

This helper requires the Stripe CLI to be installed. It obtains the signing secret using the test key in your file, saves `STRIPE_WEBHOOK_SECRET` with `600` permissions, and runs the equivalent of `stripe listen --all-snapshot --forward-to http://127.0.0.1:8088/webhooks/stripe` using that same key. It uses the configured `PORT` if different from 8088.

**Leave terminal 1 running.** Wait for the message that the signing secret was saved and the listener is ready, then start/restart BearPortal in terminal 2. The API must load the newly saved secret. Temporary connection failures before the API starts are expected.

The raw command `stripe listen --all-snapshot --forward-to ...` is valid, but without the account-matched helper it may use your CLI's different default account. Do not use thin events: this handler expects snapshot event payloads.

### 4. Apply migrations and start BearPortal in terminal 2

If you just pulled updated code, install the dependencies first:

```sh
pnpm install --frozen-lockfile
```

Then run:

```sh
pnpm trial:migrate
pnpm trial:start
```

Keep **both terminals running**: terminal 1 forwards Stripe events; terminal 2 runs BearPortal. Restart BearPortal after changing its configuration file. If you restart the listener or change its account/key, let the helper update `STRIPE_WEBHOOK_SECRET`, then restart BearPortal too.

These steps assume this server already has BearPortal's database, authentication and installation prerequisites configured. A brand-new server needs the [initial setup](docs/try-it.md) first. Do not use `trial:reset` to apply updates; it clears local test data and refuses to clear active subscription records.

### 5. Complete one test subscription

Open BearPortal at **http://localhost:8088** using your usual SSH tunnel. If your actual application uses a different browser origin, its billing and authentication origins must match that deployment.

Use a verified customer account that has not already completed a subscription. Use an email address you control so you can complete email verification. Do not use the operator account for this customer test.

1. Select **Subscribe · first month free**.
2. Confirm the Stripe payment form appears inside the BearPortal page. The browser should not navigate to a hosted payment page or display raw JSON.
3. Enter Stripe's success test card:

   | Field | Value |
   | --- | --- |
   | Card number | `4242 4242 4242 4242` |
   | Expiration | Any future date |
   | CVC | Any three digits |
   | Billing details | The test details requested by the form |

4. Submit the form. After the server confirms the subscription, BearPortal returns to the setup section. Select **Add your domain**, enter the domain, and select **Find my provider**. Continue with the normal DNS-provider credential/consent and Bearmail installation steps. An installation still needs domain/provider authorization and available resources; subscribing does not by itself prove Bearmail is installed.
5. In the Stripe test Dashboard, check the subscription: it should be **Trialing**, with the trial ending in about one calendar month, followed by the configured $20 monthly price. No paid subscription charge should be collected at signup. Tax is not collected by the current Checkout configuration.
6. In terminal 1, confirm relevant events are forwarded to `/webhooks/stripe` and receive a successful HTTP response.

Do not use real card details. This first test confirms checkout and trial setup; it does **not** test a paid renewal. Use Stripe test clocks or a separate controlled test scenario to test trial expiry and renewal without waiting a month or changing the real trial policy.

### 6. Test cancellation

In the customer account, open **Cancel subscription**, tick the confirmation and submit it. Confirm:

- The Stripe test subscription becomes canceled.
- BearPortal blocks new installation for that subscription.
- The operator page shows **Subscription cancellations · manual cleanup required**.

The operator must manually stop/release allocated resources through the existing cleanup workflow. Subscription cancellation does not delete a VM, Brevo account or tenant data. Mark the cleanup task complete only after both server and Brevo assignments are released.

To repeat a brand-new checkout test, use another verified test customer. The current application does not create another subscription or free trial for an account with a completed/canceled subscription history. A payment-decline retry before a subscription is completed is a different case.

### Troubleshooting

| What you see | What to check |
| --- | --- |
| “must specify events to forward” | Use `pnpm stripe:listen` in step 3; it includes the required snapshot flag and selects the server key’s account. |
| `Invalid Stripe configuration` / missing configuration variables | Check all four server settings (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_ID`, `BEARPORTAL_BILLING_ORIGIN`), real key/ID prefixes, unquoted values and the no-trailing-slash origin rule. |
| “Checkout is not configured yet” | Check `STRIPE_PUBLISHABLE_KEY` and restart BearPortal. CLI login alone does not supply it. |
| “Stripe could not load” | Refresh the page; check whether a browser extension or network rule blocks `https://js.stripe.com/dahlia/stripe.js`. |
| `No such price` / `resource_missing` for a price or portal | The runtime key and resource ID may belong to different accounts or sandboxes. Resolve the account alignment under **Current Server Checks**; do not replace a Price ID with a Product ID. |
| Stripe authentication or permission error | Check that the runtime key is from the same test account and has the relevant permissions in step 1. |
| “The subscription plan is not configured correctly” | Check that the Price ID is active, from the same account, USD 2000 cents, monthly with interval count 1, licensed/non-metered, and tax-exclusive. |
| `INVALID_SIGNATURE` / HTTP 400 on webhook delivery | Run `pnpm stripe:listen`, wait for its private configuration update, then restart BearPortal. Do not substitute another Dashboard endpoint’s signing secret. |
| Connection refused in the listener | Start BearPortal, check its logs and confirm it listens on port 8088. |
| “relation ... does not exist” | Run `pnpm trial:migrate` against the same database the API uses, then restart. |
| `SUBSCRIPTION_EXISTS` | That account already has subscription history. Use a fresh verified test customer for another first-time checkout. |

For additional browser tests, Stripe documents `4000 0025 0000 3155` for authentication scenarios and `4000 0000 0000 0002` for a generic decline. The exact point an error appears can differ between payment and payment-method setup flows; these cards do not replace the successful trial test above.

### When moving to a public/live deployment

The local CLI listener is for development. For a deployed server, configure a Stripe Dashboard webhook destination at `https://YOUR_PORTAL/webhooks/stripe` and use **that endpoint's signing secret**. Subscribe to these snapshot events:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.paid`
- `invoice.payment_failed`
- `invoice.finalization_failed`
- `invoice.payment_action_required`

The installed Stripe SDK uses API version `2026-10-28.endive`; configure a compatible endpoint event version. Choose test or live mode deliberately: test and live credentials, prices, portal configurations and webhook secrets are not interchangeable. A live deployment also needs HTTPS, matching authentication origins and the live-mode opt-in `BEARPORTAL_STRIPE_MODE=live`. `trial:start` is the development launcher, not a production deployment procedure.

Automatic tax remains disabled in the code, regardless of the legacy `BEARPORTAL_STRIPE_TAX_ENABLED` variable. Enabling tax later requires an explicit Checkout parameter change plus confirmed Tax settings and active registrations in the selected environment. Do not assume that setting the old variable alone enables tax collection.

## Values to Replace

There are **no `sample_only` placeholders in the Checkout Session call**. The existing `mode: "subscription"` and `line_items: [{ price: config.priceId, quantity: 1 }]` are retained. Do not replace them with `payment` or `price_...`.

The `REPLACE_...` values in step 2 are documentation examples, not working credentials. Keep already-configured valid keys, or replace these examples with real keys before starting. [`.env.example`](.env.example) also contains empty settings that must be filled if you use it as a reference; do not overwrite your existing runtime file with it.

## Configured Parameters

The only Checkout Session creation call is in [apps/api/src/billing.ts](apps/api/src/billing.ts).

| Parameter | Current value |
| --- | --- |
| `mode` | `"subscription"` — existing real product type |
| `line_items` | `[{ price: config.priceId, quantity: 1 }]` — existing configured Price ID |
| `ui_mode` | `"form"` |
| `billing_address_collection` | `"auto"` |
| `phone_number_collection` | `{ "enabled": false }` |
| `automatic_tax` | `{ "enabled": false }` |
| `payment_method_collection` | `"always"` |
| `submit_type` | `"auto"` |
| `integration_identifier` | `"custom_embedded_web_0001"` |

By your follow-up instruction, the existing customer, account-reference/metadata, free-month trial and trial end behavior are preserved. Former hosted URLs, explicit Checkout expiration, tax-ID/name collection, customer-update fields and the explicit flexible-billing-mode setting were removed from this call. The free month is implemented through the existing subscription trial fields, not a free Price.

## Project Structure and Flow

No new application endpoint, middleware, webhook handler, framework or runtime dependency was added for the embedded-form conversion. This checklist was its only new repository file. The later account-mismatch repair added [scripts/stripe-listen.ts](scripts/stripe-listen.ts) and `pnpm stripe:listen` so the listener consistently uses the application account.

- [apps/api/src/billing.ts](apps/api/src/billing.ts): the existing authenticated `POST /portal/billing/checkout` creates or reuses a form session and returns `{ "client_secret": ... }` with `Cache-Control: no-store`. The code expires previously open hosted sessions when converting to the form and uses a separate idempotency-key namespace.
- [apps/api/src/portal.ts](apps/api/src/portal.ts): loads Stripe.js directly from `https://js.stripe.com/dahlia/stripe.js` in the HTML head, exposes only the publishable key, and provides `#checkout-form` beside the subscription button. Stripe.js is not bundled or self-hosted.
- [apps/api/src/customer-session-script.ts](apps/api/src/customer-session-script.ts): renews the managed session, fetches the client secret, initializes `initCheckoutFormSdk`, mounts `createForm({layout:"expanded"})`, and displays confirmation errors.

After successful confirmation, the browser returns through the existing authenticated `/portal/billing/return?session_id=...` handler. The server checks account ownership and Stripe subscription state. Existing signed webhooks, subscription eligibility and operator cleanup remain in use; the browser cannot grant its own installation access.

The configured appearance uses the `stripe` theme, automatic labels, spaced inputs, 4px radius and spacing, white background, primary `#0570de`, danger `#df1b41`, success `#00c853`, text `#30313d`, default font and 16px base size. SDK 23.1.0 / API `2026-10-28.endive` supports this form integration; no legacy preview header was needed.

Keep the real product/Price IDs and the existing webhook-driven fulfillment. Do not add a second order system or invoice renewal scheduler. For deployment prerequisites, script/frame/network access and tax prerequisites, use the relevant steps above. Older hosted-Checkout instructions are superseded by this file for the current UI and session parameters.

## Verification and Resources

This guide was checked against the repository, the installed CLI's `stripe listen --help`, Stripe's documentation, read-only Price/portal retrieval, and a private runtime-key account check. The mismatched catalog was repaired in the runtime key’s account. Billing errors now give an operator-directed message; the browser offers sign-in only for authentication failures. That confirms the documented settings and command syntax; it does **not** prove a real browser subscription was completed. Finish steps 5–6 to verify your own configured deployment.

Run `pnpm typecheck` and `pnpm test` when validating code changes. The integration tests use an isolated database and injected Stripe responses; they do not charge real cards or prove the server's runtime key/signing secret is correct.

- [Stripe API keys](https://dashboard.stripe.com/apikeys)
- [Restricted-key creation and permissions](https://docs.stripe.com/keys/restricted-api-keys)
- [Stripe testing and card numbers](https://docs.stripe.com/testing)
- [Stripe CLI webhook forwarding](https://docs.stripe.com/stripe-cli/use-cli)
- [Stripe Support](https://support.stripe.com)
- [Stripe MCP](https://docs.stripe.com/mcp)
