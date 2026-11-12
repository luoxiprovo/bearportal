# bearos.si Stripe integration review

Prepared November 12, 2026; updated after authorization. The official Stripe CLI planner has now returned an accepted integration guide. See [the finalized integration plan](stripe-integration-plan.md) for its recommendations, the distinction from the unavailable native MCP tool, and the test-account objects created. This document preserves the initial code review.

## Business context for the planner

- Business: **bearos.si**.
- Service: business email and calendar for the human users and AI agents of a team.
- Stripe products requested: **Billing, Invoicing, Tax**.
- Existing application: TypeScript/Fastify, PostgreSQL, hosted Stripe Checkout, customer billing portal, subscription webhooks, and Bearmail provisioning.
- Existing commercial terms: USD $20 per month per organization, first calendar month free, payment method required, immediate cancellation, and manual operator cleanup after cancellation.
- Environment: start in test mode, as already agreed. Do not switch to live billing automatically.
- Merchant country: **United States**. Customers are mainly in the United States. Confirmed pricing: **USD $20/month plus applicable tax** (`tax_behavior: exclusive`). The specific US business state and existing sales-tax registrations remain unconfirmed. Do not infer registrations from the business location or `.si` domain.
- Do not change to per-seat or usage-based pricing without confirming the commercial model. Human and agent seats can be represented later if the business chooses seat-based pricing.

## Initial installation status (before account authorization)

1. Installed the official Stripe CLI with `npm install -g @stripe/cli`; verified version 1.55.11.
2. Ran `stripe agent setup`; the Stripe plugin was installed for Codex. `stripe agent setup --status --json` confirms installation.
3. The active tool list still does not expose `stripe_implementation_planner`. The installed plugin points to `https://mcp.stripe.com`. A CLI browser authorization was initiated; this is separate from authenticating the plugin's MCP connection. The separate Stripe integration in this chat was discovered as not yet installed/connected and offered for installation or connection. The local CLI plugin alone has not exposed MCP tools in the active session.
4. No API keys were printed, supplied, or embedded in source. At that initial review stage no Stripe objects had been created. The subsequent test catalog, portal and validation session are recorded in the finalized plan; no live charge or tax registration was created.

## What the current integration already does well

- Uses subscription-mode hosted Checkout and Stripe Billing rather than a custom recurring payment loop.
- Keeps card details on Stripe-hosted pages and prices server-controlled.
- Validates the configured price as USD 2000 cents, monthly, quantity one, and non-metered.
- Requires a confirmed trialing or active subscription before new installation; the browser cannot grant entitlement.
- Uses durable checkout intent, Stripe idempotency keys, transaction locks, verified webhook signatures, event deduplication, and fresh subscription retrieval.
- Offers customer-portal management and immediate cancellation with a persistent, deduplicated operator resource-release task.
- Checks normalized email duplicates before account creation and preserves trial history per account.
- Includes mocked Stripe integration tests. At initial review, Stripe tests used injected responses. Real test Checkout Session creation has since been validated and expired; completed payment and renewal scenarios still need runtime credentials.

## Initial findings to reconcile with the planner

| Area | Current state | Proposed improvement |
| --- | --- | --- |
| API keys | Configuration only accepts `sk_test_` / `sk_live_` keys | Accept appropriately scoped restricted runtime keys (`rk_`) too, keep test/live validation, and document required permissions. Use OAuth or an agent API key for MCP, separately from the application's runtime key. |
| Secrets | Local private environment configuration | On the Google Cloud deployment, load runtime secrets from Secret Manager with access restricted to the service identity. Keep all keys out of source, browser bundles, logs, and chat. |
| Business catalog | Fixed monthly price; product configured outside code | Reuse or create a clearly named bearos.si business-email-and-calendar product and USD $20 monthly price in the selected test account. Set explicit tax behavior only after the user confirms tax-inclusive versus tax-exclusive pricing. |
| Checkout tracking | No `integration_identifier` | Add a stable integration label with an eight-letter random suffix, persisted with checkout intent so retries retain identical Stripe parameters. |
| Business customer details | Customer email collected; no dedicated tax details | Collect billing address, business name and tax ID as appropriate; save address/name updates onto the existing Stripe Customer so renewal invoices have the required details. |
| Invoicing | Stripe subscription invoices, accessible through the billing portal | Configure issuer identity, business details, invoice numbering/branding and receipt delivery in Stripe; verify invoice PDF and hosted invoice access through the customer portal. Do not enable Checkout's one-time `invoice_creation` option for subscription billing or generate duplicate invoices. |
| Stripe Tax | `automatic_tax` is not enabled | Read Tax Settings and active registrations in the selected environment. Confirm merchant and customer jurisdictions and the product tax code. Only then enable automatic tax and test inclusive/exclusive totals, zero-tax and tax-ID scenarios. Do not create tax registrations without the user's confirmed jurisdictional details. |
| Invoice failures | Paid and payment-failed events handled | Add `invoice.finalization_failed` and the customer-action-needed flows so invalid tax location or required authentication does not leave a silent failure. Preserve the existing installation gate and communicate the reason. |
| Trial communications | Trial end date displayed in the account | Configure appropriate Stripe trial reminders and invoice/payment-failure communications; consider handling `customer.subscription.trial_will_end` if application notifications are needed. |
| Real test coverage | Mocked Stripe tests pass | Complete a hosted test Checkout, inspect the $0 initial invoice and first paid invoice, use test clocks for trial expiry/renewal/failure, verify cancellation and webhook retries, and confirm the cleanup notice. No live charges during setup. |

## Questions that affect the final plan

- Which US state is the merchant based in, and will any non-US customer countries be supported?
- Which VAT/GST/sales-tax registrations already exist, and are they active in the selected Stripe environment?
- Tax-exclusive pricing is confirmed: $20/month plus applicable tax.
- Is the current organization-level price staying in place, or will human/AI-agent seats affect pricing later?

## Sources

- [Stripe subscription integration design](https://docs.stripe.com/billing/subscriptions/design-an-integration)
- [Tax for recurring payments](https://docs.stripe.com/tax/subscriptions)
- [Checkout Session creation](https://docs.stripe.com/api/checkout/sessions/create)
- [Stripe Invoicing integration](https://docs.stripe.com/invoicing/integration)
- [Stripe MCP setup and planner tool](https://docs.stripe.com/mcp)

Stripe documentation was inspected with the installed `stripe docs` CLI. The installed best-practices skill was also consulted; its listed SDK version is older than the repository's installed Stripe SDK, so preserve the repository's current supported SDK/API pair rather than downgrading it.
