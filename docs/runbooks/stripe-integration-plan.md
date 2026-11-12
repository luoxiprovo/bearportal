# bearos.si Stripe integration plan

The official Stripe integration planner was called through the authenticated Stripe CLI (`stripe tools plan`) on November 12, 2026. The native MCP planner tool was not exposed in this agent session; this is an actual CLI planner result, not a claim that an MCP call succeeded. The returned guide `iguide_61VkD1hXbWCZYt4h241FFMqczmhxF` was accepted after selecting the paths matching the business requirements.

## Business and pricing

bearos.si sells business email and calendar for a team's human users and AI agents. The merchant and main customer market are in the United States. Preserve the agreed **USD $20 per organization per month, plus applicable tax**, with a free first calendar month and a payment method collected during checkout. Canceling during that month avoids the first subscription charge. No seat charges or AI usage charges have been introduced.

## Planner recommendations and application decisions

| Area | Planner recommendation | BearPortal implementation |
| --- | --- | --- |
| Payment surface | Stripe-hosted subscription Checkout | Keep hosted Checkout and server-side price selection. Collect business name, billing address and tax ID, with dynamic payment methods. |
| Billing | Flat-rate monthly subscription and free trial with payment method | Use the existing calendar-month trial, one completed trial per account, and flexible billing mode. |
| Invoices | Use Stripe Billing/Invoicing and customer self-service | Billing generates subscription invoices. The configured customer portal exposes invoice history and payment-method updates. Do not generate duplicate standalone invoices or a renewal scheduler. |
| Lifecycle | Customer Portal, automatic payment recovery and webhook reconciliation | Preserve signed/deduplicated webhooks, verified installation eligibility, and default Stripe payment recovery. Tax finalization and customer-authentication failures also block new installation until resolved. |
| Cancellation | The planner generally recommends period-end cancellation | Preserve the merchant's explicit immediate-cancellation requirement with no proration/final invoice, and a durable operator task to manually release resources. |
| Tax | Stripe Tax with confirmed tax settings and registrations | Tax-exclusive price is configured. Automatic tax is explicitly gated; the selected test account has no head-office address and no active registrations yet. No tax registration has been created. |

Some returned blueprints use preview trial-offer APIs and Accounts v2 customer accounts. Those are alternatives rather than a requirement to migrate a working Customers v1 integration. Keep the existing supported customer/Checkout integration and calendar-month trial rather than introducing an unrelated account migration or preview-only trial API.

## Test-account configuration completed

The currently authorized account is the **Business Email and Calendar for Human and Agent** test account. Test-only objects were provisioned idempotently:

- Product: `bearos_business_email_calendar` — bearos.si Business Email and Calendar.
- Price: `price_1Uap6OFFMqczmhxF0UHaVXef` — USD 2000 cents monthly, `tax_behavior=exclusive`.
- Portal configuration: `bpc_1Uap6OFFMqczmhxFOdQ6C6ne` — invoice history, payment-method updates, customer billing details, and immediate cancellation; plan switching is disabled.
- Product tax code: `txcd_10103001` — business-use SaaS, selected from Stripe's tax-code search against the supplied product description. Confirm the classification before live deployment.
- Tax settings: `pending`, missing `head_office`; active tax registrations: none. Automatic tax has not been activated.

Non-secret setup identifiers are also saved in the gitignored `.data/trial/stripe-test-setup.json` file. No live products, charges, invoices or tax registrations were created.

## Validation completed

Stripe accepted a real test-mode hosted subscription Checkout Session with the configured tax-exclusive price, business name, billing address, tax-ID collection, flexible billing mode and a free trial. The session was immediately expired after API validation; no subscription payment was completed and no charge was taken. Application tests cover tax prerequisites, invoice failure handling, cancellation and duplicate account checks. End-to-end paid renewal testing still requires the runtime key and webhook configuration.

## Runtime configuration still needed

CLI OAuth authorization allows development commands, but does not provide a permanent application API key. Provision a restricted **test** runtime key with the permissions listed in [the billing runbook](billing.md). On the Google Cloud deployment, store it and the webhook signing secret in Secret Manager and grant access only to the application service identity. Never put them in source, client-side code, logs or chat.

Select the actual application origin and configure the webhook endpoint (or a local Stripe CLI forwarder). Apply migration `012_stripe_business_billing.sql` before restarting. Keep `BEARPORTAL_STRIPE_TAX_ENABLED=0` until the account's head-office address and active registrations are confirmed. When enabled, the application verifies these prerequisites and refuses checkout if they are absent.

## Remaining Tax and launch decisions

The merchant has confirmed US-based business, mainly US customers, and tax added on top of the $20 monthly amount. Still needed: the business's full head-office address and the states where it is already registered to collect sales tax. Determine registration obligations with an appropriate tax adviser; no registration obligation has been inferred from the supplied business country or domain.

Before live launch, verify invoice issuer details/branding, trial reminder and failed-payment communications, the first paid invoice, cancellation, webhook retries, and tax-inclusive/exclusive expectations. Create live registrations separately after the merchant confirms the jurisdictions; test-account registrations do not establish legal registrations.

## References

- [Stripe subscription Checkout](https://docs.stripe.com/billing/subscriptions/build-subscriptions?payment-ui=checkout&ui=stripe-hosted)
- [Stripe tax on subscriptions](https://docs.stripe.com/tax/subscriptions)
- [Stripe customer portal](https://docs.stripe.com/customer-management/integrate-customer-portal)
- [Stripe restricted keys](https://docs.stripe.com/keys/restricted-api-keys)
