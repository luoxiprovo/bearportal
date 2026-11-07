# Validation status

Reviewed on 2026-11-07. Automated tests, browser checks and live external observations are reported separately.

## Automated checks

The latest full `pnpm test` run passed **86 tests**, and `pnpm typecheck` passed. The test launcher creates and removes a disposable `bearportal_test_*` database; explicit test URLs must all target the same dedicated database. The working database is rejected before migrations or fixture truncation. See [../tests/README.md](../tests/README.md).

Coverage includes:

- Contract/route consistency, tenant RLS, version checks, idempotency and safe database targets.
- Operator server/Brevo add/edit/remove/restore, CLI additions and listing, assignment protections, role restrictions, CSRF and credential redaction.
- User overview and live resource links, including users without organizations and support restrictions.
- Google and email/password identity flows with signed test tokens and injected provider adapters: verification/reset/refresh, project/signature/nonce checks, stable legacy account linking, operator exclusions and disabled accounts.
- Once-only domain authorization, encrypted credential retention, capacity waits across restart, stale SSH refresh, concurrent resource edits, recovery pause, provider retries and interrupted-install review.
- DNS propagation waits that do not exhaust the provider-error budget, safe preflight retries and administrator-secret availability before installation.
- Owner-only administrator credential reveal, pre-install and cross-tenant denial, no-store responses and absence of the password from ordinary HTML, overview responses and audit data.
- Automatic HTTPS completion without reinstalling or marking mail delivery verified, plus lifecycle/oversight policy and DNS/installer fixtures.

## Browser checks

Chromium checks at desktop and 390px mobile widths covered customer onboarding, capacity waits, operator resource dialogs, user allocations, search/filter behavior and installed-service access. No page-wide horizontal overflow or browser-script errors were found in those checks.

The generated administrator login was revealed and hidden through the live owner page; hiding it cleared the password field. Recorded screenshots masked the password.

Google/email-password signup, sign-in, verification/resend and callback handling were exercised with an explicitly mocked provider. These checks did not send real verification emails or create real identity accounts.

## Live Identity Platform activation

The running development server is configured for Google Cloud Identity Platform. The project/API key passed a public configuration read, and a non-account-creating password probe confirmed that email/password sign-in is enabled.

At **http://localhost:8088**, a fresh Chromium session loaded the real Google button without an origin error and opened Google's account sign-in prompt. The `http://127.0.0.1:8088` browser variant still reported an origin restriction; use localhost for Google sign-in in this deployment. A real person's Google authentication and actual verification-email delivery were not completed by these checks.

The server's Cloud token returned `ACCESS_TOKEN_SCOPE_INSUFFICIENT` for administrative provider changes. The owner configured those settings in Google Cloud Console. No OAuth client secret was saved in the application environment. Private configuration, dumps, encrypted secrets and browser artifacts remain outside Git.

See [runbooks/identity-platform.md](runbooks/identity-platform.md) for the required base localhost and port-specific OAuth origins.

## Live installation and access

The current guided backend flow assigned a prepared server and Brevo account to a customer, authenticated/verified the domain, and completed installer dry-run/apply over SSH as `bearadmin` using the saved domain authorization. The earlier local work-directory permission failure was fixed; startup now checks access before accepting setup requests.

Stalwart and Caddy were observed running. Both saved administrator/webmail HTTPS endpoints responded, and the generated administrator credential authenticated a JMAP session. The background HTTPS check changed the deployment from `tls_pending` to `succeeded`; onboarding is recorded as `installed`. The resolved installation-review action no longer asks the customer to resubmit credentials or consent.

The active database was preserved through the additive inventory/identity migrations and configuration updates. Reconstruction records in a separate recovery database were not imported.

The earlier [2026-11-05 installation record](release-evidence/2026-11-05-ssh-install.md) is historical evidence of a different controlled run with local installer overrides. Those fixes were subsequently published in Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. It is not proof that every later artifact revision or every provider has passed live validation.

## Remaining gaps

- External inbound/outbound mail delivery, calendar/MCP permissions and all-interface sending limits.
- General portal-to-engine mailbox synchronization and queued credential delivery.
- A real person's complete Google/password registration and verification-email/reset-email delivery in the configured project.
- Upstream Identity Platform MFA challenge handling and immediate upstream token-revocation checks on every API request.
- Every DNS provider and the generic production DNS/relay observer interfaces.
- A backup/restore drill, binary upgrade, observed cancellation execution and complete cleanup.
- An e2-micro capacity soak, production SLA evidence, live model execution or a general-purpose operation worker.

The API release checklist remains hardcoded incomplete, including `liveEvidence: false`. `mail_verified` remains database-locked false. Installed services, valid HTTPS and successful administrator authentication do not establish end-to-end mail delivery or production readiness.
