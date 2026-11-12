import assert from "node:assert/strict";
import { test } from "node:test";
import { renderCustomerPortal, setupProgress, type CustomerPortalView } from "../apps/api/src/portal.ts";

const base: CustomerPortalView = {
  organizationId: "org", deploymentId: null, lifecycleState: null,
  onboardingStage: null, healthState: null, serverId: null, serverState: null,
  publicIpv4: null, webmailHostname: null, mailHostname: null, backupState: null,
  backupFreshness: "missing", requiredActions: [], mailVerified: false, cloudVerified: false,
};

test("setup milestones reflect the saved stage and do not promise readiness before HTTPS", () => {
  const connected = { ...base, domainName: "example.com", dnsState: "stored" };
  const cases: [Partial<CustomerPortalView>, number, boolean][] = [
    [{ ...connected, onboardingState: "waiting_resources" }, 0, false],
    [{ ...connected, onboardingState: "queued", onboardingError: "DNS_PROPAGATION" }, 0, false],
    [{ ...connected, onboardingState: "installing" }, 1, false],
    [{ ...connected, onboardingState: "attention", onboardingError: "INSTALLER_FAILED", brevoAuthenticated: true, brevoVerified: true }, 1, false],
    [{ ...connected, onboardingState: "attention", onboardingError: "DNS_PROVIDER_CHANGED" }, 0, false],
    [{ ...connected, onboardingState: "installed", installerStatus: "tls_pending" }, 1, false],
    [{ ...connected, onboardingState: "installed", installerStatus: "succeeded" }, 1, true],
  ];
  for (const [state, current, complete] of cases) {
    const view = { ...base, ...state };
    assert.equal(setupProgress(view).current, current);
    assert.equal(setupProgress(view).complete, complete);
    const html = renderCustomerPortal(view);
    assert.equal((html.slice(html.indexOf('<ol class="milestones"')).split("</ol>")[0].match(/aria-current="step"/g) ?? []).length, complete ? 0 : 1);
    assert.ok(html.includes('aria-label="Setup progress"'));
  }
  assert.match(setupProgress({ ...connected, onboardingState: "waiting_resources" }).note, /No completion estimate/);
  assert.match(setupProgress({ ...connected, onboardingState: "attention" }).note, /paused for operator review/);
  const before = renderCustomerPortal(connected);
  assert.doesNotMatch(before, /role="progressbar"/);
  const executing = renderCustomerPortal({ ...connected, onboardingState: "installing" });
  assert.match(executing, /class="milestone-number working-spinner"/);
  assert.match(executing, /Step 2 of 2/);
  const failed = renderCustomerPortal({ ...connected, onboardingState: "attention", onboardingError: "DNS_ZONE_NOT_FOUND" });
  assert.match(failed, /could not find this domain/);
  assert.match(failed, /Error code: <code>DNS_ZONE_NOT_FOUND/);
  assert.doesNotMatch(failed, /class="milestone-number working-spinner"/);
  assert.doesNotMatch(failed, /Your account<\/strong>|Provider connection<\/strong>/);
  const pending = renderCustomerPortal({ ...connected, onboardingState: "installed", installerStatus: "tls_pending" });
  assert.match(pending, /location.reload/);
  assert.doesNotMatch(pending, /Your setup is complete/);
  const ready = renderCustomerPortal({ ...connected, onboardingState: "installed", installerStatus: "succeeded" });
  assert.match(ready, /Mail delivery and mailbox access still need verification/);
  assert.doesNotMatch(ready, /location.reload/);
});


test("Brevo verification animates during work and automatic waits while preserving the status text", () => {
  const connected = { ...base, domainName: "example.com", dnsState: "stored" };
  for (const state of [
    { onboardingState: "queued" },
    { onboardingState: "queued", onboardingError: "DNS_PROPAGATION" },
    { onboardingState: "queued", onboardingError: "BREVO_UNAVAILABLE" },
    { onboardingState: "waiting_resources" },
  ] as const) {
    const html = renderCustomerPortal({ ...connected, ...state });
    assert.match(html, /Step 1 of 2 · Verifying Brevo domain/);
    assert.match(html, /class="milestone-number working-spinner" aria-hidden="true"><\/span><div><strong>Verifying Brevo domain/);
    if (state.onboardingState === "queued" && !state.onboardingError) assert.match(html, /<small>Working<\/small>/);
    else assert.match(html, /class="waiting-status">Waiting/);
    assert.match(html, /class="setup-timing">The whole process, including domain records taking effect, may take about 7 minutes/);
  }
  const paused = renderCustomerPortal({ ...connected, onboardingState: "attention", onboardingError: "DNS_ZONE_NOT_FOUND" });
  assert.doesNotMatch(paused, /class="milestone-number working-spinner"/);
  assert.match(paused, /Paused · needs attention/);
});

test("customer journey shows the saved next action and keeps active billing below setup", () => {
  const billing = { status: "trialing", entitled: true, configured: true, trialAvailable: false, trialEndsAt: "2026-12-12T00:00:00Z", accessUntil: null, cleanupRequired: false };
  const subscribed = renderCustomerPortal({ ...base, billing });
  assert.match(subscribed, /id="next-step-title">Add your domain/);
  assert.ok(subscribed.indexOf('action="/portal/domain"') < subscribed.indexOf('id="billing-details"'));
  assert.doesNotMatch(subscribed, /<strong>Waiting for capacity<\/strong>/);
  const provider = renderCustomerPortal({ ...base, billing, domainName: "company.com", detectedProvider: "namecom" });
  assert.match(provider, /id="next-step-title">Connect your DNS provider/);
  assert.match(provider, /action="\/portal\/dns-credential"/);
  const unknownProvider = renderCustomerPortal({ ...base, billing, domainName: "company.com", detectedNameservers: ["ns.example.net"] });
  assert.match(unknownProvider, /id="next-step-title">Check your DNS provider/);
  assert.match(unknownProvider, /action="\/portal\/domain"/);
  assert.doesNotMatch(unknownProvider, /action="\/portal\/dns-credential"/);
  const running = renderCustomerPortal({ ...base, billing, domainName: "company.com", dnsState: "stored", onboardingState: "installing" });
  assert.match(running, /Setup is in progress — no action needed/);
  assert.doesNotMatch(running, /action="\/portal\/onboarding"/);
  const reconnect = renderCustomerPortal({ ...base, billing, domainName: "company.com", dnsState: "stored", detectedProvider: "namecom", onboardingState: "attention", onboardingError: "DNS_CREDENTIAL_REQUIRED" });
  assert.match(reconnect, /id="next-step-title">Reconnect your DNS provider/);
  assert.match(reconnect, /action="\/portal\/dns-credential"/);
  const ready = renderCustomerPortal({ ...base, billing, domainName: "company.com", dnsState: "stored", onboardingState: "installed", installerStatus: "succeeded" });
  assert.match(ready, /id="next-step-title">Create your first mailbox/);
  assert.match(ready, /Create a mailbox and set its password/);
  const unpaid = renderCustomerPortal({ ...base, billing: { ...billing, entitled: false, status: "none", trialAvailable: true } });
  assert.match(unpaid, /id="next-step-title">Start your subscription/);
  assert.doesNotMatch(unpaid, /action="\/portal\/domain"/);
});
