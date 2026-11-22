import { test } from "node:test";
import assert from "node:assert/strict";
import { renderHome, renderOperatorAuth, renderCustomerPortal, type CustomerPortalView } from "../apps/api/src/portal.ts";
const text = (html: string) => html.replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/g, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

test("sign-in and account creation contain account actions without sales or installation copy", () => {
  for (const authMode of ["signin", "signup"] as const) {
    const html = renderHome({ managedAuth: true, mode: "identity", authMode });
    const copy = text(html);
    assert.doesNotMatch(copy, /\$20|first month|Cancel|How it works|dedicated server|Mailbox accounts/i);
    assert.match(html, /data-auth-form/);
    assert.match(html, /data-auth-google/);
    assert.match(html, /Forgot password/);
    assert.match(html, /data-auth-resume/);
  }
  const operator = renderOperatorAuth();
  assert.doesNotMatch(text(operator), /subscription|\$20|Create an account/i);
  assert.match(operator, /data-auth-form/);
  const security = renderOperatorAuth(true);
  assert.match(security, /recovery codes/);
  assert.match(security, /private setup key expires in 10 minutes/);
});

test("homepage presents pricing once; billing keeps price, payment method and cancellation details", () => {
  const home = text(renderHome({ managedAuth: true, mode: "identity" }));
  assert.equal((home.match(/\$20/g) ?? []).length, 1);
  const base: CustomerPortalView = {
    organizationId: "org", deploymentId: null, lifecycleState: null, onboardingStage: null,
    healthState: null, serverId: null, serverState: null, publicIpv4: null, webmailHostname: null,
    mailHostname: null, backupState: null, backupFreshness: "missing", requiredActions: [],
    mailVerified: false, cloudVerified: false,
  };
  const billing = { status: "none", entitled: false, configured: true, trialAvailable: true, trialEndsAt: null, accessUntil: null, cleanupRequired: false };
  const checkout = text(renderCustomerPortal({ ...base, billing }));
  assert.match(checkout, /\$20/);
  assert.match(checkout, /payment method is required/);
  assert.match(checkout, /Cancel before your first charge/);
  const customer = renderCustomerPortal({ ...base, billing: { ...billing, status: "active", entitled: true }, domainName: "example.com", detectedProvider: "namecom" });
  assert.match(text(customer), /update mail-routing DNS/);
  assert.match(text(customer), /Existing messages won’t be migrated/);
  assert.match(customer, /name="deployConsent"[^>]*required/);
  const canceledInstallation = renderCustomerPortal({ ...base, installerStatus: "succeeded", onboardingState: "installed", billing: { ...billing, status: "canceled", cleanupRequired: true } });
  assert.match(text(canceledInstallation), /Your subscription is canceled/);
  assert.match(text(canceledInstallation), /Future subscription billing has stopped/);
  assert.doesNotMatch(canceledInstallation, /data-reveal-admin/);
  const review = renderCustomerPortal({ ...base, domainName: "example.com", installerStatus: "succeeded", onboardingState: "attention", onboardingError: "OUTCOME_UNKNOWN" });
  assert.match(text(review), /An operator must check the server/);
  assert.doesNotMatch(text(review), /Create your first mailbox|Your setup is complete/);


});
