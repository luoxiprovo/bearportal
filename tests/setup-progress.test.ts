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
    [{}, 1, false],
    [{ domainName: "example.com" }, 2, false],
    [connected, 3, false],
    [{ ...connected, onboardingState: "waiting_resources" }, 3, false],
    [{ ...connected, onboardingState: "queued", onboardingError: "DNS_PROPAGATION" }, 4, false],
    [{ ...connected, onboardingState: "installing" }, 5, false],
    [{ ...connected, onboardingState: "attention", onboardingError: "INSTALLER_FAILED", brevoAuthenticated: true, brevoVerified: true }, 5, false],
    [{ ...connected, onboardingState: "attention", onboardingError: "DNS_PROVIDER_CHANGED" }, 2, false],
    [{ ...connected, onboardingState: "installed", installerStatus: "tls_pending" }, 6, false],
    [{ ...connected, onboardingState: "installed", installerStatus: "succeeded" }, 6, true],
  ];
  for (const [state, current, complete] of cases) {
    const view = { ...base, ...state };
    assert.equal(setupProgress(view).current, current);
    assert.equal(setupProgress(view).complete, complete);
    const html = renderCustomerPortal(view);
    assert.equal((html.match(/aria-current="step"/g) ?? []).length, complete ? 0 : 1);
    assert.ok(html.includes('aria-label="Setup progress"'));
  }
  assert.match(setupProgress({ ...connected, onboardingState: "waiting_resources" }).note, /can’t give a completion time/);
  assert.match(setupProgress({ ...connected, onboardingState: "attention" }).note, /paused for our team/);
  const pending = renderCustomerPortal({ ...connected, onboardingState: "installed", installerStatus: "tls_pending" });
  assert.match(pending, /location.reload/);
  assert.doesNotMatch(pending, /Your setup is complete/);
  const ready = renderCustomerPortal({ ...connected, onboardingState: "installed", installerStatus: "succeeded" });
  assert.match(ready, /Mail delivery and mailbox access still need verification/);
  assert.doesNotMatch(ready, /location.reload/);
});
