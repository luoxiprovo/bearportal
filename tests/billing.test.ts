import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportSPKI, SignJWT } from "jose";
import Stripe from "stripe";
import { buildServer, bootstrapAdmin } from "../apps/api/src/server.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
import {
  trialEnd,
  readBillingConfig,
  subscriptionAccess,
} from "../apps/api/src/billing.ts";
import {
  renderCustomerPortal,
  type CustomerPortalView,
} from "../apps/api/src/portal.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const query = (sql: string) => queryTestDatabase(sql, superDatabaseUrl);
const q = (value: string) => "'" + value.replaceAll("'", "''") + "'";
const config = {
  secretKey: "sk_test_local",
  webhookSecret: "whsec_local",
  priceId: "price_bearportal",
  origin: "http://localhost:8088",
  taxEnabled: true,
  portalConfigurationId: "bpc_test_local",
};

test("free month uses calendar boundaries and configuration is complete", () => {
  assert.equal(
    new Date(trialEnd(new Date("2026-01-31T12:30:00Z")) * 1000).toISOString(),
    "2026-02-28T12:30:00.000Z",
  );
  assert.equal(
    new Date(trialEnd(new Date("2028-01-31T12:30:00Z")) * 1000).toISOString(),
    "2028-02-29T12:30:00.000Z",
  );
  assert.equal(
    new Date(trialEnd(new Date("2026-11-10T12:30:00Z")) * 1000).toISOString(),
    "2026-12-10T12:30:00.000Z",
  );
  assert.equal(readBillingConfig({}), undefined);
  const validEnv = {
    STRIPE_SECRET_KEY: "rk_test_local",
    STRIPE_WEBHOOK_SECRET: config.webhookSecret,
    STRIPE_PRICE_ID: config.priceId,
    BEARPORTAL_BILLING_ORIGIN: config.origin,
    BEARPORTAL_STRIPE_TAX_ENABLED: "1",
    STRIPE_PORTAL_CONFIGURATION_ID: "bpc_local",
  };
  assert.equal(readBillingConfig(validEnv)?.secretKey, "rk_test_local");
  assert.equal(readBillingConfig(validEnv)?.taxEnabled, true);
  assert.throws(() =>
    readBillingConfig({ ...validEnv, STRIPE_SECRET_KEY: "rk_live_local" }),
  );
  assert.equal(
    readBillingConfig({
      ...validEnv,
      STRIPE_SECRET_KEY: "rk_live_local",
      BEARPORTAL_STRIPE_MODE: "live",
    })?.secretKey,
    "rk_live_local",
  );

  assert.throws(() =>
    readBillingConfig({ STRIPE_SECRET_KEY: "sk_test_local" }),
  );
});

test("subscription gates installation, checkout is deduplicated, signed webhooks converge and cancellation opens manual cleanup", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events,billing_events CASCADE",
  );
  await query("UPDATE control_plane_state SET mode='normal' WHERE id=1");
  const pair = await generateKeyPair("RS256", { extractable: true });
  const issuer = "https://test.billing.local",
    audience = "billing-test";
  const admin = await bootstrapAdmin(
    databaseUrl,
    "billing-admin",
    "admin@example.org",
  );
  const uid = randomUUID(),
    org = randomUUID(),
    other = randomUUID(),
    otherOrg = randomUUID();
  await query(`INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES(${q(uid)},'billing-user','billing@example.org',true,'active'),(${q(other)},'other-user','other@example.org',true,'active');
    INSERT INTO organizations(id,owner_user_id,name,status,billing_required) VALUES(${q(org)},${q(uid)},'Billing test','active',true),(${q(otherOrg)},${q(other)},'Other','active',true)`);
  const token = async (subject: string, email: string) =>
    new SignJWT({
      email,
      email_verified: true,
      auth_time: Math.floor(Date.now() / 1000),
      amr: ["pwd", "totp"],
    })
      .setSubject(subject)
      .setIssuer(issuer)
      .setAudience(audience)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(pair.privateKey);
  const customerToken = await token("billing-user", "billing@example.org"),
    otherToken = await token("other-user", "other@example.org"),
    adminToken = await token("billing-admin", "admin@example.org");
  const stripe = new Stripe(config.secretKey);
  let customerCreates = 0,
    checkouts = 0,
    cancels = 0;
  let checkoutParams: Stripe.Checkout.SessionCreateParams | undefined;
  const until = Math.floor(Date.now() / 1000) + 3600 * 24 * 30;
  let sub = {
    id: "sub_local",
    customer: "cus_local",
    metadata: { organizationId: org },
    status: "trialing",
    trial_end: until,
    cancel_at_period_end: false,
    cancel_at: null,
    pause_collection: null,
    items: {
      data: [
        {
          price: {
            id: config.priceId,
            currency: "usd",
            unit_amount: 2000,
            recurring: { interval: "month", interval_count: 1 },
          },
          quantity: 1,
          current_period_end: until,
        },
      ],
    },
  } as unknown as Stripe.Subscription;
  let missingPrice = false;
  stripe.prices.retrieve = (async () => {
    if (missingPrice)
      throw new Stripe.errors.StripeInvalidRequestError({
        message: "No such price",
        code: "resource_missing",
        statusCode: 404,
      } as any);
    return {
      active: true,
      tax_behavior: "exclusive",
      id: config.priceId,
      currency: "usd",
      unit_amount: 2000,
      recurring: { interval: "month", interval_count: 1 },
    };
  }) as any;
  let taxReady = false;
  stripe.tax.settings.retrieve = (async () => ({
    status: taxReady ? "active" : "pending",
  })) as any;
  stripe.tax.registrations.list = (async () => ({
    data: taxReady ? [{ id: "taxreg_test", status: "active" }] : [],
  })) as any;
  stripe.customers.create = (async () => {
    customerCreates++;
    return { id: "cus_local" };
  }) as any;
  let checkoutComplete = false,
    legacyHosted = false,
    expiredSessions = 0;
  stripe.checkout.sessions.expire = (async () => {
    expiredSessions++;
    legacyHosted = false;
    return { status: "expired" };
  }) as any;
  stripe.checkout.sessions.create = (async (
    params: Stripe.Checkout.SessionCreateParams,
  ) => {
    checkouts++;
    checkoutParams = params;
    return {
      id: "cs_test_local",
      status: "open",
      ui_mode: "form",
      client_secret: "cs_test_local_secret_fixture",
      url: null,
    };
  }) as any;
  stripe.checkout.sessions.retrieve = (async () => ({
    id: "cs_test_local",
    customer: "cus_local",
    client_reference_id: org,
    status: checkoutComplete ? "complete" : "open",
    ui_mode: legacyHosted ? "hosted" : "form",
    client_secret: legacyHosted ? null : "cs_test_local_secret_fixture",
    url: legacyHosted ? "https://checkout.stripe.com/test" : null,
    subscription: checkoutComplete ? "sub_local" : null,
  })) as any;
  stripe.subscriptions.retrieve = (async () => sub) as any;
  stripe.subscriptions.cancel = (async (_id: string, params: any) => {
    assert.deepEqual(params, { invoice_now: false, prorate: false });
    cancels++;
    sub = { ...sub, status: "canceled" };
    return sub;
  }) as any;
  const app = await buildServer({
    databaseUrl,
    secretsDir: mkdtempSync(join(tmpdir(), "bearportal-billing-")),
    secretKeyHex: "ab".repeat(32),
    jwtPublicKeyPem: await exportSPKI(pair.publicKey),
    issuer,
    audience,
    billing: config,
    stripe,
    lookupNameservers: async () => ["ns1.name.com", "ns2.name.com"],
    onboardingIntervalMs: 0,
    schedulerToken: "billing-test-scheduler",
    operatorBrevo: {
      requestDomain: async () => {
        throw new Error("Stop at the provider boundary after allocation");
      },
    },
  });
  const request = (
    method: "GET" | "POST",
    url: string,
    payload?: unknown,
    auth = customerToken,
  ) =>
    app.inject({
      method,
      url,
      headers: {
        authorization: "Bearer " + auth,
        "idempotency-key": randomUUID(),
      },
      ...(payload ? { payload } : {}),
    });
  const checkout = (auth = customerToken) =>
    request("POST", "/portal/billing/checkout", { csrf: "1" }, auth);
  const webhook = async (
    id: string,
    type = "customer.subscription.updated",
    signature = true,
  ) => {
    const body = JSON.stringify({
      id,
      object: "event",
      livemode: false,
      type,
      data: {
        object: {
          id: type.startsWith("invoice.") ? "in_local" : sub.id,
          subscription: sub.id,
          customer: "cus_local",
        },
      },
    });
    return app.inject({
      method: "POST",
      url: "/webhooks/stripe",
      headers: {
        "content-type": "application/json",
        "stripe-signature": signature
          ? stripe.webhooks.generateTestHeaderString({
              payload: body,
              secret: config.webhookSecret,
            })
          : "invalid",
      },
      payload: body,
    });
  };
  try {
    const page = await request("GET", "/portal");
    assert.match(page.body, /First calendar month free/);
    assert.doesNotMatch(page.body, /action="\/portal\/domain"/);
    assert.doesNotMatch(page.body, /action="\/portal\/onboarding"/);
    const denied = await request("POST", "/v1/deployments", {
      domainId: randomUUID(),
      firstMailboxLocalPart: "hello",
      testMailConsent: true,
    });
    assert.equal(denied.statusCode, 402, denied.body);
    const provisionDenied = await request(
      "POST",
      `/v1/deployments/${randomUUID()}/provision`,
      { expectedVersion: 1 },
    );
    assert.equal(provisionDenied.statusCode, 402, provisionDenied.body);
    assert.equal(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    missingPrice = true;
    const setupError = await checkout();
    assert.equal(setupError.statusCode, 503, setupError.body);
    assert.equal(setupError.json().error.code, "BILLING_CONFIG_ERROR");
    assert.match(setupError.json().error.message, /contact the operator/);
    missingPrice = false;
    const [first, second] = await Promise.all([checkout(), checkout()]);
    assert.equal(first.statusCode, 200, first.body);
    assert.equal(second.statusCode, 200, second.body);
    assert.equal(checkouts, 1);
    assert.equal(customerCreates, 1);
    assert.ok(
      Math.abs(
        Number(checkoutParams?.subscription_data?.trial_end) - trialEnd(),
      ) < 5,
    );
    assert.equal(checkoutParams?.payment_method_collection, "always");
    assert.equal(checkoutParams?.line_items?.[0].price, config.priceId);
    assert.deepEqual(checkoutParams?.automatic_tax, { enabled: false });
    assert.equal(checkoutParams?.ui_mode, "form");
    assert.equal(checkoutParams?.billing_address_collection, "auto");
    assert.deepEqual(checkoutParams?.phone_number_collection, {
      enabled: false,
    });
    assert.equal(checkoutParams?.submit_type, "auto");
    assert.equal(
      checkoutParams?.integration_identifier,
      "custom_embedded_web_0001",
    );
    for (const key of [
      "success_url",
      "cancel_url",
      "name_collection",
      "customer_update",
      "tax_id_collection",
      "expires_at",
    ] as const)
      assert.equal(checkoutParams?.[key], undefined);
    assert.equal(checkoutParams?.customer, "cus_local");
    assert.equal(checkoutParams?.metadata?.organizationId, org);
    assert.equal(
      checkoutParams?.subscription_data?.metadata?.organizationId,
      org,
    );
    assert.equal(first.json().client_secret, "cs_test_local_secret_fixture");
    assert.equal(second.json().client_secret, first.json().client_secret);
    assert.equal(first.headers["cache-control"], "no-store");
    assert.match(page.body, /https:\/\/js.stripe.com\/dahlia\/stripe.js/);
    assert.match(page.body, /id="checkout-form"/);
    assert.equal(first.headers.location, undefined);
    legacyHosted = true;
    const migratedCheckout = await checkout();
    assert.equal(migratedCheckout.statusCode, 200, migratedCheckout.body);
    assert.equal(
      migratedCheckout.json().client_secret,
      first.json().client_secret,
    );
    assert.equal(
      expiredSessions,
      1,
      "a prior hosted session must be expired during the UI-mode switch",
    );
    assert.equal(checkouts, 2);

    assert.equal(
      (await webhook("evt_invalid", "customer.subscription.updated", false))
        .statusCode,
      400,
    );
    assert.equal(
      (
        await request(
          "GET",
          "/portal/billing/return?session_id=cs_test_local",
          undefined,
          otherToken,
        )
      ).statusCode,
      403,
    );
    checkoutComplete = true;
    const success = await request(
      "GET",
      "/portal/billing/return?session_id=cs_test_local",
    );
    assert.equal(success.statusCode, 303, success.body);
    assert.equal(success.headers.location, "/portal#setup-next-step");
    const subscribedPage = await request("GET", "/portal");
    assert.match(subscribedPage.body, /action="\/portal\/domain"/);
    assert.match(subscribedPage.body, /Add your domain/);
    assert.match(subscribedPage.body, /id="setup-next-step"/);
    assert.doesNotMatch(subscribedPage.body, /Resources are tight right now/);
    assert.doesNotMatch(
      subscribedPage.body,
      /action="\/portal\/billing\/checkout"/,
    );
    await query(
      `UPDATE billing_subscriptions SET status='invalid_plan' WHERE organization_id=${q(org)}`,
    );
    const recoveredPage = await request("GET", "/portal");
    assert.equal(recoveredPage.statusCode, 200, recoveredPage.body);
    assert.match(recoveredPage.body, /action="\/portal\/domain"/);
    assert.deepEqual(
      await query(
        `SELECT status FROM billing_subscriptions WHERE organization_id=${q(org)}`,
      ),
      [["trialing"]],
    );

    assert.match(
      (await request("GET", "/portal")).body,
      /Your first month is free/,
    );
    assert.notEqual(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    const domainSaved = await request("POST", "/portal/domain", {
      domain: "company.site",
      onboarding: "1",
      csrf: "1",
    });
    assert.equal(domainSaved.statusCode, 200, domainSaved.body);
    assert.match(domainSaved.body, /action="\/portal\/dns-credential"/);
    assert.deepEqual(
      await query(
        `SELECT normalized_name FROM domains WHERE organization_id=${q(org)}`,
      ),
      [["company.site"]],
    );
    const providerStep = await request("GET", "/portal");
    assert.match(providerStep.body, /Connect your domain/);
    assert.match(providerStep.body, /Continue Bearmail setup/);
    assert.match(providerStep.body, /action="\/portal\/dns-credential"/);
    assert.equal((await checkout()).statusCode, 409);
    let event = await webhook("evt_trial");
    assert.equal(event.statusCode, 200, event.body);
    event = await webhook("evt_trial");
    assert.equal(event.statusCode, 200, event.body);
    assert.deepEqual(
      await query("SELECT count(*) FROM billing_events WHERE id='evt_trial'"),
      [["1"]],
    );
    sub = { ...sub, status: "active" };
    assert.equal((await webhook("evt_paid")).statusCode, 200);
    assert.match(
      (await request("GET", "/portal")).body,
      /subscription is active/,
    );
    sub = {
      ...sub,
      latest_invoice: {
        id: "in_local",
        status: "draft",
        automatic_tax: { status: "requires_location_inputs" },
        last_finalization_error: { code: "customer_tax_location_invalid" },
      } as Stripe.Invoice,
    };
    assert.equal(
      (await webhook("evt_tax_failure", "invoice.finalization_failed"))
        .statusCode,
      200,
    );
    assert.equal(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    assert.match(
      (await request("GET", "/portal")).body,
      /Update your billing address/,
    );
    assert.equal(
      (await webhook("evt_stale_paid", "invoice.paid")).statusCode,
      200,
    );
    assert.equal(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
      "an old paid event must not clear a current invoice problem",
    );
    sub = {
      ...sub,
      latest_invoice: { id: "in_local", status: "paid" } as Stripe.Invoice,
    };
    assert.equal(
      (await webhook("evt_invoice_fixed", "invoice.paid")).statusCode,
      200,
    );
    assert.notEqual(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    sub = {
      ...sub,
      latest_invoice: { id: "in_local", status: "open" } as Stripe.Invoice,
    };
    assert.equal(
      (await webhook("evt_payment_action", "invoice.payment_action_required"))
        .statusCode,
      200,
    );
    assert.match(
      (await request("GET", "/portal")).body,
      /Confirm your payment with your bank/,
    );
    assert.equal(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    sub = {
      ...sub,
      latest_invoice: { id: "in_local", status: "paid" } as Stripe.Invoice,
    };
    assert.equal(
      (await webhook("evt_action_completed", "invoice.paid")).statusCode,
      200,
    );
    sub = { ...sub, status: "past_due" };
    assert.equal((await webhook("evt_failed")).statusCode, 200);
    assert.equal(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    sub = { ...sub, status: "trialing" };
    assert.equal((await webhook("evt_recovered")).statusCode, 200);
    const assignedServer = randomUUID(),
      assignedRelay = randomUUID();
    await query(`INSERT INTO servers(id,label,public_ipv4,profile_code,state,tenant_tainted_at) VALUES(${q(assignedServer)},'s-billing','8.8.4.4','e2-micro','assigned',now());
      INSERT INTO server_assignments(id,organization_id,server_id,reason) VALUES(${q(randomUUID())},${q(org)},${q(assignedServer)},'Billing test');
      INSERT INTO relay_connections(id,provider,label,provider_account_id,smtp_login,daily_limit,state) VALUES(${q(assignedRelay)},'brevo','b-billing','billing-brevo@example.org','smtp-login',300,'assigned');
      INSERT INTO relay_assignments(id,organization_id,relay_connection_id) VALUES(${q(randomUUID())},${q(org)},${q(assignedRelay)})`);
    assert.equal(
      (await request("POST", "/portal/billing/cancel", {})).statusCode,
      400,
    );
    const oldDeployment = randomUUID(), oldMailbox = randomUUID();
    await query(`INSERT INTO deployments(id,organization_id,lifecycle_state) VALUES(${q(oldDeployment)},${q(org)},'active');
      INSERT INTO mailboxes(id,organization_id,deployment_id,local_part,address,kind,state)
      VALUES(${q(oldMailbox)},${q(org)},${q(oldDeployment)},'hello','hello@company.site','customer','active')`);
    const canceled = await request("POST", "/portal/billing/cancel", {
      confirm: "1",
    });
    assert.equal(canceled.statusCode, 303, canceled.body);
    assert.equal(cancels, 1);
    assert.equal(
      (await request("POST", "/portal/billing/cancel", { confirm: "1" }))
        .statusCode,
      303,
    );
    assert.equal(cancels, 1);
    assert.equal((await webhook("evt_old_delivery")).statusCode, 200);
    assert.deepEqual(
      await query(
        `SELECT status,cleanup_required FROM billing_subscriptions WHERE organization_id=${q(org)}`,
      ),
      [["canceled", "t"]],
    );
    assert.deepEqual(
      await query(
        `SELECT count(*) FROM required_actions WHERE organization_id=${q(org)} AND code='billing.manual_release' AND state='open'`,
      ),
      [["1"]],
    );
    assert.equal(
      (await request("POST", "/portal/onboarding", { deployConsent: "1" }))
        .statusCode,
      402,
    );
    assert.match(
      (await request("GET", "/portal")).body,
      /subscription is canceled/,
    );
    const operator = await request("GET", "/operator", undefined, adminToken);
    assert.match(operator.body, /manual cleanup required/);
    assert.match(operator.body, /billing@example.org/);
    assert.match(operator.body, /Stop the mail service/);
    assert.match(operator.body, /8\.8\.4\.4/);
    assert.match(operator.body, /data-state="canceled_by_users"/);
    assert.match((await request("GET", "/operator?tab=brevo", undefined, adminToken)).body,
      /data-state="canceled_by_users"/);
    assert.deepEqual(
      await query(`SELECT state FROM servers WHERE id=${q(assignedServer)}`),
      [["assigned"]],
    );
    assert.deepEqual(
      await query(
        `SELECT state FROM relay_connections WHERE id=${q(assignedRelay)}`,
      ),
      [["assigned"]],
    );
    const cleanupUrl = `/operator/billing/${org}/cleanup`;
    assert.equal(
      (await request("POST", cleanupUrl, { confirm: "1" })).statusCode,
      403,
    );
    const blockedCleanup = await request(
      "POST",
      cleanupUrl,
      { confirm: "1" },
      adminToken,
    );
    assert.equal(blockedCleanup.statusCode, 409, blockedCleanup.body);
    for (const [type, id] of [["servers", assignedServer], ["brevo", assignedRelay]]) {
      const removal = await request("POST", `/operator/inventory/${type}/${id}/remove`,
        { expectedVersion: "1", confirm: "1", csrf: "1", idempotencyKey: randomUUID() }, adminToken);
      assert.equal(removal.statusCode, 303, removal.body);
    }
    assert.deepEqual(await query(
      `SELECT s.state,r.archived_at IS NOT NULL FROM servers s, relay_connections r
       WHERE s.id=${q(assignedServer)} AND r.id=${q(assignedRelay)}`,
    ), [["retired", "t"]]);
    const users = await request("GET", "/operator?tab=users", undefined, adminToken);
    assert.match(users.body, /Previous Brevo accounts/);
    assert.match(users.body, /b-billing · billing-brevo@example.org/);
    assert.match(users.body, /s-billing · 8\.8\.4\.4/);
    const acknowledged = await request(
      "POST",
      cleanupUrl,
      { confirm: "1" },
      adminToken,
    );
    assert.equal(acknowledged.statusCode, 303, acknowledged.body);
    assert.deepEqual(
      await query(
        `SELECT count(*) FROM required_actions WHERE organization_id=${q(org)} AND code='billing.manual_release' AND state='open'`,
      ),
      [["0"]],
    );
    assert.deepEqual(
      await query(
        `SELECT billing_trial_used_at IS NOT NULL FROM users WHERE id=${q(uid)}`,
      ),
      [["t"]],
    );

    assert.equal((await webhook("evt_after_manual_cleanup")).statusCode, 200);
    assert.deepEqual(
      await query(
        `SELECT cleanup_required FROM billing_subscriptions WHERE organization_id=${q(org)}`,
      ),
      [["f"]],
    );
    assert.deepEqual(
      await query(
        `SELECT count(*) FROM required_actions WHERE organization_id=${q(org)} AND code='billing.manual_release' AND state='open'`,
      ),
      [["0"]],
    );
    assert.match((await request("GET", "/portal")).body, /Resubscribe/);
    const secondCheckout = await checkout();
    assert.equal(secondCheckout.statusCode, 200, secondCheckout.body);
    assert.equal(customerCreates, 1);
    assert.equal(checkoutParams?.subscription_data?.trial_end, undefined);
    assert.equal((await webhook("evt_previous_subscription")).statusCode, 200);
    assert.deepEqual(await query(
      `SELECT status FROM billing_subscriptions WHERE organization_id=${q(org)};
       SELECT subscription_id,snapshot->>'status' FROM billing_subscription_history WHERE organization_id=${q(org)}`,
    ), [["pending"], ["sub_local", "canceled"]]);
    sub = { ...sub, id: "sub_returning", status: "active", trial_end: null };
    const reactivated = await webhook("evt_resubscribed");
    assert.equal(reactivated.statusCode, 200, reactivated.body);
    const returning = await request("GET", "/portal");
    assert.match(returning.body, /Your subscription is active/);
    assert.match(returning.body, /company.site/);
    assert.match(returning.body, /action="\/portal\/dns-credential"/);
    const newDeployment = randomUUID();
    await query(`INSERT INTO deployments(id,organization_id) VALUES(${q(newDeployment)},${q(org)});
      INSERT INTO mailboxes(id,organization_id,deployment_id,local_part,address,kind,state)
      VALUES(${q(randomUUID())},${q(org)},${q(newDeployment)},'hello','hello@company.site','customer','pending')`);
    assert.deepEqual(await query(
      `SELECT d.lifecycle_state,m.archived_at IS NOT NULL FROM deployments d JOIN mailboxes m ON m.deployment_id=d.id
       WHERE m.id=${q(oldMailbox)}`,
    ), [["deleted", "t"]]);

    const freshServer = randomUUID();
    await query(`INSERT INTO servers(id,label,public_ipv4,profile_code,operator_contact,state,validated_at,available_since,readiness_report)
      VALUES(${q(freshServer)},'returning-server','8.8.8.8','e2-micro','ops@example.org','available',now(),now(),'{"source":"ssh"}')`);
    const freshBrevo = await request("POST", "/operator/brevo-account", {
      loginEmail: "returning-brevo@example.org",
      apiKey: "private-api-test-key",
      smtpLogin: "returning-smtp",
      smtpKey: "private-smtp-test-key",
      dailyLimit: "300",
    }, adminToken);
    assert.equal(freshBrevo.statusCode, 200, freshBrevo.body);
    const resumeSetup = await request("POST", "/portal/dns-credential", {
      csrf: "1",
      onboarding: "1",
      deployConsent: "1",
      domain: "company.site",
      dnsUsername: "test-dns-user",
      dnsToken: "test-dns-api-token",
    });
    assert.equal(resumeSetup.statusCode, 303, resumeSetup.body);
    await query(`UPDATE onboarding_requests SET next_attempt_at=now() WHERE organization_id=${q(org)}`);
    const allocation = await app.inject({
      method: "POST",
      url: "/internal/onboarding/run",
      headers: { "x-bearportal-scheduler": "billing-test-scheduler" },
      payload: {},
    });
    assert.equal(allocation.statusCode, 200, allocation.body);
    assert.deepEqual(await query(
      `SELECT server_id FROM server_assignments WHERE organization_id=${q(org)} AND released_at IS NULL;
       SELECT r.provider_account_id FROM relay_assignments a JOIN relay_connections r ON a.relay_connection_id=r.id
       WHERE a.organization_id=${q(org)} AND a.released_at IS NULL`,
    ), [[freshServer], ["returning-brevo@example.org"]]);

    // Prices and quantities are checked against server configuration, never browser input.
    const invalid = {
      ...sub,
      items: { ...sub.items, data: [{ ...sub.items.data[0], quantity: 2 }] },
    };
    assert.equal(
      subscriptionAccess(invalid, config.priceId).status,
      "invalid_plan",
    );
    assert.equal(
      (
        await request(
          "POST",
          "/portal/billing/cancel",
          { confirm: "1" },
          otherToken,
        )
      ).statusCode,
      404,
    );
  } finally {
    await app.close();
  }
});
