import { test } from "node:test";
import assert from "node:assert/strict";
import Stripe from "stripe";
import { executeFullReset, selectStripeCustomer, validateStripeSubscription, validateResetEnvironment } from "../scripts/reset-all-test-data.ts";
const organization = "1735ff56-c55a-4a47-8ad0-dc574a230db1";
const customer = { id: "cus_test", email: "customer@example.org", livemode: false, metadata: { organizationId: organization } } as unknown as Stripe.Customer;
const sub = { id: "sub_test", customer: customer.id, livemode: false, metadata: { organizationId: organization }, items: { data: [{ price: { id: "price_test" } }], has_more: false } } as unknown as Stripe.Subscription;

test("full reset refuses live mode, remote databases, and invalid local API ports", () => {
  const env = { BEARPORTAL_ENV: "development", STRIPE_SECRET_KEY: "sk_test_synthetic", STRIPE_PRICE_ID: "price_test", MIGRATION_DATABASE_URL: "postgres://localhost/bearportal", BEARPORTAL_SECRETS_DIR: "/tmp/secrets" };
  assert.doesNotThrow(() => validateResetEnvironment(env, "/tmp/nonexistent-reset-test"));
  assert.throws(() => validateResetEnvironment({ ...env, STRIPE_SECRET_KEY: "sk_live_synthetic" }, "/tmp"), /test keys/);
  assert.throws(() => validateResetEnvironment({ ...env, BEARPORTAL_ENV: "production" }, "/tmp"), /development/);
  assert.throws(() => validateResetEnvironment({ ...env, MIGRATION_DATABASE_URL: "postgres://remote.example/bearportal" }, "/tmp"), /local/);
  assert.throws(() => validateResetEnvironment({ ...env, PORT: "bad" }, "/tmp"), /port/);
});

test("Stripe selection includes tagged customers left after local reset, skips unmarked customers, and protects operators", () => {
  assert.equal(selectStripeCustomer(customer, new Map(), new Set()), organization);
  assert.equal(selectStripeCustomer({ ...customer, metadata: {} }, new Map(), new Set()), null);
  assert.throws(() => selectStripeCustomer(customer, new Map(), new Set([customer.email!])), /operator/);
  assert.throws(() => selectStripeCustomer({ ...customer, email: customer.email!.toUpperCase() }, new Map(), new Set([customer.email!])), /operator/);
  assert.throws(() => selectStripeCustomer({ ...customer, livemode: true }, new Map(), new Set()), /live-mode/);
  assert.throws(() => selectStripeCustomer(customer, new Map([[customer.id, "00000000-0000-0000-0000-000000000000"]]), new Set()), /metadata/);
});

test("all subscriptions on a selected customer must match the configured test plan before customer deletion", () => {
  assert.doesNotThrow(() => validateStripeSubscription(sub, customer.id, organization, "price_test"));
  for (const changed of [
    { ...sub, livemode: true }, { ...sub, customer: "cus_other" },
    { ...sub, metadata: { organizationId: "other" } },
    { ...sub, items: { data: [{ price: { id: "price_other" } }] } },
    { ...sub, items: { ...sub.items, has_more: true } },
  ]) assert.throws(() => validateStripeSubscription(changed as Stripe.Subscription, customer.id, organization, "price_test"), /outside/);
});

test("a failed backup prevents all cloud mutations and restart", async () => {
  const completed: string[] = [];
  const step = (name: string) => async () => { completed.push(name); };
  await assert.rejects(executeFullReset({
    stop: step("stop"), backup: async () => { throw Error("backup failed"); },
    stripe: step("stripe"), google: step("google"), local: step("local"), verify: step("verify"), start: step("start"),
  }), /backup failed/);
  assert.deepEqual(completed, ["stop"]);
});

test("failure at each destructive or verification stage leaves later data and service startup untouched", async () => {
  const order = ["stop", "backup", "stripe", "google", "local", "verify", "start"] as const;
  for (const failed of order) {
    const completed: string[] = [];
    const steps = Object.fromEntries(order.map(name => [name, async () => {
      if (name === failed) throw Error("failed " + name);
      completed.push(name);
    }])) as Parameters<typeof executeFullReset>[0];
    await assert.rejects(executeFullReset(steps), new RegExp("failed " + failed));
    assert.deepEqual(completed, order.slice(0, order.indexOf(failed)));
  }
});

test("success backs up before cloud deletion and restarts only after local reset verification", async () => {
  const completed: string[] = [];
  const names = ["stop", "backup", "stripe", "google", "local", "verify", "start"];
  const steps = Object.fromEntries(names.map(name => [name, async () => { completed.push(name); }])) as Parameters<typeof executeFullReset>[0];
  await executeFullReset(steps);
  assert.deepEqual(completed, names);
});
