import assert from "node:assert/strict";
import { test } from "node:test";
import Stripe from "stripe";
import pg from "pg";
import { randomUUID } from "node:crypto";
import {
  assertTestCancellation,
  cancelTestSubscriptions,
} from "../scripts/cancel-test-subscriptions.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
import type { Queryable } from "../packages/servers/src/allocate.ts";
const env = {
  BEARPORTAL_ENV: "development",
  STRIPE_SECRET_KEY: "sk_test_synthetic",
  STRIPE_PRICE_ID: "price_synthetic",
};
const row = {
  organization_id: randomUUID(),
  customer_id: "cus_synthetic",
  subscription_id: "sub_synthetic",
  email: "test@example.com",
};
function subscription(
  overrides: Record<string, unknown> = {},
): Stripe.Subscription {
  return {
    id: row.subscription_id,
    customer: row.customer_id,
    livemode: false,
    status: "trialing",
    metadata: { organizationId: row.organization_id },
    items: { data: [{ price: { id: env.STRIPE_PRICE_ID } }] },
    ...overrides,
  } as unknown as Stripe.Subscription;
}
function fakeStripe(subs: Stripe.Subscription[]) {
  const cancellations: string[] = [];
  const client = {
    subscriptions: {
      retrieve: async (id: string) => {
        const sub = subs.find((s) => s.id === id);
        if (!sub) throw Error("not found");
        return sub;
      },
      cancel: async (id: string, params: unknown) => {
        assert.deepEqual(params, { invoice_now: false, prorate: false });
        cancellations.push(id);
        const sub = subs.find((s) => s.id === id)!;
        sub.status = "canceled";
        return sub;
      },
    },
  } as unknown as Pick<Stripe, "subscriptions">;
  return { client, cancellations };
}
function fakeDb(rows: unknown[]) {
  return {
    query: async (sql: string) => ({
      rows: sql.includes("SELECT b.organization_id") ? rows : [],
    }),
  } as unknown as Queryable;
}
test("test cancellation rejects live keys and production before contacting Stripe", () => {
  assert.throws(
    () =>
      assertTestCancellation({
        ...env,
        STRIPE_SECRET_KEY: "sk_live_synthetic",
      }),
    /test keys/,
  );
  assert.throws(
    () => assertTestCancellation({ ...env, BEARPORTAL_ENV: "production" }),
    /development/,
  );
  assert.throws(
    () => assertTestCancellation({ ...env, BEARPORTAL_STRIPE_MODE: "live" }),
    /test keys/,
  );
});
test("default test cancellation previews local subscriptions without canceling", async () => {
  const stripe = fakeStripe([subscription()]);
  const result = await cancelTestSubscriptions(
    fakeDb([row]),
    stripe.client,
    env,
  );
  assert.equal(result.preview, true);
  assert.equal("count" in result && result.count, 1);
  assert.equal(stripe.cancellations.length, 0);
});
test("all targets are validated before any cancellation; live objects and mismatched metadata are rejected", async () => {
  const second = { ...row, subscription_id: "sub_other" };
  for (const bad of [
    { livemode: true },
    { customer: "cus_wrong" },
    { metadata: { organizationId: randomUUID() } },
    { items: { data: [{ price: { id: "price_other" } }] } },
  ]) {
    const stripe = fakeStripe([
      subscription(),
      subscription({ ...bad, id: second.subscription_id }),
    ]);
    await assert.rejects(
      cancelTestSubscriptions(fakeDb([row, second]), stripe.client, env, {
        confirm: true,
      }),
      /does not match/,
    );
    assert.deepEqual(stripe.cancellations, []);
  }
});
test("confirmed test cancellation reconciles PostgreSQL, creates cleanup task and safely repeats", async () => {
  const { migrationUrl, superDatabaseUrl } = integrationDatabases();
  await migrate(migrationUrl);
  const query = (sql: string) => queryTestDatabase(sql, superDatabaseUrl);
  await query(
    "TRUNCATE users,organizations,billing_subscriptions,required_actions CASCADE",
  );
  const user = randomUUID();
  await query(`INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES('${user}','cancel-test-user','test@example.com',true,'active');
 INSERT INTO organizations(id,owner_user_id,name,status) VALUES('${row.organization_id}','${user}','Cancellation test','active');
 INSERT INTO billing_subscriptions(organization_id,customer_id,subscription_id,status) VALUES('${row.organization_id}','${row.customer_id}','${row.subscription_id}','trialing');`);
  const db = new pg.Client({ connectionString: migrationUrl });
  await db.connect();
  const stripe = fakeStripe([subscription()]);
  try {
    await cancelTestSubscriptions(db, stripe.client, env, { confirm: true });
    assert.deepEqual(stripe.cancellations, [row.subscription_id]);
    assert.deepEqual(
      await query("SELECT status,cleanup_required FROM billing_subscriptions"),
      [["canceled", "t"]],
    );
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM required_actions WHERE code='billing.manual_release' AND state='open'",
      ),
      [["1"]],
    );
    // Simulate a lost local commit after Stripe succeeded: rerun reconciles without recanceling.
    await query("UPDATE billing_subscriptions SET status='trialing'");
    await cancelTestSubscriptions(db, stripe.client, env, { confirm: true });
    assert.deepEqual(stripe.cancellations, [row.subscription_id]);
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM required_actions WHERE code='billing.manual_release' AND state='open'",
      ),
      [["1"]],
    );
    const result = await cancelTestSubscriptions(db, stripe.client, env, {
      confirm: true,
    });
    assert.equal("canceled" in result && result.canceled, 0);
  } finally {
    await db.end();
  }
});
