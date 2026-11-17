import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAdminIdentity,
  planIdentityCleanup,
  deleteIdentityPlan,
  identityTargets,
  type AdminIdentity,
} from "../scripts/reset-google-test-data.ts";
import type { Queryable } from "../packages/servers/src/allocate.ts";
const env = {
  BEARPORTAL_ENV: "development",
  BEARPORTAL_IDENTITY_PROJECT_ID: "test-identity-project",
};
const customer = {
  uid: "customer-uid",
  email: "test@example.org",
  providers: ["password"],
};
function database() {
  return {
    query: async (sql: string) => ({
      rows: sql.includes("LEFT JOIN identity_accounts")
        ? [{ email: "operator@example.org", uid: "operator-uid" }]
        : sql.includes("SELECT lower(verified_email)")
          ? [{ email: customer.email }]
          : sql.includes("SELECT 1 FROM operator_roles")
            ? [{ ok: 1 }]
            : [],
    }),
  } as unknown as Queryable;
}
function admin() {
  const removed: string[] = [];
  let denied = false,
    failSecond = false;
  const api: AdminIdentity = {
    permissions: async () => {
      if (denied) throw Error("denied");
    },
    lookup: async (_project, email) =>
      email === customer.email ? [customer] : [],
    remove: async (_project, uid) => {
      if (failSecond && removed.length) throw Error("interrupted");
      removed.push(uid);
    },
  };
  return {
    api,
    removed,
    deny: () => (denied = true),
    interrupt: () => (failSecond = true),
  };
}
test("Google cleanup previews only local customer emails and protects operator emails and UIDs", async () => {
  const db = database(),
    google = admin();
  const plan = await planIdentityCleanup(db, google.api, env);
  assert.deepEqual(plan.users, [customer]);
  assert.deepEqual(google.removed, []);
  await assert.rejects(
    planIdentityCleanup(db, google.api, env, ["OPERATOR@example.org"]),
    /protected/,
  );
  const alias: AdminIdentity = {
    ...google.api,
    lookup: async () => [{ ...customer, uid: "operator-uid" }],
  };
  await assert.rejects(
    planIdentityCleanup(db, alias, env, [customer.email]),
    /protected operator UID/,
  );
  assert.deepEqual(google.removed, []);
});
test("Google cleanup refuses production, live billing and missing admin permissions before deletion", async () => {
  const db = database(),
    google = admin();
  await assert.rejects(
    identityTargets(db, { ...env, BEARPORTAL_ENV: "production" }),
    /development/,
  );
  await assert.rejects(
    identityTargets(db, { ...env, STRIPE_SECRET_KEY: "sk_live_synthetic" }),
    /live Stripe/,
  );
  google.deny();
  await assert.rejects(planIdentityCleanup(db, google.api, env), /denied/);
  assert.deepEqual(google.removed, []);
});
test("explicit emails find Google-only users after local reset; missing accounts are harmless", async () => {
  const db = database(),
    google = admin();
  const plan = await planIdentityCleanup(db, google.api, env, [
    customer.email,
    "missing@example.org",
  ]);
  assert.deepEqual(plan.missing, ["missing@example.org"]);
  assert.equal(plan.users.length, 1);
});
test("Google deletion rechecks bindings and saves private progress on partial failure", async () => {
  const db = database(),
    google = admin();
  const second = {
    uid: "second-uid",
    email: "second@example.org",
    providers: ["google.com"],
  };
  const api: AdminIdentity = {
    ...google.api,
    lookup: async (_project, email) =>
      email === customer.email ? [customer] : [second],
  };
  const plan = await planIdentityCleanup(db, api, env, [
    customer.email,
    second.email,
  ]);
  const root = mkdtempSync(join(tmpdir(), "bearportal-google-cleanup-"));
  try {
    const changed: AdminIdentity = {
      ...api,
      lookup: async () => [{ ...customer, uid: "changed-uid" }],
    };
    await assert.rejects(
      deleteIdentityPlan(db, changed, env, plan, root),
      /changed since preflight|mismatched/,
    );
    assert.deepEqual(google.removed, []);
    google.interrupt();
    await assert.rejects(
      deleteIdentityPlan(db, api, env, plan, root),
      /interrupted/,
    );
    const receipt = JSON.parse(
      readFileSync(join(root, "google-identity-cleanup.json"), "utf8"),
    );
    assert.deepEqual(receipt.deleted, [customer.uid]);
    assert.equal(receipt.complete, false);
    assert.equal(
      statSync(join(root, "google-identity-cleanup.json")).mode & 0o777,
      0o600,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("Google admin transport uses project-scoped OAuth and discards credential fields", async () => {
  const calls: { url: string; body: any }[] = [];
  const transport: typeof fetch = async (input, init) => {
    const url = String(input),
      body = JSON.parse(String(init?.body));
    calls.push({ url, body });
    assert.equal(
      (init?.headers as Record<string, string>).authorization,
      "Bearer private-token-canary",
    );
    assert.equal(
      (init?.headers as Record<string, string>)["x-goog-user-project"],
      env.BEARPORTAL_IDENTITY_PROJECT_ID,
    );
    return new Response(
      JSON.stringify(
        url.includes("testIamPermissions")
          ? {
              permissions: [
                "firebaseauth.users.get",
                "firebaseauth.users.delete",
              ],
            }
          : url.endsWith(":lookup")
            ? {
                users: [
                  {
                    localId: customer.uid,
                    email: customer.email,
                    passwordHash: "private-hash-canary",
                    salt: "private-salt-canary",
                    providerUserInfo: [{ providerId: "password" }],
                  },
                ],
              }
            : {},
      ),
      { status: 200 },
    );
  };
  const api = createAdminIdentity(transport, () => "private-token-canary");
  await api.permissions(env.BEARPORTAL_IDENTITY_PROJECT_ID);
  const users = await api.lookup(
    env.BEARPORTAL_IDENTITY_PROJECT_ID,
    customer.email,
  );
  assert.deepEqual(users, [customer]);
  assert.equal(JSON.stringify(users).includes("canary"), false);
  await api.remove(env.BEARPORTAL_IDENTITY_PROJECT_ID, customer.uid);
  assert.ok(
    calls[1].url.includes("/projects/test-identity-project/accounts:lookup"),
  );
  assert.deepEqual(calls[2].body, { localId: customer.uid });
  const denied = createAdminIdentity(
    async () =>
      new Response(
        JSON.stringify({ error: { message: "private-error-canary" } }),
        { status: 403 },
      ),
    () => "private-token-canary",
  );
  await assert.rejects(
    denied.permissions(env.BEARPORTAL_IDENTITY_PROJECT_ID),
    (error) =>
      error instanceof Error &&
      /Google admin access was denied/.test(error.message) &&
      !error.message.includes("canary"),
  );
  const missingPermissions = createAdminIdentity(
    async () =>
      new Response('{"permissions":["firebaseauth.users.get"]}', {
        status: 200,
      }),
    () => "token",
  );
  await assert.rejects(
    missingPermissions.permissions(env.BEARPORTAL_IDENTITY_PROJECT_ID),
    /firebaseauth.users.delete/,
  );
});
