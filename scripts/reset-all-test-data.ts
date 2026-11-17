/** Full development reset. Deliberately does not clean external mail resources. */
import Stripe from "stripe";
import pg from "pg";
import { spawnSync } from "node:child_process";
import { createConnection } from "node:net";
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, parseEnv } from "node:util";
import { assertTestCancellation, cancelTestSubscriptions } from "./cancel-test-subscriptions.ts";
import { backupTestData, resetTestData } from "./reset-test-data.ts";
import { createAdminIdentity, identityTargets } from "./reset-google-test-data.ts";
import { deleteNonOperators, isProtected } from "./delete-google-users.ts";
import type { Queryable } from "../packages/servers/src/allocate.ts";

export function validateResetEnvironment(env: NodeJS.ProcessEnv, root: string) {
  assertTestCancellation(env);
  const database = new URL(env.MIGRATION_DATABASE_URL ?? "invalid:");
  if (!["127.0.0.1", "localhost", "[::1]"].includes(database.hostname) ||
      !/^bearportal(?:_test_[a-z0-9_]+)?$/.test(database.pathname.slice(1)))
    throw Error("Requires the local BearPortal development database.");
  const port = Number(env.PORT || "8088");
  if (!Number.isInteger(port) || port < 1 || port > 65535 ||
      !["127.0.0.1", "localhost", "::1", "0.0.0.0", "::"].includes(env.BEARPORTAL_BIND_HOST || "127.0.0.1"))
    throw Error("Requires a valid local API bind address and port.");
  if (!env.BEARPORTAL_SECRETS_DIR) throw Error("BEARPORTAL_SECRETS_DIR is required.");
  if (existsSync(join(root, ".data/server-migration-source.lock")))
    throw Error("Reset is blocked during server migration.");
}
export function selectStripeCustomer(
  customer: Stripe.Customer,
  local: Map<string, string>,
  protectedEmails: Set<string>,
): string | null {
  if (customer.livemode) throw Error("Stripe returned live-mode data; stopped.");
  const organization = local.get(customer.id) ?? customer.metadata.organizationId;
  if (!organization || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(organization)) return null;
  if (customer.metadata.organizationId !== organization)
    throw Error("Stripe customer organization metadata does not match local records.");
  if (customer.email && protectedEmails.has(customer.email.toLowerCase()))
    throw Error("A BearPortal Stripe customer matches a protected operator email; review manually.");
  return organization;
}
export function validateStripeSubscription(sub: Stripe.Subscription, customer: string, organization: string, price: string) {
  if (sub.livemode || (typeof sub.customer === "string" ? sub.customer : sub.customer.id) !== customer ||
      sub.metadata.organizationId !== organization || sub.items.has_more || sub.items.data.length !== 1 || sub.items.data[0]?.price.id !== price)
    throw Error("A selected Stripe customer has a subscription outside this BearPortal plan; review manually.");
}
async function system<T>(db: Queryable, work: () => Promise<T>) {
  await db.query("BEGIN");
  try {
    await db.query("SELECT set_config('bearportal.actor','platform_administrator',true)");
    const result = await work();
    await db.query("ROLLBACK");
    return result;
  } catch (error) { await db.query("ROLLBACK"); throw error; }
}
async function makePlan(db: Queryable, stripe: Stripe, google: ReturnType<typeof createAdminIdentity>, env: NodeJS.ProcessEnv) {
  const protection = await identityTargets(db, env);
  const local = await system(db, async () => {
    const active = await db.query(`SELECT 1 FROM jobs WHERE state='running' UNION ALL SELECT 1 FROM onboarding_requests WHERE state='installing' LIMIT 1`);
    if (active.rows.length) throw Error("An installation or job is running. Wait for it to finish before resetting.");
    const customers = (await db.query<{ customer_id: string; organization_id: string; email: string }>(
      "SELECT b.customer_id,b.organization_id,u.verified_email AS email FROM billing_subscriptions b JOIN organizations o ON o.id=b.organization_id JOIN users u ON u.id=o.owner_user_id WHERE b.customer_id IS NOT NULL",
    )).rows;
    if (customers.some(c => protection.protectedEmails.has(c.email.toLowerCase())))
      throw Error("A BearPortal Stripe customer belongs to a protected operator; review manually.");
    const counts = (await db.query(`SELECT
      (SELECT count(*)::int FROM users WHERE NOT EXISTS(SELECT 1 FROM operator_roles r WHERE r.user_id=users.id)) AS customers,
      (SELECT count(*)::int FROM servers) AS servers,
      (SELECT count(*)::int FROM relay_connections) AS brevo_accounts`)).rows[0];
    return { customers: new Map(customers.map(c => [c.customer_id, c.organization_id])), counts };
  });
  await google.permissions(protection.project);
  const identities = await google.list(protection.project);
  const preserved = identities.filter(u => isProtected(u, protection));
  if (!preserved.length) throw Error("No protected operator account found in Google; stopped.");
  const account = await stripe.accounts.retrieve(null);
  const selected: { id: string; email: string | null; organization: string; subscriptions: string[] }[] = [];
  let ignoredCustomers = 0;
  for await (const customer of stripe.customers.list({ limit: 100 })) {
    const organization = selectStripeCustomer(customer, local.customers, protection.protectedEmails);
    if (!organization) { ignoredCustomers++; continue; }
    const subscriptions: string[] = [];
    for await (const sub of stripe.subscriptions.list({ customer: customer.id, status: "all", limit: 100 })) {
      validateStripeSubscription(sub, customer.id, organization, env.STRIPE_PRICE_ID!);
      if (sub.status !== "canceled") subscriptions.push(sub.id);
    }
    selected.push({ id: customer.id, email: customer.email, organization, subscriptions });
  }
  // Also validate active local subscription bindings before any mutation.
  await cancelTestSubscriptions(db, stripe, env);
  return {
    googleProject: protection.project, stripeAccount: account.id,
    googlePreserved: preserved, googleSelected: identities.filter(u => !isProtected(u, protection)),
    stripeCustomers: selected, ignoredStripeCustomers: ignoredCustomers, local: local.counts,
    skipped: "External VMs/disks, remote mailboxes/backups, Brevo provider accounts/domains, DNS and existing backups are unchanged.",
  };
}

// Separate sequencing permits failure tests without touching real providers or systemd.
export async function executeFullReset(steps: {
  stop: () => Promise<void>; backup: () => Promise<void>;
  stripe: () => Promise<void>; google: () => Promise<void>;
  local: () => Promise<void>; verify: () => Promise<void>; start: () => Promise<void>;
}) {
  await steps.stop();
  await steps.backup();
  await steps.stripe();
  await steps.google();
  await steps.local();
  await steps.verify();
  await steps.start();
}
function service(action: "stop" | "start") {
  if (spawnSync("sudo", ["-n", "systemctl", action, "bearportal-api"], { stdio: "inherit" }).status !== 0)
    throw Error(`Could not ${action} bearportal-api. Run sudo -v first, or configure systemctl access for this user.`);
}
async function main() {
  const { values } = parseArgs({ options: {
    "env-file": { type: "string", default: ".data/trial/env" },
    project: { type: "string" }, "stripe-account": { type: "string" },
    "confirm-reset-all-test-data": { type: "boolean" }, help: { type: "boolean" },
  } });
  if (values.help) {
    console.log("pnpm reset:test-data:all\nDefault: read-only preview.\nExecute: --project PROJECT_ID --stripe-account acct_ID --confirm-reset-all-test-data\nCancels BearPortal test subscriptions, deletes matching Stripe customers, deletes all default-tenant Google users except operators, and clears local customers/inventory.\nIncludes Stripe customers with organizationId UUID metadata left after previous resets; unrelated/unmarked Stripe customers are skipped.\nPreserves operator access, configuration, products/prices and existing backups. Never cleans external mail resources.\nRequires gcloud admin login, Stripe list/delete permissions, PostgreSQL backup tools, and sudo systemctl access. On failure after stopping, API stays stopped; inspect receipts before restarting.");
    return;
  }
  const root = fileURLToPath(new URL("..", import.meta.url));
  const env = { ...process.env, ...parseEnv(readFileSync(values["env-file"]!, "utf8")) };
  validateResetEnvironment(env, root);
  if (values["confirm-reset-all-test-data"] &&
      (values.project !== env.BEARPORTAL_IDENTITY_PROJECT_ID || !values["stripe-account"]))
    throw Error("Confirmation requires the matching --project and --stripe-account from preview.");
  const db = new pg.Client({ connectionString: env.MIGRATION_DATABASE_URL });
  const stripe = new Stripe(env.STRIPE_SECRET_KEY!, { timeout: 15000, maxNetworkRetries: 2 });
  const google = createAdminIdentity();
  await db.connect();
  let stopped = false;
  let lock: string | undefined;
  let receiptPath: string | undefined;
  try {
    let plan = await makePlan(db, stripe, google, env);
    if ((values.project && values.project !== plan.googleProject) ||
        (values["stripe-account"] && values["stripe-account"] !== plan.stripeAccount))
      throw Error("Project or Stripe account does not match this deployment.");
    console.log(JSON.stringify({ preview: !values["confirm-reset-all-test-data"], ...plan }, null, 2));
    if (!values["confirm-reset-all-test-data"]) return;
    const data = join(root, ".data");
    const candidate = join(data, "full-test-reset.lock");
    if (existsSync(candidate)) throw Error("Reset lock already exists at .data/full-test-reset.lock. Check owner.json and ensure the previous process has ended before removing this stale lock.");
    mkdirSync(candidate, { mode: 0o700 }); // Existing lock fails closed; never remove another run's lock.
    lock = candidate;
    writeFileSync(join(lock, "owner.json"), JSON.stringify({ pid: process.pid, started: new Date().toISOString() }), { mode: 0o600 });
    const status = spawnSync("systemctl", ["is-active", "bearportal-api"], { encoding: "utf8" });
    const wasRunning = status.stdout.trim() === "active";
    if (!["active", "inactive", "failed"].includes(status.stdout.trim()))
      throw Error("Cannot determine API service state; stopped.");
    const port = Number(env.PORT || "8088");
    const bind = env.BEARPORTAL_BIND_HOST || "127.0.0.1";
    const host = bind === "::" ? "::1" : bind === "0.0.0.0" ? "127.0.0.1" : bind;
    const assertStopped = () => new Promise<void>((resolve, reject) => {
      const socket = createConnection({ host, port });
      socket.once("connect", () => { socket.destroy(); reject(Error("Reset requires the API listener to be stopped.")); });
      socket.once("error", (error: NodeJS.ErrnoException) => {
        socket.destroy();
        if (error.code === "ECONNREFUSED") resolve(); else reject(Error("Cannot determine whether the API listener stopped."));
      });
      socket.setTimeout(2000, () => { socket.destroy(); reject(Error("Cannot determine whether the API listener stopped.")); });
    });
    const receipt = { project: plan.googleProject, stripeAccount: plan.stripeAccount, planned: plan,
      completed: [] as { action: string; id?: string }[], complete: false };
    const save = () => {
      if (!receiptPath) throw Error("Backup receipt is not initialized.");
      writeFileSync(receiptPath + ".tmp", JSON.stringify(receipt, null, 2), { mode: 0o600 });
      renameSync(receiptPath + ".tmp", receiptPath);
    };
    const record = (action: string, id?: string) => { receipt.completed.push({ action, id }); save(); };
    await executeFullReset({
      stop: async () => { service("stop"); stopped = true; await assertStopped(); },
      backup: async () => {
        const snapshot = backupTestData(env as Record<string, string>, root);
        receiptPath = join(snapshot.backup, "full-reset-receipt.json");
        console.log("Private backup and receipt: " + snapshot.backup);
        // Refresh the plan after stopping signups/workers; credentials and raw cloud user responses are never saved.
        plan = await makePlan(db, stripe, google, env);
        if (plan.stripeAccount !== receipt.stripeAccount || plan.googleProject !== receipt.project)
          throw Error("Cloud account changed during preflight.");
        receipt.planned = plan; save();
      },
      stripe: async () => {
        await cancelTestSubscriptions(db, stripe, env, { confirm: true });
        record("local-subscriptions-canceled");
        for (const target of plan.stripeCustomers) {
          const customer = await stripe.customers.retrieve(target.id);
          if (customer.deleted) { record("stripe-customer-already-deleted", target.id); continue; }
          const protection = await identityTargets(db, env);
          if (selectStripeCustomer(customer, new Map([[target.id, target.organization]]), protection.protectedEmails) !== target.organization)
            throw Error("Stripe customer changed since preflight.");
          for await (const sub of stripe.subscriptions.list({ customer: target.id, status: "all", limit: 100 })) {
            validateStripeSubscription(sub, target.id, target.organization, env.STRIPE_PRICE_ID!);
            if (sub.status !== "canceled") {
              const canceled = await stripe.subscriptions.cancel(sub.id, { invoice_now: false, prorate: false });
              if (canceled.status !== "canceled") throw Error("Stripe cancellation was not confirmed.");
              record("stripe-subscription-canceled", sub.id);
            }
          }
          const deleted = await stripe.customers.del(target.id);
          if (!deleted.deleted) throw Error("Stripe customer deletion was not confirmed.");
          record("stripe-customer-deleted", target.id);
        }
      },
      google: async () => {
        await deleteNonOperators(plan.googleSelected, () => identityTargets(db, env), google,
          (uid, result) => record("google-" + result, uid));
      },
      local: async () => {
        await resetTestData(env as Record<string, string>, root, ["--confirm-clear-test-data"]);
        record("local-data-cleared");
      },
      verify: async () => {
        const remaining = await makePlan(db, stripe, google, env);
        if (remaining.googleSelected.length || remaining.stripeCustomers.length ||
            Number(remaining.local?.customers) || Number(remaining.local?.servers) || Number(remaining.local?.brevo_accounts))
          throw Error("Reset verification found remaining targets. Rerun preview and inspect the receipt.");
        record("verified");
      },
      start: async () => {
        if (wasRunning) {
          service("start");
          let healthy = false;
          for (let attempt = 0; attempt < 20; attempt++) {
            try {
              const response = await fetch(`http://${host === "::1" ? "[::1]" : host}:${port}/healthz`, { signal: AbortSignal.timeout(1000) });
              if (response.ok) { healthy = true; break; }
            } catch { /* Wait for the restarted API to bind. */ }
            await new Promise(resolve => setTimeout(resolve, 500));
          }
          if (!healthy) { service("stop"); throw Error("Could not verify API health after restart; API stopped again."); }
          stopped = false;
        }
        receipt.complete = true; save();
      },
    });
    console.log("Reset complete. Operator access is preserved. " + plan.skipped);
    console.log(wasRunning ? "API restarted. Sign out in your browser, then sign in again." : "API was already stopped and remains stopped. Start it with sudo systemctl start bearportal-api when ready.");
    console.log("Add clean servers and Brevo inventory before retesting installation.");
  } finally {
    if (stopped) console.error("API remains stopped. Inspect the private backup/receipt and rerun preview before retrying. Start manually with sudo systemctl start bearportal-api only when ready.");
    if (receiptPath) console.log("Receipt: " + receiptPath);
    if (lock) rmSync(lock, { recursive: true });
    await db.end();
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(error => {
  // Never print provider error objects, database connection URLs, tokens or key material.
  const safe = error instanceof Error && /^(Requires |This command|Only Stripe|STRIPE_PRICE|BEARPORTAL_|Reset |Confirmation |Project or Stripe|No protected|An installation|A selected Stripe|Stripe customer|A BearPortal Stripe|A subscription|Could not |Cannot determine|Cloud account|Google account|Google credentials|Google admin|Google returned|Google user|Invalid Google|Duplicate Google|Specify |An active operator|Database backup|Backup validation)/.test(error.message);
  console.error(safe ? error.message : "Full reset stopped. Check development configuration, cloud list/delete permissions, database backup tools and service access. Earlier cloud deletions cannot be rolled back; inspect the receipt and rerun preview.");
  process.exitCode = 1;
});
