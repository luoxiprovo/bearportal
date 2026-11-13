import Stripe from "stripe";
import pg from "pg";
import { readFileSync, existsSync } from "node:fs";
import { parseArgs, parseEnv } from "node:util";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import type { Queryable } from "../packages/servers/src/allocate.ts";

type Target = {
  organization_id: string;
  customer_id: string;
  subscription_id: string;
  email: string;
};
type Options = { confirm?: boolean; email?: string };
export function assertTestCancellation(env: NodeJS.ProcessEnv) {
  if (
    env.BEARPORTAL_ENV !== "development" ||
    process.env.BEARPORTAL_ENV === "production"
  )
    throw Error("This command requires development mode.");
  if (
    env.BEARPORTAL_STRIPE_MODE === "live" ||
    !/^(sk|rk)_test_/.test(env.STRIPE_SECRET_KEY ?? "")
  )
    throw Error(
      "Only Stripe test keys are allowed. Live subscriptions cannot be canceled by this command.",
    );
  if (!env.STRIPE_PRICE_ID?.startsWith("price_"))
    throw Error("STRIPE_PRICE_ID is required.");
}
async function system<T>(db: Queryable, work: () => Promise<T>): Promise<T> {
  await db.query("BEGIN");
  try {
    await db.query(
      "SELECT set_config('bearportal.actor','platform_administrator',true)",
    );
    const result = await work();
    await db.query("COMMIT");
    return result;
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }
}
function validate(sub: Stripe.Subscription, row: Target, price: string) {
  const customer =
    typeof sub.customer === "string" ? sub.customer : sub.customer.id;
  if (
    sub.livemode ||
    sub.id !== row.subscription_id ||
    customer !== row.customer_id ||
    sub.metadata.organizationId !== row.organization_id ||
    sub.items.data.length !== 1 ||
    sub.items.data[0]?.price.id !== price
  ) {
    throw Error(
      "A subscription does not match this BearPortal test deployment. Nothing else will be canceled; check Stripe account, customer, organization and price configuration.",
    );
  }
}
export async function cancelTestSubscriptions(
  db: Queryable,
  stripe: Pick<Stripe, "subscriptions">,
  env: NodeJS.ProcessEnv,
  options: Options = {},
) {
  assertTestCancellation(env);
  const targets = await system(
    db,
    async () =>
      (
        await db.query<Target>(
          `SELECT b.organization_id,b.customer_id,b.subscription_id,u.verified_email AS email
     FROM billing_subscriptions b JOIN organizations o ON o.id=b.organization_id JOIN users u ON u.id=o.owner_user_id
     WHERE b.subscription_id IS NOT NULL AND b.status <> 'canceled' AND ($1::text IS NULL OR lower(u.verified_email)=lower($1)) ORDER BY b.organization_id`,
          [options.email ?? null],
        )
      ).rows,
  );
  // Validate every target before the first destructive API request. Never enumerate the whole Stripe account.
  const checked: Array<{ row: Target; sub: Stripe.Subscription }> = [];
  for (const row of targets) {
    const sub = await stripe.subscriptions.retrieve(row.subscription_id);
    validate(sub, row, env.STRIPE_PRICE_ID!);
    checked.push({ row, sub });
  }
  if (!options.confirm)
    return {
      preview: true,
      subscriptions: checked.map(({ row, sub }) => ({
        email: row.email,
        subscriptionId: sub.id,
        status: sub.status,
      })),
      count: checked.length,
    };
  const completed: string[] = [];
  for (const { row } of checked) {
    // Recheck on retries; canceling an already-canceled subscription is unnecessary.
    let sub = await stripe.subscriptions.retrieve(row.subscription_id);
    validate(sub, row, env.STRIPE_PRICE_ID!);
    if (sub.status !== "canceled")
      sub = await stripe.subscriptions.cancel(sub.id, {
        invoice_now: false,
        prorate: false,
      });
    validate(sub, row, env.STRIPE_PRICE_ID!);
    if (sub.status !== "canceled")
      throw Error(
        "Stripe did not confirm immediate cancellation. Rerun the preview before retrying.",
      );
    await system(db, async () => {
      const result = await db.query<{ organization_id: string }>(
        `UPDATE billing_subscriptions SET status='canceled',access_until=now(),cancel_requested_at=coalesce(cancel_requested_at,now()),cleanup_required=true,updated_at=now()
         WHERE organization_id=$1 AND subscription_id=$2 AND customer_id=$3 RETURNING organization_id`,
        [row.organization_id, sub.id, row.customer_id],
      );
      if (!result.rows.length)
        throw Error(
          "The local subscription changed during cancellation. Rerun to reconcile it before resetting data.",
        );
      // Preserve normal operator cleanup requirements even if the webhook/API is unavailable.
      await db.query(
        `INSERT INTO required_actions(id,scope,organization_id,audience,code,instructions,state)
        SELECT $1,'tenant',$2,'operator','billing.manual_release','Test subscription canceled. Manually clean up the tenant service, server and Brevo resources before reusing them.','open'
        WHERE NOT EXISTS(SELECT 1 FROM required_actions WHERE organization_id=$2 AND code='billing.manual_release' AND state='open')`,
        [randomUUID(), row.organization_id],
      );
      await db.query(
        "UPDATE onboarding_requests SET state='attention',last_error_code='SUBSCRIPTION_CANCELED',updated_at=now() WHERE organization_id=$1 AND state <> 'installed'",
        [row.organization_id],
      );
      await db.query(
        `INSERT INTO audit_events(id,actor_type,organization_id,action,target,request_id,redacted_diff) VALUES($1,'system',$2,'billing.test_cancel',$3,$4,'{"manualReleaseRequired":true}'::jsonb)`,
        [randomUUID(), row.organization_id, sub.id, randomUUID()],
      );
    });
    completed.push(sub.id);
    console.log("Canceled test subscription: " + sub.id);
  }
  return {
    preview: false,
    canceled: completed.length,
    message:
      "Stripe and local records agree. Remote mail resources still require manual cleanup.",
  };
}
async function main() {
  const { values } = parseArgs({
    options: {
      "env-file": { type: "string", default: ".data/trial/env" },
      email: { type: "string" },
      "confirm-cancel-test-subscriptions": { type: "boolean" },
      help: { type: "boolean" },
    },
  });
  if (values.help) {
    console.log(
      "pnpm stripe:cancel-test-subscriptions [--email user@example.com] [--confirm-cancel-test-subscriptions]\nDefault: preview only. Targets only subscriptions recorded in this development database; requires Stripe test keys. Keep the API running until cancellation completes, then follow the test reset guide.",
    );
    return;
  }
  const env = {
    ...process.env,
    ...parseEnv(readFileSync(values["env-file"]!, "utf8")),
  };
  assertTestCancellation(env);
  if (
    existsSync(
      new URL("../.data/server-migration-source.lock", import.meta.url),
    )
  )
    throw Error(
      "Subscription cancellation is blocked during a server migration.",
    );
  if (!env.MIGRATION_DATABASE_URL)
    throw Error("MIGRATION_DATABASE_URL is required.");
  const db = new pg.Client({ connectionString: env.MIGRATION_DATABASE_URL });
  const stripe = new Stripe(env.STRIPE_SECRET_KEY!, {
    timeout: 15000,
    maxNetworkRetries: 2,
  });
  await db.connect();
  try {
    console.log(
      JSON.stringify(
        await cancelTestSubscriptions(db, stripe, env, {
          confirm: values["confirm-cancel-test-subscriptions"],
          email: values.email,
        }),
        null,
        2,
      ),
    );
  } finally {
    await db.end();
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  main().catch(() => {
    console.error(
      "Test cancellation stopped. Check development/test configuration, database and Stripe access, and account matching. Earlier successful cancellations remain canceled; rerun the preview to see remaining work. No API keys were logged.",
    );
    process.exitCode = 1;
  });
