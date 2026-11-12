import Stripe from "stripe";
import { randomUUID, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import type { InventoryContext } from "./inventory.ts";
import { HttpError } from "./errors.ts";

export type BillingConfig = {
  secretKey: string;
  webhookSecret: string;
  priceId: string;
  origin: string;
  taxEnabled?: boolean;
  portalConfigurationId?: string;
};
export function readBillingConfig(
  env: NodeJS.ProcessEnv,
): BillingConfig | undefined {
  const names = [
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_PRICE_ID",
    "BEARPORTAL_BILLING_ORIGIN",
  ] as const;
  if (!names.some((key) => env[key])) return undefined;
  if (names.some((key) => !env[key]))
    throw new Error(
      "Configure STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID and BEARPORTAL_BILLING_ORIGIN together.",
    );
  if (
    /^(sk|rk)_live_/.test(env.STRIPE_SECRET_KEY!) &&
    env.BEARPORTAL_STRIPE_MODE !== "live"
  )
    throw new Error(
      "Stripe is in test mode by default. Set BEARPORTAL_STRIPE_MODE=live explicitly before using live keys.",
    );
  const origin = new URL(env.BEARPORTAL_BILLING_ORIGIN!);
  if (
    origin.origin !== env.BEARPORTAL_BILLING_ORIGIN ||
    (origin.protocol !== "https:" &&
      !(
        env.BEARPORTAL_ENV !== "production" &&
        ["localhost", "127.0.0.1"].includes(origin.hostname)
      ))
  )
    throw new Error(
      "BEARPORTAL_BILLING_ORIGIN must be an HTTPS origin (localhost HTTP is allowed in development).",
    );
  if (
    !/^(sk|rk)_(test|live)_/.test(env.STRIPE_SECRET_KEY!) ||
    !env.STRIPE_WEBHOOK_SECRET!.startsWith("whsec_") ||
    !env.STRIPE_PRICE_ID!.startsWith("price_")
  )
    throw new Error("Invalid Stripe configuration.");
  return {
    secretKey: env.STRIPE_SECRET_KEY!,
    webhookSecret: env.STRIPE_WEBHOOK_SECRET!,
    priceId: env.STRIPE_PRICE_ID!,
    origin: origin.origin,
    taxEnabled: env.BEARPORTAL_STRIPE_TAX_ENABLED === "1",
    portalConfigurationId: env.STRIPE_PORTAL_CONFIGURATION_ID || undefined,
  };
}
export type BillingRow = {
  organization_id: string;
  customer_id: string | null;
  subscription_id: string | null;
  checkout_id: string | null;
  checkout_started_at: Date;
  checkout_attempt: number;
  checkout_integration_identifier: string | null;
  invoice_issue_code: string | null;
  status: string;
  trial_used_at: Date | null;
  trial_ends_at: Date | null;
  access_until: Date | null;
  cancel_requested_at: Date | null;
  cleanup_required: boolean;
};
export type BillingView = {
  status: string;
  entitled: boolean;
  configured: boolean;
  trialEndsAt: string | null;
  accessUntil: string | null;
  cleanupRequired: boolean;
  trialAvailable: boolean;
  invoiceIssue?: string | null;
};
export async function billingView(
  db: Queryable,
  organizationId: string,
  configured: boolean,
): Promise<BillingView> {
  const row = (
    await db.query<BillingRow>(
      "SELECT * FROM billing_subscriptions WHERE organization_id=$1",
      [organizationId],
    )
  ).rows[0];
  const owner = (
    await db.query<{ billing_trial_used_at: Date | null }>(
      "SELECT u.billing_trial_used_at FROM users u JOIN organizations o ON o.owner_user_id=u.id WHERE o.id=$1",
      [organizationId],
    )
  ).rows[0];
  return {
    invoiceIssue: row?.invoice_issue_code ?? null,
    trialAvailable: !owner?.billing_trial_used_at,
    status: row?.status ?? "none",
    entitled: Boolean(
      row &&
      ["trialing", "active"].includes(row.status) &&
      row.access_until &&
      new Date(row.access_until).getTime() > Date.now() &&
      !row.cancel_requested_at &&
      !row.invoice_issue_code,
    ),
    configured,
    trialEndsAt: row?.trial_ends_at?.toISOString() ?? null,
    accessUntil: row?.access_until?.toISOString() ?? null,
    cleanupRequired: row?.cleanup_required ?? false,
  };
}
export async function requireSubscription(
  db: Queryable,
  organizationId: string,
): Promise<void> {
  const row = (
    await db.query<BillingRow>(
      "SELECT * FROM billing_subscriptions WHERE organization_id=$1",
      [organizationId],
    )
  ).rows[0];
  if (
    !row ||
    !["trialing", "active"].includes(row.status) ||
    !row.access_until ||
    new Date(row.access_until).getTime() <= Date.now() ||
    row.cancel_requested_at ||
    row.invoice_issue_code
  )
    throw new HttpError(
      402,
      "SUBSCRIPTION_REQUIRED",
      "Subscribe to BearPortal before installing Bearmail. Your first month is free, then $20 USD per month plus applicable tax.",
    );
}
/** Calendar month, clamped to the final day when the next month is shorter. */
export function trialEnd(now = new Date()): number {
  const end = new Date(now);
  end.setUTCDate(1);
  end.setUTCMonth(end.getUTCMonth() + 2);
  end.setUTCDate(0);
  end.setUTCDate(Math.min(now.getUTCDate(), end.getUTCDate()));
  return Math.floor(end.getTime() / 1000);
}
export function subscriptionAccess(sub: Stripe.Subscription, priceId: string) {
  const item = sub.items.data[0];
  const validPrice =
    sub.items.data.length === 1 &&
    item?.price.id === priceId &&
    item.price.currency === "usd" &&
    item.price.unit_amount === 2000 &&
    item.price.recurring?.interval === "month" &&
    item.price.recurring.interval_count === 1 &&
    item.price.recurring.usage_type !== "metered" &&
    item.quantity === 1;
  const status =
    validPrice && !sub.pause_collection ? sub.status : "invalid_plan";
  return {
    status,
    until:
      status === "trialing"
        ? sub.trial_end
        : (item?.current_period_end ?? null),
  };
}

export function registerBilling(
  app: FastifyInstance,
  ctx: InventoryContext,
  config?: BillingConfig,
  injected?: Stripe,
) {
  const stripe =
    injected ??
    (config
      ? new Stripe(config.secretKey, { timeout: 15000, maxNetworkRetries: 2 })
      : undefined);
  const requireStripe = () => {
    if (!stripe || !config)
      throw new HttpError(
        503,
        "BILLING_UNAVAILABLE",
        "Subscriptions are not configured yet. Contact the operator.",
      );
    return { stripe, config };
  };
  const retrieveSubscription = (id: string) =>
    requireStripe().stripe.subscriptions.retrieve(id, {
      expand: ["latest_invoice"],
    });
  async function sync(
    db: Queryable,
    organizationId: string,
    sub: Stripe.Subscription,
    invoiceEvent?: { type: string; invoiceId: string },
  ) {
    const row = (
      await db.query<BillingRow>(
        "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
        [organizationId],
      )
    ).rows[0];
    const customer =
      typeof sub.customer === "string" ? sub.customer : sub.customer.id;
    if (
      !row ||
      row.customer_id !== customer ||
      sub.metadata.organizationId !== organizationId ||
      (row.subscription_id && row.subscription_id !== sub.id)
    )
      throw new HttpError(
        409,
        "BILLING_MISMATCH",
        "The subscription does not match this account.",
      );
    const { status, until } = subscriptionAccess(sub, config!.priceId);
    const invoice =
      sub.latest_invoice && typeof sub.latest_invoice !== "string"
        ? sub.latest_invoice
        : null;
    let invoiceIssue = row.invoice_issue_code;
    if (invoice?.status === "paid") invoiceIssue = null;
    else if (
      invoice?.last_finalization_error ||
      invoice?.automatic_tax?.status === "requires_location_inputs"
    ) {
      invoiceIssue =
        invoice.automatic_tax?.status === "requires_location_inputs" ||
        invoice.last_finalization_error?.code ===
          "customer_tax_location_invalid"
          ? "TAX_LOCATION_REQUIRED"
          : "INVOICE_FINALIZATION_FAILED";
    } else if (
      invoice &&
      invoiceEvent?.type === "invoice.payment_action_required" &&
      invoice.id === invoiceEvent.invoiceId
    )
      invoiceIssue = "PAYMENT_AUTHENTICATION_REQUIRED";
    const canceled =
      status === "canceled" ||
      sub.cancel_at_period_end ||
      Boolean(sub.cancel_at);
    // A local cancellation request is terminal for installation, even during webhook races.
    await db.query(
      `UPDATE billing_subscriptions SET subscription_id=$2,status=$3,
      trial_used_at=coalesce(trial_used_at,now()),trial_ends_at=to_timestamp($4),access_until=to_timestamp($5),
      cancel_requested_at=CASE WHEN $6 THEN coalesce(cancel_requested_at,now()) ELSE cancel_requested_at END,
      cleanup_required=cleanup_required OR ($6 AND cancel_requested_at IS NULL),invoice_issue_code=$7,updated_at=now() WHERE organization_id=$1`,
      [
        organizationId,
        sub.id,
        status,
        sub.trial_end,
        until,
        canceled,
        invoiceIssue,
      ],
    );
    await db.query(
      "UPDATE users SET billing_trial_used_at=coalesce(billing_trial_used_at,now()) WHERE id=(SELECT owner_user_id FROM organizations WHERE id=$1)",
      [organizationId],
    );
    if (canceled && !row.cancel_requested_at) {
      await db.query(
        `INSERT INTO required_actions(id,scope,organization_id,audience,code,instructions,state)
        VALUES($1,'tenant',$2,'operator','billing.manual_release','Subscription canceled. Manually stop the tenant service and release its server and Brevo account through the reviewed cleanup workflow. Preserve tenant data until retention and cleanup are complete.','open') ON CONFLICT DO NOTHING`,
        [randomUUID(), organizationId],
      );
      await db.query(
        "UPDATE onboarding_requests SET state='attention',last_error_code='SUBSCRIPTION_CANCELED',updated_at=now() WHERE organization_id=$1 AND state <> 'installed'",
        [organizationId],
      );
    }
    if (
      ["active", "trialing"].includes(status) &&
      !canceled &&
      !row.cancel_requested_at
    ) {
      await db.query(
        "UPDATE organizations SET billing_required=true WHERE id=$1",
        [organizationId],
      );
    }
  }
  async function system<T>(work: (db: Queryable) => Promise<T>) {
    return ctx.withSystem("inventory_worker", async (db) => {
      await ctx.setActor(db, "platform_administrator");
      return work(db);
    });
  }
  app.post("/portal/billing/checkout", async (request, reply) => {
    const { stripe, config } = requireStripe();
    reply.header("cache-control", "no-store");
    const owner = await ctx.withActor(
      request,
      "customer",
      async (_db, actor) => {
        ctx.requireVerified(actor);
        if (!actor.organizationId)
          throw new HttpError(
            422,
            "ORGANIZATION_REQUIRED",
            "Create an account first.",
          );
        ctx.consumeLimit(actor.userId, "checkout", 10, 60 * 60 * 1000);
        return { id: actor.organizationId, email: actor.email };
      },
    );
    // Persist the checkout intent before contacting Stripe. Retries reuse identical request
    // parameters even if Stripe succeeded but the following database transaction failed.
    const existingSecret = await system(async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        "billing." + owner.id,
      ]);
      await db.query(
        "INSERT INTO billing_subscriptions(organization_id,trial_ends_at,trial_used_at) SELECT o.id,to_timestamp($2),u.billing_trial_used_at FROM organizations o JOIN users u ON u.id=o.owner_user_id WHERE o.id=$1 ON CONFLICT DO NOTHING",
        [owner.id, trialEnd()],
      );
      const label =
        "bearos_billing_" +
        Array.from(randomBytes(8), (value) =>
          String.fromCharCode(97 + (value % 26)),
        ).join("");
      await db.query(
        "UPDATE billing_subscriptions SET checkout_integration_identifier=coalesce(checkout_integration_identifier,$2) WHERE organization_id=$1",
        [owner.id, label],
      );
      const row = (
        await db.query<BillingRow>(
          "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
          [owner.id],
        )
      ).rows[0];
      if (
        row.subscription_id ||
        row.cancel_requested_at ||
        row.cleanup_required
      )
        throw new HttpError(
          409,
          "SUBSCRIPTION_EXISTS",
          "This account already has a subscription. Manage it from your account or contact the operator.",
        );
      if (row.checkout_id) {
        const session = await stripe.checkout.sessions.retrieve(
          row.checkout_id,
        );
        if (
          session.status === "open" &&
          session.ui_mode === "form" &&
          session.client_secret
        )
          return session.client_secret;
        if (session.status === "open" && session.ui_mode !== "form")
          await stripe.checkout.sessions.expire(session.id);
        if (session.status === "complete")
          throw new HttpError(
            409,
            "BILLING_PROCESSING",
            "Your subscription is being confirmed. Refresh your account shortly.",
          );
      }
      if (
        new Date(row.checkout_started_at).getTime() < Date.now() - 1800_000 ||
        row.checkout_id
      ) {
        await db.query(
          "UPDATE billing_subscriptions SET checkout_id=NULL,checkout_started_at=now(),checkout_attempt=checkout_attempt+1,trial_ends_at=to_timestamp($2) WHERE organization_id=$1",
          [owner.id, trialEnd()],
        );
      }
      if (!row.customer_id) {
        const customer = await stripe.customers.create(
          { email: owner.email, metadata: { organizationId: owner.id } },
          { idempotencyKey: "customer." + owner.id },
        );
        await db.query(
          "UPDATE billing_subscriptions SET customer_id=$2 WHERE organization_id=$1",
          [owner.id, customer.id],
        );
      }
      return null;
    });
    if (existingSecret) return reply.send({ client_secret: existingSecret });
    const clientSecret = await system(async (db) => {
      const row = (
        await db.query<BillingRow>(
          "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
          [owner.id],
        )
      ).rows[0];
      if (row.subscription_id || row.cancel_requested_at)
        throw new HttpError(
          409,
          "SUBSCRIPTION_EXISTS",
          "This account already has a subscription.",
        );
      if (row.checkout_id) {
        const session = await stripe.checkout.sessions.retrieve(
          row.checkout_id,
        );
        if (
          session.status === "open" &&
          session.ui_mode === "form" &&
          session.client_secret
        )
          return session.client_secret;
        throw new HttpError(
          409,
          "BILLING_PROCESSING",
          "Your checkout is being processed. Refresh your account shortly.",
        );
      }
      const price = await stripe.prices.retrieve(config.priceId);
      if (
        !price.active ||
        price.currency !== "usd" ||
        price.unit_amount !== 2000 ||
        price.recurring?.interval !== "month" ||
        price.recurring.interval_count !== 1 ||
        price.recurring.usage_type === "metered"
      )
        throw new HttpError(
          503,
          "BILLING_PLAN_INVALID",
          "The subscription plan is not configured correctly. Contact the operator.",
        );
      if (price.tax_behavior !== "exclusive")
        throw new HttpError(
          503,
          "BILLING_PLAN_INVALID",
          "The subscription must use the tax-exclusive $20/month price.",
        );
      const customer = row.customer_id!;
      const session = await stripe.checkout.sessions.create(
        {
          mode: "subscription",
          ui_mode: "form",
          billing_address_collection: "auto",
          phone_number_collection: { enabled: false },
          automatic_tax: { enabled: false },
          payment_method_collection: "always",
          submit_type: "auto",
          integration_identifier: "custom_embedded_web_0001",
          customer,
          line_items: [{ price: config.priceId, quantity: 1 }],
          client_reference_id: owner.id,
          metadata: { organizationId: owner.id },
          subscription_data: {
            metadata: { organizationId: owner.id },
            ...(!row.trial_used_at
              ? { trial_end: Math.floor(row.trial_ends_at!.getTime() / 1000) }
              : {}),
            trial_settings: {
              end_behavior: { missing_payment_method: "cancel" },
            },
          },
        },
        {
          idempotencyKey:
            "checkout.form." + owner.id + "." + row.checkout_attempt,
        },
      );
      if (!session.client_secret)
        throw new HttpError(
          503,
          "BILLING_UNAVAILABLE",
          "Checkout is temporarily unavailable.",
        );
      await db.query(
        "UPDATE billing_subscriptions SET customer_id=$2,checkout_id=$3,updated_at=now() WHERE organization_id=$1",
        [owner.id, customer, session.id],
      );
      return session.client_secret;
    });
    return reply.send({ client_secret: clientSecret });
  });
  app.get("/portal/billing/return", async (request, reply) => {
    const { stripe } = requireStripe();
    const owner = await ctx.withActor(
      request,
      "customer",
      async (_db, actor) => {
        ctx.requireVerified(actor);
        return actor.organizationId;
      },
    );
    const sessionId = (request.query as { session_id?: string }).session_id;
    if (!owner || !sessionId || !/^cs_[a-zA-Z0-9_]+$/.test(sessionId))
      throw new HttpError(400, "VALIDATION", "Invalid checkout session.");
    await system(async (db) => {
      const row = (
        await db.query<BillingRow>(
          "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
          [owner],
        )
      ).rows[0];
      if (!row || row.checkout_id !== sessionId)
        throw new HttpError(
          403,
          "FORBIDDEN",
          "This checkout belongs to another account.",
        );
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      if (
        session.status !== "complete" ||
        typeof session.subscription !== "string" ||
        session.client_reference_id !== owner
      )
        throw new HttpError(
          409,
          "BILLING_PROCESSING",
          "Checkout is not complete. Return to your account and try again.",
        );
      await sync(db, owner, await retrieveSubscription(session.subscription));
    });
    ctx.onboardingRequested?.();
    return reply
      .code(303)
      .header("location", "/portal#setup-next-step")
      .send("");
  });
  app.post("/portal/billing/cancel", async (request, reply) => {
    const { stripe } = requireStripe();
    if ((request.body as Record<string, string>)?.confirm !== "1")
      throw new HttpError(
        400,
        "CONFIRM_REQUIRED",
        "Confirm subscription cancellation.",
      );
    const owner = await ctx.withActor(
      request,
      "customer",
      async (_db, actor) => {
        ctx.requireVerified(actor);
        return actor.organizationId;
      },
    );
    if (!owner)
      throw new HttpError(
        422,
        "ORGANIZATION_REQUIRED",
        "Create an account first.",
      );
    await system(async (db) => {
      const row = (
        await db.query<BillingRow>(
          "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
          [owner],
        )
      ).rows[0];
      if (!row?.subscription_id)
        throw new HttpError(404, "NOT_FOUND", "No subscription was found.");
      const latest = await retrieveSubscription(row.subscription_id);
      const sub =
        latest.status === "canceled"
          ? latest
          : await stripe.subscriptions.cancel(row.subscription_id, {
              invoice_now: false,
              prorate: false,
            });
      await sync(db, owner, sub);
      await db.query(
        `INSERT INTO audit_events(id,actor_type,organization_id,action,target,request_id,redacted_diff) VALUES($1,'system',$2,'billing.cancel',$3,$4,'{"manualReleaseRequired":true}'::jsonb)`,
        [randomUUID(), owner, row.subscription_id, request.id],
      );
    });
    return reply.code(303).header("location", "/portal").send("");
  });
  app.post("/portal/billing/manage", async (request, reply) => {
    const { stripe, config } = requireStripe();
    const owner = await ctx.withActor(
      request,
      "customer",
      async (_db, actor) => {
        ctx.requireVerified(actor);
        return actor.organizationId;
      },
    );
    const customer = await system(
      async (db) =>
        (
          await db.query<BillingRow>(
            "SELECT * FROM billing_subscriptions WHERE organization_id=$1",
            [owner],
          )
        ).rows[0]?.customer_id,
    );
    if (!customer)
      throw new HttpError(404, "NOT_FOUND", "No billing account was found.");
    const session = await stripe.billingPortal.sessions.create({
      customer,
      return_url: config.origin + "/portal",
      ...(config.portalConfigurationId
        ? { configuration: config.portalConfigurationId }
        : {}),
    });
    return reply.code(303).header("location", session.url).send("");
  });
  app.post("/operator/billing/:id/cleanup", async (request, reply) => {
    const id = (request.params as { id: string }).id;
    if (
      !/^[0-9a-f-]{36}$/i.test(id) ||
      (request.body as Record<string, string>)?.confirm !== "1"
    )
      throw new HttpError(
        400,
        "VALIDATION",
        "Confirm the completed manual cleanup.",
      );
    const actorId = await ctx.withActor(
      request,
      "operator",
      async (_db, actor) => {
        ctx.requireVerified(actor);
        ctx.requireMfa(actor);
        if (
          !actor.roles.some((role) =>
            ["platform_administrator", "infrastructure_operator"].includes(
              role,
            ),
          )
        )
          throw new HttpError(
            403,
            "FORBIDDEN",
            "An infrastructure operator is required.",
          );
        return actor.userId;
      },
    );
    await system(async (db) => {
      const row = (
        await db.query<BillingRow>(
          "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
          [id],
        )
      ).rows[0];
      if (!row?.cancel_requested_at)
        throw new HttpError(
          409,
          "CLEANUP_NOT_REQUIRED",
          "This subscription has not been canceled.",
        );
      const assigned = await db.query(
        "SELECT id FROM server_assignments WHERE organization_id=$1 AND released_at IS NULL UNION ALL SELECT id FROM relay_assignments WHERE organization_id=$1 AND released_at IS NULL",
        [id],
      );
      if (assigned.rows.length)
        throw new HttpError(
          409,
          "RESOURCES_STILL_ASSIGNED",
          "Release the server and Brevo assignments through the reviewed cleanup workflow first.",
        );
      await db.query(
        "UPDATE required_actions SET state='resolved',resolved_by=$2,resolved_at=now(),updated_at=now(),version=version+1 WHERE organization_id=$1 AND code='billing.manual_release' AND state='open'",
        [id, actorId],
      );
      await db.query(
        "UPDATE billing_subscriptions SET cleanup_required=false,updated_at=now() WHERE organization_id=$1",
        [id],
      );
      await ctx.audit(
        db,
        request,
        actorId,
        id,
        "billing.cleanup_confirmed",
        id,
        { resourcesReleasedManually: true },
      );
    });
    return reply.code(303).header("location", "/operator#actions").send("");
  });
  // Signature verification needs the original bytes, not Fastify's parsed/re-encoded JSON.
  app.register(async (scoped) => {
    scoped.removeContentTypeParser("application/json");
    scoped.addContentTypeParser(
      "application/json",
      { parseAs: "buffer" },
      (_request, body, done) => done(null, body),
    );
    scoped.post(
      "/webhooks/stripe",
      { bodyLimit: 1024 * 1024 },
      async (request, reply) => {
        const { stripe, config } = requireStripe();
        let event: Stripe.Event;
        try {
          event = stripe.webhooks.constructEvent(
            request.body as Buffer,
            request.headers["stripe-signature"] as string,
            config.webhookSecret,
          );
        } catch {
          throw new HttpError(
            400,
            "INVALID_SIGNATURE",
            "Invalid Stripe webhook signature.",
          );
        }
        if (event.livemode !== /^(sk|rk)_live_/.test(config.secretKey))
          throw new HttpError(
            400,
            "BILLING_MODE_MISMATCH",
            "Stripe mode mismatch.",
          );
        if (
          ![
            "checkout.session.completed",
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
            "invoice.paid",
            "invoice.payment_failed",
            "invoice.finalization_failed",
            "invoice.payment_action_required",
          ].includes(event.type)
        )
          return { received: true };
        const object = event.data.object as unknown as Record<string, any>;
        const subscriptionId = event.type.startsWith("customer.subscription.")
          ? object.id
          : (object.subscription ??
            object.parent?.subscription_details?.subscription);
        if (typeof subscriptionId !== "string") return { received: true };
        await system(async (db) => {
          const inserted = await db.query(
            "INSERT INTO billing_events(id) VALUES($1) ON CONFLICT DO NOTHING RETURNING id",
            [event.id],
          );
          if (!inserted.rows[0]) return;
          // Lock before retrieving the latest Stripe state; old events cannot restore stale access.
          const row = (
            await db.query<BillingRow>(
              "SELECT * FROM billing_subscriptions WHERE subscription_id=$1 OR customer_id=$2 FOR UPDATE",
              [subscriptionId, object.customer],
            )
          ).rows[0];
          if (!row)
            throw new HttpError(
              409,
              "BILLING_ACCOUNT_PENDING",
              "The billing account is not available yet. Retry this event.",
            );
          await sync(
            db,
            row.organization_id,
            await retrieveSubscription(subscriptionId),
            event.type.startsWith("invoice.")
              ? { type: event.type, invoiceId: object.id }
              : undefined,
          );
        });
        ctx.onboardingRequested?.();
        return reply.send({ received: true });
      },
    );
  });
  // Recover a previously rejected plan after its configuration is corrected. Access
  // still comes only from Stripe's current subscription, customer and price checks.
  return async (organizationId: string) => {
    if (!stripe || !config) return;
    await system(async (db) => {
      const row = (
        await db.query<BillingRow>(
          "SELECT * FROM billing_subscriptions WHERE organization_id=$1 FOR UPDATE",
          [organizationId],
        )
      ).rows[0];
      if (!row?.subscription_id || row.status !== "invalid_plan") return;
      await sync(
        db,
        organizationId,
        await retrieveSubscription(row.subscription_id),
      );
    });
  };
}
